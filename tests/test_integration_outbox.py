import asyncio
import hashlib
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    DetectionPipelineResult,
    IntegrationDeliveryStatus,
    IntegrationDeliveryUpdateRequest,
)
from app.scenarios import synthetic_events
from app.services.cases import CaseStore, IncidentCaseService
from app.services.correlation import get_correlation_engine
from app.services.integration_outbox import (
    DynamoDBIntegrationOutboxStore,
    IntegrationOutboxService,
    IntegrationOutboxStore,
    OutboxNotDueError,
    OutboxTerminalStateError,
)
from app.services.ocsf import get_ocsf_normalizer
from app.services.sigma import get_sigma_engine

client = TestClient(app)


def _threat_events(prefix: str):
    return [
        event.model_copy(update={"event_id": f"{prefix}-{index}"})
        for index, event in enumerate(synthetic_events())
        if event.ground_truth.scenario_id.startswith("ZT-")
    ]


def _correlation(prefix: str, tenant_id: str = "local"):
    pipelines = []
    for event in _threat_events(prefix):
        normalized = get_ocsf_normalizer().normalize(event)
        pipelines.append(
            DetectionPipelineResult(
                normalized=normalized,
                detection=get_sigma_engine().evaluate(normalized),
            )
        )
    return get_correlation_engine().correlate(pipelines, tenant_id)


def _stores(tmp_path, tenant_id: str = "local", prefix: str = "outbox"):
    case_store = CaseStore(tmp_path / f"{tenant_id}-cases.jsonl")
    outbox_store = IntegrationOutboxStore(tmp_path / f"{tenant_id}-outbox.jsonl")
    outbox_service = IntegrationOutboxService(outbox_store)
    case_service = IncidentCaseService(case_store, outbox_service)
    cases, created, reused = asyncio.run(
        case_service.create_from_correlation(
            _correlation(prefix, tenant_id),
            tenant_id,
            "analyst-1",
            "Create case and durable integration event.",
        )
    )
    assert (created, reused) == (1, 0)
    return case_store, case_service, outbox_store, outbox_service, cases[0]


def test_case_api_automatically_queues_cloudevent() -> None:
    response = client.post(
        "/cases/from-events",
        json={
            "events": [
                event.model_dump(mode="json")
                for event in _threat_events("outbox-api-create")
            ],
            "note": "Queue a standards-based integration event.",
        },
    )
    case = response.json()["cases"][0]
    outbox = client.get("/integrations/outbox?limit=100")
    records = [item for item in outbox.json() if item["event"]["subject"] == case["case_id"]]

    assert response.status_code == 200
    assert outbox.status_code == 200
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "PENDING"
    assert record["delivery_mode"] == "simulation"
    assert record["event"]["specversion"] == "1.0"
    assert record["event"]["type"].endswith("incident-case.created")
    assert record["event"]["data"]["case_version"] == 1
    assert record["event"]["data"]["evidence_sha256"] == case["evidence_sha256"]
    assert "ground_truth" not in json.dumps(record)
    canonical = json.dumps(
        record["event"]["data"],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert record["event"]["data_sha256"] == hashlib.sha256(canonical.encode()).hexdigest()


def test_case_transitions_queue_one_immutable_event_per_version() -> None:
    creation = client.post(
        "/cases/from-events",
        json={
            "events": [
                event.model_dump(mode="json")
                for event in _threat_events("outbox-api-lifecycle")
            ]
        },
    ).json()
    record = creation["cases"][0]
    for status in ("TRIAGED", "INVESTIGATING"):
        response = client.patch(
            f"/cases/{record['case_id']}",
            json={
                "status": status,
                "expected_version": record["version"],
                "assignee": "SOC Analyst",
                "note": f"Advance integration test case to {status}.",
            },
        )
        assert response.status_code == 200
        record = response.json()

    repeated = client.post(
        "/cases/from-events",
        json={
            "events": [
                event.model_dump(mode="json")
                for event in _threat_events("outbox-api-lifecycle")
            ]
        },
    )
    events = client.get("/integrations/outbox?limit=100").json()
    case_events = [item for item in events if item["event"]["subject"] == record["case_id"]]

    assert repeated.status_code == 200
    assert repeated.json()["reused_case_count"] == 1
    assert len(case_events) == 3
    assert {item["event"]["data"]["case_version"] for item in case_events} == {1, 2, 3}
    assert len({item["event"]["id"] for item in case_events}) == 3


def test_reconciliation_repairs_missing_events_and_is_idempotent(tmp_path) -> None:
    case_store = CaseStore(tmp_path / "cases.jsonl")
    case_service = IncidentCaseService(case_store)
    cases, _, _ = asyncio.run(
        case_service.create_from_correlation(
            _correlation("outbox-reconcile"),
            "local",
            "analyst-1",
            "Create case before outbox recovery.",
        )
    )
    outbox_store = IntegrationOutboxStore(tmp_path / "outbox.jsonl")
    service = IntegrationOutboxService(outbox_store)

    first = asyncio.run(service.reconcile_case(cases[0]))
    second = asyncio.run(service.reconcile_case(cases[0]))

    assert first == (1, 0)
    assert second == (0, 1)
    assert outbox_store.metrics().total_events == 1


def test_retry_backoff_moves_event_to_dead_letter_after_max_attempts(tmp_path) -> None:
    _, _, store, service, _ = _stores(tmp_path, prefix="outbox-retry")
    record = store.recent(1)[0]
    due_at = record.next_attempt_at

    for attempt in range(1, 4):
        record = asyncio.run(
            service.record_attempt(
                record.event.id,
                "local",
                "dispatcher-1",
                IntegrationDeliveryUpdateRequest(
                    outcome="retryable_failure",
                    expected_version=record.version,
                    error_code="DESTINATION_UNAVAILABLE",
                    note=f"Simulated retryable delivery failure {attempt}.",
                ),
                now=due_at,
            )
        )
        if attempt == 1:
            assert record.next_attempt_at == due_at + timedelta(seconds=30)
        if record.next_attempt_at is not None:
            due_at = record.next_attempt_at

    assert record.status == IntegrationDeliveryStatus.DEAD_LETTER
    assert record.attempt_count == 3
    assert record.next_attempt_at is None
    assert record.last_error_code == "DESTINATION_UNAVAILABLE"
    assert len(record.history) == 4


def test_retry_cannot_run_early_and_delivered_event_is_terminal(tmp_path) -> None:
    _, _, store, service, _ = _stores(tmp_path, prefix="outbox-terminal")
    record = store.recent(1)[0]
    retry = asyncio.run(
        service.record_attempt(
            record.event.id,
            "local",
            "dispatcher-1",
            IntegrationDeliveryUpdateRequest(
                outcome="retryable_failure",
                expected_version=1,
                error_code="HTTP_503",
                note="Destination returned a retryable response.",
            ),
            now=record.next_attempt_at,
        )
    )
    delivered_request = IntegrationDeliveryUpdateRequest(
        outcome="delivered",
        expected_version=retry.version,
        note="Destination acknowledged the CloudEvent.",
    )

    with pytest.raises(OutboxNotDueError):
        asyncio.run(
            service.record_attempt(
                retry.event.id,
                "local",
                "dispatcher-1",
                delivered_request,
                now=retry.history[-1].recorded_at,
            )
        )

    delivered = asyncio.run(
        service.record_attempt(
            retry.event.id,
            "local",
            "dispatcher-1",
            delivered_request,
            now=retry.next_attempt_at,
        )
    )
    assert delivered.status == IntegrationDeliveryStatus.DELIVERED
    assert delivered.delivered_at == retry.next_attempt_at
    with pytest.raises(OutboxTerminalStateError):
        asyncio.run(
            service.record_attempt(
                delivered.event.id,
                "local",
                "dispatcher-1",
                IntegrationDeliveryUpdateRequest(
                    outcome="delivered",
                    expected_version=delivered.version,
                    note="Duplicate acknowledgement must be rejected.",
                ),
            )
        )


def test_outbox_store_restores_tenant_scoped_hash_chain(tmp_path) -> None:
    path = tmp_path / "outbox.jsonl"
    case_store = CaseStore(tmp_path / "cases.jsonl")
    store = IntegrationOutboxStore(path)
    publisher = IntegrationOutboxService(store)
    case_service = IncidentCaseService(case_store, publisher)
    for tenant_id in ("tenant-a", "tenant-b"):
        asyncio.run(
            case_service.create_from_correlation(
                _correlation(f"outbox-{tenant_id}", tenant_id),
                tenant_id,
                "analyst-1",
                "Queue tenant-isolated integration evidence.",
            )
        )
    restored = IntegrationOutboxStore(path)
    tenant_a = restored.recent(10, "tenant-a")
    tenant_b = restored.recent(10, "tenant-b")

    assert restored.integrity()["ok"] is True
    assert restored.integrity()["verified_lines"] == 2
    assert len(tenant_a) == len(tenant_b) == 1
    assert tenant_a[0].event.tenant_id == "tenant-a"
    assert restored.get(tenant_a[0].event.id, "tenant-b") is None


def test_outbox_tampering_fails_closed(tmp_path) -> None:
    _, _, store, _, _ = _stores(tmp_path, prefix="outbox-tamper")
    path = tmp_path / "tamper-copy.jsonl"
    source_record = store.recent(1)[0]
    clean = IntegrationOutboxStore(path)
    asyncio.run(clean.save(source_record))
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["record_hash"] = "0" * 64
    path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
    tampered = IntegrationOutboxStore(path)

    assert tampered.integrity()["ok"] is False
    with pytest.raises(RuntimeError, match="integrity check failed"):
        asyncio.run(tampered.save(source_record))


def test_outbox_api_lists_due_events_and_rejects_early_retry() -> None:
    creation = client.post(
        "/cases/from-events",
        json={
            "events": [
                event.model_dump(mode="json")
                for event in _threat_events("outbox-api-delivery")
            ]
        },
    ).json()
    case_id = creation["cases"][0]["case_id"]
    due = client.get("/integrations/outbox?limit=100&due_only=true").json()
    record = next(item for item in due if item["event"]["subject"] == case_id)
    retry = client.post(
        f"/integrations/outbox/{record['event']['id']}/attempt",
        json={
            "outcome": "retryable_failure",
            "expected_version": 1,
            "error_code": "HTTP_503",
            "note": "Simulate a temporary SIEM endpoint failure.",
        },
    )
    early = client.post(
        f"/integrations/outbox/{record['event']['id']}/attempt",
        json={
            "outcome": "delivered",
            "expected_version": 2,
            "note": "Attempt delivery before the scheduled retry time.",
        },
    )

    assert retry.status_code == 200
    assert retry.json()["status"] == "RETRY_SCHEDULED"
    assert early.status_code == 409
    assert "not due" in early.json()["detail"]


class _FakeDynamoOutboxTable:
    def __init__(self) -> None:
        self.item: dict | None = None

    def put_item(self, **kwargs: object) -> None:
        self.item = kwargs["Item"]

    def get_item(self, **_: object) -> dict:
        return {"Item": self.item} if self.item else {}

    def query(self, **_: object) -> dict:
        return {"Items": [self.item] if self.item else []}


def test_dynamodb_outbox_reuses_existing_tenant_table(tmp_path) -> None:
    _, _, local_store, _, _ = _stores(
        tmp_path,
        tenant_id="tenant-a",
        prefix="outbox-dynamo",
    )
    record = local_store.recent(1, "tenant-a")[0]
    fake_table = _FakeDynamoOutboxTable()
    store = DynamoDBIntegrationOutboxStore.__new__(DynamoDBIntegrationOutboxStore)
    store._table = fake_table

    asyncio.run(store.save(record))

    assert fake_table.item["record_type"] == "integration_outbox"
    assert fake_table.item["tenant_id"] == "tenant-a"
    assert "ground_truth" not in fake_table.item["payload"]
    assert store.get(record.event.id, "tenant-a") == record
    assert store.get(record.event.id, "tenant-b") is None
