import asyncio
import hashlib
import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import app
from app.models import DetectionPipelineResult, IncidentCaseStatus, IncidentCaseUpdateRequest
from app.scenarios import synthetic_events
from app.services.cases import (
    CaseConflictError,
    CaseStore,
    DynamoDBCaseStore,
    IncidentCaseService,
    InvalidCaseTransitionError,
)
from app.services.correlation import get_correlation_engine
from app.services.ocsf import get_ocsf_normalizer
from app.services.sigma import get_sigma_engine

client = TestClient(app)


def _threat_events(prefix: str):
    return [
        event.model_copy(update={"event_id": f"{prefix}-{index}"})
        for index, event in enumerate(synthetic_events())
        if event.ground_truth.scenario_id.startswith("ZT-")
    ]


def _benign_events(prefix: str):
    return [
        event.model_copy(update={"event_id": f"{prefix}-{index}"})
        for index, event in enumerate(synthetic_events())
        if not event.ground_truth.scenario_id.startswith("ZT-")
    ][:2]


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


def _create_case(prefix: str) -> dict:
    response = client.post(
        "/cases/from-events",
        json={
            "events": [event.model_dump(mode="json") for event in _threat_events(prefix)],
            "note": f"Create test case for {prefix}.",
        },
    )
    assert response.status_code == 200
    assert response.json()["created_case_count"] == 1
    return response.json()["cases"][0]


def test_case_creation_is_idempotent_and_exposes_metrics() -> None:
    payload = {
        "events": [
            event.model_dump(mode="json") for event in _threat_events("case-idempotent")
        ],
        "note": "Correlated evidence accepted by analyst.",
    }
    first = client.post("/cases/from-events", json=payload)
    second = client.post("/cases/from-events", json=payload)
    cases = client.get("/cases")
    metrics = client.get("/cases/metrics")

    assert first.status_code == second.status_code == 200
    assert first.json()["created_case_count"] == 1
    assert first.json()["reused_case_count"] == 0
    assert second.json()["created_case_count"] == 0
    assert second.json()["reused_case_count"] == 1
    assert first.json()["cases"][0]["case_id"] == second.json()["cases"][0]["case_id"]
    assert first.json()["cases"][0]["response_mode"] == "simulation"
    assert first.json()["cases"][0]["history"][0]["to_status"] == "NEW"
    assert any(item["case_id"] == first.json()["cases"][0]["case_id"] for item in cases.json())
    assert metrics.status_code == 200
    assert metrics.json()["total_cases"] >= 1
    assert metrics.json()["unassigned_case_count"] >= 1


def test_case_lifecycle_requires_ordered_transitions_and_keeps_history() -> None:
    record = _create_case("case-lifecycle")
    transitions = [
        IncidentCaseStatus.TRIAGED,
        IncidentCaseStatus.INVESTIGATING,
        IncidentCaseStatus.CONTAINED,
        IncidentCaseStatus.RESOLVED,
        IncidentCaseStatus.CLOSED,
    ]
    for expected_version, status in enumerate(transitions, start=1):
        response = client.patch(
            f"/cases/{record['case_id']}",
            json={
                "status": status.value,
                "expected_version": expected_version,
                "assignee": "Docker QA",
                "note": f"Move case to {status.value} after human review.",
            },
        )
        assert response.status_code == 200
        record = response.json()

    assert record["status"] == "CLOSED"
    assert record["version"] == 6
    assert len(record["history"]) == 6
    assert record["assignee"] == "Docker QA"
    assert {item["evidence_sha256"] for item in record["history"]} == {
        record["evidence_sha256"]
    }
    assert record["response_mode"] == "simulation"


def test_case_rejects_invalid_transition_and_stale_version() -> None:
    record = _create_case("case-conflict")
    invalid = client.patch(
        f"/cases/{record['case_id']}",
        json={
            "status": "RESOLVED",
            "expected_version": 1,
            "note": "Attempt to skip mandatory review stages.",
        },
    )
    triaged = client.patch(
        f"/cases/{record['case_id']}",
        json={
            "status": "TRIAGED",
            "expected_version": 1,
            "note": "Human analyst accepted the incident.",
        },
    )
    stale = client.patch(
        f"/cases/{record['case_id']}",
        json={
            "status": "INVESTIGATING",
            "expected_version": 1,
            "note": "Stale client attempts to overwrite the case.",
        },
    )

    assert invalid.status_code == 409
    assert triaged.status_code == 200
    assert triaged.json()["assignee"] == "local-operator"
    assert stale.status_code == 409
    assert "version conflict" in stale.json()["detail"]


def test_case_creation_with_no_correlated_incident_is_safe() -> None:
    response = client.post(
        "/cases/from-events",
        json={
            "events": [
                event.model_dump(mode="json") for event in _benign_events("case-benign")
            ]
        },
    )

    assert response.status_code == 200
    assert response.json()["correlation"]["incident_count"] == 0
    assert response.json()["created_case_count"] == 0
    assert response.json()["cases"] == []


def test_case_store_restores_hash_chain_and_isolates_tenants(tmp_path) -> None:
    path = tmp_path / "cases.jsonl"
    store = CaseStore(path)
    service = IncidentCaseService(store)

    async def create_for(tenant_id: str):
        cases, created, reused = await service.create_from_correlation(
            _correlation(f"tenant-{tenant_id}", tenant_id),
            tenant_id,
            "analyst-1",
            "Tenant-scoped incident evidence accepted.",
        )
        assert (created, reused) == (1, 0)
        return cases[0]

    tenant_a = asyncio.run(create_for("tenant-a"))
    tenant_b = asyncio.run(create_for("tenant-b"))
    restored = CaseStore(path)

    assert restored.integrity()["ok"] is True
    assert restored.integrity()["verified_lines"] == 2
    assert restored.get(tenant_a.case_id, "tenant-a") == tenant_a
    assert restored.get(tenant_a.case_id, "tenant-b") is None
    assert restored.get(tenant_b.case_id, "tenant-b") == tenant_b


def test_case_store_detects_tampering_and_refuses_new_writes(tmp_path) -> None:
    path = tmp_path / "cases.jsonl"
    store = CaseStore(path)
    service = IncidentCaseService(store)
    correlation = _correlation("tamper")
    cases, _, _ = asyncio.run(
        service.create_from_correlation(
            correlation,
            "local",
            "analyst-1",
            "Create immutable case evidence.",
        )
    )
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["record_hash"] = "0" * 64
    path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
    tampered = CaseStore(path)

    assert tampered.integrity()["ok"] is False
    with pytest.raises(RuntimeError, match="integrity check failed"):
        asyncio.run(tampered.save(cases[0]))


def test_service_rejects_stale_concurrent_update(tmp_path) -> None:
    store = CaseStore(tmp_path / "cases.jsonl")
    service = IncidentCaseService(store)
    cases, _, _ = asyncio.run(
        service.create_from_correlation(
            _correlation("service-conflict"),
            "local",
            "analyst-1",
            "Create case for concurrency test.",
        )
    )
    request = IncidentCaseUpdateRequest(
        status=IncidentCaseStatus.TRIAGED,
        expected_version=1,
        note="Triage the correlated incident.",
    )
    asyncio.run(service.transition(cases[0].case_id, "local", "responder-1", request))

    with pytest.raises(CaseConflictError, match="version conflict"):
        asyncio.run(service.transition(cases[0].case_id, "local", "responder-2", request))


def test_service_rejects_skipped_lifecycle_stage(tmp_path) -> None:
    store = CaseStore(tmp_path / "cases.jsonl")
    service = IncidentCaseService(store)
    cases, _, _ = asyncio.run(
        service.create_from_correlation(
            _correlation("service-transition"),
            "local",
            "analyst-1",
            "Create case for transition test.",
        )
    )
    request = IncidentCaseUpdateRequest(
        status=IncidentCaseStatus.CLOSED,
        expected_version=1,
        note="Attempt to skip the full incident lifecycle.",
    )

    with pytest.raises(InvalidCaseTransitionError):
        asyncio.run(service.transition(cases[0].case_id, "local", "responder-1", request))


def test_case_update_requires_meaningful_visible_note() -> None:
    with pytest.raises(ValidationError, match="three visible characters"):
        IncidentCaseUpdateRequest(
            status=IncidentCaseStatus.TRIAGED,
            expected_version=1,
            note="ab ",
        )


def test_case_api_enforces_tenant_boundary_and_responder_role(monkeypatch) -> None:
    analyst_key = "tenant-a-analyst-key"
    analyst_settings = Settings(
        auth_mode="api_key",
        api_key_sha256=hashlib.sha256(analyst_key.encode()).hexdigest(),
        api_key_subject="analyst-a",
        api_key_tenant_id="tenant-a",
        api_key_roles="analyst",
    )
    monkeypatch.setattr("app.security.get_settings", lambda: analyst_settings)
    response = client.post(
        "/cases/from-events",
        headers={"X-API-Key": analyst_key},
        json={
            "events": [
                event.model_dump(mode="json") for event in _threat_events("auth-tenant-a")
            ]
        },
    )
    case_id = response.json()["cases"][0]["case_id"]
    forbidden = client.patch(
        f"/cases/{case_id}",
        headers={"X-API-Key": analyst_key},
        json={
            "status": "TRIAGED",
            "expected_version": 1,
            "note": "Analyst without responder role attempts transition.",
        },
    )

    viewer_key = "tenant-b-viewer-key"
    viewer_settings = Settings(
        auth_mode="api_key",
        api_key_sha256=hashlib.sha256(viewer_key.encode()).hexdigest(),
        api_key_subject="viewer-b",
        api_key_tenant_id="tenant-b",
        api_key_roles="viewer",
    )
    monkeypatch.setattr("app.security.get_settings", lambda: viewer_settings)
    isolated = client.get(f"/cases/{case_id}", headers={"X-API-Key": viewer_key})

    assert response.status_code == 200
    assert forbidden.status_code == 403
    assert isolated.status_code == 404


class _FakeDynamoCaseTable:
    def __init__(self) -> None:
        self.item: dict | None = None

    def put_item(self, **kwargs: object) -> None:
        self.item = kwargs["Item"]

    def get_item(self, **_: object) -> dict:
        return {"Item": self.item} if self.item else {}

    def query(self, **_: object) -> dict:
        return {"Items": [self.item] if self.item else []}


def test_dynamodb_case_store_reuses_audit_table_without_plain_ground_truth(tmp_path) -> None:
    local_store = CaseStore(tmp_path / "source.jsonl")
    local_service = IncidentCaseService(local_store)
    cases, _, _ = asyncio.run(
        local_service.create_from_correlation(
            _correlation("dynamo-case", "tenant-a"),
            "tenant-a",
            "analyst-a",
            "Prepare a durable DynamoDB case snapshot.",
        )
    )
    fake_table = _FakeDynamoCaseTable()
    store = DynamoDBCaseStore.__new__(DynamoDBCaseStore)
    store._table = fake_table

    asyncio.run(store.save(cases[0]))

    assert fake_table.item["record_type"] == "incident_case"
    assert fake_table.item["version"] == 1
    assert "ground_truth" not in fake_table.item["payload"]
    assert store.get(cases[0].case_id, "tenant-a") == cases[0]
    assert store.get(cases[0].case_id, "tenant-b") is None
    assert store.recent(1, "tenant-a") == cases
