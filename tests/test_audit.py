import asyncio
import json
from datetime import UTC, datetime

import pytest

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult, ReviewStatus
from app.scenarios import synthetic_events
from app.services.audit import AuditStore, DynamoDBAuditStore
from app.services.policy import response_preview


def test_audit_history_survives_restart(tmp_path) -> None:
    event = synthetic_events()[1]
    assessment = asyncio.run(RuleBasedAnalyzer().analyze(event))
    result = AnalysisResult(
        event_id=event.event_id,
        analyzer="rule",
        assessment=assessment,
        policy_decision=response_preview(assessment),
        latency_ms=1.5,
    )
    log_path = tmp_path / "audit.jsonl"

    first_store = AuditStore(log_path)
    asyncio.run(first_store.save(result))
    restored_store = AuditStore(log_path)

    assert restored_store.get(event.event_id) is not None
    assert restored_store.metrics().total_analyses == 1
    assert restored_store.recent(1)[0].event_id == event.event_id


def test_review_update_replaces_audit_snapshot_without_double_counting(tmp_path) -> None:
    event = synthetic_events()[4]
    assessment = asyncio.run(RuleBasedAnalyzer().analyze(event))
    result = AnalysisResult(
        event_id=event.event_id,
        analyzer="rule",
        assessment=assessment,
        policy_decision=response_preview(assessment, event),
        latency_ms=1.5,
    )
    log_path = tmp_path / "audit.jsonl"
    store = AuditStore(log_path)
    asyncio.run(store.save(result))

    updated = AnalysisResult.model_validate(
        {
            **result.model_dump(),
            "review_status": ReviewStatus.RESOLVED,
            "reviewer": "보안담당자",
            "review_note": "승인되지 않은 다운로드 세션을 종료했습니다.",
            "review_updated_at": datetime.now(UTC),
        }
    )
    asyncio.run(store.save(updated))

    restored = AuditStore(log_path)
    assert restored.metrics().total_analyses == 1
    assert restored.metrics().pending_review_count == 0
    assert restored.get(event.event_id).review_status == ReviewStatus.RESOLVED
    assert restored.recent(1)[0].reviewer == "보안담당자"


def test_audit_store_isolates_tenants(tmp_path) -> None:
    event = synthetic_events()[1]
    assessment = asyncio.run(RuleBasedAnalyzer().analyze(event))
    base = {
        "event_id": event.event_id,
        "analyzer": "rule",
        "assessment": assessment,
        "policy_decision": response_preview(assessment, event),
        "latency_ms": 1.0,
    }
    store = AuditStore(tmp_path / "audit.jsonl")
    asyncio.run(store.save(AnalysisResult(**base, tenant_id="tenant-a")))
    asyncio.run(store.save(AnalysisResult(**base, tenant_id="tenant-b")))

    assert store.metrics("tenant-a").total_analyses == 1
    assert store.metrics("tenant-b").total_analyses == 1
    assert store.get(event.event_id, "tenant-a").tenant_id == "tenant-a"
    assert store.get(event.event_id, "tenant-b").tenant_id == "tenant-b"


def test_audit_hash_chain_detects_tampering_and_refuses_append(tmp_path) -> None:
    event = synthetic_events()[1]
    assessment = asyncio.run(RuleBasedAnalyzer().analyze(event))
    record = AnalysisResult(
        event_id=event.event_id,
        analyzer="rule",
        assessment=assessment,
        policy_decision=response_preview(assessment, event),
        latency_ms=1.0,
    )
    log_path = tmp_path / "audit.jsonl"
    store = AuditStore(log_path)
    asyncio.run(store.save(record))

    envelope = json.loads(log_path.read_text(encoding="utf-8"))
    envelope["payload"] = envelope["payload"].replace(event.event_id, "tampered-event")
    log_path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")

    restored = AuditStore(log_path)
    assert restored.integrity()["ok"] is False
    assert restored.get(event.event_id) is None
    with pytest.raises(RuntimeError, match="integrity"):
        asyncio.run(restored.save(record))


class _FakeDynamoTable:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def put_item(self, *, Item: dict) -> None:
        self.items.append(Item)

    def query(self, **_: object) -> dict:
        return {"Items": list(reversed(self.items))}

    def scan(self, **_: object) -> dict:
        return {"Items": self.items}


def test_dynamodb_store_serializes_results_without_plain_event_data() -> None:
    event = synthetic_events()[1]
    assessment = asyncio.run(RuleBasedAnalyzer().analyze(event))
    record = AnalysisResult(
        event_id=event.event_id,
        analyzer="rule",
        assessment=assessment,
        policy_decision=response_preview(assessment, event),
        latency_ms=2.5,
    )
    fake_table = _FakeDynamoTable()
    store = DynamoDBAuditStore.__new__(DynamoDBAuditStore)
    store._table = fake_table

    asyncio.run(store.save(record))

    assert fake_table.items[0]["event_id"] == event.event_id
    assert "ground_truth" not in fake_table.items[0]["payload"]
    assert store.recent(1)[0].analysis_id == record.analysis_id
    assert store.metrics().average_latency_ms == 2.5
