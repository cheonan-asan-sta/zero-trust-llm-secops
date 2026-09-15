import asyncio

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult
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
