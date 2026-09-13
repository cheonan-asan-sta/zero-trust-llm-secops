import asyncio

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult
from app.scenarios import synthetic_events
from app.services.audit import AuditStore
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
