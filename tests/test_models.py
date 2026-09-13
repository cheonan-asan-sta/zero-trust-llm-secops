import asyncio

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import RiskLevel
from app.scenarios import synthetic_events


def test_ground_truth_is_removed_from_analysis_payload() -> None:
    event = synthetic_events()[3]
    payload = event.analysis_payload()
    assert "ground_truth" not in payload


def test_synthetic_set_contains_normal_and_threat_events() -> None:
    events = synthetic_events()
    levels = {event.ground_truth.risk_level for event in events if event.ground_truth}
    assert RiskLevel.LOW in levels
    assert RiskLevel.CRITICAL in levels


def test_rule_baseline_matches_synthetic_risk_labels() -> None:
    analyzer = RuleBasedAnalyzer()
    for event in synthetic_events():
        result = asyncio.run(analyzer.analyze(event))
        assert event.ground_truth is not None
        assert result.risk_level == event.ground_truth.risk_level
