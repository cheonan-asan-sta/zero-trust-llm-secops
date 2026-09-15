import asyncio

from app.analyzers.hybrid import HybridAnalyzer
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.config import Settings
from app.models import (
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    ViolationType,
)
from app.scenarios import synthetic_events


class FakeLLM:
    name = "fake-openai"

    def __init__(self, assessment: SecurityAssessment | None = None) -> None:
        self.calls = 0
        self.assessment = assessment

    async def analyze(self, event):
        self.calls += 1
        if self.assessment is None:
            raise RuntimeError("provider unavailable")
        return self.assessment


class SlowLLM:
    name = "slow-openai"

    async def analyze(self, event):
        await asyncio.sleep(1)
        raise AssertionError("timeout should cancel this call")


def _event(scenario_id: str):
    return next(
        event for event in synthetic_events() if event.ground_truth.scenario_id == scenario_id
    )


def test_high_confidence_rule_result_skips_llm() -> None:
    llm = FakeLLM()
    analyzer = HybridAnalyzer(Settings(), llm=llm)

    assessment = asyncio.run(analyzer.analyze(_event("NORMAL-01")))

    assert llm.calls == 0
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.recommended_action == RecommendedAction.ALLOW


def test_low_confidence_case_uses_llm_and_merges_conservatively() -> None:
    llm = FakeLLM(
        SecurityAssessment(
            risk_score=48,
            risk_level=RiskLevel.MEDIUM,
            violation_type=ViolationType.CREDENTIAL_ANOMALY,
            rationale="서로 다른 지역에서 인증 실패가 반복되었습니다.",
            recommended_action=RecommendedAction.REQUIRE_MFA,
            confidence=0.92,
            evidence=["network.location_anomaly"],
            requires_human_review=False,
        )
    )
    analyzer = HybridAnalyzer(Settings(), llm=llm)

    assessment = asyncio.run(analyzer.analyze(_event("ZT-S02")))

    assert llm.calls == 1
    assert assessment.risk_level == RiskLevel.MEDIUM
    assert assessment.recommended_action == RecommendedAction.REQUIRE_MFA
    assert "network.location_anomaly" in assessment.evidence


def test_llm_failure_falls_back_to_rule_and_requires_review() -> None:
    llm = FakeLLM()
    analyzer = HybridAnalyzer(Settings(), llm=llm)
    event = _event("ZT-S02")
    baseline = RuleBasedAnalyzer().assess(event)

    assessment = asyncio.run(analyzer.analyze(event))

    assert llm.calls == 1
    assert assessment.risk_level == baseline.risk_level
    assert assessment.violation_type == baseline.violation_type
    assert assessment.recommended_action == baseline.recommended_action
    assert assessment.requires_human_review is True


def test_llm_timeout_stays_inside_latency_budget() -> None:
    analyzer = HybridAnalyzer(
        Settings(hybrid_llm_timeout_seconds=0.5),
        llm=SlowLLM(),
    )

    assessment = asyncio.run(analyzer.analyze(_event("ZT-S02")))

    assert assessment.requires_human_review is True
    assert "사람 검토" in assessment.rationale
