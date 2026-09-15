import asyncio

from openai import OpenAIError

from app.analyzers.base import Analyzer
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.config import Settings
from app.models import RiskLevel, SecurityAssessment, SecurityEvent, ViolationType

_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class HybridAnalyzer:
    name = "hybrid"

    def __init__(self, settings: Settings, llm: Analyzer | None = None) -> None:
        self._rule = RuleBasedAnalyzer()
        self._llm = llm or OpenAIAnalyzer(settings)
        self._confidence_threshold = settings.hybrid_confidence_threshold
        self._llm_timeout_seconds = settings.hybrid_llm_timeout_seconds

    async def analyze(self, event: SecurityEvent) -> SecurityAssessment:
        baseline = self._rule.assess(event)
        if baseline.confidence >= self._confidence_threshold:
            return baseline

        try:
            llm_assessment = await asyncio.wait_for(
                self._llm.analyze(event),
                timeout=self._llm_timeout_seconds,
            )
        except (TimeoutError, OpenAIError, RuntimeError, TypeError, ValueError):
            return baseline.model_copy(
                update={
                    "rationale": baseline.rationale
                    + " LLM 교차 검토를 완료하지 못해 사람 검토로 전환합니다.",
                    "requires_human_review": True,
                }
            )
        return self._merge(baseline, llm_assessment)

    def _merge(
        self,
        baseline: SecurityAssessment,
        llm_assessment: SecurityAssessment,
    ) -> SecurityAssessment:
        risk_level = max(
            (baseline.risk_level, llm_assessment.risk_level),
            key=lambda level: _RISK_ORDER[level],
        )
        violation = (
            baseline.violation_type
            if baseline.violation_type != ViolationType.NORMAL
            else llm_assessment.violation_type
        )
        action = self._rule.recommended_action(risk_level, violation)
        evidence = list(dict.fromkeys([*baseline.evidence, *llm_assessment.evidence]))[:20]
        return SecurityAssessment(
            risk_score=max(baseline.risk_score, llm_assessment.risk_score),
            risk_level=risk_level,
            violation_type=violation,
            rationale="규칙 기준선과 LLM 심층 검토를 결합했습니다. " + llm_assessment.rationale,
            recommended_action=action,
            confidence=round((baseline.confidence + llm_assessment.confidence) / 2, 3),
            evidence=evidence,
            requires_human_review=(
                baseline.requires_human_review
                or llm_assessment.requires_human_review
                or baseline.violation_type != llm_assessment.violation_type
            ),
        )
