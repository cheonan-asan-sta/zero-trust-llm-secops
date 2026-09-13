from app.models import (
    PolicyDecision,
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
)

ALLOWED_ACTIONS = set(RecommendedAction)


def enforce_assessment_safety(assessment: SecurityAssessment) -> SecurityAssessment:
    updates: dict = {}

    if assessment.recommended_action not in ALLOWED_ACTIONS:
        updates["recommended_action"] = RecommendedAction.HOLD_FOR_REVIEW
        updates["requires_human_review"] = True

    if assessment.confidence < 0.5:
        updates["recommended_action"] = RecommendedAction.HOLD_FOR_REVIEW
        updates["requires_human_review"] = True

    if assessment.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        updates["requires_human_review"] = True

    if (
        assessment.risk_level == RiskLevel.CRITICAL
        and assessment.recommended_action == RecommendedAction.ALLOW
    ):
        updates["recommended_action"] = RecommendedAction.HOLD_FOR_REVIEW
        updates["requires_human_review"] = True

    return assessment.model_copy(update=updates) if updates else assessment


def response_preview(assessment: SecurityAssessment) -> PolicyDecision:
    safe = enforce_assessment_safety(assessment)
    review = safe.requires_human_review

    if review:
        reason = "고위험 또는 불확실한 결과이므로 실제 조치 전에 사람 검토가 필요합니다."
    else:
        reason = "허용 목록과 위험 기준을 통과했습니다. 결과는 모의 대응으로만 반환합니다."

    return PolicyDecision(
        action=safe.recommended_action,
        allowed=safe.recommended_action in ALLOWED_ACTIONS,
        requires_human_review=review,
        reason=reason,
    )
