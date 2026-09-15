from app.models import (
    PolicyDecision,
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    SecurityEvent,
)

ALLOWED_ACTIONS = set(RecommendedAction)
_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def enforce_assessment_safety(
    assessment: SecurityAssessment,
    event: SecurityEvent | None = None,
) -> SecurityAssessment:
    updates: dict = {}
    score_level = _risk_level_for_score(assessment.risk_score)
    risk_level = max(
        (assessment.risk_level, score_level),
        key=lambda level: _RISK_ORDER[level],
    )
    action = assessment.recommended_action
    review = assessment.requires_human_review

    if risk_level != assessment.risk_level:
        updates["risk_level"] = risk_level

    if action not in ALLOWED_ACTIONS:
        action = RecommendedAction.HOLD_FOR_REVIEW
        review = True
    if assessment.confidence < 0.5:
        action = RecommendedAction.HOLD_FOR_REVIEW
        review = True
    if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        review = True
    if risk_level == RiskLevel.CRITICAL and action == RecommendedAction.ALLOW:
        action = RecommendedAction.HOLD_FOR_REVIEW
        review = True
    if action in {
        RecommendedAction.REDUCE_PRIVILEGE,
        RecommendedAction.ISOLATE_SESSION,
    }:
        review = True

    if event is not None:
        role_mismatch = bool(
            event.resource.required_role and event.user.role != event.resource.required_role
        )
        context_requires_review = (
            not event.user.active
            or event.device.security_posture == "compromised"
            or role_mismatch
        )
        if context_requires_review:
            review = True
            if action == RecommendedAction.ALLOW:
                action = RecommendedAction.HOLD_FOR_REVIEW

    if action != assessment.recommended_action:
        updates["recommended_action"] = action
    if review != assessment.requires_human_review:
        updates["requires_human_review"] = review
    return assessment.model_copy(update=updates) if updates else assessment


def response_preview(
    assessment: SecurityAssessment,
    event: SecurityEvent | None = None,
) -> PolicyDecision:
    safe = enforce_assessment_safety(assessment, event)
    review = safe.requires_human_review
    controls = ["simulation-only", "action-allowlist"]

    if assessment.confidence < 0.5:
        controls.append("low-confidence-hold")
    if safe.risk_level != assessment.risk_level:
        controls.append("risk-score-consistency")
    if safe.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        controls.append("high-risk-human-review")
    if safe.recommended_action in {
        RecommendedAction.REDUCE_PRIVILEGE,
        RecommendedAction.ISOLATE_SESSION,
    }:
        controls.append("disruptive-action-human-review")

    exception_id = None
    if event and event.behavior.policy_exception:
        exception_id = event.behavior.policy_exception.exception_id
        controls.append("scoped-exception-validated")

    if review:
        reason = "고위험 또는 불확실한 결과이므로 실제 조치 전에 사람 검토가 필요합니다."
    else:
        reason = "허용 목록과 위험 기준을 통과했습니다. 결과는 모의 대응으로만 반환합니다."

    return PolicyDecision(
        action=safe.recommended_action,
        allowed=safe.recommended_action in ALLOWED_ACTIONS,
        requires_human_review=review,
        reason=reason,
        controls_applied=controls,
        exception_id=exception_id,
    )


def _risk_level_for_score(score: int) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
