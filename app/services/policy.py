from app.analyzers.rule_based import LARGE_DOWNLOAD_MB
from app.models import (
    EventAction,
    PolicyDecision,
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    SecurityEvent,
    VerifiedReviewControls,
)

ALLOWED_ACTIONS = set(RecommendedAction)
MEDIUM_RISK_SCORE = 25
SCOPED_DOWNLOAD_REASON = "승인 범위에 맞는 대량 다운로드에 민감 자료의 잔여 위험을 반영했습니다."
_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def enforce_verified_review_safety(assessment: SecurityAssessment, snapshot: dict):
    """Restrict an ALLOW recommendation, never manufacture a threat classification.

    The snapshot is collected by the server, not accepted from a client. This
    advisory guard issues no grant and leaves PE/PA/PEP authorization separate.
    """

    def group(name):
        value = snapshot.get(name)
        return value if isinstance(value, dict) else {}

    signal, caller, policy, session = (
        group(name) for name in ("signal", "caller", "policy", "session")
    )
    reasons = []
    if not (
        snapshot.get("not_an_access_grant") is True
        and signal.get("signature_verified") is True
        and caller.get("session_operator_binding_verified") is True
    ):
        reasons.append("verified_provenance_incomplete")
    if (
        not all(
            policy.get(key) is True
            for key in ("resource_registered", "role_permitted", "action_permitted")
        )
        or type(policy.get("mfa_required")) is not bool
        or (policy.get("mfa_required") is True and signal.get("mfa_observation") != "success")
    ):
        reasons.append("server_policy_requirements_not_satisfied")
    if not (
        session.get("decision") == "ALLOW"
        and session.get("status") == "ACTIVE"
        and session.get("approval_currently_usable") is True
        and session.get("challenge_pending") is False
    ):
        reasons.append("current_session_not_usable")
    if "execution" in snapshot:
        execution = group("execution")
        comparisons = execution.get("exact_field_comparisons")
        if not (
            execution.get("observation_status") == "complete"
            and execution.get("session_revision_bound") is True
            and execution.get("capture_signature_verified") is True
            and execution.get("comparison_scope_complete") is True
            and isinstance(comparisons, list)
            and 0 < len(comparisons) <= 8
            and any(
                isinstance(item, dict) and item.get("one_coherent_policy_matches") is True
                for item in comparisons
            )
        ):
            reasons.append("execution_scope_not_proven")
    before = assessment.recommended_action
    after = (
        RecommendedAction.HOLD_FOR_REVIEW
        if reasons and before == RecommendedAction.ALLOW
        else before
    )
    result = assessment.model_copy(
        update={"recommended_action": after, "requires_human_review": True}
    )
    controls = VerifiedReviewControls(
        action_before_guard=before,
        action_after_guard=after,
        action_adjusted=before != after,
        allow_recommendation_supported=not reasons,
        restrictions=reasons,
    )
    return result, controls


def _scoped_sensitive_download(event: SecurityEvent | None) -> bool:
    return bool(
        event is not None
        and event.action == EventAction.DOWNLOAD
        and event.behavior.policy_exception is not None
        and event.resource.sensitivity in {"high", "critical"}
        and event.behavior.download_volume_mb >= LARGE_DOWNLOAD_MB
    )


def enforce_assessment_safety(
    assessment: SecurityAssessment,
    event: SecurityEvent | None = None,
) -> SecurityAssessment:
    updates: dict = {}
    scoped_download = _scoped_sensitive_download(event)
    score = max(assessment.risk_score, MEDIUM_RISK_SCORE) if scoped_download else assessment.risk_score
    if score != assessment.risk_score:
        updates["risk_score"] = score
    score_level = _risk_level_for_score(score)
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
            not event.user.active or event.device.security_posture == "compromised" or role_mismatch
        )
        if context_requires_review:
            review = True
            if action == RecommendedAction.ALLOW:
                action = RecommendedAction.HOLD_FOR_REVIEW

    if scoped_download and risk_level == RiskLevel.MEDIUM and action == RecommendedAction.ALLOW:
        action = RecommendedAction.REQUIRE_MFA
        updates["rationale"] = SCOPED_DOWNLOAD_REASON

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
    scoped_download = _scoped_sensitive_download(event)
    if scoped_download:
        controls.append("scoped-sensitive-download-risk-floor")

    if review:
        reason = "고위험 또는 불확실한 결과이므로 실제 조치 전에 사람 검토가 필요합니다."
    elif scoped_download and safe.recommended_action == RecommendedAction.REQUIRE_MFA:
        reason = "승인 범위에 맞는 민감 자료 대량 다운로드이므로 추가 MFA를 권고합니다."
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
    if score >= MEDIUM_RISK_SCORE:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
