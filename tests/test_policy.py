import pytest

from app.models import (
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    SecurityEvent,
    ViolationType,
)
from app.scenarios import synthetic_events
from app.services.policy import enforce_assessment_safety, response_preview


def test_low_confidence_is_sent_to_review() -> None:
    assessment = SecurityAssessment(
        risk_score=78,
        risk_level=RiskLevel.CRITICAL,
        violation_type=ViolationType.CREDENTIAL_ANOMALY,
        rationale="필수 필드 일부가 누락되어 판단 근거가 충분하지 않습니다.",
        recommended_action=RecommendedAction.ISOLATE_SESSION,
        confidence=0.38,
        evidence=["network.location_anomaly"],
        requires_human_review=False,
    )

    safe = enforce_assessment_safety(assessment)
    assert safe.recommended_action == RecommendedAction.HOLD_FOR_REVIEW
    assert safe.requires_human_review is True


def test_risk_score_cannot_be_downgraded_by_declared_level() -> None:
    assessment = SecurityAssessment(
        risk_score=92,
        risk_level=RiskLevel.LOW,
        violation_type=ViolationType.UNKNOWN,
        rationale="높은 위험 점수와 선언 위험도가 서로 일치하지 않는 결과입니다.",
        recommended_action=RecommendedAction.ALLOW,
        confidence=0.9,
        evidence=["device.security_posture"],
        requires_human_review=False,
    )

    safe = enforce_assessment_safety(assessment)
    decision = response_preview(assessment)

    assert safe.risk_level == RiskLevel.CRITICAL
    assert safe.recommended_action == RecommendedAction.HOLD_FOR_REVIEW
    assert "risk-score-consistency" in decision.controls_applied


@pytest.mark.parametrize(("volume", "sensitivity", "approved", "applies"), [
    (499, "high", True, False),
    (500, "high", True, True),
    (700, "critical", True, True),
    (700, "internal", True, False),
    (700, "high", False, False),
])
def test_scoped_sensitive_download_has_auditable_risk_floor(volume, sensitivity, approved, applies):
    data = synthetic_events()[2].analysis_payload()
    data["resource"]["sensitivity"] = sensitivity
    data["behavior"]["download_volume_mb"] = volume
    if not approved:
        data["behavior"].update(policy_exception_approved=False, policy_exception=None)
    event = SecurityEvent.model_validate(data)
    assessment = SecurityAssessment(
        risk_score=10, risk_level=RiskLevel.LOW, violation_type=ViolationType.NORMAL,
        rationale="범위 내 작업으로 판단했습니다.", recommended_action=RecommendedAction.ALLOW,
        confidence=0.9, evidence=["resource.sensitivity"], requires_human_review=False,
    )

    safe = enforce_assessment_safety(assessment, event)
    decision = response_preview(safe, event)
    assert enforce_assessment_safety(safe, event) == safe
    assert safe.risk_score == (25 if applies else 10)
    assert safe.risk_level == (RiskLevel.MEDIUM if applies else RiskLevel.LOW)
    assert decision.action == (RecommendedAction.REQUIRE_MFA if applies else RecommendedAction.ALLOW)
    assert ("scoped-sensitive-download-risk-floor" in decision.controls_applied) is applies
    assert safe.violation_type == ViolationType.NORMAL
    assert safe.evidence == assessment.evidence


@pytest.mark.parametrize(("score", "risk", "confidence", "action", "expected"), [
    (90, RiskLevel.CRITICAL, 0.9, RecommendedAction.ALLOW, RecommendedAction.HOLD_FOR_REVIEW),
    (10, RiskLevel.LOW, 0.4, RecommendedAction.ALLOW, RecommendedAction.HOLD_FOR_REVIEW),
    (55, RiskLevel.HIGH, 0.9, RecommendedAction.REDUCE_PRIVILEGE, RecommendedAction.REDUCE_PRIVILEGE),
])
def test_download_policy_keeps_stronger_responses(score, risk, confidence, action, expected):
    event = synthetic_events()[2]
    assessment = SecurityAssessment(
        risk_score=score, risk_level=risk, violation_type=ViolationType.CREDENTIAL_ANOMALY,
        rationale="추가 위험 신호가 있습니다.", recommended_action=action,
        confidence=confidence, evidence=["auth_context.failed_attempts"], requires_human_review=True,
    )
    safe = enforce_assessment_safety(assessment, event)
    assert safe.recommended_action == expected
    assert safe.requires_human_review
    assert safe.risk_level == (RiskLevel.MEDIUM if risk == RiskLevel.LOW else risk)
    assert safe.violation_type == assessment.violation_type
