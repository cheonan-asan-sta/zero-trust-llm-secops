from app.models import (
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    ViolationType,
)
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
