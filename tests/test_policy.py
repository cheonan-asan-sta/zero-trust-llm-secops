from app.models import (
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    ViolationType,
)
from app.services.policy import enforce_assessment_safety


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
