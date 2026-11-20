import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from app.analyzers.hybrid import HybridAnalyzer
from app.config import Settings
from app.models import SecurityAssessment, ViolationType
from app.services.session_analysis_evidence import collect_session_evidence
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab


def assessment(violation=ViolationType.NORMAL):
    return SecurityAssessment(
        risk_score=10,
        risk_level="LOW",
        violation_type=violation,
        rationale="Local replay",
        evidence=["action"],
        recommended_action="ALLOW",
        confidence=0.8,
        requires_human_review=True,
    )


@pytest.fixture
def lab(tmp_path):
    return LocalSessionAnalysisLab(tmp_path / "authority")


def analyze(signed, context, response):
    llm = AsyncMock()
    if response is None:
        llm.analyze_with_evidence.side_effect = RuntimeError("provider unavailable")
    else:
        llm.analyze_with_evidence.return_value = response
    result = asyncio.run(
        HybridAnalyzer(Settings(), llm).analyze_with_evidence(signed.event, context)
    )
    llm.analyze_with_evidence.assert_awaited_once_with(signed.event, context)
    return result


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[row[0] for row in SCENARIOS])
def test_verified_remote_policy_with_a_normal_model_output(lab, scenario):
    signed, context = lab.create(scenario)
    before = lab.service.history(signed.session_id, lab.principal)
    result = analyze(signed, context, assessment())
    assert result.violation_type == (
        ViolationType.ACCESS_POLICY_VIOLATION if scenario[1] else ViolationType.NORMAL
    )
    if signed.event.action == "REMOTE_ACCESS":
        assert result.recommended_action == "HOLD_FOR_REVIEW"
        assert result.requires_human_review
        assert any(path.startswith("verified_session.") for path in result.evidence)
    assert lab.service.history(signed.session_id, lab.principal) == before


def test_generic_step_up_never_suppresses_model_threat(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    result = analyze(signed, context, assessment(ViolationType.CREDENTIAL_ANOMALY))
    assert result.violation_type == ViolationType.CREDENTIAL_ANOMALY
    assert result.recommended_action == "HOLD_FOR_REVIEW"


def test_generic_step_up_never_suppresses_observed_fanout(lab):
    signed, _ = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    event = signed.event.model_copy(
        update={
            "event_id": "fanout-control",
            "behavior": signed.event.behavior.model_copy(update={"distinct_resources_10m": 8}),
        }
    )
    signal = lab.sign(event, "fanout-control")
    lab.service.evaluate_signed(signal, lab.principal)
    context = collect_session_evidence(lab.service, signal, lab.principal)
    result = analyze(signal, context, assessment())
    assert result.violation_type == ViolationType.LATERAL_MOVEMENT
    assert "behavior.distinct_resources_10m" in result.evidence


def test_verified_denial_survives_model_unavailability(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "required_mfa_unknown"))
    result = analyze(signed, context, None)
    assert result.violation_type == ViolationType.ACCESS_POLICY_VIOLATION
    assert "verified_session.policy.mfa_required" in result.evidence
    assert result.recommended_action == "HOLD_FOR_REVIEW"


def test_outstanding_signed_challenge_does_not_clear_generic_rule(lab):
    signed, _ = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    event = signed.event.model_copy(
        update={
            "event_id": "outstanding-challenge",
            "timestamp": max(datetime.now(UTC), signed.event.timestamp + timedelta(microseconds=1)),
        }
    )
    signed = lab.sign(event, signed.session_id, expected_version=1)
    issued = lab.service.evaluate_signed(signed, lab.principal)
    assert "SIGNED_MFA_CHALLENGE_REQUIRED" in issued.session.reason_codes
    context = collect_session_evidence(lab.service, signed, lab.principal)
    result = analyze(signed, context, assessment())
    assert result.violation_type == ViolationType.LATERAL_MOVEMENT


def test_generic_step_up_without_model_output_is_reviewed_as_unknown(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    result = analyze(signed, context, None)
    assert result.violation_type == ViolationType.UNKNOWN
    assert result.recommended_action == "HOLD_FOR_REVIEW"
    assert result.requires_human_review


def test_verified_policy_and_model_rationale_fit_the_response_contract(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    response = assessment().model_copy(update={"rationale": "x" * 1000})
    result = analyze(signed, context, response)
    assert (
        SecurityAssessment.model_validate(result.model_dump()).violation_type
        == ViolationType.NORMAL
    )
