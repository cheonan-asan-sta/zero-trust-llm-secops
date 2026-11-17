import copy
import hashlib
import json
from pathlib import Path

import pytest

from app.models import SecurityAssessment
from app.services.policy import enforce_verified_review_safety


def assessment(action="ALLOW"):
    return SecurityAssessment(
        risk_score=10,
        risk_level="LOW",
        violation_type="NORMAL",
        rationale="Original model rationale",
        evidence=["device.managed"],
        recommended_action=action,
        confidence=0.8,
        requires_human_review=False,
    )


def snapshot():
    return {
        "not_an_access_grant": True,
        "signal": {"signature_verified": True, "mfa_observation": "success"},
        "caller": {"session_operator_binding_verified": True},
        "policy": {
            "resource_registered": True,
            "role_permitted": True,
            "action_permitted": True,
            "mfa_required": True,
        },
        "session": {
            "decision": "ALLOW",
            "status": "ACTIVE",
            "approval_currently_usable": True,
            "challenge_pending": False,
        },
        "execution": {
            "observation_status": "complete",
            "session_revision_bound": True,
            "capture_signature_verified": True,
            "comparison_scope_complete": True,
            "exact_field_comparisons": [{"one_coherent_policy_matches": True}],
        },
    }


@pytest.mark.parametrize(
    "path,value",
    [
        ("not_an_access_grant", False),
        ("signal.signature_verified", "true"),
        ("caller.session_operator_binding_verified", False),
        ("policy.resource_registered", False),
        ("policy.role_permitted", False),
        ("policy.action_permitted", False),
        ("policy.mfa_required", "false"),
        ("signal.mfa_observation", "unknown"),
        ("session.decision", "STEP_UP"),
        ("session.status", "REVOKED"),
        ("session.approval_currently_usable", False),
        ("session.challenge_pending", True),
        ("execution.observation_status", "missing"),
        ("execution.observation_status", "incomplete"),
        ("execution.observation_status", "conflict"),
        ("execution.observation_status", "stale"),
        ("execution.session_revision_bound", False),
        ("execution.capture_signature_verified", False),
        ("execution.comparison_scope_complete", False),
        ("execution.exact_field_comparisons", []),
        ("execution.exact_field_comparisons", [{"one_coherent_policy_matches": False}]),
        ("execution.exact_field_comparisons", [{"one_coherent_policy_matches": "true"}]),
        ("execution", None),
    ],
)
def test_incomplete_or_denied_verified_facts_restrict_allow_without_relabelling(path, value):
    context, original = snapshot(), assessment()
    current = context
    keys = path.split(".")
    for key in keys[:-1]:
        current = current[key]
    current[keys[-1]] = value
    untouched = copy.deepcopy(context)
    result, controls = enforce_verified_review_safety(original, context)
    assert result.recommended_action.value == "HOLD_FOR_REVIEW"
    assert result.requires_human_review is True
    assert controls.action_before_guard.value == "ALLOW" and controls.action_adjusted
    assert controls.restrictions and not controls.allow_recommendation_supported
    assert context == untouched
    assert original.model_dump(
        exclude={"recommended_action", "requires_human_review"}
    ) == result.model_dump(exclude={"recommended_action", "requires_human_review"})


def test_complete_bound_scope_keeps_advisory_allow_and_human_review():
    result, controls = enforce_verified_review_safety(assessment(), snapshot())
    assert result.recommended_action.value == "ALLOW" and result.requires_human_review
    assert controls.allow_recommendation_supported and not controls.action_adjusted


@pytest.mark.parametrize(
    "action", ["REQUIRE_MFA", "REDUCE_PRIVILEGE", "ISOLATE_SESSION", "HOLD_FOR_REVIEW"]
)
def test_other_existing_response_recommendations_are_preserved(action):
    context = snapshot()
    context["execution"] = None
    original = assessment(action)
    result, controls = enforce_verified_review_safety(original, context)
    assert result.recommended_action == original.recommended_action
    assert controls.restrictions and not controls.action_adjusted


def test_mfa_not_required_is_not_reinterpreted_as_a_requirement():
    context = snapshot()
    context.pop("execution")
    context["policy"]["mfa_required"] = False
    context["signal"]["mfa_observation"] = "unknown"
    result, controls = enforce_verified_review_safety(assessment(), context)
    assert result.recommended_action.value == "ALLOW" and not controls.restrictions


def test_replay_of_twelve_actual_responses_restricts_all_four_allow_suggestions_without_new_model_calls():
    path = (
        Path(__file__).resolve().parents[1]
        / "docs/infrastructure-results/llm-evidence-grounding-before-guard-20261117.json"
    )
    source = path.read_bytes()
    rows = json.loads(source)["rows"]
    adjusted = 0
    for row in rows:
        response = row["response"]
        original = SecurityAssessment.model_validate(response["assessment"])
        result, controls = enforce_verified_review_safety(
            original, response["verification_context"]
        )
        assert result.recommended_action.value == "HOLD_FOR_REVIEW"
        assert result.violation_type == original.violation_type
        adjusted += controls.action_adjusted
    assert len(rows) == 12 and adjusted == 4
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(source).digest()
