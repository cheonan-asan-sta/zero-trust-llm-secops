import copy
import json

import pytest

from app.grounded_prompting import grounded_input
from app.scenarios import synthetic_events
from app.services.sigma import get_sigma_engine


@pytest.mark.parametrize(
    "value,result",
    [
        (499, False),
        (500, True),
        (501, True),
        (None, None),
        (False, None),
        ("500", None),
        (float("inf"), None),
        (float("nan"), None),
    ],
)
def test_exact_numeric_boundaries_never_create_a_whole_rule_classification(value, result):
    engine = get_sigma_engine()
    event = {"unmapped": {"behavior": {"download_volume_mb": value}}}
    comparisons = engine.observation_comparisons(event)
    row = next(
        r
        for r in comparisons
        if r["field_expression"] == "unmapped.behavior.download_volume_mb|gte"
    )
    assert row["predicate_result"] is result
    assert row["right_observed"] == 500
    assert row["operands_available"] is (result is not None)
    assert engine.evaluate_fields(event).matches == []  # Other mandatory fields are absent.
    assert not any(
        k in row for k in ("violation_type", "risk_score", "matched", "verdict", "label")
    )


@pytest.mark.parametrize(
    "role,required,result",
    [
        ("employee", "employee", False),
        ("employee", "administrator", True),
        (None, "administrator", None),
    ],
)
def test_role_field_reference_uses_observed_values_not_permissions(role, required, result):
    event = {
        "actor": {"user": {"role": role}},
        "unmapped": {"resource": {"required_role": required}},
    }
    before = copy.deepcopy(event)
    rows = get_sigma_engine().observation_comparisons(event)
    row = next(r for r in rows if "fieldref" in r["field_expression"])
    assert row["predicate_result"] is result
    assert row["left_observed"] == required and row["right_observed"] == role
    assert event == before


def test_comparison_context_is_explicit_opt_in_and_contains_no_case_metadata():
    event = synthetic_events()[0]
    default = json.loads(grounded_input(event)[0]["content"])
    opted_in = json.loads(grounded_input(event, include_comparisons=True)[0]["content"])
    assert "server_observation_comparisons" not in default
    comparisons = opted_in.pop("server_observation_comparisons")
    opted_in.pop("comparison_scope")
    assert opted_in == default
    assert comparisons
    for row in comparisons:
        assert not any(
            k in row
            for k in (
                "test_case_ids",
                "family_id",
                "scenario_id",
                "ground_truth",
                "violation_type",
                "matched",
            )
        )
