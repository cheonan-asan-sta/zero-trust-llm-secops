import asyncio
from pathlib import Path

import pytest

from scripts.evaluate_llm_grounded import (
    include_unattempted,
    metrics,
    reservation,
    run,
    select_cases,
)


def test_budget_stop_retains_unattempted_cases_as_unknown():
    requests = [{"id": "a", "arm": "grounded"}, {"id": "b", "arm": "grounded"}]
    rows = [{"id": "a", "arm": "grounded", "truth": True, "prediction": True}]
    scored = include_unattempted(rows, requests, {"a": True, "b": False})
    assert len(scored) == 2 and scored[-1]["error"] == "not_attempted"
    result = metrics(scored)
    assert result["FP"] == 1 and result["unknown_or_error"] == 1
    assert result["precision"] == 0.5


def test_pilot_uses_only_balanced_development_families():
    cases = select_cases(Path(__file__).resolve().parents[1] / "app/data/benchmark/cases.jsonl")
    assert len(cases) == len({c.family_id for c in cases}) == 24
    assert all(c.split == "development" for c in cases)
    assert sum(c.threat for c in cases) == 12
    assert len({c.domain for c in cases}) == 6


def test_abstentions_or_errors_cannot_disappear_from_denominators():
    m = metrics(
        [
            {"truth": True, "prediction": True},
            {"truth": True, "prediction": None},
            {"truth": False, "prediction": False},
            {"truth": False, "prediction": None},
        ]
    )
    assert m["TP"] == m["FN"] == m["FP"] == m["TN"] == 1
    assert m["F1"] == 0.5 and m["unknown_or_error"] == 2


def test_followup_families_do_not_overlap_pilot_and_remain_development():
    path = Path(__file__).resolve().parents[1] / "app/data/benchmark/cases.jsonl"
    first = select_cases(path)
    followup = select_cases(path, 2, 1)
    assert len(followup) == 12 and sum(c.threat for c in followup) == 6
    assert not {c.family_id for c in first} & {c.family_id for c in followup}
    assert all(c.split == "development" for c in followup)


def test_input_byte_bound_and_output_reservation_include_headroom():
    assert reservation([{"role": "user", "content": "한국어"}]) > 0.0054
    with pytest.raises(ValueError, match="input_bound"):
        reservation([{"role": "user", "content": "x" * 33000}])


def test_fixed_maximum_requests_cannot_exhaust_five_dollars_even_across_three_pilots():
    per_request = 32768 * 0.75 / 1000000 + 1200 * 4.5 / 1000000
    assert per_request * 48 * 3 < 5


@pytest.mark.parametrize(
    "options",
    [
        {"model": "unsupported"},
        {"max_budget": float("nan")},
        {"max_budget": 6},
        {"llm_arms": ()},
        {"llm_arms": ("bad",)},
    ],
)
def test_bad_provider_or_budget_options_stop_before_credentials_or_network(tmp_path, options):
    with pytest.raises(ValueError, match="evaluation_options"):
        asyncio.run(run(tmp_path / "new", **options))
    assert not (tmp_path / "new").exists()
