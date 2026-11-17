import pytest

from scripts.llm_evaluation_uncertainty import describe, wilson


def test_small_perfect_sample_still_has_wide_illustrative_interval():
    interval = wilson(6, 6)
    assert interval["lower"] == pytest.approx(0.6096657121)
    assert interval["upper"] == pytest.approx(1)
    assert wilson(0, 6)["upper"] == pytest.approx(1 - interval["lower"])
    assert wilson(73, 73)["lower"] > 0.95
    assert wilson(72, 72)["lower"] < 0.95


@pytest.mark.parametrize("successes,trials", [(1, 0), (-1, 2), (1, -2), (True, 1), (1.2, 3)])
def test_invalid_counts_are_not_coerced(successes, trials):
    with pytest.raises(ValueError):
        wilson(successes, trials)


def test_zero_support_is_undefined_instead_of_perfect():
    assert wilson(0, 0) is None


def test_repeated_family_variants_are_visible_and_unknowns_remain_errors():
    rows = [
        {"id": "a", "family_id": "same", "truth": True, "prediction": True},
        {"id": "b", "family_id": "same", "truth": False, "prediction": None},
    ]
    result = describe(rows)
    assert result["cases"] == 2 and result["families"] == 1
    assert result["family_clustering_present"]
    assert result["metrics"]["FP"] == 1 and result["metrics"]["unknown_or_error"] == 1
    assert result["F1_interval"] is None
    assert result["independent_acceptance"] is False
    with pytest.raises(ValueError, match="separate_repetitions"):
        describe([rows[0], rows[0]])
