import math

import pytest

from scripts.f1_lab.confidence import exact_interval, independent_trial_reference


def test_exact_interval_matches_nist_90_percent_example_four_of_twenty():
    result = exact_interval(4, 20, confidence=.90)
    assert result['lower'] == pytest.approx(.071354, abs=1e-6)
    assert result['upper'] == pytest.approx(.401029, abs=1e-6)


def test_no_errors_is_not_certainty_and_needs_actual_independent_support():
    for n in (1, 14, 42, 54, 72, 300):
        failures = exact_interval(0, n)
        successes = exact_interval(n, n)
        assert failures['upper'] == pytest.approx(1-.025**(1/n))
        assert successes['lower'] == pytest.approx(.025**(1/n))
        assert failures['upper'] > 0 and successes['lower'] < 1
    assert exact_interval(0, 42)['upper'] > .05
    assert exact_interval(54, 54)['lower'] < .95
    assert math.ceil(math.log(.025)/math.log(.95)) == 72


@pytest.mark.parametrize('k,n', [(0, 0), (0, 5), (2, 5), (3, 5), (5, 5), (10, 20)])
def test_complementary_outcomes_have_complementary_intervals(k, n):
    first, opposite = exact_interval(k, n), exact_interval(n-k, n)
    if n == 0:
        assert first['lower'] is first['upper'] is None
    else:
        assert first['lower'] == pytest.approx(1-opposite['upper'])
        assert first['upper'] == pytest.approx(1-opposite['lower'])


@pytest.mark.parametrize('k,n', [(-1, 10), (11, 10), (True, 10), (0, -1), (0, 10001)])
def test_invalid_reference_counts_do_not_produce_a_passing_interval(k, n):
    with pytest.raises(ValueError):
        exact_interval(k, n)


def test_even_perfect_controlled_fixture_is_not_population_evidence():
    result = independent_trial_reference({'tp': 54, 'fp': 0, 'fn': 0, 'tn': 42})
    assert not result['bounds_meet_targets_under_hypothetical_independence']
    assert result['population_target_supported'] is False
    large = independent_trial_reference({'tp': 300, 'fp': 0, 'fn': 0, 'tn': 300})
    assert large['bounds_meet_targets_under_hypothetical_independence']
    assert large['population_target_supported'] is False
    asserted = independent_trial_reference({'tp': 300, 'fp': 0, 'fn': 0, 'tn': 300}, assumptions_verified=True)
    assert asserted['conditional_bounds_and_caller_assumption_pass']
    assert asserted['population_target_supported'] is False
