from collections import Counter

import pytest

from scripts.evaluate_rba_login_environment import NETWORK, available_for_new_review, choose
from scripts.f1_lab.login_environment import Change, Environment, SuccessfulEnvironments

FIRST = Environment(b"a", b"country-a", b"asn-a", b"browser-a", b"os-a", b"device-a")
SECOND = Environment(b"b", b"country-b", b"asn-b", b"browser-b", b"os-b", b"device-b")


def test_history_is_account_scoped_and_uses_only_prior_successes():
    history = SuccessfulEnvironments()
    assert history.observe(b"account", 1000, FIRST)[0] == 0
    assert history.observe(b"another", 2000, SECOND)[0] == 0
    flags, delay = history.observe(b"account", 2000, SECOND)
    assert flags & NETWORK == NETWORK
    assert flags & Change.NEW_PROFILE
    assert delay == 0
    flags, _ = history.observe(b"account", 3000, FIRST)
    assert not flags & (
        Change.NEW_COUNTRY | Change.NEW_ASN | Change.NEW_ADDRESS | Change.NEW_PROFILE
    )
    with pytest.raises(ValueError, match="out of order"):
        history.observe(b"account", 2500, FIRST)


def test_ambiguous_prior_success_or_missing_fields_are_unavailable():
    history = SuccessfulEnvironments()
    assert history.observe(b"account", 1000, FIRST)[0] == 0
    assert history.observe(b"account", 1000, SECOND)[0] == 0
    flags, _ = history.observe(b"account", 2000, FIRST)
    assert flags == 0
    flags, _ = history.observe(b"account", 3000, Environment(None, None, None, None, None, None))
    assert flags == Change.PRIOR_SUCCESS


def test_new_review_cannot_restore_cleared_alerts_or_add_on_failures():
    assert available_for_new_review(True, False, False)
    assert not available_for_new_review(True, True, False)
    assert not available_for_new_review(True, True, True)
    assert not available_for_new_review(False, False, False)


def test_candidate_choice_prefers_zero_new_false_positives_and_keeps_shadow_separate():
    baseline = {"tp": 0, "fp": 2, "fn": 2, "tn": 10, "inference_errors": 0}
    narrow = int(NETWORK | Change.NEW_PROFILE)
    wide = int(NETWORK)
    observations = Counter({(narrow, 0, True): 1, (wide, 0, True): 1, (wide, 0, False): 1})
    decision = choose(baseline, observations)
    assert decision["qualified_on_reviewed"] is True
    assert decision["selection"]["recovered_true_positives"] == 1
    assert decision["selection"]["new_false_positives"] == 0
    observations[narrow, 0, False] = 1
    decision = choose(baseline, observations)
    assert decision["qualified_on_reviewed"] is False
    assert decision["selection"]["recovered_true_positives"] == 2
