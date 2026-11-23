from collections import Counter

import pytest

from scripts.evaluate_rba_ato_separation import NETWORK, choose_candidate, decisions
from scripts.f1_lab.ato_triage import Device, Factor, Takeover, assess_login
from scripts.f1_lab.login_environment import Change


@pytest.mark.parametrize(
    ("success", "drift", "factor", "device", "expected"),
    [
        (False, True, Factor.REJECTED_REQUIRED_FACTOR, Device.NEW, Takeover.NO_SIGNAL),
        (None, True, Factor.UNKNOWN, Device.NEW, Takeover.NO_SIGNAL),
        (True, False, Factor.UNKNOWN, Device.NEW, Takeover.NO_SIGNAL),
        (True, True, Factor.UNKNOWN, Device.UNKNOWN, Takeover.REVIEW),
        (True, True, Factor.VERIFIED, Device.KNOWN, Takeover.REVIEW),
        (True, True, Factor.REJECTED_REQUIRED_FACTOR, Device.UNKNOWN, Takeover.PRIORITY_REVIEW),
        (True, True, Factor.VERIFIED, Device.NEW, Takeover.PRIORITY_REVIEW),
    ],
)
def test_takeover_classification_preserves_warning(success, drift, factor, device, expected):
    for warning in (True, False):
        result = assess_login(
            warning=warning,
            success=success,
            environment_change=drift,
            factor=factor,
            device=device,
        )
        assert result.repeated_failure_warning is warning
        assert result.takeover is expected


def test_profile_proxy_keeps_broad_signal_for_review_and_cannot_restore_a_cleared_warning():
    rule = {"window_index": 5, "any_of": [int(Change.CHANGED_OS)]}
    network_only = decisions(True, False, False, int(NETWORK), 0, rule)
    assert network_only == {
        "prior_combined": True,
        "separate_warning": False,
        "ato_review": True,
        "profile_priority_proxy": False,
    }
    confirmed_proxy = decisions(True, False, False, int(NETWORK | Change.CHANGED_OS), 0, rule)
    assert confirmed_proxy["profile_priority_proxy"] and confirmed_proxy["ato_review"]
    assert not any(decisions(True, True, False, int(NETWORK | Change.CHANGED_OS), 0, rule).values())
    failed_with_warning = decisions(False, True, True, 0, 0, rule)
    assert failed_with_warning["separate_warning"] and not failed_with_warning["ato_review"]


def test_filter_freezing_prefers_retaining_all_development_positives_when_possible():
    device = int(NETWORK | Change.CHANGED_DEVICE)
    both = int(NETWORK | Change.CHANGED_DEVICE | Change.CHANGED_OS)
    groups = Counter(
        {
            (device, 0, True): 1,
            (both, 0, True): 1,
            (device, 0, False): 1,
            (int(NETWORK), 0, False): 2,
        }
    )
    frozen = choose_candidate(groups)
    assert frozen["broad_tp"] == frozen["tp"] == 2
    assert frozen["fp"] == 1 < frozen["broad_fp"]
