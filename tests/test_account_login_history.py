from types import SimpleNamespace

import pytest

from scripts.f1_lab.account_login_history import (
    FAILURE_WINDOW_MS,
    AccountLoginHistory,
    repeated_failure_warning,
    review_repeated_login,
)
from scripts.local_keycloak_login_history import compare_login_history


def test_history_drops_only_repeated_failure_warning_after_a_familiar_success():
    history = AccountLoginHistory(max_accounts=2)

    def add(moment, success, account=b"account", client=b"source"):
        return history.observe(account=account, moment=moment, success=success, client=client)

    for moment in range(3):
        add(moment, False)
    first_success = add(3, True)
    baseline = repeated_failure_warning(first_success, True)
    assert baseline and review_repeated_login(baseline=baseline, prior=first_success, success=True)
    assert not add(4, True, account=b"other").prior_failures
    normal_followup = add(4, True)
    assert not review_repeated_login(baseline=True, prior=normal_followup, success=True)
    assert review_repeated_login(
        baseline=True, prior=normal_followup, success=True, hard_alert=True
    )
    assert review_repeated_login(baseline=True, prior=None, success=True)
    assert review_repeated_login(baseline=True, prior=normal_followup, success=False)
    add(5, False)
    uncertain = add(6, True)
    assert uncertain.failures_since_success
    assert review_repeated_login(baseline=True, prior=uncertain, success=True)
    assert not add(5 + FAILURE_WINDOW_MS + 1, True).prior_failures
    with pytest.raises(ValueError, match="out of order"):
        add(1, True)


def test_same_time_outcomes_do_not_create_prior_history_or_resolve_failure():
    history = AccountLoginHistory(max_accounts=1)

    def add(moment, success, client):
        return history.observe(account=b"subject", moment=moment, success=success, client=client)

    add(1, True, b"client-a")
    assert not add(1, False, b"client-a").same_recent_client
    add(1, True, b"client-b")
    later = add(2, True, b"client-a")
    assert not later.same_recent_client
    assert later.failures_since_success


def test_keycloak_current_session_is_exact_and_foreign_failures_are_excluded():
    def event(number, subject, kind, session=None):
        return {
            "id": str(number),
            "time": number,
            "realmId": "realm",
            "clientId": "app",
            "userId": subject,
            "type": kind,
            "sessionId": session,
            "ipAddress": "192.0.2.1",
            "error": "invalid_credentials" if kind == "LOGIN_ERROR" else None,
        }

    rows = [event(number, "account", "LOGIN_ERROR") for number in range(1, 4)]
    rows += [
        event(4, "account", "LOGIN", "earlier"),
        event(5, "other", "LOGIN_ERROR"),
        event(6, "account", "LOGIN", "current"),
        event(7, "account", "LOGIN_ERROR"),
    ]

    def compare(events, session="current"):
        return compare_login_history(
            events,
            realm_id="realm",
            client_id="app",
            binding=SimpleNamespace(subject="account", session=session),
        )

    evidence = compare(list(reversed(rows)))
    assert evidence["earlier_same_account_failures"] == 3
    assert evidence["earlier_same_account_successes"] == 1
    assert evidence["baseline_repeated_failure_warning"] is True
    assert evidence["candidate_repeated_failure_warning"] is False
    assert (
        compare([event(8, None, "LOGIN_ERROR"), *rows])["candidate_repeated_failure_warning"]
        is False
    )
    earlier_unknown = event(8, None, "LOGIN_ERROR") | {"time": 4}
    assert compare([earlier_unknown, *rows])["candidate_repeated_failure_warning"] is True
    tied = event(8, "account", "LOGIN_ERROR") | {"time": 6}
    assert compare([tied, *rows])["candidate_repeated_failure_warning"] is True
    with pytest.raises(ValueError, match="no exact"):
        compare(rows, "another-session")
    with pytest.raises(ValueError, match="duplicate"):
        compare([*rows, rows[0]])
    with pytest.raises(ValueError, match="scope mismatch"):
        compare([*rows, {**event(8, "account", "LOGIN_ERROR"), "realmId": "other-realm"}])
