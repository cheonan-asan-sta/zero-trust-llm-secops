"""Security invariants for session state, expiry, isolation and durable grants."""

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest

from app.security import Principal
from app.services.zero_trust import JournalUnavailable, SessionConflict, SessionMissing
from app.zero_trust_models import SessionRevocationRequest


@pytest.mark.parametrize("offset,decision", [
    pytest.param(-300, "HOLD", id="signal-at-age-limit"),
    pytest.param(-299.999999, "ALLOW", id="signal-before-age-limit"),
    pytest.param(30, "ALLOW", id="future-at-tolerance"),
    pytest.param(30.000001, "HOLD", id="future-after-tolerance"),
])
def test_signal_age_boundary(lab, offset, decision):
    result = lab.evaluate(when=lab.now + timedelta(seconds=offset))
    assert result.session.decision == decision
    assert (result.grant_token is not None) == (decision == "ALLOW")


@pytest.mark.parametrize("resource,role,ttl", [
    ("zt-demo-documents", "employee", 60),
    ("zt-demo-vault", "administrator", 30),
])
@pytest.mark.parametrize("delta,allowed", [(-0.000001, True), (0, False), (0.000001, False)])
def test_resource_grant_expires_at_exact_boundary(lab, resource, role, ttl, delta, allowed):
    result = lab.evaluate(resource={"resource_id": resource}, user={"role": role})
    assert result.session.decision == "ALLOW"
    assert result.session.grant_expires_at == lab.now + timedelta(seconds=ttl)
    access = lab.access(result.grant_token, resource=resource,
                        at=lab.now + timedelta(seconds=ttl + delta))
    assert access.allowed is allowed
    assert (access.content is not None) is allowed


def test_old_but_valid_signal_shortens_grant_instead_of_resetting_its_age(lab):
    result = lab.evaluate(when=lab.now - timedelta(seconds=299))
    assert result.session.grant_expires_at == lab.now + timedelta(seconds=1)
    assert not lab.access(result.grant_token, at=lab.now + timedelta(seconds=1)).allowed


def test_clock_rollback_cannot_use_a_grant_before_its_evaluation(lab):
    token = lab.evaluate().grant_token
    denied = lab.access(token, at=lab.now - timedelta(microseconds=1))
    assert not denied.allowed and denied.content is None
    assert lab.access(token).allowed


@pytest.mark.parametrize("changes", [
    {"session": "session-other"},
    {"resource": "zt-demo-vault"},
    {"action": "DOWNLOAD"},
    {"action": "ADMIN"},
    {"resource": "unregistered-resource"},
])
def test_wrong_access_scope_does_not_consume_the_legitimate_grant(lab, changes):
    token = lab.evaluate().grant_token
    denied = lab.access(token, **changes)
    assert not denied.allowed and denied.content is None
    assert lab.access(token).allowed
    assert not lab.access(token).allowed


@pytest.mark.parametrize("subject,tenant", [
    ("operator-other", "tenant-a"), ("operator-a", "tenant-other"),
])
def test_wrong_principal_does_not_consume_the_legitimate_grant(lab, subject, tenant):
    token = lab.evaluate().grant_token
    other = Principal(subject, tenant, lab.operator.roles, "api_key")
    assert not lab.access(token, principal=other).allowed
    assert lab.access(token).allowed


@pytest.mark.parametrize("change", ["hold", "step-up", "deny", "manual-revoke"])
def test_changing_one_session_preserves_an_unrelated_session(lab, change):
    first = lab.evaluate()
    other = lab.evaluate(session="session-other", event_id="other-event")
    if change == "manual-revoke":
        lab.service.revoke("session-a", SessionRevocationRequest(expected_version=1, note="review"),
                           lab.operator, now=lab.now + timedelta(seconds=1))
    else:
        changes = {
            "hold": {"auth_context": {"authentication_result": "unknown"}},
            "step-up": {"auth_context": {"mfa": "unknown"}},
            "deny": {"device": {"security_posture": "compromised"}},
        }[change]
        lab.evaluate(version=1, event_id="changed", when=lab.now + timedelta(seconds=1), **changes)
    assert not lab.access(first.grant_token).allowed
    assert lab.access(other.grant_token, session="session-other").allowed
    assert lab.service.history("session-other", lab.operator)[-1].version == 1


def test_identical_session_and_event_ids_in_different_tenants_stay_isolated(lab):
    other = Principal("operator-a", "tenant-b", lab.operator.roles, "api_key")
    first = lab.evaluate()
    second = lab.evaluate(principal=other)
    assert first.grant_token != second.grant_token
    assert not lab.access(first.grant_token, principal=other).allowed
    lab.service.revoke("session-a", SessionRevocationRequest(expected_version=1, note="review"),
                       lab.operator, now=lab.now)
    assert lab.access(second.grant_token, principal=other).allowed
    assert lab.service.history("session-a", other)[-1].status == "ACTIVE"


@pytest.mark.parametrize("change", ["stale-version", "same-time", "changed-user", "changed-device"])
def test_rejected_update_preserves_current_version_and_grant(lab, change):
    first = lab.evaluate()
    updates = {"version": 1, "event_id": "next-event", "when": lab.now + timedelta(seconds=1)}
    if change == "stale-version":
        updates["version"] = 0
    elif change == "same-time":
        updates["when"] = lab.now
    elif change == "changed-user":
        updates["user"] = {"user_id": "user-other"}
    else:
        updates["device"] = {"device_id": "device-other"}
    with pytest.raises(SessionConflict):
        lab.evaluate(**updates)
    assert lab.service.history("session-a", lab.operator) == [first.session]
    assert lab.access(first.grant_token).allowed


def test_replaying_an_old_event_after_revocation_does_not_restore_its_old_decision(lab):
    lab.evaluate()
    revoked = lab.service.revoke(
        "session-a", SessionRevocationRequest(expected_version=1, note="review"),
        lab.operator, now=lab.now + timedelta(seconds=1),
    )
    replay = lab.evaluate()
    assert replay.duplicate and replay.grant_token is None
    assert replay.session == revoked
    assert len(lab.service.history("session-a", lab.operator)) == 2


@pytest.mark.parametrize("operation", ["history", "revoke"])
def test_other_tenant_cannot_discover_or_change_a_session(lab, operation):
    token = lab.evaluate().grant_token
    other = Principal("operator-a", "tenant-other", lab.operator.roles, "api_key")
    with pytest.raises(SessionMissing):
        if operation == "history":
            lab.service.history("session-a", other)
        else:
            lab.service.revoke("session-a", SessionRevocationRequest(expected_version=1, note="review"),
                               other, now=lab.now)
    assert lab.service.sessions(other) == []
    assert lab.access(token).allowed


@pytest.mark.parametrize("payload", [
    pytest.param("{", id="invalid-json"),
    pytest.param("null", id="null-record"),
    pytest.param("[]", id="array-record"),
    pytest.param('{"kind":"unknown"}', id="unknown-record-kind"),
    pytest.param('{"kind":"decision","session":{}}', id="incomplete-decision"),
])
@pytest.mark.parametrize("operation", ["evaluate", "access", "history"])
def test_invalid_persisted_records_fail_closed_even_with_a_matching_hash(lab, payload, operation):
    token = lab.evaluate().grant_token
    prior = "0" * 64
    digest = hashlib.sha256((prior + "." + payload).encode()).hexdigest()
    with sqlite3.connect(lab.service.path) as connection:
        connection.execute("UPDATE journal SET payload=?, record_hash=? WHERE seq=1", (payload, digest))
    with pytest.raises(JournalUnavailable):
        if operation == "evaluate":
            lab.evaluate(event_id="next-event", version=1, when=lab.now + timedelta(seconds=1))
        elif operation == "access":
            lab.access(token)
        else:
            lab.service.history("session-a", lab.operator)
    assert not lab.service.integrity()["ok"]


@pytest.mark.parametrize("damage", ["sequence-gap", "previous-hash", "record-hash"])
def test_broken_journal_linkage_rejects_access(lab, damage):
    token = lab.evaluate().grant_token
    statements = {
        "sequence-gap": "UPDATE journal SET seq=2 WHERE seq=1",
        "previous-hash": "UPDATE journal SET previous_hash='bad' WHERE seq=1",
        "record-hash": "UPDATE journal SET record_hash='bad' WHERE seq=1",
    }
    with sqlite3.connect(lab.service.path) as connection:
        connection.execute(statements[damage])
    with pytest.raises(JournalUnavailable):
        lab.access(token)
    assert not lab.service.integrity()["ok"]


def test_concurrent_identical_delivery_issues_one_grant_and_one_decision(lab):
    barrier = Barrier(6)

    def deliver(_):
        barrier.wait(timeout=10)
        return lab.evaluate()

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(deliver, range(6)))
    assert sum(result.grant_token is not None for result in results) == 1
    assert sum(result.duplicate for result in results) == 5
    assert len(lab.service.history("session-a", lab.operator)) == 1
    assert lab.service.integrity()["verified_entries"] == 1


def test_concurrent_access_and_revocation_have_no_success_after_the_revocation_record(lab):
    token = lab.evaluate().grant_token
    barrier = Barrier(2)

    def use():
        barrier.wait(timeout=10)
        return lab.access(token)

    def revoke():
        barrier.wait(timeout=10)
        return lab.service.revoke(
            "session-a", SessionRevocationRequest(expected_version=1, note="review"),
            lab.operator, now=lab.now,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        used, revoked = pool.submit(use), pool.submit(revoke)
        used.result()
        assert revoked.result().status == "REVOKED"
    assert not lab.access(token).allowed
    with sqlite3.connect(lab.service.path) as connection:
        entries = [json.loads(row[0]) for row in connection.execute(
            "SELECT payload FROM journal ORDER BY seq",
        )]
    revoked_at = next(i for i, item in enumerate(entries)
                      if item.get("session", {}).get("status") == "REVOKED")
    assert all(not item["allowed"] for item in entries[revoked_at + 1:] if item["kind"] == "access")


@pytest.mark.parametrize("operation", ["evaluate", "access", "revoke"])
def test_write_failure_rolls_back_the_entire_state_change(lab, monkeypatch, operation):
    first = lab.evaluate()
    append = lab.service._append

    def append_then_fail(transaction, entry):
        append(transaction, entry)
        raise OSError("simulated local storage failure")

    with monkeypatch.context() as patch:
        patch.setattr(lab.service, "_append", append_then_fail)
        with pytest.raises(JournalUnavailable):
            if operation == "evaluate":
                lab.evaluate(version=1, event_id="next-event", when=lab.now + timedelta(seconds=1))
            elif operation == "access":
                lab.access(first.grant_token)
            else:
                lab.service.revoke(
                    "session-a", SessionRevocationRequest(expected_version=1, note="review"),
                    lab.operator, now=lab.now,
                )
    assert lab.service.integrity()["verified_entries"] == 1
    assert lab.service.history("session-a", lab.operator) == [first.session]
    assert lab.access(first.grant_token).allowed
