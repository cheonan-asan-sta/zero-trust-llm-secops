"""Finite restrictive revisions after the ordinary session evaluation boundary."""

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
import test_continuous_signal_policy as shared
from pydantic import ValidationError

from app.services import policy_journal
from app.services.zero_trust import JournalUnavailable, SessionConflict, ZeroTrustOperations
from app.zero_trust_models import (
    SessionDecision,
    SessionEvaluationRequest,
    SessionRevocationRequest,
)


@pytest.fixture
def lab(tmp_path):
    return shared.lab.__wrapped__(tmp_path)


def seed(lab, *, decision="ALLOW"):
    first = lab.session(signed=True)
    session = first.session.model_copy(update={
        "version": 200, "event_id": "legacy-cap", "decision": decision,
        "status": {"ALLOW": "ACTIVE", "STEP_UP": "STEP_UP_REQUIRED", "HOLD": "HELD", "DENY": "REVOKED"}[decision],
        "grant_expires_at": None, "reason_codes": ["SESSION_HISTORY_CAPACITY"],
        "risk_score": 42, "evidence": ["preserved legacy evidence"],
    })
    with lab.service._transaction() as txn:
        lab.service._append(txn, {"kind": "decision", "session": session.model_dump(mode="json"), "grant_hash": None})
    return session


def latest(lab, service=None):
    return (service or lab.service).history("session-a", lab.principal)[-1]


def logical(lab):
    with lab.service._transaction() as txn:
        return copy.deepcopy(txn[1])


def advance(lab, stages):
    if stages >= 1:
        lab.apply(lab.observation("step", kind="device", subject="device-a", security_posture="at_risk"))
    if stages >= 2:
        lab.apply(lab.observation("hold", kind="device", subject="device-a", security_posture="unknown",
                                  at=lab.now + timedelta(seconds=2)))
    if stages >= 3:
        lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=90))


def test_all_four_reserved_revisions_are_finite_monotonic_and_survive_archive(lab):
    seed(lab)
    advance(lab, 3)
    held = latest(lab)
    assert held.version == 203 and held.status == "HELD"
    assert "SIGNAL_PROOF_EXPIRED" in held.reason_codes
    before = logical(lab)
    assert lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=91))["changed"] == 0
    assert logical(lab) == before
    signal = lab.observation("deny", at=lab.now + timedelta(seconds=92))
    result = lab.apply(signal)
    assert result["changed_sessions"] == 1
    assert lab.apply(signal)["duplicate"]
    lab.service.compact_journal()
    restarted = ZeroTrustOperations(lab.service.path, signal_verifier=lab.verifier)
    history = restarted.history("session-a", lab.principal)
    assert [row.version for row in history] == [1, 200, 201, 202, 203, 204]
    assert [row.decision for row in history[2:]] == ["STEP_UP", "HOLD", "HOLD", "DENY"]
    assert all(row.grant_expires_at is None for row in history[1:])
    assert all(row.evidence[0] == "preserved legacy evidence" for row in history[1:])
    assert restarted.revalidate_sessions(now=lab.now + timedelta(seconds=93))["changed"] == 0
    assert history[-1].status == "REVOKED"


@pytest.mark.parametrize("stages", [0, 1, 2, 3])
def test_manual_revocation_uses_remaining_revision_and_current_cas_only(lab, stages):
    seed(lab)
    advance(lab, stages)
    previous = latest(lab)
    request = SessionRevocationRequest(expected_version=previous.version, note="reviewed manual stop")
    current = lab.service.revoke("session-a", request, lab.principal, now=lab.now + timedelta(seconds=100))
    assert current.version == previous.version + 1 and current.status == "REVOKED"
    assert set(previous.reason_codes).issubset(current.reason_codes)
    assert current.evidence == previous.evidence and current.grant_expires_at is None
    with pytest.raises(SessionConflict):
        lab.service.revoke("session-a", request, lab.principal)
    before = logical(lab)
    repeated = lab.service.revoke("session-a", SessionRevocationRequest(
        expected_version=current.version, note="same final state"), lab.principal)
    assert repeated == current and logical(lab) == before


@pytest.mark.parametrize("version,decision,reason,valid", [
    (200, "ALLOW", [], True), (201, "STEP_UP", [], True), (201, "HOLD", [], True),
    (201, "DENY", [], True), (202, "STEP_UP", [], False), (202, "HOLD", [], True),
    (203, "STEP_UP", [], False), (203, "HOLD", [], False),
    (203, "HOLD", ["SIGNAL_PROOF_EXPIRED"], True), (203, "DENY", [], True),
    (204, "HOLD", ["SIGNAL_PROOF_EXPIRED"], False), (204, "DENY", [], True),
    (205, "DENY", [], False), (201, "ALLOW", [], False),
])
def test_output_model_security_revision_rank_budget(lab, version, decision, reason, valid):
    data = lab.session().session.model_dump() | {
        "version": version, "decision": decision, "reason_codes": reason,
        "status": {"ALLOW": "ACTIVE", "STEP_UP": "STEP_UP_REQUIRED", "HOLD": "HELD", "DENY": "REVOKED"}[decision],
        "grant_expires_at": None,
    }
    if valid:
        assert SessionDecision.model_validate(data).version == version
    else:
        with pytest.raises(ValidationError):
            SessionDecision.model_validate(data)


@pytest.mark.parametrize("changes", [
    {"status": "ACTIVE"}, {"status": "STEP_UP_REQUIRED"}, {"grant_expires_at": "2026-11-05T00:00:00Z"},
])
def test_overflow_output_cannot_carry_active_status_or_a_grant(lab, changes):
    data = lab.session().session.model_dump() | {
        "version": 201, "decision": "HOLD", "status": "HELD", "grant_expires_at": None,
    } | changes
    with pytest.raises(ValidationError):
        SessionDecision.model_validate(data)


def test_ordinary_evaluation_cannot_use_reserved_security_revisions(lab):
    seed(lab, decision="HOLD")
    lab.apply(lab.observation())
    before = logical(lab)
    with pytest.raises(SessionConflict):
        lab.session(version=200, at=lab.now + timedelta(seconds=3))
    data = lab.session("other").session
    event = lab.session("event-source", signed=True, return_signal=True).event
    with pytest.raises(ValidationError):
        SessionEvaluationRequest(session_id=data.session_id, expected_version=201, event=event)
    assert logical(lab)[:len(before)] == before


def overflow_record(lab):
    previous = seed(lab, decision="HOLD")
    now = lab.now + timedelta(seconds=90)
    current = previous.model_dump(mode="json") | {
        "version": 201, "event_id": "check-security", "evaluated_at": now.isoformat(),
        "reason_codes": [*previous.reason_codes, "SIGNAL_PROOF_EXPIRED"],
    }
    return {"kind": "decision", "session": current, "grant_hash": None,
            "trigger": "periodic_revalidation", "revalidation": {
                "previous_version": 200, "reason_code": "SIGNAL_PROOF_EXPIRED", "checked_at": now.isoformat(),
            }}


@pytest.mark.parametrize("damage", [
    "missing-predecessor", "gap", "user", "resource", "source", "grant", "event", "risk",
    "reason", "evidence", "challenge", "writer", "checked-at", "revalidation-version",
])
def test_checksummed_overflow_corruption_fails_closed_in_tail_and_archive(lab, damage):
    record = overflow_record(lab)
    if damage == "missing-predecessor":
        record["session"]["session_id"] = "missing-session"
    elif damage == "gap":
        record["session"]["version"] = 202
    elif damage in {"user", "resource", "source"}:
        record["session"][{"user": "user_id", "resource": "resource_id", "source": "signal_source_id"}[damage]] = "changed"
    elif damage == "grant":
        record["grant_hash"] = "a" * 64
    elif damage == "event":
        record["session"]["event_id"] = "legacy-cap"
    elif damage == "risk":
        record["session"]["risk_score"] = 41
    elif damage == "reason":
        record["session"]["reason_codes"] = ["SIGNAL_PROOF_EXPIRED"]
    elif damage == "evidence":
        record["session"]["evidence"] = []
    elif damage == "challenge":
        record["session"]["challenge_id"] = "unexpected-challenge"
    elif damage == "writer":
        del record["trigger"]
    elif damage == "checked-at":
        record["revalidation"]["checked_at"] = lab.now.isoformat()
    else:
        record["revalidation"]["previous_version"] = 199
    # Inject a structurally valid, correctly chained storage entry, bypassing the
    # domain writer. The reader must reject forged restrictive revisions too.
    with policy_journal.transaction(lab.service.path, lab.service.journal_limits) as txn:
        policy_journal.append(txn, record)
        policy_journal.compact(txn)
    assert lab.service.integrity()["ok"] is False
    for operation in (lambda: lab.service.history("session-a", lab.principal), lab.service.compact_journal):
        with pytest.raises(JournalUnavailable):
            operation()


def test_overflow_fanout_rolls_back_and_retry_restarts_once(lab, monkeypatch):
    seed(lab, decision="HOLD")
    other = lab.session("related")
    signal = lab.observation()
    before = logical(lab)
    original = lab.service._append
    calls = []

    def fail_after_first(txn, record):
        original(txn, record)
        calls.append(1)
        if len(calls) == 1:
            raise OSError("injected post-append failure")

    with monkeypatch.context() as context:
        context.setattr(lab.service, "_append", fail_after_first)
        with pytest.raises(JournalUnavailable):
            lab.apply(signal)
    assert logical(lab) == before
    restarted = ZeroTrustOperations(lab.service.path, signal_verifier=lab.verifier)
    lab.service = restarted
    # Fixture closures refer to the original service, which shares this DB; its
    # next transaction must observe the restarted store's exact same state.
    result = lab.apply(signal)
    assert result["changed_sessions"] == 2
    assert latest(lab).version == 201
    assert restarted.history("related", lab.principal)[-1].version == other.session.version + 1
    assert lab.apply(signal)["changed_sessions"] == 0


def test_concurrent_overflow_redelivery_adds_one_restriction_and_marker(lab):
    seed(lab, decision="HOLD")
    signal = lab.observation()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: lab.apply(signal), range(12)))
    assert sum(result["changed_sessions"] for result in results) == 1
    assert latest(lab).version == 201
    assert [row.version for row in lab.service.history("session-a", lab.principal)] == [1, 200, 201]


@pytest.mark.parametrize("version", [1, 200])
def test_security_revision_cannot_reset_to_legacy_allow(lab, version):
    previous = seed(lab, decision="HOLD")
    lab.apply(lab.observation())
    before = logical(lab)
    reset = previous.model_dump(mode="json") | {
        "version": version, "decision": "ALLOW", "status": "ACTIVE", "event_id": "forged-reset",
        "grant_expires_at": (lab.now + timedelta(seconds=60)).isoformat(),
    }
    record = {"kind": "decision", "session": reset, "grant_hash": "a" * 64}
    with pytest.raises(JournalUnavailable), lab.service._transaction() as txn:
        lab.service._append(txn, record)
    assert logical(lab) == before
    with policy_journal.transaction(lab.service.path, lab.service.journal_limits) as txn:
        policy_journal.append(txn, record)
        policy_journal.compact(txn)
    assert lab.service.integrity()["ok"] is False
    with pytest.raises(JournalUnavailable):
        lab.service.history("session-a", lab.principal)
