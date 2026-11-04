"""Background proof/source restrictions without a request, new proof, or new grant."""

import base64
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalVerifier,
    canonical_observation,
    canonical_signal,
)
from app.services.zero_trust import JournalUnavailable, SessionConflict, ZeroTrustOperations
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionEvaluationRequest,
    SessionRevocationRequest,
    SignedSessionSignal,
)


def _public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _rows(service):
    with sqlite3.connect(service.path) as connection:
        return connection.execute("SELECT * FROM journal ORDER BY seq").fetchall()


@pytest.fixture
def lab(tmp_path):
    now = datetime(2026, 11, 4, 12, tzinfo=UTC)
    keys = {tenant: Ed25519PrivateKey.generate() for tenant in ("tenant-a", "tenant-b")}
    observation_key = Ed25519PrivateKey.generate()
    principals = {tenant: Principal("operator", tenant, frozenset({Role.ADMIN}), "api_key")
                  for tenant in keys}

    def source(tenant, source_id, key, **updates):
        return {"tenant_id": tenant, "source_id": source_id,
                "user_ids": ["user-a", "user-b"], "device_ids": ["device-a", "device-b"],
                "roles": ["employee"], "keys": [{
                    "key_id": "key-1", "public_key_pem": _public(key),
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                }], **updates}

    registry = {"sources": [source(tenant, "session-source", key) for tenant, key in keys.items()]}
    registry["sources"].append(source("tenant-a", "observation-source", observation_key,
                                       observation_kinds=["identity"]))
    path = tmp_path / "sources.json"

    def save():
        path.write_text(json.dumps(registry), encoding="utf-8")

    save()
    verifier = SignalVerifier(path)
    service = ZeroTrustOperations(tmp_path / "sessions.sqlite3", signal_verifier=verifier)

    def signed(session_id="session-a", *, tenant="tenant-a", at=None, expires=None,
               version=0, mfa="success", authentication="success"):
        at = at or now
        data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        data.update(event_id=f"{tenant}-{session_id}-{version}", timestamp=at)
        data["user"].update(user_id="user-a", role="employee", active=True)
        data["device"].update(device_id="device-a", managed=True, security_posture="healthy")
        data["resource"].update(resource_id="zt-demo-documents", required_role=None)
        data["auth_context"].update(authentication_result=authentication, mfa=mfa)
        request = SignedSessionSignal(
            session_id=session_id, expected_version=version, event=data,
            tenant_id=tenant, source_id="session-source", key_id="key-1", issued_at=at,
            expires_at=expires or at + timedelta(seconds=90), signature="A" * 86,
        )
        signature = base64.urlsafe_b64encode(keys[tenant].sign(canonical_signal(request)))
        return request.model_copy(update={"signature": signature.decode().rstrip("=")})

    def create(session_id="session-a", *, tenant="tenant-a", **kwargs):
        request = signed(session_id, tenant=tenant, **kwargs)
        return service.evaluate_signed(request, principals[tenant], now=request.issued_at)

    def latest(session_id="session-a", tenant="tenant-a", operations=None):
        return (operations or service).history(session_id, principals[tenant])[-1]

    def access(token, *, at, operations=None):
        return (operations or service).access(ProtectedAccessRequest(
            session_id="session-a", resource_id="zt-demo-documents", action="READ", grant_token=token,
        ), principals["tenant-a"], now=at)

    return SimpleNamespace(now=now, keys=keys, observation_key=observation_key,
                           principals=principals, registry=registry, path=path, save=save,
                           verifier=verifier, service=service, signed=signed, create=create,
                           latest=latest, access=access)


def test_expiry_changes_session_without_access_and_keeps_original_evidence(lab):
    original = lab.create().session
    at = original.signal_expires_at
    result = lab.service.revalidate_sessions(now=at)
    held = lab.latest()
    assert result == {"checked": 1, "changed": 1, "held": 1, "revoked": 0}
    assert (held.decision, held.status, held.version) == ("HOLD", "HELD", 2)
    assert "SIGNAL_PROOF_EXPIRED" in held.reason_codes
    assert held.grant_expires_at is None
    for field in ("tenant_id", "operator_id", "user_id", "device_id", "source_ip", "observed_at",
                  "resource_id", "action", "signal_trust", "signal_source_id", "signal_key_id",
                  "signal_source_digest", "signal_expires_at", "input_digest_sha256",
                  "evidence", "matched_rule_ids", "policy_digest_sha256"):
        assert getattr(held, field) == getattr(original, field)
    entry = json.loads(_rows(lab.service)[-1][1])
    assert entry["grant_hash"] is None
    assert entry["trigger"] == "periodic_revalidation"


def test_expiry_preserves_outstanding_mfa_challenge_and_never_issues_a_grant(lab):
    first = lab.create(mfa="unknown")
    assert first.session.challenge_id and first.grant_token is None
    result = lab.service.revalidate_sessions(now=first.session.signal_expires_at)
    held = lab.latest()
    assert result["held"] == 1
    assert (held.challenge_id, held.challenge_expires_at) == (
        first.session.challenge_id, first.session.challenge_expires_at,
    )
    assert held.grant_expires_at is None


@pytest.mark.parametrize("mutation", [
    "source_disabled", "source_deleted", "key_disabled", "key_deleted", "key_expired",
    "key_not_yet_valid", "key_replaced", "user_scope", "device_scope", "role_scope",
    "observation_only",
])
def test_source_or_scope_change_revokes_without_any_access_request(lab, mutation):
    first = lab.create(mfa="unknown").session
    source = lab.registry["sources"][0]
    key = source["keys"][0]
    at = lab.now + timedelta(seconds=1)
    if mutation == "source_disabled":
        source["enabled"] = False
    elif mutation == "source_deleted":
        lab.registry["sources"].remove(source)
    elif mutation == "key_disabled":
        key["enabled"] = False
    elif mutation == "key_deleted":
        key["key_id"] = "replacement-key-id"
    elif mutation == "key_expired":
        key["not_after"] = at.isoformat()
    elif mutation == "key_not_yet_valid":
        key["not_before"] = (at + timedelta(seconds=1)).isoformat()
    elif mutation == "key_replaced":
        key["public_key_pem"] = _public(Ed25519PrivateKey.generate())
    elif mutation == "user_scope":
        source["user_ids"] = ["user-b"]
    elif mutation == "device_scope":
        source["device_ids"] = ["device-b"]
    elif mutation == "role_scope":
        source["roles"] = ["viewer"]
    else:
        source["observation_kinds"] = ["identity"]
    lab.save()
    assert lab.service.revalidate_sessions(now=at) == {
        "checked": 1, "changed": 1, "held": 0, "revoked": 1,
    }
    revoked = lab.latest()
    assert (revoked.decision, revoked.status, revoked.version) == ("DENY", "REVOKED", 2)
    assert "SIGNAL_SOURCE_REVOKED" in revoked.reason_codes
    assert revoked.challenge_id is None and revoked.challenge_expires_at is None
    assert revoked.grant_expires_at is None
    assert revoked.signal_source_digest == first.signal_source_digest
    assert revoked.evidence == first.evidence
    assert json.loads(_rows(lab.service)[-1][1])["grant_hash"] is None


def test_source_revocation_wins_when_proof_also_expired(lab):
    first = lab.create().session
    lab.registry["sources"][0]["enabled"] = False
    lab.save()
    result = lab.service.revalidate_sessions(now=first.signal_expires_at)
    assert result == {"checked": 1, "changed": 1, "held": 0, "revoked": 1}
    assert lab.latest().status == "REVOKED"
    assert "SIGNAL_SOURCE_REVOKED" in lab.latest().reason_codes


def test_repeated_expiry_is_noop_and_later_key_revocation_escalates_once(lab):
    first = lab.create().session
    at = first.signal_expires_at
    lab.service.revalidate_sessions(now=at)
    rows = _rows(lab.service)
    assert lab.service.revalidate_sessions(now=at + timedelta(seconds=1)) == {
        "checked": 1, "changed": 0, "held": 0, "revoked": 0,
    }
    assert _rows(lab.service) == rows
    lab.registry["sources"][0]["keys"][0]["enabled"] = False
    lab.save()
    assert lab.service.revalidate_sessions(now=at + timedelta(seconds=2))["revoked"] == 1
    revoked = lab.latest()
    assert revoked.version == 3 and revoked.status == "REVOKED"
    assert "SIGNAL_PROOF_EXPIRED" in revoked.reason_codes
    assert "SIGNAL_SOURCE_REVOKED" in revoked.reason_codes
    rows = _rows(lab.service)
    assert lab.service.revalidate_sessions(now=at + timedelta(seconds=3)) == {
        "checked": 0, "changed": 0, "held": 0, "revoked": 0,
    }
    assert _rows(lab.service) == rows


def test_grant_ttl_expiry_alone_does_not_create_a_session_decision(lab):
    first = lab.create()
    at = first.session.grant_expires_at + timedelta(seconds=1)
    assert at < first.session.signal_expires_at
    rows = _rows(lab.service)
    assert lab.service.revalidate_sessions(now=at) == {
        "checked": 1, "changed": 0, "held": 0, "revoked": 0,
    }
    assert _rows(lab.service) == rows
    assert lab.latest() == first.session
    assert lab.access(first.grant_token, at=at).reason_code == "GRANT_EXPIRED"


def test_demo_and_already_revoked_sessions_are_excluded(lab):
    request = lab.signed("demo-session")
    lab.service.evaluate(SessionEvaluationRequest(
        session_id=request.session_id, expected_version=0, event=request.event,
    ), lab.principals["tenant-a"], now=lab.now)
    lab.create()
    lab.service.revoke("session-a", SessionRevocationRequest(expected_version=1, note="operator stop"),
                       lab.principals["tenant-a"], now=lab.now)
    rows = _rows(lab.service)
    assert lab.service.revalidate_sessions(now=lab.now + timedelta(days=2)) == {
        "checked": 0, "changed": 0, "held": 0, "revoked": 0,
    }
    assert _rows(lab.service) == rows


def test_latest_state_is_keyed_by_tenant_and_session_id(lab):
    first = lab.create("shared-session", tenant="tenant-a").session
    other = lab.create("shared-session", tenant="tenant-b").session
    lab.registry["sources"][0]["enabled"] = False
    lab.save()
    assert lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=1)) == {
        "checked": 2, "changed": 1, "held": 0, "revoked": 1,
    }
    assert lab.latest("shared-session", "tenant-a").version == first.version + 1
    assert lab.latest("shared-session", "tenant-b") == other
    assert len(lab.service.sessions(lab.principals["tenant-a"])) == 1
    assert len(lab.service.sessions(lab.principals["tenant-b"])) == 1


def test_all_tenants_are_revalidated_and_persist_across_operations_restart(lab):
    lab.create(tenant="tenant-a")
    lab.create(tenant="tenant-b")
    restarted = ZeroTrustOperations(lab.service.path, signal_verifier=SignalVerifier(lab.path))
    assert restarted.revalidate_sessions(now=lab.now + timedelta(seconds=90)) == {
        "checked": 2, "changed": 2, "held": 2, "revoked": 0,
    }
    for tenant in lab.principals:
        assert lab.latest(tenant=tenant).status == "HELD"
        assert lab.latest(tenant=tenant).version == 2
    rows = _rows(lab.service)
    again = ZeroTrustOperations(lab.service.path, signal_verifier=SignalVerifier(lab.path))
    assert again.revalidate_sessions(now=lab.now + timedelta(seconds=91))["changed"] == 0
    assert _rows(lab.service) == rows


def test_one_validated_registry_snapshot_is_used_for_the_entire_batch(lab, monkeypatch):
    lab.create()
    lab.create("session-b")
    snapshot = lab.verifier._sources()
    calls = 0

    def one_snapshot():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise AssertionError("registry was read twice during a single batch")
        return snapshot

    monkeypatch.setattr(lab.verifier, "_sources", one_snapshot)
    assert lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=90))["held"] == 2
    assert calls == 1


@pytest.mark.parametrize("broken", ["invalid_json", "missing_file", "invalid_public_key"])
def test_registry_failure_aborts_before_any_session_transition(lab, broken):
    lab.create()
    lab.create("session-b")
    rows = _rows(lab.service)
    if broken == "invalid_json":
        lab.path.write_text("{broken", encoding="utf-8")
    elif broken == "missing_file":
        lab.path.unlink()
    else:
        lab.registry["sources"][1]["keys"][0]["public_key_pem"] = "X" * 100
        lab.save()
    with pytest.raises(SignalRegistryUnavailable):
        lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=90))
    assert _rows(lab.service) == rows


@pytest.mark.parametrize("missing", ["signal_source_digest", "signal_source_id", "signal_key_id"])
def test_incomplete_persisted_source_binding_fails_closed(lab, missing):
    first = lab.create().session
    unbound = first.model_copy(update={"version": 2, missing: None})
    with lab.service._transaction() as transaction:
        lab.service._append(transaction, {"kind": "decision", "session": unbound.model_dump(mode="json"),
                                          "grant_hash": None})
    assert lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=1))["revoked"] == 1
    assert lab.latest().status == "REVOKED"
    assert "SIGNAL_SOURCE_REVOKED" in lab.latest().reason_codes


@pytest.mark.parametrize("failure_after", [1, 2])
def test_store_error_rolls_back_all_session_transitions(lab, monkeypatch, failure_after):
    first = lab.create().session
    second = lab.create("session-b").session
    rows = _rows(lab.service)
    append = lab.service._append
    count = 0

    def failing(transaction, entry):
        nonlocal count
        append(transaction, entry)
        count += 1
        if count == failure_after:
            raise sqlite3.OperationalError("injected write failure")

    monkeypatch.setattr(lab.service, "_append", failing)
    with pytest.raises(JournalUnavailable):
        lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=90))
    assert _rows(lab.service) == rows
    assert lab.latest() == first and lab.latest("session-b") == second
    monkeypatch.setattr(lab.service, "_append", append)
    assert lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=90))["changed"] == 2


def test_version_bound_aborts_entire_batch_without_changing_earlier_candidate(lab):
    first = lab.create().session
    second = lab.create("session-b").session
    capped = second.model_copy(update={"version": 200})
    with lab.service._transaction() as transaction:
        lab.service._append(transaction, {"kind": "decision", "session": capped.model_dump(mode="json"),
                                          "grant_hash": None})
    rows = _rows(lab.service)
    with pytest.raises(JournalUnavailable):
        lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=90))
    assert _rows(lab.service) == rows
    assert lab.latest() == first and lab.latest("session-b") == capped


def test_journal_capacity_cannot_commit_a_partial_batch(lab):
    lab.create()
    lab.create("session-b")
    with lab.service._transaction() as transaction:
        for _ in range(9997):
            lab.service._append(transaction, {"kind": "access", "allowed": False})
    rows = _rows(lab.service)
    with pytest.raises(JournalUnavailable):
        lab.service.revalidate_sessions(now=lab.now + timedelta(seconds=90))
    assert _rows(lab.service) == rows
    assert lab.latest().version == lab.latest("session-b").version == 1
    assert lab.service.integrity()["verified_entries"] == 9999


@pytest.mark.parametrize("invalid", [datetime(2026, 11, 4, tzinfo=UTC).replace(tzinfo=None), "2026-11-04", 0, float("nan")])
def test_invalid_now_is_rejected_before_registry_or_transaction(lab, monkeypatch, invalid):
    lab.create()
    rows = _rows(lab.service)

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid time must be rejected before I/O")

    monkeypatch.setattr(lab.verifier, "_sources", forbidden)
    monkeypatch.setattr(lab.service, "_transaction", forbidden)
    with pytest.raises(ValueError):
        lab.service.revalidate_sessions(now=invalid)
    assert _rows(lab.service) == rows


def test_simultaneous_ticks_commit_only_one_restriction_with_real_sqlite(lab):
    lab.create()
    other = ZeroTrustOperations(lab.service.path, signal_verifier=SignalVerifier(lab.path))
    barrier = Barrier(2)

    def tick(operations):
        barrier.wait(timeout=5)
        return operations.revalidate_sessions(now=lab.now + timedelta(seconds=90))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(tick, [lab.service, other]))
    assert sum(result["changed"] for result in results) == 1
    assert lab.latest().version == 2
    assert len(lab.service.history("session-a", lab.principals["tenant-a"])) == 2


def test_tick_serializes_with_fresh_signed_reevaluation(lab):
    lab.create()
    other = ZeroTrustOperations(lab.service.path, signal_verifier=SignalVerifier(lab.path))
    at = lab.now + timedelta(seconds=91)
    fresh = lab.signed(at=at, version=1)
    barrier = Barrier(2)

    def tick():
        barrier.wait(timeout=5)
        return lab.service.revalidate_sessions(now=at)

    def evaluate():
        barrier.wait(timeout=5)
        try:
            return other.evaluate_signed(fresh, lab.principals["tenant-a"], now=at)
        except SessionConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        tick_future = pool.submit(tick)
        evaluation = pool.submit(evaluate).result(timeout=10)
        result = tick_future.result(timeout=10)
    latest = lab.latest()
    assert latest.version == 2
    assert len(lab.service.history("session-a", lab.principals["tenant-a"])) == 2
    if evaluation is None:
        assert latest.status == "HELD" and result["held"] == 1
    else:
        assert latest == evaluation.session and latest.status == "ACTIVE"
        assert result["changed"] == 0


def test_tick_serializes_with_adverse_observation_without_restoring_access(lab):
    first = lab.create()
    other = ZeroTrustOperations(lab.service.path, signal_verifier=SignalVerifier(lab.path))
    at = lab.now + timedelta(seconds=91)
    observation = SignedContinuousSignal(
        tenant_id="tenant-a", event_id="concurrent-risk", source_id="observation-source", key_id="key-1",
        issued_at=at, expires_at=at + timedelta(seconds=90), observed_at=at,
        observation={"kind": "identity", "subject_id": "user-a", "active": True,
                     "authentication_result": "failure"}, signature="A" * 86,
    )
    signature = base64.urlsafe_b64encode(lab.observation_key.sign(canonical_observation(observation)))
    observation = observation.model_copy(update={"signature": signature.decode().rstrip("=")})
    digest = hashlib.sha256(canonical_observation(observation)).hexdigest()
    lab.verifier.verify_observation(observation, lab.principals["tenant-a"], at)
    barrier = Barrier(2)

    def tick():
        barrier.wait(timeout=5)
        return lab.service.revalidate_sessions(now=at)

    def apply():
        barrier.wait(timeout=5)
        return other.apply_observation(observation, digest, now=at)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(tick), pool.submit(apply)]
        for future in results:
            future.result(timeout=10)
    assert lab.latest().status == "REVOKED" and lab.latest().version in (2, 3)
    assert lab.access(first.grant_token, at=at).reason_code == "SESSION_NOT_AUTHORIZED"
    assert lab.service.integrity()["ok"]


def test_tick_and_access_cannot_allow_an_expired_proof(lab):
    first = lab.create()
    other = ZeroTrustOperations(lab.service.path, signal_verifier=SignalVerifier(lab.path))
    at = lab.now + timedelta(seconds=91)
    barrier = Barrier(2)

    def tick():
        barrier.wait(timeout=5)
        return lab.service.revalidate_sessions(now=at)

    def access():
        barrier.wait(timeout=5)
        return lab.access(first.grant_token, at=at, operations=other)

    with ThreadPoolExecutor(max_workers=2) as pool:
        tick_future = pool.submit(tick)
        result = pool.submit(access).result(timeout=10)
        assert tick_future.result(timeout=10)["held"] == 1
    assert not result.allowed
    assert result.reason_code in {"SIGNAL_PROOF_EXPIRED", "SESSION_NOT_AUTHORIZED"}
    assert lab.latest().status == "HELD" and lab.latest().version == 2
    assert lab.service.integrity()["ok"]
