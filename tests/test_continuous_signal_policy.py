"""Authority separation and crash-safe, restrictive continuous session updates."""

import base64
import copy
import hashlib
import json
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.continuous_signal_models import SignedContinuousSignal
from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    SignalVerifier,
    canonical_observation,
    canonical_signal,
)
from app.services.zero_trust import JournalUnavailable, SessionConflict, ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionEvaluationRequest,
    SignedSessionSignal,
)


@pytest.fixture
def lab(tmp_path):
    now = datetime(2026, 11, 2, 12, tzinfo=UTC)
    principal = Principal("analyst-a", "tenant-a", frozenset({Role.ADMIN}), "api_key")
    key = Ed25519PrivateKey.generate()
    session_key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    registry = {"sources": [{
        "source_id": "collector", "tenant_id": "tenant-a", "observation_kinds": ["identity", "device"],
        "user_ids": ["user-a", "user-b"], "device_ids": ["device-a", "device-b"],
        "roles": ["employee"], "keys": [{
            "key_id": "key-a", "public_key_pem": public,
            "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
        }],
    }, {
        "source_id": "session-collector", "tenant_id": "tenant-a",
        "user_ids": ["user-a", "user-b"], "device_ids": ["device-a", "device-b"],
        "roles": ["employee"], "keys": [{
            "key_id": "key-a", "public_key_pem": session_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
            "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
        }],
    }]}
    registry_path = tmp_path / "registry.json"

    def save():
        registry_path.write_text(json.dumps(registry), encoding="utf-8")

    save()
    verifier = SignalVerifier(registry_path)
    service = ZeroTrustOperations(tmp_path / "sessions.sqlite3", signal_verifier=verifier)

    def sign(model):
        canonical = canonical_observation if isinstance(model, SignedContinuousSignal) else canonical_signal
        signer = session_key if model.source_id == "session-collector" else key
        signature = base64.urlsafe_b64encode(signer.sign(canonical(model))).decode().rstrip("=")
        return model.model_copy(update={"signature": signature})

    def observation(event_id="observation-a", *, kind="identity", subject="user-a", at=None,
                    issued=None, **updates):
        at = at or now + timedelta(seconds=1)
        issued = issued or at
        claims = {"kind": kind, "subject_id": subject}
        claims.update({"active": True, "authentication_result": "failure"} if kind == "identity"
                      else {"managed": True, "security_posture": "compromised"})
        claims.update(updates)
        return sign(SignedContinuousSignal(
            tenant_id="tenant-a", event_id=event_id, source_id="collector", key_id="key-a",
            issued_at=issued, expires_at=issued + timedelta(seconds=90), observed_at=at,
            observation=claims, signature="A" * 86,
        ))

    def session(session_id="session-a", *, user="user-a", device="device-a",
                operator=principal, signed=False, at=now, version=0,
                source="session-collector", return_signal=False):
        data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        data.update(event_id=f"{session_id}-{version}", timestamp=at)
        data["user"].update(user_id=user, role="employee", active=True)
        data["device"].update(device_id=device, managed=True, security_posture="healthy")
        data["resource"].update(resource_id="zt-demo-documents", required_role=None)
        data["auth_context"].update(authentication_result="success", mfa="success")
        event = SecurityEvent.model_validate(data)
        request = SessionEvaluationRequest(session_id=session_id, expected_version=version, event=event)
        if signed:
            signal = sign(SignedSessionSignal(
                **request.model_dump(), tenant_id=operator.tenant_id,
                source_id=source, key_id="key-a", issued_at=at,
                expires_at=at + timedelta(seconds=90), signature="A" * 86,
            ))
            if return_signal:
                return signal
            return service.evaluate_signed(signal, operator, now=at)
        return service.evaluate(request, operator, now=at)

    def apply(signal, at=None):
        at = at or signal.issued_at
        verified = verifier.verify_observation(signal, principal, at, enforce_freshness=False)
        return service.apply_observation(signal, verified.input_digest, now=at)

    def access(token, session_id="session-a", operator=principal):
        return service.access(ProtectedAccessRequest(
            session_id=session_id, resource_id="zt-demo-documents", action="READ", grant_token=token,
        ), operator, now=now + timedelta(seconds=5))

    return SimpleNamespace(now=now, principal=principal, key=key, registry=registry, save=save,
                           verifier=verifier, service=service, sign=sign, observation=observation,
                           session=session, apply=apply, access=access)


@pytest.mark.parametrize("kind,changes", [
    ("identity", {"mfa": "success"}),
    ("identity", {"managed": True}),
    ("device", {"active": True}),
])
def test_observation_cannot_claim_another_authority_or_prove_mfa(lab, kind, changes):
    with pytest.raises(ValidationError):
        lab.observation(kind=kind, subject="device-a" if kind == "device" else "user-a", **changes)


@pytest.mark.parametrize("kinds", [["identity"], ["device"], ["identity", "device"]])
def test_observation_only_source_cannot_switch_to_full_session_schema(lab, kinds):
    lab.registry["sources"][0]["observation_kinds"] = kinds
    lab.save()
    full = lab.session(signed=True, source="collector", return_signal=True)
    with pytest.raises(SignalRejected):
        lab.verifier.verify(full, lab.principal, lab.now)
    application = FastAPI()
    application.include_router(zero_trust_router(lab.service))
    install_zero_trust_error_handlers(application)
    application.dependency_overrides[get_principal] = lambda: lab.principal
    with TestClient(application) as client:
        response = client.post("/zero-trust/signals/evaluate", json=full.model_dump(mode="json"))
    assert response.status_code == 401
    assert lab.service.sessions(lab.principal) == []


def test_legacy_session_source_cannot_switch_to_observation_schema(lab):
    # The legacy default still permits the original full-session proof, while it
    # grants no new observation authority. The keys are separate between domains.
    assert lab.session(signed=True).session.decision == "ALLOW"
    signal = lab.sign(lab.observation().model_copy(update={"source_id": "session-collector"}))
    with pytest.raises(SignalRejected):
        lab.verifier.verify_observation(signal, lab.principal, signal.issued_at)
    inbox = SignalInbox(lab.service.path)
    application = FastAPI()
    application.include_router(zero_trust_router(
        lab.service, ContinuousSignalService(lab.service, inbox),
    ))
    install_zero_trust_error_handlers(application)
    application.dependency_overrides[get_principal] = lambda: lab.principal
    with TestClient(application) as client:
        response = client.post("/zero-trust/signals/inbox", json=signal.model_dump(mode="json"))
    assert response.status_code == 401
    assert inbox.metrics("tenant-a", now=lab.now)["total"] == 0


@pytest.mark.parametrize("kinds", [[], ["identity"], ["device"]])
def test_source_authorities_cannot_alias_the_same_public_key_within_a_tenant(lab, kinds):
    alias = copy.deepcopy(lab.registry["sources"][0])
    alias.update(source_id="alias-source", observation_kinds=kinds)
    # Equivalent key bytes with a different valid PEM wrapping still conflict.
    body = "".join(alias["keys"][0]["public_key_pem"].splitlines()[1:-1])
    alias["keys"][0]["public_key_pem"] = (
        "-----BEGIN PUBLIC KEY-----\n" + "\n".join(textwrap.wrap(body, 48))
        + "\n-----END PUBLIC KEY-----\n"
    )
    assert alias["keys"][0]["public_key_pem"] != lab.registry["sources"][0]["keys"][0]["public_key_pem"]
    lab.registry["sources"].append(alias)
    lab.save()
    assert not lab.verifier.readiness()["ok"]
    with pytest.raises(SignalRegistryUnavailable):
        lab.verifier.verify_observation(lab.observation(), lab.principal, lab.now + timedelta(seconds=1))


def test_explicit_registration_can_scope_the_same_key_to_another_tenant(lab):
    other = copy.deepcopy(lab.registry["sources"][0])
    other.update(source_id="other-tenant-source", tenant_id="tenant-b")
    lab.registry["sources"].append(other)
    lab.save()
    assert lab.verifier.readiness()["ok"]
    signal = lab.sign(lab.observation().model_copy(update={
        "tenant_id": "tenant-b", "source_id": "other-tenant-source",
    }))
    principal = Principal("analyst-b", "tenant-b", lab.principal.roles, "api_key")
    assert lab.verifier.verify_observation(signal, principal, signal.issued_at).source_id == other["source_id"]


@pytest.mark.parametrize("mutation", ["missing_permission", "wrong_kind", "wrong_subject",
                                      "disabled_source", "revoked_key", "wrong_tenant"])
def test_observation_requires_explicit_current_scoped_authority(lab, mutation):
    signal = lab.observation()
    source = lab.registry["sources"][0]
    if mutation == "missing_permission":
        source.pop("observation_kinds")
    elif mutation == "wrong_kind":
        source["observation_kinds"] = ["device"]
    elif mutation == "wrong_subject":
        source["user_ids"] = ["user-b"]
    elif mutation == "disabled_source":
        source["enabled"] = False
    elif mutation == "revoked_key":
        source["keys"][0]["enabled"] = False
    else:
        source["tenant_id"] = "tenant-b"
    lab.save()
    with pytest.raises(SignalRejected):
        lab.verifier.verify_observation(signal, lab.principal, signal.issued_at)


def test_signature_binds_observation_kind_subject_and_claims(lab):
    signal = lab.observation()
    tampered = signal.model_copy(update={"observation": signal.observation.model_copy(
        update={"authentication_result": "success"},
    )})
    with pytest.raises(SignalRejected):
        lab.verifier.verify_observation(tampered, lab.principal, signal.issued_at)
    with pytest.raises(SessionConflict):
        lab.service.apply_observation(signal, "0" * 64, now=signal.issued_at)


def test_delayed_worker_can_restrict_but_receiver_rejects_expired_signals(lab):
    first = lab.session()
    signal = lab.observation()
    later = signal.expires_at + timedelta(seconds=5)
    with pytest.raises(SignalRejected):
        lab.verifier.verify_observation(signal, lab.principal, later)
    assert lab.apply(signal, at=later)["changed_sessions"] == 1
    assert not lab.access(first.grant_token).allowed
    lab.registry["sources"][0]["keys"][0]["enabled"] = False
    lab.save()
    with pytest.raises(SignalRejected):
        lab.verifier.verify_observation(signal, lab.principal, later, enforce_freshness=False)


def test_identity_fanout_preserves_source_and_spares_other_users_and_tenants(lab):
    first = lab.session(signed=True)
    lab.session("session-two", device="device-b", signed=True)
    unrelated = lab.session("session-other", user="user-b")
    other_tenant = Principal("analyst-a", "tenant-b", lab.principal.roles, "api_key")
    tenant_result = lab.session("session-tenant-b", operator=other_tenant)
    result = lab.apply(lab.observation())
    assert result == {"matched_sessions": 2, "changed_sessions": 2,
                      "stale": False, "duplicate": False}
    changed = lab.service.history("session-a", lab.principal)[-1]
    for field in ("signal_trust", "signal_source_id", "signal_key_id", "signal_source_digest",
                  "signal_expires_at", "operator_id", "user_id", "device_id"):
        assert getattr(changed, field) == getattr(first.session, field)
    assert changed.status == "REVOKED" and changed.grant_expires_at is None
    assert not lab.access(first.grant_token).allowed
    assert lab.access(unrelated.grant_token, "session-other").allowed
    assert lab.access(tenant_result.grant_token, "session-tenant-b", other_tenant).allowed
    assert lab.service.integrity()["ok"]


@pytest.mark.parametrize("kind,subject,claims,expected", [
    ("identity", "user-a", {"authentication_result": "unknown"}, "HOLD"),
    ("identity", "user-a", {"active": False, "authentication_result": "success"}, "DENY"),
    ("device", "device-a", {"security_posture": "unknown"}, "HOLD"),
    ("device", "device-a", {"security_posture": "at_risk"}, "STEP_UP"),
    ("device", "device-a", {"managed": False, "security_posture": "healthy"}, "DENY"),
])
def test_adverse_observations_restrict_without_granting(lab, kind, subject, claims, expected):
    first = lab.session()
    lab.apply(lab.observation(kind=kind, subject=subject, **claims))
    current = lab.service.history("session-a", lab.principal)[-1]
    assert current.decision == expected and current.grant_expires_at is None
    assert not lab.access(first.grant_token).allowed


def test_positive_observation_never_issues_or_restores_a_grant(lab):
    first = lab.session()
    positive = lab.observation(authentication_result="success")
    assert lab.apply(positive)["changed_sessions"] == 0
    assert lab.service.history("session-a", lab.principal)[-1].version == 1
    assert lab.access(first.grant_token).allowed
    lab.apply(lab.observation("deny", at=lab.now + timedelta(seconds=2)))
    later_positive = lab.observation("positive", at=lab.now + timedelta(seconds=3),
                                     authentication_result="success")
    assert lab.apply(later_positive)["changed_sessions"] == 0
    assert lab.service.history("session-a", lab.principal)[-1].status == "REVOKED"


def test_old_positive_and_old_adverse_never_relax_stronger_evidence(lab):
    lab.session()
    later = lab.observation("later-positive", at=lab.now + timedelta(seconds=5),
                            authentication_result="success")
    lab.apply(later)
    # An earlier adverse event arriving behind a positive watermark can only tighten.
    result = lab.apply(lab.observation("delayed-adverse", at=lab.now + timedelta(seconds=2)))
    assert result["stale"] and result["changed_sessions"] == 1
    result = lab.apply(lab.observation("older-positive", at=lab.now + timedelta(seconds=1),
                                       authentication_result="success"))
    assert result["stale"] and result["changed_sessions"] == 0
    assert lab.service.history("session-a", lab.principal)[-1].status == "REVOKED"


@pytest.mark.parametrize("claim,expected", [("unknown", "HOLD"), ("failure", "DENY")])
def test_synchronous_reevaluation_and_new_sessions_cannot_bypass_observations(lab, claim, expected):
    lab.session()
    lab.apply(lab.observation(authentication_result=claim))
    lab.apply(lab.observation("positive", at=lab.now + timedelta(seconds=2),
                              authentication_result="success"))
    recovered = lab.session(version=2, at=lab.now + timedelta(seconds=3))
    fresh = lab.session("session-new", at=lab.now + timedelta(seconds=4))
    assert recovered.session.decision == fresh.session.decision == expected
    assert recovered.grant_token is None and fresh.grant_token is None


def test_committed_effects_retry_after_restart_do_not_add_versions(lab):
    lab.session()
    signal = lab.observation()
    assert lab.apply(signal)["changed_sessions"] == 1
    restarted = ZeroTrustOperations(lab.service.path, signal_verifier=lab.verifier)
    result = restarted.apply_observation(signal, hashlib.sha256(canonical_observation(signal)).hexdigest(),
                                         now=signal.issued_at)
    assert result["duplicate"] and result["changed_sessions"] == 0
    assert len(restarted.history("session-a", lab.principal)) == 2
    assert restarted.integrity()["verified_entries"] == 3
    changed = lab.observation(authentication_result="unknown")
    with pytest.raises(SessionConflict):
        lab.apply(changed)


def test_readonly_result_recovers_committed_effects_after_source_revocation(lab):
    lab.session()
    signal = lab.observation()
    digest = hashlib.sha256(canonical_observation(signal)).hexdigest()
    assert lab.service.observation_result("tenant-a", signal.event_id, digest) is None
    lab.apply(signal)
    lab.registry["sources"][0]["keys"][0]["enabled"] = False
    lab.save()
    with pytest.raises(SignalRejected):
        lab.verifier.verify_observation(signal, lab.principal, signal.issued_at,
                                        enforce_freshness=False)
    restarted = ZeroTrustOperations(lab.service.path, signal_verifier=lab.verifier)
    assert restarted.observation_result("tenant-a", signal.event_id, digest) == {
        "matched_sessions": 1, "changed_sessions": 0, "stale": False, "duplicate": True,
    }
    assert restarted.observation_result("tenant-b", signal.event_id, digest) is None
    assert restarted.observation_result("tenant-a", "different-event", digest) is None
    with pytest.raises(SessionConflict):
        restarted.observation_result("tenant-a", signal.event_id, "0" * 64)
    assert restarted.integrity()["verified_entries"] == 3
    assert len(restarted.history("session-a", lab.principal)) == 2


@pytest.mark.parametrize("failure_after", [1, 2, 3])
def test_fanout_and_marker_rollback_together_on_mid_transaction_failure(lab, monkeypatch, failure_after):
    lab.session()
    lab.session("session-two", device="device-b")
    signal = lab.observation()
    original = lab.service._append
    calls = 0

    def failing(transaction, entry):
        nonlocal calls
        calls += 1
        original(transaction, entry)
        if calls == failure_after:
            raise RuntimeError("simulated worker process interruption")

    monkeypatch.setattr(lab.service, "_append", failing)
    with pytest.raises(RuntimeError):
        lab.apply(signal)
    monkeypatch.setattr(lab.service, "_append", original)
    assert lab.service.integrity()["verified_entries"] == 2
    assert all(s.version == 1 and s.status == "ACTIVE" for s in lab.service.sessions(lab.principal))
    assert lab.apply(signal)["changed_sessions"] == 2
    assert lab.service.integrity()["verified_entries"] == 5


def test_concurrent_redelivery_commits_exactly_one_fanout(lab):
    lab.session()
    signal = lab.observation()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: lab.apply(signal), range(2)))
    assert sum(result["changed_sessions"] for result in results) == 1
    assert sum(result["duplicate"] for result in results) == 1
    assert lab.service.integrity()["verified_entries"] == 3


def test_invalid_observation_marker_fails_journal_closed(lab):
    with lab.service._transaction() as transaction:
        lab.service._append(transaction, {"kind": "observation", "tenant_id": "tenant-a"})
    assert not lab.service.integrity()["ok"]
    with pytest.raises(JournalUnavailable):
        lab.session()


def test_fanout_preflights_session_version_limit_before_any_write(lab):
    first = lab.session()
    second = lab.session("session-two", device="device-b")
    capped = second.session.model_copy(update={
        "version": 200, "decision": "HOLD", "status": "HELD", "grant_expires_at": None,
    })
    with lab.service._transaction() as transaction:
        lab.service._append(transaction, {
            "kind": "decision", "session": capped.model_dump(mode="json"), "grant_hash": None,
        })
    with pytest.raises(SessionConflict):
        lab.apply(lab.observation())
    assert lab.service.history("session-a", lab.principal)[-1] == first.session
    assert lab.service.integrity()["verified_entries"] == 3


def test_journal_capacity_never_commits_partial_fanout_and_full_journal_is_readable(lab):
    lab.session()
    lab.session("session-two", device="device-b")
    with lab.service._transaction() as transaction:
        for _ in range(9997):
            lab.service._append(transaction, {"kind": "access", "allowed": False})
    with pytest.raises(JournalUnavailable):
        lab.apply(lab.observation())
    assert all(s.version == 1 for s in lab.service.sessions(lab.principal))
    assert lab.service.integrity()["verified_entries"] == 9999
    with lab.service._transaction() as transaction:
        lab.service._append(transaction, {"kind": "access", "allowed": False})
    assert lab.service.integrity()["verified_entries"] == 10000
    with pytest.raises(JournalUnavailable):
        lab.apply(lab.observation())
    assert lab.service.integrity()["ok"]
