import base64
import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.behavior_context_models import BehaviorScope, SignedBehaviorCapture
from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.behavior_context_trust import behavior_snapshot
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import (
    SignalRejected,
    SignalVerifier,
    canonical_behavior_capture,
    canonical_observation,
    canonical_signal,
)
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations
from app.zero_trust_models import SessionRevocationRequest, SignedSessionSignal, TrustedSignalSource

NOW = datetime(2026, 11, 10, 9, tzinfo=UTC)
PRINCIPAL = Principal("operator", "tenant-a", frozenset({Role.ADMIN}), "test")
SCOPE = BehaviorScope(source="cloudtrail", user_id="user-a", device_id="device-a",
                      resource_id="zt-demo-documents", action="READ", principal_hash="cloud-actor")


def sign(model, key, canonical):
    signature = base64.urlsafe_b64encode(key.sign(canonical(model))).decode().rstrip("=")
    return model.model_copy(update={"signature": signature})


@pytest.fixture
def context_lab(tmp_path):
    keys = {name: Ed25519PrivateKey.generate() for name in ("identity", "behavior", "device", "guardduty", "proof")}
    sources = []
    for name, key in keys.items():
        source = {
            "source_id": name, "tenant_id": "tenant-a", "user_ids": ["user-a", "user-b"],
            "device_ids": ["device-a", "device-b"], "roles": ["employee"],
            "keys": [{"key_id": "key", "public_key_pem": key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(), "not_before": (NOW - timedelta(days=1)).isoformat(),
                "not_after": (NOW + timedelta(days=1)).isoformat()}],
        }
        if name == "behavior":
            source["behavior_scopes"] = [SCOPE.model_dump(mode="json")]
        elif name == "device":
            source["observation_kinds"] = ["device"]
        elif name == "guardduty":
            source["observation_kinds"] = ["guardduty"]
            source["guardduty_resource_ids"] = ["zt-demo-documents", "zt-demo-vault"]
        elif name == "proof":
            source["observation_kinds"] = ["session_proof"]
            source["session_proof_resource_ids"] = ["zt-demo-documents", "zt-demo-vault"]
        sources.append(source)
    registry_path = tmp_path / "registry.json"

    def save():
        registry_path.write_text(json.dumps({"sources": sources}))

    save()
    verifier = SignalVerifier(registry_path)
    operations = ZeroTrustOperations(tmp_path / "operations.sqlite3", signal_verifier=verifier)
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event.update(event_id="initial-session", timestamp=NOW)
    event["user"].update(user_id="user-a", role="employee", active=True)
    event["device"].update(device_id="device-a", managed=True, security_posture="healthy")
    event["resource"].update(resource_id="zt-demo-documents", required_role=None)
    event["auth_context"].update(authentication_result="success", mfa="success")
    signal = SignedSessionSignal.model_validate({
        "session_id": "session-a", "expected_version": 0, "event": event,
        "tenant_id": "tenant-a", "source_id": "identity", "key_id": "key",
        "issued_at": NOW, "expires_at": NOW + timedelta(seconds=90), "signature": "A" * 86,
    })
    signal = sign(signal, keys["identity"], canonical_signal)
    result = operations.evaluate_signed(signal, PRINCIPAL, now=NOW)
    assert result.session.status == "ACTIVE"

    def capture(**updates):
        data = {
            "capture_id": "capture-a", "tenant_id": "tenant-a", "source_id": "behavior",
            "key_id": "key", "issued_at": NOW + timedelta(seconds=2),
            "expires_at": NOW + timedelta(seconds=92), "scope": SCOPE,
            "session_id": "session-a", "session_version": 1,
            "session_input_sha256": result.session.input_digest_sha256,
            "connection_ids": ["cloud-key"], "signature": "A" * 86,
            "activity": {"source": "cloudtrail", "original_group_id": "group-a", "events": [
                {"id": "event-a", "timestamp": NOW + timedelta(seconds=1), "kind": "AwsApiCall",
                 "api_service": "s3.amazonaws.com", "api_action": "PutObject",
                 "resource_hashes": ["object-a"], "principal_hash": "cloud-actor",
                 "connection_id": "cloud-key", "outcome": "success"},
            ]},
        }
        data.update(updates)
        return sign(SignedBehaviorCapture.model_validate(data), keys["behavior"], canonical_behavior_capture)

    def observation(kind="device", *, event_id="adverse-a", **updates):
        if kind == "device":
            values = {"kind": kind, "subject_id": "device-a", "managed": True,
                      "security_posture": "compromised"}
            source = "device"
        elif kind == "guardduty":
            values = {"kind": kind, "subject_id": "user-a", "resource_id": "zt-demo-documents",
                      "finding_sha256": "e" * 64}
            source = "guardduty"
        else:
            values = {"kind": "session_proof", "subject_id": "user-a", "device_id": "device-a",
                      "resource_id": "zt-demo-documents", "session_id": "session-a",
                      "session_version": 1, "action": "READ", "proof_sha256": "a" * 64,
                      "session_input_sha256": result.session.input_digest_sha256,
                      "violation": "nonce_reuse"}
            source = "proof"
        values.update(updates)
        request = SignedContinuousSignal.model_validate({
            "tenant_id": "tenant-a", "source_id": source, "key_id": "key", "event_id": event_id,
            "issued_at": NOW + timedelta(seconds=3), "observed_at": NOW + timedelta(seconds=3),
            "expires_at": NOW + timedelta(seconds=93), "observation": values, "signature": "A" * 86,
        })
        return sign(request, keys[source], canonical_observation)

    def commit(request):
        service = ContinuousSignalService(operations, SignalInbox(operations.path))
        service.accept(request, PRINCIPAL, now=NOW + timedelta(seconds=3))
        return service.process_one(now=NOW + timedelta(seconds=3))

    return SimpleNamespace(keys=keys, sources=sources, save=save, operations=operations,
                           verifier=verifier, capture=capture, signal=signal, result=result,
                           observation=observation, commit=commit)


def test_capture_verification_is_scoped_and_domain_separated(context_lab):
    capture = context_lab.capture()
    proof = context_lab.verifier.verify_behavior_capture(capture, PRINCIPAL, NOW + timedelta(seconds=2))
    assert proof.input_digest == hashlib.sha256(canonical_behavior_capture(capture)).hexdigest()
    assert b'"schema_version":"zt-behavior-1"' in canonical_behavior_capture(capture)
    assert proof.challenge_id is None
    changed = capture.model_copy(update={"capture_id": "other-capture"})
    with pytest.raises(SignalRejected, match="signature"):
        context_lab.verifier.verify_behavior_capture(changed, PRINCIPAL, NOW + timedelta(seconds=2))


@pytest.mark.parametrize("changes", [
    {"tenant_id": "tenant-b"}, {"source_id": "identity"}, {"key_id": "missing"},
    {"scope": SCOPE.model_copy(update={"resource_id": "zt-demo-vault"})},
])
def test_capture_rejects_wrong_authority_or_scope(context_lab, changes):
    capture = context_lab.capture(**changes)
    with pytest.raises(SignalRejected):
        context_lab.verifier.verify_behavior_capture(capture, PRINCIPAL, NOW + timedelta(seconds=2))


def test_capture_requires_authenticated_analyst_and_validated_shape(context_lab):
    capture = context_lab.capture()
    viewer = Principal("viewer", "tenant-a", frozenset({Role.VIEWER}), "test")
    with pytest.raises(SignalRejected, match="analyst"):
        context_lab.verifier.verify_behavior_capture(capture, viewer, NOW + timedelta(seconds=2))
    malformed = sign(capture.model_copy(update={"connection_ids": ["another-key"]}),
                     context_lab.keys["behavior"], canonical_behavior_capture)
    with pytest.raises(SignalRejected, match="shape"):
        context_lab.verifier.verify_behavior_capture(malformed, PRINCIPAL, NOW + timedelta(seconds=2))


@pytest.mark.parametrize("offset", [1, 63, 93])
def test_capture_intake_rejects_future_stale_or_expired(context_lab, offset):
    with pytest.raises(SignalRejected, match="freshness"):
        context_lab.verifier.verify_behavior_capture(context_lab.capture(), PRINCIPAL,
                                                    NOW + timedelta(seconds=offset))


def test_expired_capture_is_historically_readable_but_cannot_support_normal(context_lab):
    capture = context_lab.capture()
    snapshot = behavior_snapshot(context_lab.operations, capture, PRINCIPAL, NOW + timedelta(seconds=93))
    assert snapshot["binding_valid"] is True
    assert snapshot["normal_session_eligible"] is False


def test_behavior_authority_cannot_issue_session_proof(context_lab):
    request = context_lab.signal.model_copy(update={"source_id": "behavior"})
    request = sign(request, context_lab.keys["behavior"], canonical_signal)
    with pytest.raises(SignalRejected, match="cannot assert a full session"):
        context_lab.verifier.verify(request, PRINCIPAL, NOW)


def test_legacy_source_serialization_and_live_proof_digest_are_preserved(context_lab):
    source = TrustedSignalSource.model_validate(context_lab.sources[0])
    serialized = source.model_dump(mode="json")
    assert "behavior_scopes" not in serialized
    assert context_lab.result.session.signal_source_digest == hashlib.sha256(source.model_dump_json().encode()).hexdigest()
    dedicated = TrustedSignalSource.model_validate(context_lab.sources[1])
    assert dedicated.model_dump(mode="json")["behavior_scopes"] == [SCOPE.model_dump(mode="json")]


def test_behavior_source_cannot_alias_observation_authority(context_lab):
    source = context_lab.sources[1] | {"observation_kinds": ["device"]}
    with pytest.raises(ValueError, match="dedicated"):
        TrustedSignalSource.model_validate(source)


def test_behavior_source_cannot_sign_compromise_observations(context_lab):
    request = context_lab.observation().model_copy(update={"source_id": "behavior"})
    request = sign(request, context_lab.keys["behavior"], canonical_observation)
    with pytest.raises(SignalRejected, match="kind or subject scope"):
        context_lab.commit(request)


def test_normal_snapshot_is_read_only_and_rechecks_session_signer(context_lab):
    before = context_lab.operations.journal_status()
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=2))
    assert snapshot["binding_valid"] and snapshot["normal_session_eligible"]
    assert snapshot["evidence"] == []
    assert context_lab.operations.journal_status() == before
    context_lab.sources[0]["keys"][0]["enabled"] = False
    context_lab.save()
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=2))
    assert snapshot["binding_valid"] and not snapshot["normal_session_eligible"]


def test_capture_key_revocation_rejects_historical_replay(context_lab):
    context_lab.sources[1]["keys"][0]["enabled"] = False
    context_lab.save()
    with pytest.raises(SignalRejected, match="key"):
        behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                          NOW + timedelta(seconds=2))


@pytest.mark.parametrize("updates", [
    {"session_id": "session-absent"}, {"session_version": 2},
    {"session_input_sha256": "b" * 64},
])
def test_snapshot_requires_exact_signed_session_revision(context_lab, updates):
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(**updates), PRINCIPAL,
                                 NOW + timedelta(seconds=2))
    assert not snapshot["binding_valid"] and not snapshot["normal_session_eligible"]
    assert snapshot["evidence"] == []


def test_capture_events_cannot_precede_bound_session(context_lab):
    capture = context_lab.capture()
    event = capture.activity.events[0].model_copy(update={"timestamp": NOW - timedelta(seconds=1)})
    capture = sign(capture.model_copy(update={"activity": capture.activity.model_copy(update={"events": [event]})}),
                   context_lab.keys["behavior"], canonical_behavior_capture)
    assert not behavior_snapshot(context_lab.operations, capture, PRINCIPAL,
                                 NOW + timedelta(seconds=2))["binding_valid"]


@pytest.mark.parametrize("kind,reason", [
    ("device", "trusted_device_compromise"), ("guardduty", "trusted_guardduty_finding"),
    ("session_proof", "trusted_session_proof_violation"),
])
def test_worker_committed_adverse_signal_is_available_as_scoped_evidence(context_lab, kind, reason):
    delivery = context_lab.commit(context_lab.observation(kind))
    assert delivery["state"] == "completed"
    before = context_lab.operations.journal_status()
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=4))
    assert snapshot["binding_valid"] and not snapshot["normal_session_eligible"]
    assert snapshot["current_status"] == "REVOKED"
    assert [item["reason"] for item in snapshot["evidence"]] == [reason]
    assert context_lab.operations.journal_status() == before


@pytest.mark.parametrize("kind,updates", [
    ("device", {"subject_id": "device-b"}),
    ("guardduty", {"subject_id": "user-b"}),
    ("guardduty", {"resource_id": "zt-demo-vault"}),
    ("session_proof", {"session_version": 2}),
    ("session_proof", {"session_input_sha256": "c" * 64}),
    ("session_proof", {"action": "DOWNLOAD"}),
    ("session_proof", {"device_id": "device-b"}),
])
def test_unrelated_or_unapplied_signals_do_not_become_attack_evidence(context_lab, kind, updates):
    context_lab.commit(context_lab.observation(kind, **updates))
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=4))
    assert snapshot["evidence"] == []
    assert snapshot["normal_session_eligible"]


def test_administrative_isolation_is_not_compromise_evidence(context_lab):
    context_lab.commit(context_lab.observation(managed=False, security_posture="healthy"))
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=4))
    assert snapshot["current_status"] == "REVOKED"
    assert snapshot["evidence"] == []
    assert not snapshot["normal_session_eligible"]


def test_same_named_subject_in_another_tenant_does_not_supply_evidence(context_lab):
    context_lab.sources.append(context_lab.sources[2] | {"tenant_id": "tenant-b"})
    context_lab.save()
    request = context_lab.observation().model_copy(update={"tenant_id": "tenant-b"})
    request = sign(request, context_lab.keys["device"], canonical_observation)
    other = Principal("operator-b", "tenant-b", frozenset({Role.ANALYST}), "test")
    service = ContinuousSignalService(context_lab.operations, SignalInbox(context_lab.operations.path))
    service.accept(request, other, now=NOW + timedelta(seconds=3))
    completed = service.process_one(now=NOW + timedelta(seconds=3))
    assert completed["state"] == "completed" and completed["result"]["matched_sessions"] == 0
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=4))
    assert snapshot["normal_session_eligible"] and snapshot["evidence"] == []


def test_manual_revocation_does_not_claim_an_attack(context_lab):
    context_lab.operations.revoke("session-a", SessionRevocationRequest(expected_version=1, note="planned maintenance"),
                                  PRINCIPAL, now=NOW + timedelta(seconds=3))
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=4))
    assert snapshot["current_status"] == "REVOKED" and snapshot["evidence"] == []


def test_rejected_signature_never_enters_context_evidence(context_lab):
    request = context_lab.observation().model_copy(update={"signature": "A" * 86})
    with pytest.raises(SignalRejected, match="signature"):
        context_lab.commit(request)
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=4))
    assert snapshot["evidence"] == [] and snapshot["normal_session_eligible"]


def test_committed_compromise_is_not_erased_by_later_observation_key_revocation(context_lab):
    context_lab.commit(context_lab.observation())
    context_lab.sources[2]["keys"][0]["enabled"] = False
    context_lab.save()
    snapshot = behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                                 NOW + timedelta(seconds=4))
    assert snapshot["evidence"][0]["reason"] == "trusted_device_compromise"


def test_corrupt_policy_journal_cannot_provide_normal_context(context_lab):
    with sqlite3.connect(context_lab.operations.path) as connection:
        connection.execute("UPDATE journal SET payload=? WHERE seq=1", ('{}',))
    with pytest.raises(JournalUnavailable):
        behavior_snapshot(context_lab.operations, context_lab.capture(), PRINCIPAL,
                          NOW + timedelta(seconds=2))
