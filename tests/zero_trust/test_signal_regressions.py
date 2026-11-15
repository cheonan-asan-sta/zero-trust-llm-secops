"""Signed proof mutation, trust registry and key/challenge time boundaries."""

import base64
import copy
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from pydantic import ValidationError

from app.services.trusted_signals import SignalRegistryUnavailable, SignalRejected
from app.services.zero_trust import SessionConflict
from app.zero_trust_models import SignedSessionSignal


@pytest.mark.parametrize("field,value", [
    ("session_id", "other-session"),
    ("expected_version", 1),
    ("tenant_id", "other-tenant"),
    ("source_id", "other-source"),
    ("key_id", "other-key"),
    ("challenge_id", "x" * 32),
    ("event.event_id", "other-event"),
    ("event.user.user_id", "other-user"),
    ("event.user.active", False),
    ("event.device.device_id", "other-device"),
    ("event.device.security_posture", "compromised"),
    ("event.resource.resource_id", "zt-demo-vault"),
    ("event.action", "DOWNLOAD"),
    ("event.auth_context.mfa", "unknown"),
    ("event.network.ip", "192.0.2.99"),
    ("event.behavior.unusual_time", True),
    ("issued_at", "2026-10-27T11:59:59Z"),
    ("expires_at", "2026-10-27T12:01:00Z"),
    ("event.timestamp", "2026-10-27T11:59:59Z"),
])
def test_mutating_any_security_relevant_signed_field_is_rejected(lab, field, value):
    payload = lab.signed().model_dump(mode="json")
    target = payload
    components = field.split(".")
    for component in components[:-1]:
        target = target[component]
    target[components[-1]] = value
    changed = SignedSessionSignal.model_validate(payload)
    with pytest.raises(SignalRejected):
        lab.service.evaluate_signed(changed, lab.operator, now=lab.now)
    assert lab.service.sessions(lab.operator) == []
    assert lab.service.integrity()["verified_entries"] == 0


def test_noncanonical_signature_encoding_is_rejected_even_if_decoded_bytes_match(lab):
    request = lab.signed()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(request.signature[-1])
    altered = request.signature[:-1] + alphabet[last ^ 1]
    assert base64.urlsafe_b64decode(altered + "==") == base64.urlsafe_b64decode(
        request.signature + "==",
    )
    with pytest.raises(SignalRejected):
        lab.service.evaluate_signed(request.model_copy(update={"signature": altered}),
                                    lab.operator, now=lab.now)
    assert lab.service.sessions(lab.operator) == []


@pytest.mark.parametrize("elapsed,accepted", [(60, True), (60.000001, False), (-0.000001, False)])
def test_proof_freshness_exact_boundary(lab, elapsed, accepted):
    request = lab.signed()
    now = lab.now + timedelta(seconds=elapsed)
    if accepted:
        proof = lab.service.signal_verifier.verify(request, lab.operator, now)
        assert proof.source_id == "source-a"
    else:
        with pytest.raises(SignalRejected):
            lab.service.signal_verifier.verify(request, lab.operator, now)


@pytest.mark.parametrize("delta,accepted", [(-0.000001, True), (0, False), (0.000001, False)])
def test_proof_expiry_exact_boundary(lab, delta, accepted):
    request = lab.signed(expires_at=lab.now + timedelta(seconds=10))
    now = lab.now + timedelta(seconds=10 + delta)
    if accepted:
        assert lab.service.signal_verifier.verify(request, lab.operator, now)
    else:
        with pytest.raises(SignalRejected):
            lab.service.signal_verifier.verify(request, lab.operator, now)


@pytest.mark.parametrize("start_delta,accepted", [(0, True), (0.000001, False)])
def test_key_not_before_exact_boundary(lab, start_delta, accepted):
    lab.registry["sources"][0]["keys"][0]["not_before"] = (
        lab.now + timedelta(seconds=start_delta)
    ).isoformat()
    lab.save_registry()
    if accepted:
        assert lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now).grant_token
    else:
        with pytest.raises(SignalRejected):
            lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now)


def test_proof_cannot_outlive_its_signing_key(lab):
    lab.registry["sources"][0]["keys"][0]["not_after"] = (
        lab.now + timedelta(seconds=30)
    ).isoformat()
    lab.save_registry()
    with pytest.raises(SignalRejected):
        lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now)
    assert lab.service.sessions(lab.operator) == []
    result = lab.service.evaluate_signed(
        lab.signed(expires_at=lab.now + timedelta(seconds=30)), lab.operator, now=lab.now,
    )
    assert result.session.grant_expires_at == lab.now + timedelta(seconds=30)
    assert not lab.access(result.grant_token, at=lab.now + timedelta(seconds=30)).allowed


@pytest.mark.parametrize("seconds", [0, -1, 120.000001])
def test_invalid_proof_lifetime_is_rejected_at_the_contract_boundary(lab, seconds):
    payload = lab.signed().model_dump(mode="json")
    payload["expires_at"] = (lab.now + timedelta(seconds=seconds)).isoformat()
    with pytest.raises(ValidationError):
        SignedSessionSignal.model_validate(payload)


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
def test_proof_validity_requires_an_explicit_timezone(lab, field):
    payload = lab.signed().model_dump(mode="json")
    payload[field] = payload[field].rstrip("Z")
    with pytest.raises(ValidationError):
        SignedSessionSignal.model_validate(payload)


@pytest.mark.parametrize("damage", [
    "missing-file", "invalid-json", "oversized-file", "duplicate-source", "duplicate-key",
    "empty-keys", "bad-pem", "wrong-key-type", "invalid-key-window", "naive-key-time",
    "unknown-registry-field",
])
def test_registry_damage_blocks_new_decisions_and_existing_access(lab, damage):
    token = lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now).grant_token
    source = lab.registry["sources"][0]
    if damage == "duplicate-source":
        lab.registry["sources"].append(copy.deepcopy(source))
    elif damage == "duplicate-key":
        source["keys"].append(copy.deepcopy(source["keys"][0]))
    elif damage == "empty-keys":
        source["keys"] = []
    elif damage == "bad-pem":
        source["keys"][0]["public_key_pem"] = "not-a-valid-pem" * 5
    elif damage == "wrong-key-type":
        source["keys"][0]["public_key_pem"] = Ed448PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    elif damage == "invalid-key-window":
        source["keys"][0]["not_after"] = source["keys"][0]["not_before"]
    elif damage == "naive-key-time":
        source["keys"][0]["not_before"] = "2026-10-26T12:00:00"
    elif damage == "unknown-registry-field":
        lab.registry["trust_everyone"] = True
    lab.save_registry()
    if damage == "missing-file":
        lab.registry_path.unlink()
    elif damage == "invalid-json":
        lab.registry_path.write_text("{", encoding="utf-8")
    elif damage == "oversized-file":
        lab.registry_path.write_text(" " * 256_001, encoding="utf-8")
    with pytest.raises(SignalRegistryUnavailable):
        lab.access(token)
    with pytest.raises(SignalRegistryUnavailable):
        lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now)
    assert not lab.service.integrity()["ok"]
    assert len(lab.service.history("session-a", lab.operator)) == 1


def test_registry_formatting_changes_do_not_revoke_an_unchanged_source(lab):
    result = lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now)
    lab.registry_path.write_text(json.dumps(lab.registry, indent=4, sort_keys=True), encoding="utf-8")
    assert lab.access(result.grant_token).allowed


def test_changing_another_tenants_registry_does_not_revoke_this_tenants_grant(lab):
    result = lab.service.evaluate_signed(lab.signed(), lab.operator, now=lab.now)
    other = copy.deepcopy(lab.registry["sources"][0])
    other["tenant_id"] = "tenant-b"
    lab.registry["sources"].append(other)
    lab.save_registry()
    assert lab.access(result.grant_token).allowed
    assert lab.service.signal_verifier.readiness("tenant-a")["source_count"] == 1
    assert lab.service.signal_verifier.readiness("tenant-b")["source_count"] == 1


@pytest.mark.parametrize("offset,recovered", [(119.999999, True), (120, False)])
def test_challenge_exact_expiry_boundary(lab, offset, recovered):
    first = lab.service.evaluate_signed(
        lab.signed(event_updates={"auth_context": {"mfa": "unknown"}}),
        lab.operator, now=lab.now,
    )
    now = lab.now + timedelta(seconds=offset)
    result = lab.service.evaluate_signed(lab.signed(
        version=1, event_id="mfa-result", when=now, challenge_id=first.session.challenge_id,
    ), lab.operator, now=now)
    assert (result.session.decision == "ALLOW") is recovered
    assert (result.grant_token is not None) is recovered
    if not recovered:
        assert result.session.challenge_id != first.session.challenge_id


def test_a_challenge_from_one_session_cannot_complete_another_sessions_step_up(lab):
    first = lab.service.evaluate_signed(
        lab.signed(event_updates={"auth_context": {"mfa": "unknown"}}), lab.operator, now=lab.now,
    )
    second = lab.service.evaluate_signed(lab.signed(
        session="session-other", event_id="other-event",
        event_updates={"auth_context": {"mfa": "unknown"}},
    ), lab.operator, now=lab.now)
    now = lab.now + timedelta(seconds=1)
    result = lab.service.evaluate_signed(lab.signed(
        session="session-other", event_id="cross-challenge", version=1, when=now,
        challenge_id=first.session.challenge_id,
    ), lab.operator, now=now)
    assert result.session.decision == "STEP_UP" and result.grant_token is None
    assert result.session.challenge_id == second.session.challenge_id


def test_valid_challenge_cannot_override_a_compromised_device(lab):
    first = lab.service.evaluate_signed(
        lab.signed(event_updates={"auth_context": {"mfa": "unknown"}}), lab.operator, now=lab.now,
    )
    now = lab.now + timedelta(seconds=1)
    result = lab.service.evaluate_signed(lab.signed(
        event_id="compromised", version=1, when=now, challenge_id=first.session.challenge_id,
        event_updates={"device": {"security_posture": "compromised"}},
    ), lab.operator, now=now)
    assert result.session.decision == "DENY" and result.grant_token is None
    assert result.session.challenge_id is None


def test_challenge_is_not_accepted_without_an_outstanding_step_up(lab):
    with pytest.raises(SessionConflict):
        lab.service.evaluate_signed(lab.signed(challenge_id="x" * 32), lab.operator, now=lab.now)
    assert lab.service.sessions(lab.operator) == []
