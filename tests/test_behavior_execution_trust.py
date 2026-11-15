"""Execution evidence has narrow, separate authority and preserves legacy serialization."""

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.behavior_context_models import ApprovalCreate, BehaviorScope
from app.behavior_execution_models import (
    ExecutionActor,
    ExecutionDestination,
    ExecutionPolicy,
    SignedExecutionEvidence,
)
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    SignalVerifier,
    canonical_execution_evidence,
    canonical_signal,
)
from app.zero_trust_models import SignedSessionSignal, TrustedSignalSource

NOW = datetime(2026, 11, 10, 9, tzinfo=UTC)
PRINCIPAL = Principal("operator", "tenant-a", frozenset({Role.ADMIN}), "test")
SCOPE = BehaviorScope(source="cloudtrail", user_id="user-a", device_id="device-a",
                      resource_id="zt-demo-documents", action="READ", principal_hash="actor-a")
ACTOR = {"principal_id": "runner-a", "workload_id": "backup-a", "executable_sha256": "a" * 64}
DESTINATION = {"kind": "https", "host": "archive.example.test", "port": 443, "path": "/backup"}


def sign(model, key, canonical=canonical_execution_evidence):
    signature = base64.urlsafe_b64encode(key.sign(canonical(model))).decode().rstrip("=")
    return model.model_copy(update={"signature": signature})


@pytest.fixture
def execution_lab(tmp_path):
    keys = {name: Ed25519PrivateKey.generate() for name in ("identity", "behavior", "execution")}
    sources = []
    for name, key in keys.items():
        source = {
            "source_id": name, "tenant_id": "tenant-a", "enabled": True,
            "user_ids": ["user-a", "user-b"], "device_ids": ["device-a", "device-b"],
            "roles": ["employee"], "keys": [{
                "key_id": "key", "enabled": True,
                "public_key_pem": key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode(),
                "not_before": (NOW - timedelta(hours=1)).isoformat(),
                "not_after": (NOW + timedelta(hours=1)).isoformat(),
            }],
        }
        if name == "behavior":
            source["behavior_scopes"] = [SCOPE.model_dump(mode="json")]
        elif name == "execution":
            source["execution_scopes"] = [SCOPE.model_dump(mode="json")]
        sources.append(source)
    path = tmp_path / "sources.json"

    def save():
        path.write_text(json.dumps({"sources": sources}))

    def evidence(**updates):
        values = {
            "tenant_id": "tenant-a", "evidence_id": "execution-a", "source_id": "execution",
            "key_id": "key", "issued_at": NOW, "expires_at": NOW + timedelta(seconds=90),
            "observed_at": NOW - timedelta(seconds=1), "scope": SCOPE,
            "session_id": "session-a", "session_version": 1, "session_input_sha256": "b" * 64,
            "capture_id": "capture-a", "capture_input_sha256": "c" * 64,
            "event_ids": ["event-a"], "connection_ids": ["connection-a"],
            "actor": ACTOR, "destinations": [DESTINATION], "signature": "A" * 86,
        }
        values.update(updates)
        return sign(SignedExecutionEvidence.model_validate(values), keys["execution"])

    save()
    return SimpleNamespace(keys=keys, sources=sources, save=save, path=path,
                           verifier=SignalVerifier(path), evidence=evidence)


def test_execution_signature_covers_all_observations_and_binding(execution_lab):
    evidence = execution_lab.evidence()
    proof = execution_lab.verifier.verify_execution_evidence(evidence, PRINCIPAL, NOW)
    assert proof.input_digest == hashlib.sha256(canonical_execution_evidence(evidence)).hexdigest()
    assert proof.challenge_id is None
    assert b'"schema_version":"zt-execution-1"' in canonical_execution_evidence(evidence)
    for field, value in {"capture_id": "other-capture", "event_ids": ["other-event"],
                         "session_input_sha256": "d" * 64,
                         "actor": ExecutionActor.model_validate(ACTOR | {"workload_id": "other-job"}),
                         "destinations": [ExecutionDestination.model_validate(
                             DESTINATION | {"host": "other.example.test"})]}.items():
        with pytest.raises(SignalRejected, match="signature"):
            execution_lab.verifier.verify_execution_evidence(
                evidence.model_copy(update={field: value}), PRINCIPAL, NOW,
            )


def test_signed_missing_observations_stay_missing(execution_lab):
    evidence = execution_lab.evidence(actor=None, destinations=None)
    execution_lab.verifier.verify_execution_evidence(evidence, PRINCIPAL, NOW)
    assert evidence.actor is evidence.destinations is None
    payload = json.loads(canonical_execution_evidence(evidence))
    assert payload["actor"] is payload["destinations"] is None


@pytest.mark.parametrize("changes", [
    {"tenant_id": "tenant-b"}, {"source_id": "identity"}, {"source_id": "behavior"},
    {"key_id": "unknown"}, {"scope": SCOPE.model_copy(update={"device_id": "device-b"})},
])
def test_execution_rejects_other_authority_or_binding_scope(execution_lab, changes):
    with pytest.raises(SignalRejected):
        execution_lab.verifier.verify_execution_evidence(execution_lab.evidence(**changes), PRINCIPAL, NOW)


def test_execution_requires_analyst_and_validated_direct_caller(execution_lab):
    viewer = Principal("viewer", "tenant-a", frozenset({Role.VIEWER}), "test")
    with pytest.raises(SignalRejected, match="analyst"):
        execution_lab.verifier.verify_execution_evidence(execution_lab.evidence(), viewer, NOW)
    malformed = execution_lab.evidence().model_copy(update={"event_ids": ["event-a", "event-a"]})
    malformed = sign(malformed, execution_lab.keys["execution"])
    with pytest.raises(SignalRejected, match="shape"):
        execution_lab.verifier.verify_execution_evidence(malformed, PRINCIPAL, NOW)


@pytest.mark.parametrize("offset", [-1, 61, 90])
def test_first_intake_rejects_future_stale_expired(execution_lab, offset):
    with pytest.raises(SignalRejected, match="freshness"):
        execution_lab.verifier.verify_execution_evidence(
            execution_lab.evidence(), PRINCIPAL, NOW + timedelta(seconds=offset),
        )


def test_historical_check_does_not_turn_expired_evidence_fresh(execution_lab):
    proof = execution_lab.verifier.verify_execution_evidence(
        execution_lab.evidence(), PRINCIPAL, NOW + timedelta(seconds=91), enforce_freshness=False,
    )
    assert proof.expires_at <= NOW + timedelta(seconds=91)
    execution_lab.sources[2]["keys"][0]["enabled"] = False
    execution_lab.save()
    with pytest.raises(SignalRejected, match="key"):
        execution_lab.verifier.verify_execution_evidence(
            execution_lab.evidence(), PRINCIPAL, NOW + timedelta(seconds=91), enforce_freshness=False,
        )


def test_execution_source_cannot_assert_full_session(execution_lab):
    request = SignedSessionSignal(
        session_id="session-a", expected_version=0, event=synthetic_events()[0],
        tenant_id="tenant-a", source_id="execution", key_id="key", issued_at=NOW,
        expires_at=NOW + timedelta(seconds=90), signature="A" * 86,
    )
    request = sign(request, execution_lab.keys["execution"], canonical_signal)
    with pytest.raises(SignalRejected, match="cannot assert a full session"):
        execution_lab.verifier.verify(request, PRINCIPAL, NOW)


@pytest.mark.parametrize("extra", [
    {"behavior_scopes": [SCOPE]}, {"observation_kinds": ["device"]},
    {"guardduty_resource_ids": ["zt-demo-documents"]},
    {"session_proof_resource_ids": ["zt-demo-documents"]},
])
def test_execution_source_is_dedicated(execution_lab, extra):
    with pytest.raises(ValueError, match="dedicated"):
        TrustedSignalSource.model_validate(execution_lab.sources[2] | extra)


@pytest.mark.parametrize("changes", [
    {"execution_scopes": [SCOPE, SCOPE]}, {"user_ids": ["other-user"]},
    {"device_ids": ["other-device"]},
])
def test_execution_scope_is_unique_and_within_registered_subjects(execution_lab, changes):
    with pytest.raises(ValueError):
        TrustedSignalSource.model_validate(execution_lab.sources[2] | changes)


def test_same_key_cannot_alias_execution_and_behavior_authority(execution_lab):
    execution_lab.sources[2]["keys"][0]["public_key_pem"] = execution_lab.sources[1]["keys"][0]["public_key_pem"]
    execution_lab.save()
    with pytest.raises(SignalRegistryUnavailable):
        execution_lab.verifier.verify_execution_evidence(execution_lab.evidence(), PRINCIPAL, NOW)


def test_new_optional_fields_do_not_change_legacy_serialized_records(execution_lab):
    source = TrustedSignalSource.model_validate(execution_lab.sources[0])
    serialized = source.model_dump(mode="json")
    assert "execution_scopes" not in serialized
    assert "behavior_scopes" not in serialized
    assert source.model_dump_json() == json.dumps(serialized, separators=(",", ":"))
    request = ApprovalCreate(
        approval_id="approval-a", baseline_id="baseline-a", valid_from=NOW,
        valid_until=NOW + timedelta(seconds=60), note="Existing bounded approval",
    )
    assert "execution_policy" not in request.model_dump(mode="json")
    assert "execution_policy" not in json.loads(request.model_dump_json())


@pytest.mark.parametrize("changes", [
    {"host": "ARCHIVE.example.test"}, {"host": "archive.example.test."},
    {"host": "*.example.test"}, {"host": "user@archive.example.test"},
    {"host": "archive.example.test:443"}, {"host": "192.000.2.1"},
    {"host": "xn--invalid..test"}, {"host": "예시.test"},
    {"path": "/backup/../other"}, {"path": "/backup//other"},
    {"path": "/backup/%2e%2e/other"}, {"path": "/backup?to=other"},
    {"path": "/backup#other"}, {"path": "/backup\\other"},
    {"port": None}, {"port": True}, {"port": "443"}, {"port": 65536},
])
def test_destination_aliases_and_coercion_are_rejected(changes):
    with pytest.raises(ValueError):
        ExecutionDestination.model_validate(DESTINATION | changes)


def test_destination_policy_exact_addresses_and_duplicates():
    bucket = {"kind": "s3", "host": "backup-bucket", "port": None, "path": "/daily/object"}
    value = ExecutionPolicy(actor=ACTOR, destinations=[DESTINATION, bucket])
    assert value.destinations[0].model_dump() == DESTINATION
    assert value.destinations[1].model_dump() == bucket
    for destinations in ([DESTINATION, DESTINATION], [], [bucket | {"port": 443}],
                         [bucket | {"host": "192.0.2.1"}]):
        with pytest.raises(ValueError):
            ExecutionPolicy(actor=ACTOR, destinations=destinations)


@pytest.mark.parametrize("changes", [
    {"event_ids": []}, {"connection_ids": []}, {"connection_ids": ["a", "a"]},
    {"destinations": []}, {"destinations": [DESTINATION, DESTINATION]},
    {"observed_at": NOW + timedelta(seconds=1)},
    {"observed_at": NOW - timedelta(seconds=301)},
    {"issued_at": NOW.replace(tzinfo=None)},
    {"expires_at": NOW + timedelta(seconds=121)},
    {"actor": ACTOR | {"verified": True}}, {"session_version": True},
])
def test_execution_contract_rejects_ambiguous_or_self_verified_input(execution_lab, changes):
    with pytest.raises(ValueError):
        execution_lab.evidence(**changes)
