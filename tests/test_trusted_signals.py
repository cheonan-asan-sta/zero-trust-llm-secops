import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    SignalVerifier,
    canonical_signal,
)
from app.services.zero_trust import SessionConflict, ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionEvaluationRequest,
    SignedSessionSignal,
)
from scripts.local_signal_collector import _NoRedirect, demonstrate, initialize

NOW = datetime.now(UTC)
OPERATOR = Principal("local-collector-operator", "tenant-a", frozenset({Role.ADMIN}), "api_key")


def signal(private_key, *, version=0, when=NOW, session="signed-session", event_id="signed-event",
           challenge_id=None, **updates):
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event.update(event_id=event_id, timestamp=when)
    event["user"].update(user_id="signed-user", role="employee")
    event["device"].update(device_id="signed-device")
    event["resource"].update(resource_id="zt-demo-documents", required_role=None)
    event["auth_context"].update(authentication_result="success", mfa="success")
    payload = {"session_id": session, "expected_version": version, "event": event,
               "tenant_id": "tenant-a", "source_id": "local-idp", "key_id": "key-1",
               "issued_at": when, "expires_at": when + timedelta(seconds=90),
               "challenge_id": challenge_id, "signature": "A" * 86}
    for key, value in updates.items():
        if key in event:
            if isinstance(value, dict):
                event[key].update(value)
            else:
                event[key] = value
        else:
            payload[key] = value
    request = SignedSessionSignal.model_validate(payload)
    signature = base64.urlsafe_b64encode(private_key.sign(canonical_signal(request))).decode().rstrip("=")
    return request.model_copy(update={"signature": signature})


@pytest.fixture
def setup(tmp_path):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    registry = {"sources": [{
        "source_id": "local-idp", "tenant_id": "tenant-a", "enabled": True,
        "user_ids": ["signed-user"], "device_ids": ["signed-device"], "roles": ["employee"],
        "keys": [{"key_id": "key-1", "public_key_pem": public, "enabled": True,
                  "not_before": (NOW - timedelta(days=1)).isoformat(),
                  "not_after": (NOW + timedelta(days=1)).isoformat()}],
    }]}
    path = tmp_path / "sources.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    verifier = SignalVerifier(path)
    service = ZeroTrustOperations(tmp_path / "operations.sqlite3", signal_verifier=verifier)
    return service, private, registry, path


def evaluate(service, request, *, now=None):
    return service.evaluate_signed(request, OPERATOR, now=now or request.issued_at)


def access(service, token, now=NOW):
    return service.access(ProtectedAccessRequest(
        session_id="signed-session", resource_id="zt-demo-documents", action="READ", grant_token=token,
    ), OPERATOR, now=now)


def test_signed_source_is_recorded_and_grant_bounded_by_proof_expiry(setup):
    service, key, _, _ = setup
    request = signal(key, expires_at=NOW + timedelta(seconds=10))
    result = evaluate(service, request)
    assert result.session.signal_trust == "verified_source"
    assert result.session.signal_source_id == "local-idp"
    assert result.session.grant_expires_at == NOW + timedelta(seconds=10)
    assert access(service, result.grant_token).allowed


def test_signed_mfa_challenge_requires_binding_and_old_proof_cannot_recover(setup):
    service, key, _, _ = setup
    first = evaluate(service, signal(key))
    step_up = evaluate(service, signal(key, version=1, when=NOW + timedelta(seconds=1),
                                      event_id="step-up", auth_context={"mfa": "unknown"}))
    assert step_up.session.decision == "STEP_UP" and step_up.session.challenge_id
    assert not access(service, first.grant_token).allowed
    no_challenge = evaluate(service, signal(key, version=2, when=NOW + timedelta(seconds=2),
                                           event_id="unbound-success"))
    assert no_challenge.session.decision == "STEP_UP"
    assert no_challenge.session.challenge_id == step_up.session.challenge_id
    recovered = evaluate(service, signal(key, version=3, when=NOW + timedelta(seconds=3),
                                        event_id="bound-success", challenge_id=step_up.session.challenge_id))
    assert recovered.session.decision == "ALLOW" and recovered.session.challenge_id is None
    assert access(service, recovered.grant_token, NOW + timedelta(seconds=3)).allowed
    with pytest.raises(SessionConflict):
        evaluate(service, signal(key, version=4, when=NOW + timedelta(seconds=4),
                                 event_id="challenge-replay", challenge_id=step_up.session.challenge_id))


def test_intermediate_hold_cannot_clear_outstanding_mfa_challenge(setup):
    service, key, _, _ = setup
    first = evaluate(service, signal(key, auth_context={"mfa": "unknown"}))
    held = evaluate(service, signal(key, version=1, event_id="held", when=NOW + timedelta(seconds=1),
                                   auth_context={"authentication_result": "unknown"}))
    assert held.session.decision == "HOLD"
    assert held.session.challenge_id == first.session.challenge_id
    again = evaluate(service, signal(key, version=2, event_id="retry", when=NOW + timedelta(seconds=2)))
    assert again.session.decision == "STEP_UP" and again.grant_token is None


def test_expired_challenge_rotates_nonce_instead_of_recovering(setup):
    service, key, _, _ = setup
    first = evaluate(service, signal(key, auth_context={"mfa": "unknown"}))
    result = evaluate(service, signal(key, version=1, event_id="late-mfa",
                                     when=NOW + timedelta(seconds=121), challenge_id=first.session.challenge_id))
    assert result.session.decision == "STEP_UP"
    assert result.session.challenge_id != first.session.challenge_id
    assert result.grant_token is None


@pytest.mark.parametrize("changes", [
    {"tenant_id": "tenant-b"}, {"source_id": "unknown"}, {"key_id": "unknown"},
    {"user": {"user_id": "unauthorized-user"}}, {"device": {"device_id": "unauthorized-device"}},
    {"user": {"role": "administrator"}},
])
def test_source_scope_is_explicit_and_tenant_bound(setup, changes):
    service, key, _, _ = setup
    with pytest.raises(SignalRejected):
        evaluate(service, signal(key, **changes))
    assert service.sessions(OPERATOR) == []


def test_altered_payload_or_wrong_signer_is_rejected(setup):
    service, key, _, _ = setup
    request = signal(key)
    altered = request.event.model_copy(update={"network": request.event.network.model_copy(
        update={"ip": "192.0.2.99"})})
    with pytest.raises(SignalRejected):
        evaluate(service, request.model_copy(update={"event": altered}))
    with pytest.raises(SignalRejected):
        evaluate(service, signal(Ed25519PrivateKey.generate()))


@pytest.mark.parametrize("seconds", [-1, 61, 91])
def test_future_old_or_expired_signal_rejected_before_session_mutation(setup, seconds):
    service, key, _, _ = setup
    with pytest.raises(SignalRejected):
        evaluate(service, signal(key), now=NOW + timedelta(seconds=seconds))
    assert service.sessions(OPERATOR) == []


def test_demo_and_verified_sessions_cannot_change_trust_mode(setup):
    service, key, _, _ = setup
    signed = signal(key)
    evaluate(service, signed)
    with pytest.raises(SessionConflict):
        service.evaluate(SessionEvaluationRequest(session_id="signed-session", expected_version=1,
            event=SecurityEvent.model_validate(signed.event.model_dump())), OPERATOR, now=NOW)
    unsigned = signed.model_copy(update={"session_id": "demo-session"})
    service.evaluate(SessionEvaluationRequest(session_id="demo-session", expected_version=0,
                                              event=unsigned.event.model_copy(
                                                  update={"event_id": "demo-event"})), OPERATOR, now=NOW)
    with pytest.raises(SessionConflict):
        evaluate(service, signal(key, session="demo-session", version=1, event_id="new-event"))


def test_exact_replay_is_idempotent_and_changed_signed_metadata_conflicts(setup):
    service, key, _, _ = setup
    first = signal(key)
    evaluate(service, first)
    duplicate = evaluate(service, first)
    assert duplicate.duplicate and duplicate.grant_token is None
    assert duplicate.session.version == 1
    with pytest.raises(SessionConflict):
        evaluate(service, signal(key, expires_at=NOW + timedelta(seconds=80)))


@pytest.mark.parametrize("change", ["source_disabled", "key_disabled", "scope_changed", "key_expired"])
def test_source_revocation_and_scope_change_invalidate_outstanding_grants(setup, change):
    service, key, registry, path = setup
    result = evaluate(service, signal(key))
    source = registry["sources"][0]
    if change == "source_disabled":
        source["enabled"] = False
    elif change == "key_disabled":
        source["keys"][0]["enabled"] = False
    elif change == "scope_changed":
        source["roles"] = ["viewer"]
    else:
        source["keys"][0]["not_after"] = NOW.isoformat()
    path.write_text(json.dumps(registry), encoding="utf-8")
    assert access(service, result.grant_token).reason_code == "SIGNAL_SOURCE_REVOKED"


def test_registry_failure_blocks_access_and_readiness(setup):
    service, key, _, path = setup
    result = evaluate(service, signal(key))
    path.write_text("broken JSON", encoding="utf-8")
    with pytest.raises(SignalRegistryUnavailable):
        access(service, result.grant_token)
    assert not service.integrity()["ok"]


def test_key_rotation_requires_reevaluation_and_survives_restart(setup):
    service, key, registry, path = setup
    first = evaluate(service, signal(key))
    new_key = Ed25519PrivateKey.generate()
    new_public = new_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    old_key = registry["sources"][0]["keys"][0]
    registry["sources"][0]["keys"].append({**old_key, "key_id": "key-2", "public_key_pem": new_public})
    path.write_text(json.dumps(registry), encoding="utf-8")
    assert not access(service, first.grant_token).allowed
    newer = evaluate(service, signal(new_key, key_id="key-2", version=1, event_id="rotated",
                                    when=NOW + timedelta(seconds=1)))
    restored = ZeroTrustOperations(service.path, signal_verifier=SignalVerifier(path))
    assert access(restored, newer.grant_token, NOW + timedelta(seconds=1)).allowed


def test_concurrent_challenge_proofs_can_issue_only_one_new_version(setup):
    service, key, _, _ = setup
    first = evaluate(service, signal(key, auth_context={"mfa": "unknown"}))
    def complete(index):
        try:
            return evaluate(service, signal(key, version=1, event_id=f"complete-{index}",
                when=NOW + timedelta(seconds=1), challenge_id=first.session.challenge_id))
        except SessionConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(complete, range(2)))
    assert sum(result is not None and result.grant_token is not None for result in results) == 1


def test_signed_signal_api_enforces_verification_and_local_boundary(setup):
    service, key, registry, path = setup
    registry["sources"].append({**registry["sources"][0], "tenant_id": "tenant-b"})
    path.write_text(json.dumps(registry), encoding="utf-8")
    isolated = FastAPI()
    isolated.include_router(zero_trust_router(service))
    install_zero_trust_error_handlers(isolated)
    isolated.dependency_overrides[get_principal] = lambda: OPERATOR
    with TestClient(isolated) as client:
        request = signal(key, when=datetime.now(UTC))
        bad = request.model_copy(update={"signature": "A" * 86})
        assert client.post("/zero-trust/signals/evaluate", json=bad.model_dump(mode="json")).status_code == 401
        result = client.post("/zero-trust/signals/evaluate", json=request.model_dump(mode="json"))
        assert result.status_code == 200 and result.json()["session"]["signal_trust"] == "verified_source"
        assert client.get("/zero-trust/signals/status").json()["source_count"] == 1
        isolated.dependency_overrides[get_principal] = lambda: Principal(
            "viewer", "tenant-a", frozenset({Role.VIEWER}), "api_key")
        assert client.post("/zero-trust/signals/evaluate", json=request.model_dump(mode="json")).status_code == 403
    production = FastAPI()
    production.include_router(zero_trust_router(None))
    production.dependency_overrides[get_principal] = lambda: OPERATOR
    with TestClient(production) as client:
        assert client.get("/zero-trust/signals/status").status_code == 404
        assert client.post("/zero-trust/signals/evaluate", json=request.model_dump(mode="json")).status_code == 404


def test_verified_session_cannot_switch_to_another_registered_source(setup):
    service, key, registry, path = setup
    evaluate(service, signal(key))
    registry["sources"].append({**registry["sources"][0], "source_id": "another-idp"})
    path.write_text(json.dumps(registry), encoding="utf-8")
    with pytest.raises(SessionConflict):
        evaluate(service, signal(key, version=1, event_id="switch-source", source_id="another-idp",
                                 when=NOW + timedelta(seconds=1)))


def test_collector_private_key_stays_out_of_public_registry_and_existing_files_are_preserved(tmp_path):
    result = initialize(tmp_path, "local")
    private = (tmp_path / "private.pem").read_bytes()
    public = (tmp_path / "sources.json").read_bytes()
    assert b"PRIVATE KEY" not in public and "PRIVATE KEY" not in json.dumps(result)
    assert set(result) == {"status", "public_registry"}
    assert SignalVerifier(tmp_path / "sources.json").readiness()["ok"]
    with pytest.raises(FileExistsError):
        initialize(tmp_path, "local")
    assert (tmp_path / "private.pem").read_bytes() == private
    assert (tmp_path / "sources.json").read_bytes() == public


def test_collector_rejects_remote_destinations_and_redirects_before_loading_keys(tmp_path):
    for url in ["https://example.com", "http://192.0.2.1", "http://user@localhost", "http://localhost/path"]:
        with pytest.raises(ValueError, match="loopback"):
            demonstrate(tmp_path, url, "local")
    with pytest.raises(ValueError, match="redirects"):
        _NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.com")
