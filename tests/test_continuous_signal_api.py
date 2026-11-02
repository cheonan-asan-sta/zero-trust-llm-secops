"""HTTP contract tests for the local durable observation receiver and worker."""

import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import InboxUnavailable, SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation, canonical_signal
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import ProtectedAccessRequest, SignedSessionSignal

BASE = "/zero-trust/signals/inbox"
OPERATOR = Principal("signal-operator", "tenant-a", frozenset({Role.ADMIN}), "api_key")


def signed_observation(key, *, event_id="identity-event", when=None, **updates):
    when = when or datetime.now(UTC)
    payload = {
        "tenant_id": "tenant-a", "event_id": event_id,
        "source_id": "identity-collector", "key_id": "key-1",
        "issued_at": when, "observed_at": when,
        "expires_at": when + timedelta(seconds=90),
        "observation": {"kind": "identity", "subject_id": "signed-user", "active": False,
                        "authentication_result": "failure"},
        "signature": "A" * 86,
    }
    payload.update(updates)
    request = SignedContinuousSignal.model_validate(payload)
    signature = base64.urlsafe_b64encode(key.sign(canonical_observation(request))).decode().rstrip("=")
    return request.model_copy(update={"signature": signature})


def isolated_app(operations, continuous, principal=OPERATOR):
    app = FastAPI()
    app.include_router(zero_trust_router(operations, continuous))
    install_zero_trust_error_handlers(app)
    app.dependency_overrides[get_principal] = lambda: principal
    return app


def start_session(receiver, session_id, *, user_id="signed-user", when=None):
    when = when or datetime.now(UTC) - timedelta(seconds=5)
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event.update(event_id=f"start-{session_id}", timestamp=when)
    event["user"].update(user_id=user_id, role="employee")
    event["device"].update(device_id="signed-device")
    event["resource"].update(resource_id="zt-demo-documents", required_role=None)
    event["auth_context"].update(authentication_result="success", mfa="success")
    request = SignedSessionSignal.model_validate({
        "session_id": session_id, "expected_version": 0, "event": event,
        "tenant_id": "tenant-a", "source_id": "session-idp", "key_id": "key-1",
        "issued_at": when, "expires_at": when + timedelta(seconds=90), "signature": "A" * 86,
    })
    signature = base64.urlsafe_b64encode(
        receiver.session_key.sign(canonical_signal(request)),
    ).decode().rstrip("=")
    return receiver.operations.evaluate_signed(
        request.model_copy(update={"signature": signature}), OPERATOR, now=when,
    )


@pytest.fixture
def receiver(tmp_path):
    key = Ed25519PrivateKey.generate()
    session_key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    now = datetime.now(UTC)
    registry = {"sources": [{
        "source_id": "identity-collector", "tenant_id": "tenant-a", "enabled": True,
        "user_ids": ["signed-user", "unrelated-user"],
        "device_ids": ["signed-device"], "roles": ["employee"],
        "observation_kinds": ["identity"],
        "keys": [{"key_id": "key-1", "public_key_pem": public, "enabled": True,
                  "not_before": (now - timedelta(days=1)).isoformat(),
                  "not_after": (now + timedelta(days=1)).isoformat()}],
    }]}
    registry["sources"].append({
        **registry["sources"][0], "source_id": "session-idp", "observation_kinds": [],
        "keys": [{**registry["sources"][0]["keys"][0], "public_key_pem": (
            session_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        )}],
    })
    registry_path = tmp_path / "sources.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    operations = ZeroTrustOperations(
        tmp_path / "operations.sqlite3", signal_verifier=SignalVerifier(registry_path),
    )
    inbox = SignalInbox(operations.path)
    continuous = ContinuousSignalService(operations, inbox)
    app = isolated_app(operations, continuous)
    with TestClient(app) as client:
        yield SimpleNamespace(
            key=key, session_key=session_key, registry=registry, registry_path=registry_path,
            operations=operations, inbox=inbox, continuous=continuous, app=app, client=client,
        )


def test_saved_receipt_is_observable_and_exact_replay_is_idempotent(receiver):
    request = signed_observation(receiver.key)
    first = receiver.client.post(BASE, json=request.model_dump(mode="json"))
    assert first.status_code == 202
    receipt = first.json()
    assert receipt["event_id"] == request.event_id
    assert receipt["state"] == "pending" and not receipt["duplicate"]
    assert receipt["received_at"] and receipt["attempts"] == 0
    assert {"payload", "submitted_by", "lease_token", "signature"}.isdisjoint(receipt)
    status = receiver.client.get(f"{BASE}/{request.event_id}")
    assert status.status_code == 200 and status.json()["state"] == "pending"
    duplicate = receiver.client.post(BASE, json=request.model_dump(mode="json"))
    assert duplicate.status_code == 202 and duplicate.json()["duplicate"]
    assert duplicate.json()["received_at"] == receipt["received_at"]


def test_event_id_cannot_be_rebound_to_a_different_valid_signed_payload(receiver):
    request = signed_observation(receiver.key)
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
    changed = signed_observation(
        receiver.key, when=request.issued_at,
        observation={"kind": "identity", "subject_id": "signed-user", "active": True,
                     "authentication_result": "success"},
    )
    assert receiver.client.post(BASE, json=changed.model_dump(mode="json")).status_code == 409
    assert receiver.client.get(f"{BASE}/{request.event_id}").json()["state"] == "pending"


@pytest.mark.parametrize("updates", [
    {"tenant_id": "tenant-b"}, {"source_id": "unregistered"}, {"key_id": "unregistered"},
    {"observation": {"kind": "identity", "subject_id": "another-user", "active": False,
                     "authentication_result": "failure"}},
    {"observation": {"kind": "device", "subject_id": "signed-device", "managed": False,
                     "security_posture": "compromised"}},
])
def test_receiver_checks_tenant_source_key_subject_and_observation_authority(receiver, updates):
    request = signed_observation(receiver.key, **updates)
    response = receiver.client.post(BASE, json=request.model_dump(mode="json"))
    assert response.status_code == 401
    assert receiver.client.get(f"{BASE}/{request.event_id}").status_code == 404


def test_altered_signature_and_missing_observation_permission_are_rejected(receiver):
    request = signed_observation(receiver.key)
    bad = request.model_copy(update={"signature": "A" * 86})
    assert receiver.client.post(BASE, json=bad.model_dump(mode="json")).status_code == 401
    del receiver.registry["sources"][0]["observation_kinds"]
    receiver.registry_path.write_text(json.dumps(receiver.registry), encoding="utf-8")
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 401
    assert receiver.client.get(f"{BASE}/{request.event_id}").status_code == 404


def test_viewer_can_read_but_cannot_submit_and_other_tenant_cannot_read_receipt(receiver):
    request = signed_observation(receiver.key)
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
    viewer = Principal("viewer", "tenant-a", frozenset({Role.VIEWER}), "api_key")
    receiver.app.dependency_overrides[get_principal] = lambda: viewer
    assert receiver.client.get(BASE).status_code == 200
    assert receiver.client.get(f"{BASE}/{request.event_id}").status_code == 200
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 403
    other = Principal("other-viewer", "tenant-b", frozenset({Role.VIEWER}), "api_key")
    receiver.app.dependency_overrides[get_principal] = lambda: other
    assert receiver.client.get(f"{BASE}/{request.event_id}").status_code == 404


def test_summary_is_tenant_scoped_and_tracks_processing(receiver):
    request = signed_observation(receiver.key)
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
    before = receiver.client.get(BASE)
    assert before.status_code == 200
    assert before.json()["pending"] == 1 and before.json()["total"] == 1
    receiver.continuous.process_one()
    after = receiver.client.get(BASE).json()
    assert after["pending"] == 0 and after["completed"] == 1
    other = Principal("other-viewer", "tenant-b", frozenset({Role.VIEWER}), "api_key")
    receiver.app.dependency_overrides[get_principal] = lambda: other
    isolated = receiver.client.get(BASE).json()
    assert isolated["total"] == 0 and isolated["completed"] == 0


def test_storage_failure_never_returns_acceptance(receiver, monkeypatch):
    def unavailable(*args, **kwargs):
        raise InboxUnavailable("injected storage failure")

    monkeypatch.setattr(receiver.inbox, "accept", unavailable)
    request = signed_observation(receiver.key)
    response = receiver.client.post(BASE, json=request.model_dump(mode="json"))
    assert response.status_code == 503
    assert receiver.client.get(f"{BASE}/{request.event_id}").status_code == 404


def test_pending_capacity_is_reported_as_backpressure(receiver):
    receiver.inbox.max_pending = 1
    first = signed_observation(receiver.key, event_id="first-event")
    second = signed_observation(receiver.key, event_id="second-event")
    assert receiver.client.post(BASE, json=first.model_dump(mode="json")).status_code == 202
    assert receiver.client.post(BASE, json=second.model_dump(mode="json")).status_code == 429
    assert receiver.client.get(f"{BASE}/{second.event_id}").status_code == 404
    assert receiver.client.post(BASE, json=first.model_dump(mode="json")).status_code == 202


def test_worker_completion_can_be_read_after_service_restart(receiver):
    request = signed_observation(receiver.key)
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
    result = receiver.continuous.process_one()
    assert result["event_id"] == request.event_id and result["state"] == "completed"
    restored_inbox = SignalInbox(receiver.inbox.path)
    restored = ContinuousSignalService(receiver.operations, restored_inbox)
    with TestClient(isolated_app(receiver.operations, restored)) as client:
        receipt = client.get(f"{BASE}/{request.event_id}")
        assert receipt.status_code == 200 and receipt.json()["state"] == "completed"
        assert receipt.json()["attempts"] == 1 and receipt.json()["completed_at"]
    assert restored.process_one() is None


def test_worker_revokes_related_sessions_only_and_next_http_access_is_denied(receiver):
    first = start_session(receiver, "related-one")
    second = start_session(receiver, "related-two")
    unrelated = start_session(receiver, "unrelated-one", user_id="unrelated-user")
    assert all(item.grant_token for item in [first, second, unrelated])
    request = signed_observation(receiver.key)
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
    assert receiver.continuous.process_one()["state"] == "completed"
    for session_id, result in [("related-one", first), ("related-two", second),
                               ("unrelated-one", unrelated)]:
        access = ProtectedAccessRequest(
            session_id=session_id, resource_id="zt-demo-documents", action="READ",
            grant_token=result.grant_token,
        )
        response = receiver.client.post(
            "/zero-trust/protected-access", json=access.model_dump(mode="json"),
        )
        assert response.status_code == (200 if session_id == "unrelated-one" else 403)
    assert receiver.operations.history("unrelated-one", OPERATOR)[-1].version == 1


@pytest.mark.parametrize("max_attempts", [1, 3])
@pytest.mark.parametrize("revoke_key", [False, True])
def test_effects_committed_before_ack_failure_are_not_applied_twice_after_restart(
    receiver, monkeypatch, max_attempts, revoke_key,
):
    receiver.inbox.max_attempts = max_attempts
    start_session(receiver, "crash-recovery")
    request = signed_observation(receiver.key)
    assert receiver.client.post(BASE, json=request.model_dump(mode="json")).status_code == 202
    complete = receiver.inbox.complete

    def failed_ack(*args, **kwargs):
        raise InboxUnavailable("injected failure after durable policy effects")

    monkeypatch.setattr(receiver.inbox, "complete", failed_ack)
    with pytest.raises(InboxUnavailable):
        receiver.continuous.process_one()
    history = receiver.operations.history("crash-recovery", OPERATOR)
    assert history[-1].status == "REVOKED"
    changed_version = history[-1].version
    monkeypatch.setattr(receiver.inbox, "complete", complete)
    if revoke_key:
        receiver.registry["sources"][0]["keys"][0]["enabled"] = False
        receiver.registry_path.write_text(json.dumps(receiver.registry), encoding="utf-8")
    restored_operations = ZeroTrustOperations(
        receiver.operations.path, signal_verifier=SignalVerifier(receiver.registry_path),
    )
    restored = ContinuousSignalService(
        restored_operations, SignalInbox(receiver.inbox.path, max_attempts=max_attempts),
    )
    retry = restored.process_one(now=request.issued_at + timedelta(seconds=31))
    assert retry["state"] == "completed" and retry["attempts"] == min(2, max_attempts)
    recovered_history = restored_operations.history("crash-recovery", OPERATOR)
    assert recovered_history[-1].version == changed_version
    assert len(recovered_history) == len(history)


def test_production_and_unconfigured_receiver_do_not_expose_inbox(receiver):
    request = signed_observation(receiver.key).model_dump(mode="json")
    for operations, continuous in [(None, None), (receiver.operations, None)]:
        with TestClient(isolated_app(operations, continuous)) as client:
            assert client.post(BASE, json=request).status_code == 404
            assert client.get(BASE).status_code == 404
            assert client.get(f"{BASE}/unknown-event").status_code == 404
