"""Bound trusted proof findings through HTTP intake, durable processing and PEP."""

import base64
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.continuous_signal_models import SignedContinuousSignal
from app.security import get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SessionEvaluationResult

BASE = "/zero-trust"
INBOX = f"{BASE}/signals/inbox"
PROOF_REASON = "CONTINUOUS_SESSION_PROOF_DENY"
PROOF_SHA = "a" * 64


def public_key(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def journal(path):
    with closing(sqlite3.connect(path)) as connection:
        return [json.loads(row[0]) for row in
                connection.execute("SELECT payload FROM journal ORDER BY seq")]


@pytest.fixture
def proof_api(lab, monkeypatch):
    current = lab.now

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return current.astimezone(tz) if tz else current.replace(tzinfo=None)

    monkeypatch.setattr("app.services.zero_trust.datetime", FixedDateTime)
    monkeypatch.setattr("app.services.continuous_signals.datetime", FixedDateTime)
    collector_key = Ed25519PrivateKey.generate()
    source = lab.registry["sources"][0]
    lab.registry["sources"].append({
        **source,
        "source_id": "proof-collector",
        "observation_kinds": ["session_proof"],
        "user_ids": ["user-a", "user-b"],
        "device_ids": ["device-a", "device-b"],
        "session_proof_resource_ids": ["zt-demo-documents", "zt-demo-vault"],
        "keys": [{**source["keys"][0], "public_key_pem": public_key(collector_key)}],
    })
    lab.save_registry()
    service = ContinuousSignalService(lab.service, SignalInbox(lab.service.path))
    application = FastAPI()
    application.include_router(zero_trust_router(lab.service, service))
    install_zero_trust_error_handlers(application)
    application.dependency_overrides[get_principal] = lambda: lab.operator

    def start(session="session-a", version=0):
        request = lab.signed(
            session=session, version=version, when=current,
            event_id=f"signal-{session}-{version}",
        )
        response = client.post(f"{BASE}/signals/evaluate", json=request.model_dump(mode="json"))
        assert response.status_code == 200
        result = SessionEvaluationResult.model_validate(response.json())
        assert result.session.status == "ACTIVE" and result.grant_token
        return result

    def observation(session, *, observed_at=None, event_id="proof-event", **updates):
        request = SignedContinuousSignal.model_validate({
            "tenant_id": session.tenant_id,
            "event_id": event_id,
            "source_id": "proof-collector",
            "key_id": "key-a",
            "issued_at": current,
            "expires_at": current + timedelta(seconds=60),
            "observed_at": observed_at or current,
            "observation": {
                "kind": "session_proof",
                "subject_id": session.user_id,
                "device_id": session.device_id,
                "session_id": session.session_id,
                "session_version": session.version,
                "session_input_sha256": session.input_digest_sha256,
                "resource_id": session.resource_id,
                "action": session.action,
                "proof_sha256": PROOF_SHA,
                "violation": "scope_mismatch",
                **updates,
            },
            "signature": "A" * 86,
        })
        signature = base64.urlsafe_b64encode(
            collector_key.sign(canonical_observation(request)),
        ).decode().rstrip("=")
        return request.model_copy(update={"signature": signature})

    def submit(request):
        return client.post(INBOX, json=request.model_dump(mode="json"))

    def process():
        # Reopen the stores after acceptance, as a separate worker would.
        operations = ZeroTrustOperations(
            lab.service.path, signal_verifier=SignalVerifier(lab.registry_path),
        )
        return ContinuousSignalService(operations, SignalInbox(operations.path)).process_one(
            now=current,
        )

    def history(session_id):
        response = client.get(f"{BASE}/sessions/{session_id}")
        assert response.status_code == 200
        return response.json()

    def access(result):
        return client.post(f"{BASE}/protected-access", json={
            "session_id": result.session.session_id,
            "resource_id": result.session.resource_id,
            "action": result.session.action,
            "grant_token": result.grant_token,
        })

    def advance():
        nonlocal current
        current += timedelta(seconds=1)

    with TestClient(application) as client:
        yield SimpleNamespace(client=client, start=start, observation=observation, submit=submit,
                              process=process, history=history, access=access, advance=advance)


@pytest.mark.parametrize("violation", ["scope_mismatch", "nonce_reuse", "unauthorized_key_rotation"])
def test_verified_proof_finding_revokes_only_its_session_and_is_audited(lab, proof_api, violation):
    affected = proof_api.start()
    peer = proof_api.start("session-b")
    proof_api.advance()
    request = proof_api.observation(affected.session, violation=violation)
    accepted = proof_api.submit(request)
    assert accepted.status_code == 202 and accepted.json()["state"] == "pending"
    assert proof_api.history("session-a")[-1]["status"] == "ACTIVE"

    result = proof_api.process()
    assert result["state"] == "completed"
    assert result["result"]["matched_sessions"] == result["result"]["changed_sessions"] == 1
    history = proof_api.history("session-a")
    revoked = history[-1]
    assert [item["version"] for item in history] == [1, 2]
    assert (revoked["decision"], revoked["status"], revoked["grant_expires_at"]) == (
        "DENY", "REVOKED", None,
    )
    assert PROOF_REASON in revoked["reason_codes"]

    replay = proof_api.submit(request)
    assert replay.status_code == 202 and replay.json()["duplicate"]
    assert proof_api.process() is None
    assert proof_api.history("session-a") == history
    blocked = proof_api.access(affected)
    assert blocked.status_code == 403
    assert blocked.json() == {
        "allowed": False, "reason_code": "SESSION_NOT_AUTHORIZED",
        "session_version": 2, "content": None, "enforcement_mode": "local_simulation",
    }
    assert proof_api.access(peer).status_code == 200
    assert proof_api.history("session-b")[-1]["version"] == 1
    fresh = proof_api.start("session-c")
    assert proof_api.access(fresh).status_code == 200

    records = journal(lab.service.path)
    transitions = [entry for entry in records if entry.get("observation_event_id") == request.event_id]
    assert len(transitions) == 1 and transitions[0]["grant_hash"] is None
    assert transitions[0]["session"] == revoked
    observations = [entry for entry in records if entry["kind"] == "observation"]
    assert len(observations) == 1
    assert observations[0]["observation"] == request.observation.model_dump(mode="json")
    assert any(entry["kind"] == "access" and entry["session_id"] == "session-a"
               and not entry["allowed"] and entry["session_version"] == 2 for entry in records)


@pytest.mark.parametrize("updates", [
    {"session_id": "unknown-session"},
    {"session_version": 2},
    {"session_input_sha256": "b" * 64},
    {"resource_id": "zt-demo-vault"},
    {"action": "DOWNLOAD"},
    {"subject_id": "user-b"},
    {"device_id": "device-b"},
    {"old_observation": True},
])
def test_mismatched_proof_findings_cannot_change_the_current_session(lab, proof_api, updates):
    active = proof_api.start()
    proof_api.advance()
    claim = dict(updates)
    old = claim.pop("old_observation", False)
    observed_at = lab.now - timedelta(seconds=1) if old else None
    request = proof_api.observation(active.session, observed_at=observed_at, **claim)
    assert proof_api.submit(request).status_code == 202
    result = proof_api.process()
    assert result["state"] == "completed" and result["result"]["changed_sessions"] == 0
    assert [row["status"] for row in proof_api.history("session-a")] == ["ACTIVE"]
    assert proof_api.access(active).status_code == 200


def test_delayed_finding_cannot_revoke_a_fresh_session_revision(proof_api):
    initial = proof_api.start()
    request = proof_api.observation(initial.session)
    assert proof_api.submit(request).status_code == 202
    proof_api.advance()
    fresh = proof_api.start(version=1)
    result = proof_api.process()
    assert result["state"] == "completed" and result["result"]["changed_sessions"] == 0
    assert [row["status"] for row in proof_api.history("session-a")] == ["ACTIVE", "ACTIVE"]
    assert proof_api.access(fresh).status_code == 200


def test_untrusted_proof_findings_are_rejected_before_enqueue(proof_api):
    active = proof_api.start()
    wrong_device = proof_api.observation(active.session, device_id="outside-scope")
    tampered = proof_api.observation(active.session).model_copy(update={"signature": "A" * 86})
    for request in (wrong_device, tampered):
        assert proof_api.submit(request).status_code == 401
        assert proof_api.client.get(f"{INBOX}/{request.event_id}").status_code == 404
    assert proof_api.process() is None
    assert proof_api.history("session-a")[-1]["status"] == "ACTIVE"


def test_rotated_key_cannot_sign_a_backdated_session_proof(lab, api):
    key = Ed25519PrivateKey.generate()
    source_keys = lab.registry["sources"][0]["keys"]
    source_keys.append({
        **source_keys[0], "key_id": "key-b", "public_key_pem": public_key(key),
        "not_before": lab.now.isoformat(),
    })
    lab.save_registry()
    early = lab.signed(signer=key, key_id="key-b", when=lab.now - timedelta(seconds=1))
    denied = api.client.post(f"{BASE}/signals/evaluate", json=early.model_dump(mode="json"))
    assert denied.status_code == 401
    assert lab.service.sessions(lab.operator) == []
    assert lab.service.integrity()["verified_entries"] == 0

    on_time = lab.signed(signer=key, key_id="key-b")
    response = api.client.post(f"{BASE}/signals/evaluate", json=on_time.model_dump(mode="json"))
    assert response.status_code == 200
    assert response.json()["grant_token"]
