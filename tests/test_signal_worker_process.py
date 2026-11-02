"""Kill real worker processes at durable boundaries, then recover from SQLite."""

import base64
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_observation
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations
from app.zero_trust_models import ProtectedAccessRequest, SessionEvaluationRequest
from scripts.signal_worker import build_service

ROOT = Path(__file__).parents[1]
OPERATOR = Principal("process-test", "tenant-a", frozenset({Role.ADMIN}), "api_key")


@pytest.fixture
def environment(tmp_path):
    now = datetime.now(UTC) - timedelta(seconds=2)
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    registry = tmp_path / "sources.json"
    registry.write_text(json.dumps({"sources": [{
        "source_id": "identity", "tenant_id": "tenant-a", "user_ids": ["target-user"],
        "device_ids": ["device"], "roles": ["employee"], "observation_kinds": ["identity"],
        "keys": [{"key_id": "key", "public_key_pem": pem,
                  "not_before": (now - timedelta(days=1)).isoformat(),
                  "not_after": (now + timedelta(days=1)).isoformat()}],
    }]}), encoding="utf-8")
    db = tmp_path / "state.sqlite3"
    operations = ZeroTrustOperations(db, signal_verifier=SignalVerifier(registry))
    inbox = SignalInbox(db, lease_seconds=1)
    service = ContinuousSignalService(operations, inbox)
    event = synthetic_events()[0].model_copy(deep=True)
    event.event_id = "initial-event"
    event.timestamp = now
    event.user.user_id = "target-user"
    event.user.role = "employee"
    event.device.device_id = "device"
    event.resource.resource_id = "zt-demo-documents"
    event.auth_context.authentication_result = "success"
    event.auth_context.mfa = "success"
    initial = operations.evaluate(
        SessionEvaluationRequest(session_id="process-session", expected_version=0, event=event),
        OPERATOR, now=now,
    )
    assert initial.session.decision == "ALLOW"
    when = now + timedelta(seconds=1)
    observation = SignedContinuousSignal(
        tenant_id="tenant-a", event_id="identity-disabled", source_id="identity", key_id="key",
        observed_at=when, issued_at=when, expires_at=when + timedelta(seconds=90),
        observation={"kind": "identity", "subject_id": "target-user", "active": False,
                     "authentication_result": "failure"}, signature="A" * 86,
    )
    signature = base64.urlsafe_b64encode(key.sign(canonical_observation(observation))).decode()
    observation.signature = signature.rstrip("=")
    service.accept(observation, OPERATOR, now=when)
    return service, initial, observation, registry, now


def access(operations, token, when):
    return operations.access(ProtectedAccessRequest(
        session_id="process-session", resource_id="zt-demo-documents",
        action="READ", grant_token=token,
    ), OPERATOR, now=when)


@pytest.mark.parametrize("boundary", ["before_effects", "after_effects"])
@pytest.mark.parametrize("max_attempts", [1, 3])
def test_process_death_then_lease_recovery_preserves_exactly_once_policy_effect(
    environment, boundary, max_attempts,
):
    service, initial, observation, registry, now = environment
    code = """
import os, sys
from datetime import datetime
from pathlib import Path
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
db, registry, when, boundary, max_attempts = sys.argv[1:]
ops = ZeroTrustOperations(Path(db), signal_verifier=SignalVerifier(Path(registry)))
inbox = SignalInbox(Path(db), lease_seconds=1, max_attempts=int(max_attempts))
def stop(*args, **kwargs):
    os._exit(73)
if boundary == 'before_effects':
    ops.apply_observation = stop
else:
    inbox.complete = stop
ContinuousSignalService(ops, inbox).process_one(now=datetime.fromisoformat(when))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(service.inbox.path), str(registry),
         observation.issued_at.isoformat(), boundary, str(max_attempts)],
        cwd=ROOT, capture_output=True, text=True, timeout=20, check=False,
    )
    assert result.returncode == 73, result.stderr
    assert service.inbox.get(OPERATOR.tenant_id, observation.event_id)["state"] == "processing"
    current = service.operations.history("process-session", OPERATOR)[-1]
    assert current.version == (2 if boundary == "after_effects" else 1)
    if boundary == "after_effects" and max_attempts == 1:
        # Completed effects are reconciled without granting fresh authority to
        # a signer whose key was revoked after policy commit but before ACK.
        sources = json.loads(registry.read_text("utf-8"))
        sources["sources"][0]["enabled"] = False
        registry.write_text(json.dumps(sources), encoding="utf-8")
    restored_ops = ZeroTrustOperations(
        service.operations.path, signal_verifier=SignalVerifier(registry),
    )
    restored = ContinuousSignalService(restored_ops, SignalInbox(
        service.inbox.path, lease_seconds=1, max_attempts=max_attempts,
    ))
    receipt = restored.process_one(now=now + timedelta(seconds=3))
    if boundary == "before_effects" and max_attempts == 1:
        assert receipt["state"] == "failed" and receipt["attempts"] == 1
        assert receipt["last_error"] == "PROCESSING_EXHAUSTED"
        assert restored_ops.history("process-session", OPERATOR)[-1].version == 1
        return
    assert receipt["state"] == "completed"
    assert receipt["attempts"] == (1 if max_attempts == 1 else 2)
    assert receipt["result"]["duplicate"] == (boundary == "after_effects")
    history = restored_ops.history("process-session", OPERATOR)
    assert len(history) == 2 and history[-1].version == 2
    assert history[-1].status == "REVOKED"
    denied = access(restored_ops, initial.grant_token, now + timedelta(seconds=3))
    assert not denied.allowed and denied.content is None
    assert restored.process_one(now=now + timedelta(seconds=4)) is None


def test_transient_policy_failure_retries_then_completes(environment, monkeypatch):
    service, initial, observation, _, now = environment
    original = service.operations.apply_observation

    def unavailable(*args, **kwargs):
        raise JournalUnavailable("injected transaction failure")

    monkeypatch.setattr(service.operations, "apply_observation", unavailable)
    failed_attempt = service.process_one(now=observation.issued_at)
    assert failed_attempt["state"] == "pending"
    assert failed_attempt["last_error"] == "JOURNAL_UNAVAILABLE"
    assert service.operations.history("process-session", OPERATOR)[-1].version == 1
    assert service.process_one(now=now + timedelta(seconds=1.5)) is None
    monkeypatch.setattr(service.operations, "apply_observation", original)
    result = service.process_one(now=now + timedelta(seconds=2))
    assert result["state"] == "completed" and result["attempts"] == 2
    assert not access(service.operations, initial.grant_token, now + timedelta(seconds=2)).allowed


def test_permanent_processing_failure_is_retained_and_visible(environment, monkeypatch):
    service, _, observation, _, _ = environment
    service.inbox.max_attempts = 2

    def broken(*args, **kwargs):
        raise RuntimeError("must not leak private input from exception")

    monkeypatch.setattr(service.operations, "apply_observation", broken)
    service.process_one(now=observation.issued_at)
    final = service.process_one(now=observation.issued_at + timedelta(seconds=1))
    assert final["state"] == "failed" and final["attempts"] == 2
    assert final["last_error"] == "PROCESSING_ERROR" and final["result"] is None
    assert "private input" not in json.dumps(final)
    assert service.summary(OPERATOR)["failed"] == 1
    assert service.operations.history("process-session", OPERATOR)[-1].version == 1


def test_cli_drains_a_persisted_signal_in_a_separate_process(environment):
    service, initial, observation, registry, now = environment
    env = os.environ | {
        "APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule",
        "ZERO_TRUST_DB_PATH": str(service.inbox.path),
        "TRUSTED_SIGNAL_SOURCES_PATH": str(registry),
    }
    result = subprocess.run(
        [sys.executable, "-m", "scripts.signal_worker", "--once"], cwd=ROOT,
        env=env, capture_output=True, text=True, timeout=20, check=False,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output == {"worker": "delivery", "state": "completed", "attempts": 1}
    assert service.inbox.get(OPERATOR.tenant_id, observation.event_id)["state"] == "completed"
    assert not access(service.operations, initial.grant_token, now + timedelta(seconds=2)).allowed


def test_worker_refuses_production_before_creating_storage(tmp_path):
    from app.config import Settings

    path = tmp_path / "production.sqlite3"
    settings = Settings(
        app_environment="production", auth_mode="api_key", api_key_sha256="a" * 64,
        zero_trust_db_path=path,
    )
    with pytest.raises(ValueError, match="local/test"):
        build_service(settings)
    assert not path.exists()
