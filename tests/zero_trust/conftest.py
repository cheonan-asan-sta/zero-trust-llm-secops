"""Isolated keys, stores and clocks for local Zero Trust regression tests."""

import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.trusted_signals import SignalVerifier, canonical_signal
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionEvaluationRequest,
    SignedSessionSignal,
)


@pytest.fixture
def lab(tmp_path):
    now = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
    operator = Principal("operator-a", "tenant-a", frozenset({Role.ADMIN}), "api_key")
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    registry = {"sources": [{
        "source_id": "source-a", "tenant_id": "tenant-a", "enabled": True,
        "user_ids": ["user-a"], "device_ids": ["device-a"], "roles": ["employee"],
        "keys": [{"key_id": "key-a", "public_key_pem": public, "enabled": True,
                  "not_before": (now - timedelta(days=1)).isoformat(),
                  "not_after": (now + timedelta(days=1)).isoformat()}],
    }]}
    path = tmp_path / "sources.json"

    def save_registry():
        path.write_text(json.dumps(registry), encoding="utf-8")

    save_registry()
    service = ZeroTrustOperations(tmp_path / "operations.sqlite3", signal_verifier=SignalVerifier(path))

    def event(event_id="event-one", *, when=now, **updates):
        data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        data.update(event_id=event_id, timestamp=when)
        data["user"].update(user_id="user-a", role="employee", active=True)
        data["device"].update(device_id="device-a", managed=True, security_posture="healthy")
        data["resource"].update(resource_id="zt-demo-documents", required_role=None)
        data["auth_context"].update(authentication_result="success", mfa="success")
        for name, value in updates.items():
            if isinstance(value, dict):
                data[name].update(value)
            else:
                data[name] = value
        return SecurityEvent.model_validate(data)

    def request(*, session="session-a", version=0, **updates):
        return SessionEvaluationRequest(
            session_id=session, expected_version=version, event=event(**updates),
        )

    def signed(*, signer=key, session="session-a", version=0, when=now,
               event_id="event-one", event_updates=None, **updates):
        data = {
            "session_id": session, "expected_version": version,
            "event": event(event_id, when=when, **(event_updates or {})),
            "tenant_id": "tenant-a", "source_id": "source-a", "key_id": "key-a",
            "issued_at": when, "expires_at": when + timedelta(seconds=90),
            "signature": "A" * 86,
        }
        data.update(updates)
        signal = SignedSessionSignal.model_validate(data)
        signature = base64.urlsafe_b64encode(signer.sign(canonical_signal(signal))).decode().rstrip("=")
        return signal.model_copy(update={"signature": signature})

    def evaluate(*, principal=operator, at=now, **updates):
        return service.evaluate(request(**updates), principal, now=at)

    def access(token, *, principal=operator, at=now, session="session-a",
               resource="zt-demo-documents", action="READ"):
        return service.access(ProtectedAccessRequest(
            session_id=session, resource_id=resource, action=action, grant_token=token,
        ), principal, now=at)

    return SimpleNamespace(
        now=now, operator=operator, key=key, registry=registry, registry_path=path,
        service=service, event=event, request=request, signed=signed,
        evaluate=evaluate, access=access, save_registry=save_registry,
    )


@pytest.fixture
def api(lab, monkeypatch):
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return lab.now.astimezone(tz) if tz else lab.now.replace(tzinfo=None)

    monkeypatch.setattr("app.services.zero_trust.datetime", FixedDateTime)
    application = FastAPI()
    application.include_router(zero_trust_router(lab.service))
    install_zero_trust_error_handlers(application)
    application.dependency_overrides[get_principal] = lambda: lab.operator
    with TestClient(application) as client:
        yield SimpleNamespace(app=application, client=client)
