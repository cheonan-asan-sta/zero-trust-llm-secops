"""Ephemeral fixture authority for outcomes observed before authentication starts."""

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models import SecurityEvent
from app.services.session_analysis_evidence import event_digest
from app.services.trusted_signals import canonical_auth_attempt
from app.zero_trust_models import SignedAuthAttemptReceipt


class LocalAuthAttemptLab:
    """Only the local test gateway owns the private key and closes attempt state."""

    def __init__(self, session_lab):
        self.key = Ed25519PrivateKey.generate()
        self.tenant_id = session_lab.principal.tenant_id
        self.source_id = "local-auth-attempt-gateway"
        self.pending = {}
        self.closed = set()
        now = datetime.now(UTC)
        public_key = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        session_lab.registry["sources"].append(
            {
                "source_id": self.source_id,
                "tenant_id": self.tenant_id,
                "user_ids": ["local-user"],
                "device_ids": ["local-device"],
                "roles": ["employee"],
                "auth_attempt_resource_ids": ["remote-read"],
                "keys": [
                    {
                        "key_id": "ephemeral-attempt-key",
                        "public_key_pem": public_key.decode(),
                        "not_before": (now - timedelta(minutes=1)).isoformat(),
                        "not_after": (now + timedelta(hours=1)).isoformat(),
                    }
                ],
            }
        )
        session_lab.save_registry()

    def open(self, event_id, *, failed_attempts=0):
        if event_id in self.pending or event_id in self.closed:
            raise ValueError("duplicate local authentication attempt")
        event = SecurityEvent.model_validate(
            {
                "event_id": event_id,
                "timestamp": datetime.now(UTC),
                "user": {"user_id": "local-user", "role": "employee", "active": True},
                "device": {
                    "device_id": "local-device",
                    "managed": True,
                    "security_posture": "healthy",
                },
                "network": {"ip": "192.0.2.80", "location": "local-lab", "access_method": "vpn"},
                "resource": {
                    "resource_id": "remote-read",
                    "resource_type": "document",
                    "sensitivity": "internal",
                },
                "action": "READ",
                "auth_context": {
                    "authentication_result": "unknown",
                    "mfa": "unknown",
                    "failed_attempts": failed_attempts,
                },
                "behavior": {},
            }
        )
        self.pending[event_id] = event
        return event

    def _close(self, event_id, outcome):
        event = self.pending.pop(event_id)
        self.closed.add(event_id)
        now = datetime.now(UTC)
        receipt = SignedAuthAttemptReceipt(
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            key_id="ephemeral-attempt-key",
            event_digest_sha256=event_digest(event),
            outcome=outcome,
            issued_at=now,
            expires_at=now + timedelta(seconds=60),
            signature="A" * 86,
        )
        signature = base64.urlsafe_b64encode(self.key.sign(canonical_auth_attempt(receipt)))
        return receipt.model_copy(update={"signature": signature.decode().rstrip("=")})

    def cancel(self, event_id):
        return self._close(event_id, "client_cancelled")

    def check_upstream(self, event_id, probe: Callable[[], httpx.Response]):
        """Observe the configured identity-provider health request before authentication."""
        try:
            response = probe()
        except (httpx.ConnectError, httpx.ConnectTimeout):
            return self._close(event_id, "upstream_unavailable")
        if response.status_code in {502, 503, 504}:
            return self._close(event_id, "upstream_unavailable")
        return None
