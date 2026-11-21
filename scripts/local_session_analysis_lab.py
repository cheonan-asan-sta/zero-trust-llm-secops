"""Ephemeral local authority lab, separate from historical/native benchmarks.

Expected labels below are authored from scenario intent before executing PE/PA/PEP;
they are never inferred from the policy engine result or sent to the LLM.
"""

import base64
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models import SecurityEvent
from app.security import Principal, Role
from app.services.session_analysis_evidence import collect_session_evidence
from app.services.trusted_signals import SignalVerifier, canonical_signal
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import SessionRevocationRequest, SignedSessionSignal

SCENARIOS = (
    ("role_denied", True, "remote-admin", "employee", "success", True, "REMOTE_ACCESS"),
    ("action_denied", True, "remote-read", "employee", "success", True, "REMOTE_ACCESS"),
    ("required_mfa_unknown", True, "remote-team", "employee", "unknown", True, "REMOTE_ACCESS"),
    ("required_mfa_failed", True, "remote-team", "employee", "failed", True, "REMOTE_ACCESS"),
    ("revoked_request", True, "remote-team", "employee", "success", True, "REMOTE_ACCESS"),
    ("unregistered_resource", True, "unregistered", "employee", "success", True, "REMOTE_ACCESS"),
    ("permitted_admin", False, "remote-admin", "administrator", "success", True, "REMOTE_ACCESS"),
    ("permitted_team", False, "remote-team", "employee", "success", True, "REMOTE_ACCESS"),
    ("mfa_not_required", False, "remote-no-mfa", "employee", "not_required", True, "REMOTE_ACCESS"),
    (
        "mfa_unknown_not_required",
        False,
        "remote-no-mfa",
        "employee",
        "unknown",
        True,
        "REMOTE_ACCESS",
    ),
    ("read_over_vpn", False, "remote-read", "employee", "success", True, "READ"),
    ("permitted_healthy_byod", False, "remote-byod", "employee", "success", False, "REMOTE_ACCESS"),
)


def remote_policy_bundle():
    resources = []
    for name, roles, actions, mfa, managed in (
        ("remote-admin", ["administrator"], ["REMOTE_ACCESS"], True, True),
        ("remote-team", ["employee", "administrator"], ["REMOTE_ACCESS"], True, True),
        ("remote-read", ["employee"], ["READ"], True, True),
        ("remote-no-mfa", ["employee"], ["REMOTE_ACCESS"], False, True),
        ("remote-byod", ["employee"], ["REMOTE_ACCESS"], True, False),
    ):
        resources.append(
            {
                "resource_id": name,
                "resource_type": "document",
                "sensitivity": "internal",
                "roles": roles,
                "actions": actions,
                "require_mfa": mfa,
                "require_managed": managed,
            }
        )
    return {"version": "local-remote-policy-1", "resources": resources}


class LocalSessionAnalysisLab:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.key = Ed25519PrivateKey.generate()  # Never persisted or sent to the API.
        self.principal = Principal(
            "local-operator", "local-lab", frozenset({Role.ADMIN}), "api_key"
        )
        now = datetime.now(UTC)
        public = (
            self.key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        self.registry = {
            "sources": [
                {
                    "source_id": "local-session-collector",
                    "tenant_id": "local-lab",
                    "user_ids": ["local-user"],
                    "device_ids": ["local-device"],
                    "roles": ["employee", "administrator"],
                    "keys": [
                        {
                            "key_id": "ephemeral-key",
                            "public_key_pem": public,
                            "not_before": (now - timedelta(minutes=1)).isoformat(),
                            "not_after": (now + timedelta(hours=1)).isoformat(),
                        }
                    ],
                }
            ]
        }
        self.registry_path = self.directory / "public-registry.json"
        self.save_registry()
        self.policy_path = self.directory / "server-policy.json"
        self.policy_path.write_bytes(json.dumps(remote_policy_bundle()).encode())
        self.service = ZeroTrustOperations(
            self.directory / "operations.sqlite3",
            self.policy_path,
            SignalVerifier(self.registry_path),
        )

    def save_registry(self):
        self.registry_path.write_bytes(json.dumps(self.registry).encode())

    def sign(self, event, session_id, expected_version=0, *, challenge_id=None):
        now = datetime.now(UTC)
        unsigned = SignedSessionSignal(
            session_id=session_id,
            expected_version=expected_version,
            event=event,
            tenant_id="local-lab",
            source_id="local-session-collector",
            key_id="ephemeral-key",
            issued_at=now,
            expires_at=now + timedelta(seconds=120),
            challenge_id=challenge_id,
            signature="A" * 86,
        )
        signature = (
            base64.urlsafe_b64encode(self.key.sign(canonical_signal(unsigned))).decode().rstrip("=")
        )
        return unsigned.model_copy(update={"signature": signature})

    def create(self, scenario):
        name, _, resource, role, mfa, managed, action = scenario
        nonce = secrets.token_hex(12)
        event = SecurityEvent.model_validate(
            {
                "event_id": "event-" + nonce,
                "timestamp": datetime.now(UTC),
                "user": {"user_id": "local-user", "role": role, "active": True},
                "device": {
                    "device_id": "local-device",
                    "managed": managed,
                    "security_posture": "healthy",
                },
                "network": {"ip": "192.0.2.80", "location": "local-lab", "access_method": "vpn"},
                "resource": {
                    "resource_id": resource,
                    "resource_type": "document",
                    "sensitivity": "internal",
                    "required_role": role,
                },
                "action": action,
                "auth_context": {
                    "authentication_result": "success",
                    "mfa": mfa,
                    "failed_attempts": 1 if mfa == "failed" else 0,
                },
                "behavior": {},
            }
        )
        session_id = "session-" + nonce
        signal = self.sign(event, session_id)
        result = self.service.evaluate_signed(signal, self.principal)
        if name == "revoked_request":
            revoked = self.service.revoke(
                session_id,
                SessionRevocationRequest(
                    expected_version=result.session.version,
                    note="Local predeclared revocation scenario",
                ),
                self.principal,
            )
            event = event.model_copy(
                update={
                    "event_id": "event-" + secrets.token_hex(12),
                    "timestamp": datetime.now(UTC),
                }
            )
            signal = self.sign(event, session_id, revoked.version)
            self.service.evaluate_signed(signal, self.principal)
        context = collect_session_evidence(self.service, signal, self.principal)
        return signal, context
