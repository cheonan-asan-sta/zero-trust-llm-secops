"""Synthetic offline recovery fixture; tokens remain in the private lab volume."""

import argparse
import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.policy_journal import JournalLimits
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import SignalVerifier, canonical_signal
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionEvaluationRequest,
    SessionRevocationRequest,
    SignedSessionSignal,
)
from scripts.app_state_recovery import canonical, local_only, require

PRINCIPAL = Principal("recovery-test", "recovery-tenant", frozenset({Role.ADMIN}), "api_key")
LIMITS = JournalLimits(max_active_records=8, archive_batch_size=4, max_archive_records=2000)


def evaluate(service, session, now, principal=PRINCIPAL, private=None):
    data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    data.update(event_id="recovery-" + session, timestamp=now.isoformat())
    data["user"].update(role="employee", active=True)
    data["resource"].update(resource_id="zt-demo-documents", required_role=None)
    data["auth_context"].update(authentication_result="success", mfa="success")
    if private is None:
        result = service.evaluate(SessionEvaluationRequest(session_id=session, expected_version=0,
            event=SecurityEvent.model_validate(data)), principal, now=now)
    else:
        request = SignedSessionSignal(session_id=session, expected_version=0, event=SecurityEvent.model_validate(data),
            tenant_id=principal.tenant_id, source_id="recovery-source", key_id="current", issued_at=now,
            expires_at=now + timedelta(seconds=90), signature="A" * 86)
        signature = base64.urlsafe_b64encode(private.sign(canonical_signal(request))).decode().rstrip("=")
        result = service.evaluate_signed(request.model_copy(update={"signature": signature}), principal, now=now)
    require(result.session.decision == "ALLOW", "fixture_allow_required")
    return result.grant_token


def access(service, name, token, now, principal=PRINCIPAL):
    return service.access(ProtectedAccessRequest(session_id=name, resource_id="zt-demo-documents",
        action="READ", grant_token=token), principal, now=now)


def accept(inbox, event, now, tenant=PRINCIPAL.tenant_id):
    payload = {"event_id": event, "signature": "synthetic-signature"}
    digest = hashlib.sha256(json.dumps({"event_id": event}, sort_keys=True).encode()).hexdigest()
    return inbox.accept(tenant, event, payload, digest, PRINCIPAL.subject, now)


def prepare(directory):
    local_only()
    directory.mkdir(parents=True, exist_ok=True)
    require(not any(directory.iterdir()), "fresh_fixture_required")
    now = datetime.now(UTC)
    private = Ed25519PrivateKey.generate()
    keys = []
    for key_id, key, enabled in (("current", private, True), ("disabled", Ed25519PrivateKey.generate(), False)):
        keys.append({"key_id": key_id, "enabled": enabled,
            "public_key_pem": key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            "not_before": (now - timedelta(days=1)).isoformat(), "not_after": (now + timedelta(days=1)).isoformat()})
    event = synthetic_events()[0]
    registry = {"sources": [{"source_id": "recovery-source", "tenant_id": PRINCIPAL.tenant_id, "enabled": True,
        "user_ids": [event.user.user_id], "device_ids": [event.device.device_id], "roles": ["employee"], "keys": keys}]}
    (directory / "sources.json").write_bytes(canonical(registry))
    service = ZeroTrustOperations(directory / "app.sqlite3", journal_limits=LIMITS,
                                  signal_verifier=SignalVerifier(directory / "sources.json"))
    tokens = {name: evaluate(service, name, now, private=private) for name in ("consumed", "revoked", "pending")}
    require(access(service, "consumed", tokens["consumed"], now).allowed, "fixture_consume")
    service.revoke("revoked", SessionRevocationRequest(expected_version=1, note="synthetic prior revocation"),
                   PRINCIPAL, now=now)
    for _ in range(12):
        require(not access(service, "consumed", tokens["consumed"], now).allowed, "fixture_replay")
    # Keep completed, live lease and pending receipts, including a terminal archive.
    inbox = SignalInbox(service.path, max_records=2, lease_seconds=30)
    accept(inbox, "completed", now)
    item = inbox.claim(now=now)
    inbox.complete(PRINCIPAL.tenant_id, "completed", item["lease_token"], {"revoked": 1}, now)
    accept(inbox, "processing", now + timedelta(microseconds=1))
    inbox.claim(now=now + timedelta(seconds=1))
    accept(inbox, "pending", now + timedelta(microseconds=2))
    fixture = {"now": now.isoformat(), "tokens": tokens}
    (directory / "fixture.json").write_bytes(canonical(fixture))
    return {"prepared": True, "sessions": len(tokens), "journal_archived": True, "inbox_states": 3}


def verify(directory, fixture_directory):
    local_only()
    fixture = json.loads((fixture_directory / "fixture.json").read_bytes())
    now = datetime.fromisoformat(fixture["now"]) + timedelta(seconds=1)
    service = ZeroTrustOperations(directory / "app.sqlite3")
    results = {name: access(service, name, token, now).reason_code for name, token in fixture["tokens"].items()}
    require(set(results.values()) == {"SESSION_NOT_AUTHORIZED"}, "restored_grant_accepted")
    return {"old_grants_denied": len(results), "reason": "SESSION_NOT_AUTHORIZED", "fixed_clock": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "verify"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--fixture-directory", type=Path)
    args = parser.parse_args()
    result = prepare(args.directory) if args.operation == "prepare" else verify(args.directory, args.fixture_directory)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
