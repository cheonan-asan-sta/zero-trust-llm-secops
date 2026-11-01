#!/usr/bin/env python3
"""Separate local-only collector for signed source and challenge end-to-end testing.

Run as python -m scripts.local_signal_collector. Never prints keys, proofs or grants.
"""

import argparse
import base64
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.scenarios import synthetic_events
from app.services.trusted_signals import canonical_signal
from app.zero_trust_models import SignedSessionSignal


def initialize(directory: Path, tenant: str) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    private_path, registry_path = directory / "private.pem", directory / "sources.json"
    if private_path.exists() or registry_path.exists():
        raise FileExistsError("Collector files already exist; choose a new directory")
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    now = datetime.now(UTC)
    registry = {"sources": [{"source_id": "local-idp", "tenant_id": tenant, "enabled": True,
        "user_ids": ["collector-demo-user"], "device_ids": ["collector-demo-device"],
        "roles": ["employee"], "keys": [{"key_id": "key-1", "public_key_pem": public,
            "enabled": True, "not_before": (now - timedelta(seconds=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat()}]}]}
    private_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
    # Exclusive create; private material never enters the API container or stdout.
    with os.fdopen(os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(private_bytes)
    with registry_path.open("x", encoding="utf-8") as handle:
        json.dump(registry, handle, ensure_ascii=False, indent=2)
    return {"status": "initialized", "public_registry": str(registry_path)}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Collector API redirects are not allowed")


def _post(base_url: str, path: str, data: dict):
    request = Request(base_url + path, data=json.dumps(data).encode(), method="POST",
                      headers={"Content-Type": "application/json"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=10) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        return exc.code, json.load(exc)


def demonstrate(directory: Path, base_url: str, tenant: str) -> dict:
    target = urlsplit(base_url)
    if (target.scheme != "http" or target.hostname not in {"127.0.0.1", "localhost", "::1"}
            or target.username or target.password or target.path not in {"", "/"}
            or target.query or target.fragment):
        raise ValueError("Collector demo only supports an HTTP loopback API")
    base_url = base_url.rstrip("/")
    private = serialization.load_pem_private_key((directory / "private.pem").read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError("Expected an Ed25519 collector key")
    session_id = "collector-" + uuid.uuid4().hex
    version = 0
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event["user"].update(user_id="collector-demo-user", role="employee")
    event["device"].update(device_id="collector-demo-device")
    event["resource"].update(resource_id="zt-demo-documents", required_role=None)
    event["auth_context"].update(authentication_result="success", mfa="success")

    def evaluate(challenge=None):
        nonlocal version
        now = datetime.now(UTC)
        event.update(event_id="collector-event-" + uuid.uuid4().hex, timestamp=now.isoformat())
        signal = SignedSessionSignal.model_validate({
            "session_id": session_id, "expected_version": version, "event": event,
            "tenant_id": tenant, "source_id": "local-idp", "key_id": "key-1",
            "issued_at": now, "expires_at": now + timedelta(seconds=90),
            "challenge_id": challenge, "signature": "A" * 86,
        })
        signature = base64.urlsafe_b64encode(private.sign(canonical_signal(signal))).decode().rstrip("=")
        signal = signal.model_copy(update={"signature": signature})
        status, result = _post(base_url, "/zero-trust/signals/evaluate", signal.model_dump(mode="json"))
        if status != 200:
            raise RuntimeError(f"Signed collector request failed with HTTP {status}")
        version = result["session"]["version"]
        return result

    def access(token):
        return _post(base_url, "/zero-trust/protected-access", {
            "session_id": session_id, "resource_id": "zt-demo-documents", "action": "READ",
            "grant_token": token,
        })[0]

    initial = evaluate()
    assert initial["session"]["signal_trust"] == "verified_source"
    assert access(initial["grant_token"]) == 200
    event["auth_context"]["mfa"] = "unknown"
    challenged = evaluate()
    assert challenged["session"]["decision"] == "STEP_UP"
    event["auth_context"]["mfa"] = "success"
    unbound = evaluate()
    assert unbound["session"]["decision"] == "STEP_UP" and unbound["grant_token"] is None
    recovered = evaluate(unbound["session"]["challenge_id"])
    assert recovered["session"]["decision"] == "ALLOW"
    event["device"]["security_posture"] = "compromised"
    revoked = evaluate()
    assert revoked["session"]["status"] == "REVOKED"
    assert access(recovered["grant_token"]) == 403
    return {"status": "passed", "signed_source_verified": True, "unbound_mfa_rejected": True,
            "bound_mfa_recovered": True, "revoked_grant_denied": True,
            "session_id": session_id, "session_version": version}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["init", "demo"])
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--tenant", default="local")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    args = parser.parse_args()
    if args.operation == "init":
        result = initialize(args.directory, args.tenant)
    else:
        result = demonstrate(args.directory, args.base_url, args.tenant)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
