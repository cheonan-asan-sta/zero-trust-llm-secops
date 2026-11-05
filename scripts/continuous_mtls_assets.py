"""Ephemeral assets and container helpers for the local continuous mTLS profile.

Host callers consume assets() in RAM and provision named volumes through stdin.
There is deliberately no CLI command that prints the complete asset bundle.
Operator probe/mint responses may contain test grants and must remain private.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import uuid
from datetime import UTC, datetime, timedelta
from http.client import HTTPException
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.scenarios import synthetic_events
from app.services.trusted_signals import canonical_signal
from app.zero_trust_models import SignedSessionSignal
from scripts import mtls_transport as tls
from scripts.mtls_fixtures import authority, leaf

TENANT = "local"
USER = "runtime-user"
OTHER = "runtime-other"
DEVICES = ("runtime-device", "other-device")
OPERATOR = "runtime-operator"
TLS = Path("/tls")
AUTH = Path("/auth")
COLLECTOR = Path("/collector/producer")
ROOT = Path(__file__).resolve().parents[1]


def assets(*, monitoring=False) -> dict[str, dict[str, str]]:
    """Generate only in-memory private leaf/signing keys; retain no CA private key."""
    ca = authority("Continuous local runtime CA")
    ca_pem = ca[1].public_bytes(serialization.Encoding.PEM).decode()
    servers = ("core-a", "gateway", "bridge-auth", "bridge-consume", "resource", "proxy")
    clients = ("core-operator", "gateway-client", "pep-bridge", "collector", "proxy-auth",
               "bridge-probe", "resource-consumer", "proxy-resource", "resource-auditor", "frontend")
    if monitoring:
        from scripts.monitoring_runtime_assets import CLIENTS, SERVERS
        servers += SERVERS
        clients += CLIENTS
    leaves = {name: leaf(ca, name, server=name in servers) for name in (*servers, *clients)}

    def credentials(*names):
        files = {"ca.pem": ca_pem}
        for name in names:
            files[name + ".pem"] = leaves[name]["cert"]
            files[name + ".key"] = leaves[name]["key"]
        return files

    def server(filename, name, peers):
        return credentials(name) | {filename: json.dumps({
            "ca": "ca.pem", "cert": name + ".pem", "key": name + ".key",
            "peers": {leaves[peer]["fingerprint"]: role for peer, role in peers.items()},
        })}

    def client(filename, caller, target, host, port):
        return credentials(caller) | {filename: json.dumps({
            "host": host, "port": port, "server_name": target, "ca": "ca.pem",
            "cert": caller + ".pem", "key": caller + ".key",
            "server_pins": [leaves[target]["fingerprint"]],
        })}

    api_key = secrets.token_urlsafe(32)
    signing_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    registry = {"sources": [{
        "tenant_id": TENANT, "source_id": "runtime-session", "enabled": True,
        "user_ids": [USER, OTHER], "device_ids": list(DEVICES), "roles": ["employee"],
        "keys": [{"key_id": "session-key", "enabled": True,
                  "public_key_pem": signing_key.public_key().public_bytes(
                      serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
                  ).decode(), "not_before": (now - timedelta(seconds=30)).isoformat(),
                  "not_after": (now + timedelta(days=1)).isoformat()}],
    }]}
    material = {
        "registry": {"sources.json": json.dumps(registry)},
        "core-tls": server("server.json", "core-a", {
            "gateway-client": "api-gateway", "core-operator": "core-operator",
        }),
        "gateway-tls": server("profile.json", "gateway", {
            "collector": "collector", "pep-bridge": "pep-bridge",
        }) | client("backend.json", "gateway-client", "core-a", "core", 8000),
        "bridge-tls": server("auth.json", "bridge-auth", {
            "proxy-auth": "proxy-auth", "bridge-probe": "bridge-probe",
        }) | server("consume.json", "bridge-consume", {
            "resource-consumer": "resource-consumer",
        }) | client("core.json", "pep-bridge", "gateway", "gateway", 8443) | {
            "front.json": json.dumps({"forwarded_peers": [leaves["frontend"]["fingerprint"]]}),
        },
        "resource-tls": server("server.json", "resource", {
            "proxy-resource": "proxy-resource", "resource-auditor": "resource-auditor",
        }) | client("consume.json", "resource-consumer", "bridge-consume", "bridge", 8082)
        | client("audit.json", "resource-auditor", "resource", "127.0.0.1", 8083),
        "proxy-tls": credentials("proxy", "proxy-auth", "proxy-resource"),
        "collector-tls": client("profile.json", "collector", "gateway", "gateway", 8443),
        "operator-tls": client("core.json", "core-operator", "core-a", "core", 8000)
        | client("frontend.json", "frontend", "proxy", "proxy", 8080)
        | client("resource.json", "resource-auditor", "resource", "resource", 8083),
        "core-auth": {"api-key.sha256": hashlib.sha256(api_key.encode()).hexdigest()},
        "collector-auth": {"api-key.txt": api_key},
        "operator-auth": {"api-key.txt": api_key, "session-private.pem": signing_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()},
        "secret": {"secret": secrets.token_urlsafe(32)},
        "config": {"all-hops.conf": (ROOT / "infra/mtls/all-hops-nginx.conf").read_text("utf-8")},
    }
    if monitoring:
        from scripts.monitoring_runtime_assets import assets as monitor_assets
        material.update(monitor_assets(server, client, credentials))
    return material


def _credential(name, *, digest=False):
    path = AUTH / name
    if path.stat().st_size > 4096:
        raise ValueError("runtime credential size")
    value = path.read_text("utf-8").strip()
    if not re.fullmatch(r"[a-f0-9]{64}" if digest else r"[A-Za-z0-9_-]{32,128}", value):
        raise ValueError("runtime credential format")
    return value


def service(role):
    if os.environ.get("APP_ENVIRONMENT", "local") not in {"local", "test"}:
        raise ValueError("continuous runtime is local/test only")
    os.environ["ANALYZER_MODE"] = "rule"
    if role == "app":
        os.environ.update(AUTH_MODE="api_key", API_KEY_SHA256=_credential("api-key.sha256", digest=True),
                          API_KEY_SUBJECT=OPERATOR, API_KEY_TENANT_ID=TENANT,
                          API_KEY_ROLES="responder")
        command = ["-m", "scripts.mtls_native", "api", "--profile", str(TLS / "server.json")]
    elif role == "collector":
        os.environ["AUTH_MODE"] = "disabled"
        os.environ["SIGNAL_COLLECTOR_API_KEY"] = _credential("api-key.txt")
        command = ["-m", "scripts.continuous_signal_collector", "run", "--directory", str(COLLECTOR),
                   "--base-url", "https://gateway:8443", "--tls-profile", str(TLS / "profile.json"),
                   "--poll-seconds", "0.05"]
    else:
        raise ValueError("unknown runtime role")
    os.execv(sys.executable, [sys.executable, *command])


def _input():
    raw = sys.stdin.buffer.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("runtime input size")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise TypeError("runtime input shape")
    return data


def _request(data):
    profile_name = data.get("profile", "core")
    if profile_name not in {"core", "frontend", "resource"}:
        raise ValueError("runtime probe profile")
    target, method = data.get("path", "/health/live"), data.get("method", "GET")
    if (not isinstance(target, str) or not target.startswith("/") or len(target) > 2048
            or any(char in target for char in "\r\n") or method not in {"GET", "POST"}):
        raise ValueError("runtime probe target")
    headers = data.get("headers", {})
    if not isinstance(headers, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        or any(char in key + value for char in "\r\n") or len(key + value) > 4096
        for key, value in headers.items()
    ):
        raise ValueError("runtime probe headers")
    headers = {key: value for key, value in headers.items() if key.lower() != "x-api-key"}
    headers["X-API-Key"] = _credential("api-key.txt")
    observed = {}
    status, body = tls.request(TLS / (profile_name + ".json"), target, data.get("body"), headers,
                               method=method, observed=observed)
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeError):
        parsed = None
    return {"status": status, "body": parsed, "body_sha256": hashlib.sha256(body).hexdigest(),
            "tls_version": observed.get("tls_version")}


def mint(data):
    now = datetime.now(UTC) - timedelta(seconds=1)
    lifetime = data.get("expires_seconds", 90)
    if isinstance(lifetime, bool) or not isinstance(lifetime, (int, float)) or not 1 < lifetime <= 120:
        raise ValueError("runtime proof lifetime")
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event.update(event_id="runtime-mint-" + uuid.uuid4().hex, timestamp=now)
    event["user"].update(user_id=data.get("user_id", USER), role="employee", active=True)
    event["device"].update(device_id=data.get("device_id", DEVICES[0]), managed=True,
                           security_posture="healthy")
    event["auth_context"].update(authentication_result="success", mfa="success")
    event["resource"].update(resource_id="zt-demo-documents", required_role=None)
    signal = SignedSessionSignal(
        session_id=data["session_id"], expected_version=0, event=event, tenant_id=TENANT,
        source_id=data.get("source_id", "runtime-session"), key_id="session-key", issued_at=now,
        expires_at=now + timedelta(seconds=lifetime), signature="A" * 86,
    )
    key_file = data.get("signing_key_file", "session-private.pem")
    if not isinstance(key_file, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}-private\.pem", key_file):
        raise ValueError("runtime signing key filename")
    path = AUTH / key_file
    if path.stat().st_size > 16384:
        raise ValueError("runtime signing key size")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("runtime signing algorithm")
    signal.signature = base64.urlsafe_b64encode(key.sign(canonical_signal(signal))).decode().rstrip("=")
    return _request({"profile": "core", "path": "/zero-trust/signals/evaluate", "method": "POST",
                     "body": signal.model_dump(mode="json")})


def append(data):
    from scripts.collector_input import append_event
    from scripts.continuous_signal_collector import InputRecord
    record = InputRecord(
        event_id=data["event_id"], observed_at=data.get("observed_at", data.get(
            "timestamp", datetime.now(UTC) - timedelta(seconds=1))),
        observation=data.get("observation", {
            "kind": "identity", "subject_id": data.get("subject", USER),
            "active": data.get("active", False),
            "authentication_result": data.get("authentication_result", "failure"),
        }),
    )
    if record.observation.kind != "identity":
        raise ValueError("runtime feed requires identity observation")
    return append_event(COLLECTOR, record.model_dump(mode="json"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["service", "probe", "mint", "append"])
    parser.add_argument("role", nargs="?", choices=["app", "collector"])
    args = parser.parse_args(argv)
    try:
        if args.mode == "service":
            service(args.role)
            return 0
        result = {"probe": _request, "mint": mint, "append": append}[args.mode](_input())
        print(json.dumps(result), flush=True)
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnsupportedAlgorithm, HTTPException):
        print(json.dumps({"status": 0, "body": None, "body_sha256": None,
                          "tls_version": None, "error": "RUNTIME_HELPER_FAILED"}), flush=True)
        return 0 if args.mode in {"probe", "mint"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
