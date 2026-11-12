"""Capture local OIDC bearer and protected-access outcomes without retaining credentials."""

import json
import secrets
import sqlite3
import tempfile
import time
from contextlib import ExitStack, closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.scenarios import synthetic_events
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import SignedSessionSignal
from scripts.test_signal_compose import sign

ISSUER = "https://local-identity.invalid"
AUDIENCE = "local-secops-api"
KID = "local-oidc-signing-key"
SIGNAL_SOURCE = "local-oidc-session-source"
SIGNAL_KEY = "local-oidc-session-key"
BEARER_MODES = frozenset({
    "valid", "expired", "missing", "wrong_audience", "future_nbf", "viewer", "wrong_key",
    "tampered", "wrong_issuer", "unknown_kid", "foreign_tenant",
})


def _bearer(case, mode, trusted_key, untrusted_key, *, owner_headers=None):
    if mode not in BEARER_MODES:
        raise ValueError("unsupported_local_oidc_bearer_mode")
    if mode == "missing":
        return {}
    if mode == "valid" and owner_headers is not None:
        return owner_headers
    if mode == "tampered":
        owner_token = owner_headers["Authorization"].removeprefix("Bearer ")
        header, _, signature = owner_token.split(".")
        claims = jwt.decode(owner_token, options={"verify_signature": False})
        claims["sub"] = case["attacker_id"]
        altered = jwt.utils.base64url_encode(json.dumps(claims).encode()).decode("ascii")
        return {"Authorization": f"Bearer {header}.{altered}.{signature}"}
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": case["owner_id"],
        "tenant_id": case["tenant_id"], "roles": ["analyst"],
        "iat": now - timedelta(minutes=2), "exp": now + timedelta(minutes=5),
    }
    if mode == "expired":
        claims["exp"] = now - timedelta(minutes=1)
    elif mode == "wrong_audience":
        claims["aud"] = "other-local-api"
    elif mode == "future_nbf":
        claims["nbf"] = now + timedelta(minutes=2)
    elif mode == "viewer":
        claims["roles"] = ["viewer"]
    elif mode == "wrong_issuer":
        claims["iss"] = "https://other-identity.invalid"
    elif mode == "foreign_tenant":
        claims.update(sub=case["attacker_id"], tenant_id=case["tenant_id"] + "-other")
    signing_key = untrusted_key if mode == "wrong_key" else trusted_key
    kid = "unpublished-local-key" if mode == "unknown_kid" else KID
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": kid})
    return {"Authorization": "Bearer " + token}


def _session_signal(case, signer, now):
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event.update(event_id=case["case_id"] + "-event", timestamp=now.isoformat(), action=case["action"])
    event["user"].update(user_id=case["account_id"], role=case["account_role"], active=True)
    event["device"].update(device_id=case["device_id"], managed=True, security_posture="healthy")
    event["network"].update(ip=case.get("client_ip", "192.0.2.1"))
    event["resource"].update(resource_id=case["resource_id"], required_role=None)
    event["auth_context"].update(authentication_result="success", mfa="success")
    return sign(SignedSessionSignal(
        session_id=case["case_id"] + "-session", expected_version=0, event=event,
        tenant_id=case["tenant_id"], source_id=SIGNAL_SOURCE, key_id=SIGNAL_KEY,
        issued_at=now, expires_at=now + timedelta(seconds=90), signature="A" * 86,
    ), signer)


def _operations(case, directory, signer, now):
    registry = directory / "sources.json"
    public_key = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    registry.write_text(json.dumps({"sources": [{
        "source_id": SIGNAL_SOURCE, "tenant_id": case["tenant_id"],
        "user_ids": [case["account_id"]], "device_ids": [case["device_id"]],
        "roles": [case["account_role"]], "keys": [{
            "key_id": SIGNAL_KEY, "public_key_pem": public_key,
            "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
        }],
    }]}), encoding="utf-8")
    return ZeroTrustOperations(directory / "journal.sqlite3", signal_verifier=SignalVerifier(registry))


def _capture_app(operations, observations, *, capture_origin=False):
    app = FastAPI()
    app.include_router(zero_trust_router(operations))
    install_zero_trust_error_handlers(app)
    previous = None

    @app.middleware("http")
    async def observe(request, call_next):
        nonlocal previous
        started = time.perf_counter_ns()
        response = await call_next(request)
        finished = time.perf_counter_ns()
        principal = getattr(request.state, "principal", None)
        observation = {
            "http_status": response.status_code,
            "duration_ms": (finished - started) // 1_000_000,
            "since_previous_ms": None if previous is None else (finished - previous) // 1_000_000,
            "authenticated_subject": principal.subject if principal else None,
            "authenticated_tenant": principal.tenant_id if principal else None,
        }
        if capture_origin:
            observation.update(
                observed_origin=request.client.host if request.client is not None else None,
                operation=request.url.path,
                method=request.method,
            )
        observations.append(observation)
        previous = finished
        return response

    return app


def _post(client, observations, path, request, headers):
    before = len(observations)
    response = client.post(path, json=request, headers=headers)
    if len(observations) != before + 1 or observations[-1]["http_status"] != response.status_code:
        raise RuntimeError("local_oidc_request_evidence_missing")
    body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    observation = observations[-1] | {
        "content_present": body.get("content") is not None,
        "reason_code": body.get("reason_code"),
    }
    if "observed_origin" in observation:
        if "event" in request:
            event = request["event"]
            observation.update(requested_resource=event["resource"]["resource_id"], requested_action=event["action"])
        else:
            observation.update(requested_resource=request["resource_id"], requested_action=request["action"])
    return observation, body


def _last_journal_row(database):
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute("SELECT seq, payload FROM journal ORDER BY seq DESC LIMIT 1").fetchone()
    return (row[0], json.loads(row[1])) if row else (0, {})


def _check_access_journal(before, after, request, observed, body):
    if "allowed" not in body:
        return before == after[0]
    seq, evidence = after
    expected = {
        "kind": "access", "session_id": request["session_id"],
        "resource_id": request["resource_id"], "action": request["action"],
        "operator_id": observed["authenticated_subject"], "tenant_id": observed["authenticated_tenant"],
        "allowed": body["allowed"], "reason_code": body.get("reason_code"),
        "session_version": body.get("session_version"),
    }
    return seq == before + 1 and all(evidence.get(key) == value for key, value in expected.items())


def _capture_case(case, directory, signal_signer, trusted_key, untrusted_key):
    now = datetime.now(UTC)
    operations = _operations(case, directory, signal_signer, now)
    signal = _session_signal(case, signal_signer, now)
    owner_headers = _bearer(case, "valid", trusted_key, untrusted_key)
    observations = []
    result = {"case_id": case["case_id"], "policy_digest_sha256": operations.policy_digest, "attempts": []}
    origins = case.get("origins")
    app = _capture_app(operations, observations, capture_origin=origins is not None)
    with ExitStack() as stack:
        if origins is None:
            clients = {"first": stack.enter_context(TestClient(app))}
        else:
            clients = {
                name: stack.enter_context(TestClient(app, client=(address, 50000)))
                for name, address in origins.items()
            }
        grant, grant_body = _post(
            clients["first"], observations, "/zero-trust/signals/evaluate", signal.model_dump(mode="json"),
            owner_headers,
        )
        grant_token = grant_body.get("grant_token")
        grant["grant_issued"] = isinstance(grant_token, str) and bool(grant_token)
        grant["journal_matches"] = None
        result["grant"] = grant
        if not grant["grant_issued"]:
            return result
        for attempt in case["attempts"]:
            if attempt["grant_kind"] not in {"issued", "invalid"}:
                raise ValueError("unsupported_local_oidc_grant_kind")
            request = {"session_id": signal.session_id, "resource_id": case["resource_id"],
                       "action": case["action"], "grant_token": (
                           grant_token if attempt["grant_kind"] == "issued" else secrets.token_urlsafe(32)
                       )}
            before, _ = _last_journal_row(operations.path)
            observed, body = _post(
                clients[attempt["origin"] if origins is not None else "first"],
                observations, "/zero-trust/protected-access", request,
                _bearer(case, attempt["bearer"], trusted_key, untrusted_key, owner_headers=owner_headers),
            )
            observed["journal_matches"] = _check_access_journal(
                before, _last_journal_row(operations.path), request, observed, body,
            )
            result["attempts"].append(observed)
    return result


def capture_cases(cases, scratch: Path):
    """Run planned requests in isolated stores and retain only observed evidence."""
    trusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    untrusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signal_signer = Ed25519PrivateKey.generate()
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(trusted_key.public_key(), as_dict=True)
    jwk.update(kid=KID, use="sig", alg="RS256")
    settings = Settings(_env_file=None, app_environment="test", analyzer_mode="rule", auth_mode="oidc",
                        oidc_issuer=ISSUER, oidc_audience=AUDIENCE, oidc_jwks_url=ISSUER + "/keys")
    jwks = jwt.PyJWKClient(settings.oidc_jwks_url, cache_jwk_set=False)
    scratch.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(dir=scratch, prefix="oidc-capture-") as root, patch(
        "app.security.get_settings", return_value=settings,
    ), patch("app.security._jwks_client", return_value=jwks), patch.object(
        jwks, "fetch_data", return_value={"keys": [jwk]},
    ):
        for index, case in enumerate(cases):
            directory = Path(root) / str(index)
            directory.mkdir()
            results.append(_capture_case(case, directory, signal_signer, trusted_key, untrusted_key))
    return results
