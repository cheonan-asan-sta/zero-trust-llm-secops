"""Independent watchdog processes, durable boundaries and HTTP enforcement."""

import base64
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
from app.zero_trust_models import SessionEvaluationRequest, SignedSessionSignal
from scripts.session_watchdog import build_service

ROOT = Path(__file__).parents[1]
OPERATOR = Principal("watchdog-operator", "tenant-a", frozenset({Role.ADMIN}), "api_key")


def wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError("watchdog did not reach its expected durable state")


def output(result):
    assert result.returncode == 0, "watchdog command failed"
    assert "PRIVATE KEY" not in result.stdout + result.stderr
    assert "watchdog-user" not in result.stdout + result.stderr
    assert "watchdog-device" not in result.stdout + result.stderr
    parsed = json.loads(result.stdout.splitlines()[-1])
    assert set(parsed) == {"watchdog", "checked", "changed", "held", "revoked"}
    assert parsed["watchdog"] == "revalidated"
    return parsed


@pytest.fixture
def lab(tmp_path):
    now = datetime.now(UTC)
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    registry_path = tmp_path / "sources.json"
    registry = {"sources": [{
        "source_id": "session-authority", "tenant_id": tenant,
        "user_ids": ["watchdog-user"], "device_ids": ["watchdog-device"],
        "roles": ["employee"], "keys": [{
            "key_id": "key-a", "public_key_pem": pem,
            "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=1)).isoformat(),
        }],
    } for tenant in ("tenant-a", "tenant-b")]}

    def save():
        temporary = registry_path.with_suffix(".next")
        temporary.write_text(json.dumps(registry), encoding="utf-8")
        temporary.replace(registry_path)

    save()
    db = tmp_path / "sessions.sqlite3"
    service = ZeroTrustOperations(db, signal_verifier=SignalVerifier(registry_path))
    environment = os.environ | {
        "APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule",
        "ZERO_TRUST_DB_PATH": str(db), "TRUSTED_SIGNAL_SOURCES_PATH": str(registry_path),
    }

    def session(session_id="signed-session", *, expires_in=90, issued_ago=10,
                principal=OPERATOR, signed=True):
        issued = now - timedelta(seconds=issued_ago)
        data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        data.update(event_id="initial-" + session_id, timestamp=issued)
        data["user"].update(user_id="watchdog-user", role="employee", active=True)
        data["device"].update(device_id="watchdog-device", managed=True, security_posture="healthy")
        data["auth_context"].update(authentication_result="success", mfa="success")
        data["resource"].update(resource_id="zt-demo-documents", required_role=None)
        event = SecurityEvent.model_validate(data)
        request = SessionEvaluationRequest(session_id=session_id, expected_version=0, event=event)
        if not signed:
            return service.evaluate(request, principal, now=issued)
        signal = SignedSessionSignal(
            **request.model_dump(), tenant_id=principal.tenant_id, source_id="session-authority",
            key_id="key-a", issued_at=issued, expires_at=now + timedelta(seconds=expires_in),
            signature="A" * 86,
        )
        signature = base64.urlsafe_b64encode(key.sign(canonical_signal(signal))).decode().rstrip("=")
        signal.signature = signature
        result = service.evaluate_signed(signal, principal, now=issued)
        assert result.session.decision == "ALLOW" and result.grant_token
        return result

    def disable_source():
        registry["sources"][0]["enabled"] = False
        save()

    return SimpleNamespace(now=now, key=key, registry=registry, registry_path=registry_path,
                           service=service, db=db, env=environment, session=session,
                           save=save, disable_source=disable_source, directory=tmp_path)


def run_once(lab, *args):
    return subprocess.run(
        [sys.executable, "-m", "scripts.session_watchdog", "--once", *args],
        cwd=ROOT, env=lab.env, capture_output=True, text=True, timeout=15, check=False,
    )


def http_access(lab, session_id, token, principal=OPERATOR):
    application = FastAPI()
    application.include_router(zero_trust_router(lab.service))
    install_zero_trust_error_handlers(application)
    application.dependency_overrides[get_principal] = lambda: principal
    with TestClient(application) as client:
        response = client.post("/zero-trust/protected-access", json={
            "session_id": session_id, "resource_id": "zt-demo-documents", "action": "READ",
            "grant_token": token,
        })
    return response


def test_no_new_observation_expired_proof_is_held_once_and_http_access_is_denied(lab):
    initial = lab.session(expires_in=-2)
    demo = lab.session("demo-session", signed=False)
    assert initial.session.status == "ACTIVE"
    first = output(run_once(lab))
    assert first["changed"] == first["held"] == 1 and first["revoked"] == 0
    session = lab.service.history("signed-session", OPERATOR)[-1]
    assert session.version == 2 and session.status == "HELD"
    assert "SIGNAL_PROOF_EXPIRED" in session.reason_codes
    assert session.grant_expires_at is None
    assert lab.service.history("demo-session", OPERATOR)[-1] == demo.session
    second = output(run_once(lab))
    assert second["changed"] == 0
    assert len(lab.service.history("signed-session", OPERATOR)) == 2
    denied = http_access(lab, "signed-session", initial.grant_token)
    assert denied.status_code == 403 and denied.json()["content"] is None
    assert denied.json()["reason_code"] == "SESSION_NOT_AUTHORIZED"


def test_grant_ttl_alone_does_not_hold_or_revoke_a_session(lab):
    initial = lab.session(issued_ago=65, expires_in=20)
    summary = output(run_once(lab))
    assert summary["checked"] == 1 and summary["changed"] == 0
    assert lab.service.history("signed-session", OPERATOR)[-1] == initial.session
    denied = http_access(lab, "signed-session", initial.grant_token)
    assert denied.status_code == 403 and denied.json()["reason_code"] == "GRANT_EXPIRED"


def test_key_scope_loss_revokes_only_its_tenant_and_preserves_unrelated_http_access(lab):
    first = lab.session()
    other = Principal("other-operator", "tenant-b", OPERATOR.roles, "api_key")
    unrelated = lab.session("other-session", principal=other)
    lab.disable_source()
    summary = output(run_once(lab))
    assert summary["checked"] == 2 and summary["revoked"] == summary["changed"] == 1
    session = lab.service.history("signed-session", OPERATOR)[-1]
    assert session.status == "REVOKED" and session.grant_expires_at is None
    assert "SIGNAL_SOURCE_REVOKED" in session.reason_codes
    assert http_access(lab, "signed-session", first.grant_token).status_code == 403
    assert http_access(lab, "other-session", unrelated.grant_token, other).status_code == 200
    assert lab.service.history("other-session", other)[-1].version == 1


def test_two_independent_watchdogs_commit_one_transition(lab):
    lab.session()
    lab.disable_source()
    processes = [subprocess.Popen(
        [sys.executable, "-m", "scripts.session_watchdog", "--once"],
        cwd=ROOT, env=lab.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for _ in range(2)]
    results = []
    try:
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            results.append(output(SimpleNamespace(returncode=process.returncode,
                                                  stdout=stdout, stderr=stderr)))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
    assert sum(result["changed"] for result in results) == 1
    history = lab.service.history("signed-session", OPERATOR)
    assert len(history) == 2 and history[-1].version == 2
    assert history[-1].status == "REVOKED"


@pytest.mark.parametrize("boundary", ["before_append", "after_commit_before_output"])
def test_process_death_at_journal_boundary_recovers_without_duplicate_versions(lab, boundary):
    initial = lab.session()
    lab.disable_source()
    code = """
import os, sys
import scripts.session_watchdog as watchdog
from app.services.zero_trust import ZeroTrustOperations
def stop(*args, **kwargs):
    os._exit(73)
if sys.argv[1] == 'before_append':
    ZeroTrustOperations._append = staticmethod(stop)
else:
    watchdog.print = stop
raise SystemExit(watchdog.main(['--once']))
"""
    killed = subprocess.run(
        [sys.executable, "-c", code, boundary], cwd=ROOT, env=lab.env,
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert killed.returncode == 73
    before = lab.service.history("signed-session", OPERATOR)
    assert len(before) == (1 if boundary == "before_append" else 2)
    summary = output(run_once(lab))
    assert summary["changed"] == (1 if boundary == "before_append" else 0)
    after = lab.service.history("signed-session", OPERATOR)
    assert len(after) == 2 and after[-1].version == 2 and after[-1].status == "REVOKED"
    assert http_access(lab, "signed-session", initial.grant_token).status_code == 403


def test_broken_registry_once_fails_closed_then_restored_registry_allows_revalidation(lab):
    initial = lab.session(expires_in=-2)
    lab.registry_path.write_text("malformed-private-marker", encoding="utf-8")
    failed = run_once(lab)
    assert failed.returncode == 1 and not failed.stdout
    assert json.loads(failed.stderr) == {
        "watchdog": "unavailable", "error": "SIGNAL_REGISTRY_UNAVAILABLE",
    }
    assert "malformed-private-marker" not in failed.stderr
    assert lab.service.history("signed-session", OPERATOR)[-1] == initial.session
    lab.save()
    restored = output(run_once(lab))
    assert restored["held"] == restored["changed"] == 1


def test_polling_process_recovers_registry_failure_and_stops_gracefully(lab):
    lab.session(expires_in=-2)
    lab.registry_path.write_text("malformed-registry", encoding="utf-8")
    stdout_path, stderr_path = lab.directory / "watchdog.stdout", lab.directory / "watchdog.stderr"
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        process = subprocess.Popen(
            [sys.executable, "-m", "scripts.session_watchdog", "--interval-seconds", "0.05"],
            cwd=ROOT, env=lab.env, stdout=stdout, stderr=stderr,
        )
        try:
            wait_until(lambda: "SIGNAL_REGISTRY_UNAVAILABLE" in stderr_path.read_text())
            lab.save()
            wait_until(lambda: lab.service.history("signed-session", OPERATOR)[-1].status == "HELD")
            # Windows Popen.terminate uses TerminateProcess, not a Python SIGTERM
            # handler. Recovery is exercised there; graceful SIGTERM is POSIX-only.
            if os.name == "nt":
                process.kill()
            else:
                process.terminate()
            process.wait(timeout=10)
            if os.name != "nt":
                assert process.returncode == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    assert "revalidated" in stdout_path.read_text()
    assert len(lab.service.history("signed-session", OPERATOR)) == 2
    assert "watchdog-user" not in stdout_path.read_text() + stderr_path.read_text()


@pytest.mark.parametrize("interval", ["nan", "inf", "0", "0.001", "60.1"])
def test_cli_rejects_invalid_intervals(lab, interval):
    result = run_once(lab, "--interval-seconds", interval)
    assert result.returncode == 2 and not result.stdout


def test_production_is_rejected_before_any_session_database_is_created(tmp_path):
    path = tmp_path / "production.sqlite3"
    with pytest.raises(ValueError):
        build_service(SimpleNamespace(app_environment="production", zero_trust_db_path=path))
    environment = os.environ | {
        "APP_ENVIRONMENT": "production", "AUTH_MODE": "api_key", "API_KEY_SHA256": "a" * 64,
        "ZERO_TRUST_DB_PATH": str(path),
    }
    result = subprocess.run(
        [sys.executable, "-m", "scripts.session_watchdog", "--once"],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 1 and not path.exists()
    assert json.loads(result.stderr)["watchdog"] == "unavailable"
