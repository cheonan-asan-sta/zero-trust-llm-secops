"""Guard the automatic fallback at the analysis audit persistence boundary."""

import hashlib
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main, security
from app.config import Settings
from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.services.audit import AuditStore
from app.services.login_delivery import LoginDeliveryIdentity, lock_login_delivery
from app.services.sqlite_audit import SQLiteAuditStore
from app.services.trusted_signals import LoginEvidenceExpired, SignalVerifier
from app.zero_trust_models import LoginDeliveryRequest, SignedLoginEvidence
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector
from scripts.login_delivery_spool import LoginDeliverySpool


@pytest.fixture
def observed_login():
    payload = synthetic_events()[0].analysis_payload()
    payload["action"] = "LOGIN"
    payload["timestamp"] = datetime.now(UTC)
    event = SecurityEvent.model_validate(payload)
    proof = SignedLoginEvidence(
        tenant_id="local", source_id="local-login", key_id="local-key",
        event_digest_sha256="1" * 64, device_state="revoked_verified_device",
        issued_at=event.timestamp, expires_at=event.timestamp + timedelta(seconds=30),
        signature="A" * 86,
    )
    return event, proof


def collector(client):
    # Only the delivery stage runs in these tests. Integration coverage mints real receipts.
    return KeycloakLoginAnalysisCollector(
        client, settings=None, authority=None, registry=None, gateway_id="local",
        source_id="local-login", key_id="local-key", signing_key=None,
    )


@pytest.mark.parametrize("expires_after_write", [False, True])
def test_expiry_fallback_preserves_one_result_across_commit_boundary(
    expires_after_write, observed_login, tmp_path, monkeypatch,
):
    event, proof = observed_login
    api_key = "test-login-delivery-key"
    settings = Settings(
        _env_file=None, app_environment="test", auth_mode="api_key", analyzer_mode="rule",
        api_key_sha256=hashlib.sha256(api_key.encode()).hexdigest(),
    )
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    audit = AuditStore(tmp_path / "audit.jsonl")
    monkeypatch.setattr(main, "audit_store", audit)
    expiry = False

    def check(*_):
        if expiry:
            raise LoginEvidenceExpired("simulated expiry at the audit boundary")
        return "2" * 64

    monkeypatch.setattr(SignalVerifier, "verify_login_evidence", check)
    if expires_after_write:
        save = audit.save

        async def save_then_expire(result):
            nonlocal expiry
            await save(result)
            expiry = True

        monkeypatch.setattr(audit, "save", save_then_expire)
    else:
        analyze = main.RuleBasedAnalyzer.analyze

        async def analyze_then_expire(self, observed):
            nonlocal expiry
            result = await analyze(self, observed)
            expiry = True
            return result

        monkeypatch.setattr(main.RuleBasedAnalyzer, "analyze", analyze_then_expire)

    with TestClient(
        main.app, base_url="http://127.0.0.1", headers={"X-API-Key": api_key},
    ) as client:
        if expires_after_write:
            with pytest.raises(httpx.HTTPStatusError) as failed:
                collector(client).submit(event, proof)
            assert failed.value.response.status_code == 401
        else:
            delivered = collector(client).submit(event, proof)
            assert delivered.evidence_state == "expired"
            assert delivered.response.status_code == 200
    assert audit.integrity()["verified_lines"] == 1
    assert (audit.get(event.event_id).verified_login_detection is not None) == expires_after_write


@pytest.mark.parametrize("status", [307, 401, 410, 429, 503, None])
def test_unconfirmed_failure_is_never_retried_as_baseline(status, observed_login):
    event, proof = observed_login
    request_handler = (
        Mock(side_effect=httpx.ReadTimeout("ambiguous write result")) if status is None
        else Mock(return_value=httpx.Response(status, json={"detail": "not receipt expiry"}))
    )
    with httpx.Client(
        base_url="http://127.0.0.1", transport=httpx.MockTransport(request_handler),
    ) as client:
        error = httpx.ReadTimeout if status is None else httpx.HTTPStatusError
        with pytest.raises(error):
            collector(client).submit(event, proof)
    request_handler.assert_called_once()
    assert request_handler.call_args.args[0].url.path == "/analysis/verified-login"


def test_committed_login_replay_reopens_audit_without_analyzing_twice(observed_login, tmp_path, monkeypatch):
    event, _ = observed_login
    api_key = "test-durable-login-api-key"
    settings = Settings(
        _env_file=None, app_environment="test", auth_mode="api_key", analyzer_mode="rule",
        api_key_sha256=hashlib.sha256(api_key.encode()).hexdigest(),
    )
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    monkeypatch.setattr(main, "audit_store", store)
    runs = 0
    analyze = main.RuleBasedAnalyzer.analyze

    async def count(analyzer, observed):
        nonlocal runs
        runs += 1
        return await analyze(analyzer, observed)

    monkeypatch.setattr(main.RuleBasedAnalyzer, "analyze", count)
    body = LoginDeliveryRequest(event=event, tenant_id="local", collector_subject="service-client")
    payload = body.model_dump(mode="json")
    with TestClient(main.app, headers={"X-API-Key": api_key}) as api:
        initial = api.post("/analysis/login-delivery", json=payload)
        assert initial.status_code == 200, initial.text
        assert initial.json()["duplicate"] is False
        reopened = SQLiteAuditStore(store.path)
        monkeypatch.setattr(main, "audit_store", reopened)
        repeated = api.post("/analysis/login-delivery", json=payload)
        assert repeated.json() == {**initial.json(), "duplicate": True}
        assert api.post("/analysis/login-delivery", json={**payload, "tenant_id": "other"}).status_code == 403
        assert api.post("/analysis/login-delivery", json={**payload, "collector_subject": "other"}).status_code == 403
        changed = payload["event"]["network"]
        changed["location"] = "different-location"
        assert api.post("/analysis/login-delivery", json=payload).status_code == 409
    assert reopened.integrity()["verified_lines"] == runs == 1


def test_spool_survives_abrupt_process_exit(observed_login, tmp_path):
    event, proof = observed_login
    body = LoginDeliveryRequest(event=event, evidence=proof, tenant_id="local", collector_subject="service-client")
    path = tmp_path / "pending.sqlite3"
    program = (
        "import os, sys; "
        "from scripts.login_delivery_spool import LoginDeliverySpool, LoginDeliveryRequest; "
        "queue = LoginDeliverySpool(sys.argv[1], origin='http://127.0.0.1/', "
        "tenant_id='local', collector_subject='service-client'); "
        "queue.enqueue(LoginDeliveryRequest.model_validate_json(sys.stdin.buffer.read())); os._exit(0)"
    )
    subprocess.run([sys.executable, "-c", program, str(path)], input=body.model_dump_json().encode(),
                   check=True, timeout=20)
    queue = LoginDeliverySpool(path, origin="http://127.0.0.1/", tenant_id="local", collector_subject="service-client")
    assert queue.counts() == {"pending": 1, "held": 0}
    assert queue.peek() == body


def test_same_login_lock_is_shared_across_api_processes(observed_login, tmp_path):
    event, _ = observed_login
    body = LoginDeliveryRequest(event=event, tenant_id="local", collector_subject="service-client")
    identity = LoginDeliveryIdentity.from_request(body)
    path = tmp_path / "audit.sqlite3"
    program = """
import sys
from pathlib import Path
from app.services.login_delivery import LoginDeliveryBusy, LoginDeliveryIdentity, lock_login_delivery
try:
    with lock_login_delivery(Path(sys.argv[1]), LoginDeliveryIdentity(sys.argv[2], '')):
        print('acquired')
except LoginDeliveryBusy:
    print('busy')
"""

    def child():
        return subprocess.check_output([sys.executable, "-c", program, str(path), identity.analysis_id], timeout=20).strip()

    with lock_login_delivery(path, identity):
        assert child() == b"busy"
    assert child() == b"acquired"
