"""Guard the automatic fallback at the analysis audit persistence boundary."""

import base64
import hashlib
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app import main, security
from app.config import Settings
from app.models import RecommendedAction, SecurityEvent
from app.scenarios import synthetic_events
from app.services.audit import AuditStore
from app.services.login_delivery import LoginDeliveryIdentity, lock_login_delivery
from app.services.session_analysis_evidence import event_digest
from app.services.sqlite_audit import SQLiteAuditStore
from app.services.trusted_signals import (
    LoginEvidenceExpired,
    SignalVerifier,
    canonical_login_evidence,
)
from app.zero_trust_models import LoginDeliveryRequest, SignedLoginEvidence
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector
from scripts.login_delivery_spool import LoginDeliverySpool, LoginRetryPolicy


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


@pytest.fixture
def delayed_login_api(observed_login, tmp_path, monkeypatch):
    event, proof = observed_login
    registry = tmp_path / "sources.json"
    key = "fixture-delayed-login"
    settings = Settings(
        _env_file=None, app_environment="test", auth_mode="api_key", analyzer_mode="rule",
        api_key_sha256=hashlib.sha256(key.encode()).hexdigest(), trusted_signal_sources_path=registry,
    )
    audit = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "audit_store", audit)
    signer = Ed25519PrivateKey.generate()

    def signed_body(case):
        now = datetime.now(UTC)
        issued = now - timedelta(seconds=3650 if case == "outside_window" else 45)
        values = event.analysis_payload()
        values["timestamp"] = issued
        values["auth_context"].update(authentication_result="success", mfa="success", failed_attempts=0)
        values["network"]["location_anomaly"] = case != "no_anomaly"
        login = SecurityEvent.model_validate(values)
        expires = issued + timedelta(seconds=30)
        source = {
            "source_id": proof.source_id, "tenant_id": "local", "enabled": case != "disabled_source",
            "user_ids": [login.user.user_id], "device_ids": [login.device.device_id], "roles": [login.user.role],
            "login_evidence_resource_ids": [login.resource.resource_id],
            "keys": [{
                "key_id": proof.key_id, "enabled": case != "disabled_key",
                "public_key_pem": signer.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode(),
                "not_before": (issued - timedelta(seconds=1)).isoformat(),
                "not_after": (expires if case == "expired_key" else now + timedelta(minutes=5)).isoformat(),
            }],
        }
        registry.write_text(json.dumps({"sources": [source]}), encoding="utf-8")
        signed = proof.model_copy(update={
            "event_digest_sha256": event_digest(login), "issued_at": issued, "expires_at": expires,
            "device_state": "known" if case == "known_device" else "revoked_verified_device",
        })
        signature = base64.urlsafe_b64encode(signer.sign(canonical_login_evidence(signed))).decode().rstrip("=")
        signed = signed.model_copy(update={"signature": signature if case != "tampered" else "A" * 86})
        if case == "wrong_event":
            login = login.model_copy(update={"event_id": "different-event"})
        return LoginDeliveryRequest(event=login, evidence=signed, tenant_id="local", collector_subject="service-client")

    with TestClient(main.app, headers={"X-API-Key": key}) as api:
        yield api, audit, registry, signed_body


@pytest.mark.parametrize("case,expected", [
    ("delayed_threat", 200), ("known_device", 200), ("no_anomaly", 200), ("outside_window", 200),
    ("tampered", 401), ("wrong_event", 401), ("disabled_source", 401), ("disabled_key", 401), ("expired_key", 401),
])
def test_expired_login_can_only_add_a_bounded_historical_review(delayed_login_api, case, expected):
    api, audit, _, signed_body = delayed_login_api
    body = signed_body(case)
    payload = body.model_dump(mode="json")
    live_path = "/analysis/verified-login"
    verified_payload = {name: payload[name] for name in ("event", "evidence")}
    assert api.post(live_path, json=verified_payload).status_code == 401
    assert api.post(live_path + "?report_expiry=true", json=verified_payload).status_code == (
        410 if expected == 200 else 401
    )
    response = api.post("/analysis/login-delivery", json=payload)
    assert response.status_code == expected, response.text
    if expected == 401:
        assert audit.integrity()["verified_lines"] == 0
        return
    receipt = response.json()
    assert receipt["evidence_state"] == "expired" and receipt["duplicate"] is False
    result = receipt["result"]
    assert "verified_login_detection" not in result and "verification_context" not in result
    historical = result.get("delayed_login_review")
    if case == "delayed_threat":
        assert historical["reason"] == "expired_revoked_device_observation"
        assert result["policy_decision"]["requires_human_review"]
        assert result["policy_decision"]["action"] == RecommendedAction.HOLD_FOR_REVIEW
        assert "인증 근거가 만료" in result["policy_decision"]["reason"]
    else:
        assert historical is None
        assert not result["policy_decision"]["requires_human_review"]
    assert api.post("/analysis/login-delivery", json=payload).json() == {**receipt, "duplicate": True}
    assert audit.integrity()["verified_lines"] == 1


def test_delayed_login_source_withdrawal_stops_audit_commit(delayed_login_api, monkeypatch):
    api, audit, registry, signed_body = delayed_login_api
    body = signed_body("delayed_threat")
    analyze = main.RuleBasedAnalyzer.analyze

    async def withdraw_source(analyzer, event):
        result = await analyze(analyzer, event)
        registry.write_text('{"sources":[]}', encoding="utf-8")
        return result

    monkeypatch.setattr(main.RuleBasedAnalyzer, "analyze", withdraw_source)
    response = api.post("/analysis/login-delivery", json=body.model_dump(mode="json"))
    assert response.status_code == 401
    assert audit.integrity()["verified_lines"] == 0


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
from app.services.login_delivery import LoginDeliveryBusy, lock_login_delivery
try:
    with lock_login_delivery(Path(sys.argv[1]), sys.argv[2]):
        print('acquired')
except LoginDeliveryBusy:
    print('busy')
"""

    def child():
        return subprocess.check_output([sys.executable, "-c", program, str(path), identity.analysis_id], timeout=20).strip()

    with lock_login_delivery(path, identity.analysis_id):
        assert child() == b"busy"
    assert child() == b"acquired"


def test_old_queue_keeps_pending_and_held_envelopes_during_upgrade(observed_login, tmp_path):
    event, proof = observed_login
    first = LoginDeliveryRequest(event=event, evidence=proof, tenant_id="local", collector_subject="service-client")
    second = first.model_copy(update={"event": event.model_copy(update={"event_id": "previously-held"})})
    path = tmp_path / "legacy.sqlite3"
    origin = "http://127.0.0.1/"
    with closing(sqlite3.connect(path)) as con, con:
        con.executescript(
            "CREATE TABLE login_queue_binding (id INTEGER PRIMARY KEY, binding TEXT NOT NULL);"
            "CREATE TABLE login_queue (seq INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,"
            "payload TEXT NOT NULL,payload_sha256 TEXT NOT NULL,held_status INTEGER);"
        )
        con.execute("INSERT INTO login_queue_binding VALUES (1,?)", (json.dumps([origin, "local", "service-client"]),))
        for body, held in ((first, None), (second, 403)):
            con.execute("INSERT INTO login_queue(event_id,payload,payload_sha256,held_status) VALUES (?,?,?,?)",
                        (body.event.event_id, body.model_dump_json(), LoginDeliveryIdentity.from_request(body).payload_sha256, held))

    for _ in range(2):
        queue = LoginDeliverySpool(path, origin=origin, tenant_id="local", collector_subject="service-client")
        assert queue.counts() == {"pending": 1, "held": 1}
        assert queue.peek() == first
        assert queue.held()[0]["failure_code"] == "http_403"
    cli = [sys.executable, "-m", "scripts.login_delivery_spool", str(path), "--origin", origin,
           "--tenant-id", "local", "--collector-subject", "service-client"]
    assert json.loads(subprocess.check_output([*cli, "status"], timeout=20))["held"] == 1
    held = json.loads(subprocess.check_output([*cli, "held"], timeout=20))
    assert held[0]["event_id"] == second.event.event_id and held[0]["http_status"] == 403
    assert json.loads(subprocess.check_output([*cli, "requeue", second.event.event_id], timeout=20)) == {
        "requeued": second.event.event_id,
    }
    assert not queue.requeue(second.event.event_id)
    queue.acknowledge(first, now=0, policy=LoginRetryPolicy(success_interval=0))
    assert queue.peek() == second


def test_invalid_receipt_waits_without_blocking_other_ready_logins(observed_login, tmp_path):
    event, _ = observed_login
    now = 100.0
    posted = []

    def exchange(request):
        event_id = json.loads(request.content)["event"]["event_id"]
        posted.append(event_id)
        return httpx.Response(403) if event_id == "other-ready" else httpx.Response(200, json={})

    with httpx.Client(base_url="http://127.0.0.1", transport=httpx.MockTransport(exchange)) as client:
        delivery = KeycloakLoginAnalysisCollector(
            client, settings=None, authority=None, registry=None, gateway_id="local", source_id="local",
            key_id="local", signing_key=None, spool_path=tmp_path / "queue.sqlite3",
            tenant_id="local", collector_subject="service-client",
            retry_policy=LoginRetryPolicy(base_delay=2, max_attempts=2, success_interval=0), clock=lambda: now,
        )
        assert delivery.submit(event, None).evidence_state == "queued"
        with pytest.raises(httpx.HTTPStatusError):
            delivery.submit(event.model_copy(update={"event_id": "other-ready"}), None)
        assert delivery.flush_pending() == 0 and posted == [event.event_id, "other-ready"]
        now += 2
        assert delivery.flush_pending() == 0 and posted[-1] == event.event_id
        assert [(row["failure_code"], row["attempts"]) for row in delivery.spool.held()] == [
            ("receipt_invalid", 2), ("http_403", 1),
        ]
