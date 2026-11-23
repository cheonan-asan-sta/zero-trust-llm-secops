"""Guard the automatic fallback at the analysis audit persistence boundary."""

import hashlib
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
from app.services.trusted_signals import LoginEvidenceExpired, SignalVerifier
from app.zero_trust_models import SignedLoginEvidence
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector


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
