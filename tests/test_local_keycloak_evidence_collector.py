import httpx
import pytest
from jwt import InvalidTokenError

from app import security
from app.config import Settings
from scripts.local_keycloak_evidence_collector import LocalKeycloakEvidenceCollector
from scripts.local_session_analysis_lab import LocalSessionAnalysisLab


@pytest.fixture
def lab_settings(tmp_path):
    lab = LocalSessionAnalysisLab(tmp_path / "lab")
    settings = Settings(
        _env_file=None,
        app_environment="test",
        oidc_issuer="http://127.0.0.1:18080/realms/acceptance",
        oidc_audience="acceptance",
    )
    return lab, settings


def test_collector_ignores_proxy_errors_and_does_not_call_them_mfa_failures(lab_settings):
    lab, settings = lab_settings
    responses = iter(
        [
            httpx.Response(400, json={"error": "invalid_grant"}),
            httpx.Response(400, json={"error": "invalid_request"}),
            httpx.Response(503),
        ]
    )
    with httpx.Client(transport=httpx.MockTransport(lambda _: next(responses))) as client:
        collector = LocalKeycloakEvidenceCollector(lab, settings, client)
        rejected = collector.sign_in(username="local", password="fixture")
        malformed = collector.sign_in(username="local", password="fixture")
        unavailable = collector.sign_in(username="local", password="fixture")
    assert rejected.signal is not None
    assert rejected.signal.event.auth_context.authentication_result == "failure"
    assert rejected.signal.event.auth_context.mfa == "unknown"
    assert malformed.signal is None and unavailable.signal is None
    assert len(collector.attempts.closed) == 3
    assert not collector.attempts.pending


def test_collector_requires_verified_provider_token_before_recording_success(
    lab_settings, monkeypatch
):
    lab, settings = lab_settings

    def verify(token, _settings):
        if token == "wrong-subject":
            return {"preferred_username": "different-user", "tenant_id": lab.principal.tenant_id}
        if token != "verified-fixture-token":
            raise InvalidTokenError
        return {"preferred_username": "local", "tenant_id": lab.principal.tenant_id}

    monkeypatch.setattr(security, "_decode_oidc_token", verify)
    responses = iter(
        [
            httpx.Response(200, json={"id_token": "invalid", "access_token": "fixture"}),
            httpx.Response(200, json={"id_token": "wrong-subject", "access_token": "fixture"}),
            httpx.Response(
                200, json={"id_token": "verified-fixture-token", "access_token": "fixture"}
            ),
            httpx.Response(
                200, json={"id_token": "verified-fixture-token", "access_token": "fixture"}
            ),
        ]
    )
    with httpx.Client(transport=httpx.MockTransport(lambda _: next(responses))) as client:
        collector = LocalKeycloakEvidenceCollector(lab, settings, client)
        invalid = collector.sign_in(username="local", password="fixture", otp="123456")
        wrong_subject = collector.sign_in(username="local", password="fixture", otp="123456")
        missing = collector.sign_in(username="local", password="fixture")
        valid = collector.sign_in(username="local", password="fixture", otp="123456", action="READ")
    assert invalid.signal is None and wrong_subject.signal is None and missing.signal is None
    assert valid.signal is not None
    assert valid.signal.event.auth_context.mfa == "success"
    assert "verified-fixture-token" not in valid.signal.model_dump_json()
    assert valid.signal.session_id == valid.signal.event.event_id
    with pytest.raises(KeyError):
        collector.attempts.cancel(valid.signal.event.event_id)


def test_collector_will_not_issue_terminal_receipt_after_exchange_starts(lab_settings):
    lab, settings = lab_settings

    def disconnect(_):
        raise httpx.ReadTimeout("simulated incomplete exchange")

    with httpx.Client(transport=httpx.MockTransport(disconnect)) as client:
        collector = LocalKeycloakEvidenceCollector(lab, settings, client)
        with pytest.raises(httpx.ReadTimeout):
            collector.sign_in(username="local", password="fixture")
        assert len(collector.attempts.closed) == 1
        event_id = next(iter(collector.attempts.closed))
        with pytest.raises(KeyError):
            collector.attempts.cancel(event_id)
        with pytest.raises(KeyError):
            collector.probe_readiness(event_id)


def test_otp_binding_matches_verified_identity_and_the_exact_token(lab_settings):
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta

    from app.security import Principal, Role
    from scripts.local_keycloak_evidence_collector import LocalOTPBinding

    lab, _ = lab_settings
    expires = (datetime.now(UTC) + timedelta(minutes=2)).replace(microsecond=0)
    claims = {"sub": "fixture-identity", "sid": "fixture-session", "exp": expires.timestamp()}
    binding = LocalOTPBinding.from_verified_claims(claims, "fixture-original-token", lab.principal.tenant_id)
    principal = Principal(
        claims["sub"], lab.principal.tenant_id, frozenset({Role.ANALYST}), "oidc", expires, claims["sid"]
    )
    assert binding.matches(principal, "fixture-original-token")
    assert not binding.matches(principal, "fixture-refreshed-token")
    assert not binding.matches(replace(principal, oidc_session_id="other"), "fixture-original-token")
    assert not binding.matches(replace(principal, tenant_id="other"), "fixture-original-token")
    assert LocalOTPBinding.from_verified_claims(
        {**claims, "exp": True}, "fixture-original-token", lab.principal.tenant_id
    ) is None
