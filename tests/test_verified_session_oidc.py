from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app import main, security
from app.config import Settings
from app.models import SecurityAssessment
from scripts.local_oidc_authority import LocalOIDCAuthority
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab


@pytest.fixture
def oidc_route(tmp_path, monkeypatch):
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
            openai_prompt_mode="grounded",
        )
        lab = LocalSessionAnalysisLab(tmp_path / "authority")
        signal, _ = lab.create(next(s for s in SCENARIOS if s[0] == "permitted_team"))
        analyzer = Mock(name="local-no-paid-provider")
        analyzer.name = "openai"
        analyzer.analyze_with_evidence = AsyncMock(
            return_value=SecurityAssessment(
                risk_score=10,
                risk_level="LOW",
                violation_type="NORMAL",
                rationale="로컬 검증 경로 시험",
                recommended_action="HOLD_FOR_REVIEW",
                confidence=0.8,
                evidence=["verified_session.policy.role_permitted"],
                requires_human_review=True,
            )
        )
        audit = Mock()
        audit.save = AsyncMock()
        monkeypatch.setattr(main, "get_settings", lambda: config)
        monkeypatch.setattr(security, "get_settings", lambda: config)
        monkeypatch.setattr(main, "zero_trust_operations", lab.service)
        monkeypatch.setattr(main, "get_analyzer", lambda: analyzer)
        monkeypatch.setattr(main, "audit_store", audit)
        assert security.get_principal not in main.app.dependency_overrides
        with TestClient(main.app) as client:
            yield authority, client, signal, analyzer, audit
        security._jwks_client.cache_clear()


def test_token_expiration_during_analysis_prevents_publishing_a_valid_provider_result(
    oidc_route, monkeypatch
):
    authority, _, _, analyzer, audit = oidc_route
    clock = {"now": datetime.now(UTC)}
    expiration = clock["now"] + timedelta(seconds=30)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"].astimezone(tz) if tz else clock["now"].replace(tzinfo=None)

    monkeypatch.setattr("app.services.session_analysis_evidence.datetime", Clock)
    assessment = analyzer.analyze_with_evidence.return_value

    async def expire(event, context):
        assert context.expires_at <= expiration
        assert "authentication_valid_until" in context.for_event(event)["caller"]
        clock["now"] = expiration + timedelta(seconds=1)
        return assessment

    analyzer.analyze_with_evidence.side_effect = expire
    response = post(oidc_route, authority.issue(exp=expiration))
    assert response.status_code == 502
    analyzer.analyze_with_evidence.assert_awaited_once()
    audit.save.assert_not_awaited()


def test_fractional_numericdate_remains_exact_verified_expiration(oidc_route):
    authority, _, _, _, _ = oidc_route
    expiration = datetime.now(UTC).timestamp() + 120.125
    response = post(oidc_route, authority.issue(exp=expiration))
    assert response.status_code == 200
    value = response.json()["verification_context"]["caller"]["authentication_valid_until"]
    assert datetime.fromisoformat(value).timestamp() == pytest.approx(expiration, abs=0.000002)


def test_128_character_subject_is_not_truncated_or_rejected_as_invalid(oidc_route):
    authority, _, _, analyzer, audit = oidc_route
    response = post(oidc_route, authority.issue(sub="s" * 128))
    assert response.status_code == 409  # Authenticated, but not the session's exact operator.
    analyzer.analyze_with_evidence.assert_not_awaited()
    audit.save.assert_not_awaited()


def post(fixture, token):
    _, client, signal, _, _ = fixture
    return client.post(
        "/analysis/verified-session",
        json=signal.model_dump(mode="json"),
        headers={"Authorization": "Bearer " + token} if token else {},
    )


def test_real_loopback_jwks_and_bearer_reach_verified_analysis(oidc_route):
    authority, _, _, analyzer, audit = oidc_route
    response = post(oidc_route, authority.issue())
    assert response.status_code == 200
    assert authority.fetches >= 1
    analyzer.analyze_with_evidence.assert_awaited_once()
    audit.save.assert_awaited_once()
    assert response.json()["verification_context"]["external_enterprise_identity_verified"] is False
    assert response.json()["verification_context"]["caller"]["authentication_method"] == "oidc"
    assert (
        response.json()["verification_context"]["caller"][
            "event_subject_mfa_independently_verified"
        ]
        is False
    )


@pytest.mark.parametrize(
    "mode",
    [
        "missing",
        "expired",
        "audience",
        "issuer",
        "future",
        "viewer",
        "no_role",
        "foreign_tenant",
        "foreign_operator",
        "invalid_subject",
        "null_tenant",
        "tampered",
        "long_subject",
        "string_expiration",
        "infinite_expiration",
    ],
)
def test_bad_bearer_cannot_call_llm_or_write_success_audit(oidc_route, mode):
    authority, _, _, analyzer, audit = oidc_route
    now = datetime.now(UTC)
    changes = {
        "expired": {"exp": now - timedelta(seconds=30)},
        "audience": {"aud": "wrong-audience"},
        "issuer": {"iss": "https://other.invalid"},
        "future": {"nbf": now + timedelta(minutes=2)},
        "viewer": {"roles": ["viewer"]},
        "no_role": {"roles": []},
        "foreign_tenant": {"tenant_id": "different-tenant"},
        "foreign_operator": {"sub": "other-operator"},
        "invalid_subject": {"sub": None},
        "null_tenant": {"tenant_id": None},
        "long_subject": {"sub": "x" * 129},
        "string_expiration": {"exp": str(int((now + timedelta(minutes=2)).timestamp()))},
        "infinite_expiration": {"exp": float("inf")},
    }
    token = None if mode == "missing" else authority.issue(**changes.get(mode, {}))
    if mode == "tampered":
        head, payload, signature = token.split(".")
        signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        token = f"{head}.{payload}.{signature}"
    response = post(oidc_route, token)
    assert response.status_code in {400, 401, 403, 409}, response.status_code
    analyzer.analyze_with_evidence.assert_not_awaited()
    audit.save.assert_not_awaited()
