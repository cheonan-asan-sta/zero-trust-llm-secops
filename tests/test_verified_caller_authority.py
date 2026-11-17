"""Actual API identity resolution, local revocation mid-review, no paid provider."""

import asyncio
import hashlib
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from openai import AsyncOpenAI
from pydantic import SecretStr
from starlette.requests import Request

from app import main, security
from app.analyzers.evidence_agent import EvidenceReviewAgent
from app.config import Settings
from app.models import SecurityAssessment
from app.services.audit import AuditStore
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab
from tests.test_structured_response import envelope


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.mark.parametrize("change", ["role", "tenant", "subject", "key", "mode"])
def test_request_local_revalidator_rejects_changed_legacy_authority_without_raw_key(
    change, monkeypatch
):
    key = "local-only-ephemeral-caller-test-key"
    config = Settings(
        _env_file=None,
        auth_mode="api_key",
        api_key_sha256=sha(key),
        api_key_subject="local-operator",
        api_key_tenant_id="local-lab",
        api_key_roles="analyst",
    )
    monkeypatch.setattr(security, "get_settings", lambda: config)
    request = Request({"type": "http", "headers": []})
    principal = asyncio.run(security.get_principal(request, None, key))
    check = request.state.authentication_revalidator
    check()
    assert key not in repr(principal)
    # The callback captures the digest and identity, never the plaintext API key.
    assert all(cell.cell_contents != key for cell in check.__closure__)
    field, value = {
        "role": ("api_key_roles", "viewer"),
        "tenant": ("api_key_tenant_id", "other-tenant"),
        "subject": ("api_key_subject", "other-operator"),
        "key": ("api_key_sha256", SecretStr(sha("rotated-local-only-key"))),
        "mode": ("auth_mode", "oidc"),
    }[change]
    config = config.model_copy(update={field: value})
    with pytest.raises(HTTPException) as rejected:
        check()
    assert rejected.value.status_code == 401


@pytest.fixture(params=["/analysis/verified-session", "/analysis/evidence-review"])
def verified_api_key_route(tmp_path, monkeypatch, request):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("account registry requires the existing POSIX no-follow file contract")
    lab = LocalSessionAnalysisLab(tmp_path / "authority")
    signal, _ = lab.create(next(s for s in SCENARIOS if s[0] == "permitted_team"))
    key = "local-only-ephemeral-account-key"
    account = {
        "sha256": sha(key),
        "subject": lab.principal.subject,
        "tenant_id": lab.principal.tenant_id,
        "roles": ["analyst"],
        "enabled": True,
    }
    path = tmp_path / "accounts.json"

    def save(value=account):
        path.write_text(json.dumps({"schema": "api-key-accounts-1", "accounts": [value]}))

    save()
    settings = Settings(
        _env_file=None,
        app_environment="test",
        auth_mode="api_key",
        api_key_sha256=sha("different-local-only-root-key"),
        api_key_accounts_path=path,
        openai_prompt_mode="grounded",
        analyzer_mode="openai",
        openai_evidence_agent_enabled=True,
    )
    assessment = SecurityAssessment(
        risk_score=10,
        risk_level="LOW",
        violation_type="NORMAL",
        rationale="Free caller authority boundary test",
        recommended_action="HOLD_FOR_REVIEW",
        confidence=0.8,
        evidence=["verified_session.policy.role_permitted"],
        requires_human_review=True,
    )
    analyzer = Mock()
    analyzer.name = "openai"
    analyzer.analyze_with_evidence = AsyncMock(return_value=assessment)

    class LocalNoPaidAgent:
        async def review(self, event, context, history_getter):
            result = await analyzer.analyze_with_evidence(event, context)
            return (
                result,
                context,
                {"mode": "explicit_test_double_no_paid_provider", "provider_calls": 0},
            )

    audit = AuditStore(tmp_path / "audit.jsonl")
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "zero_trust_operations", lab.service)
    monkeypatch.setattr(main, "get_analyzer", lambda: analyzer)
    monkeypatch.setattr(main, "get_evidence_agent", LocalNoPaidAgent)
    monkeypatch.setattr(main, "audit_store", audit)
    assert security.get_principal not in main.app.dependency_overrides
    with TestClient(main.app) as client:
        yield SimpleNamespace(
            client=client,
            route=request.param,
            signal=signal,
            key=key,
            account=account,
            path=path,
            save=save,
            analyzer=analyzer,
            audit=audit,
            lab=lab,
            settings=settings,
        )


@pytest.mark.parametrize("change", ["disabled", "role", "tenant", "subject", "malformed"])
def test_authority_changed_during_review_cannot_publish_or_audit(verified_api_key_route, change):
    env = verified_api_key_route
    original = env.analyzer.analyze_with_evidence.return_value
    journal = env.lab.service.analysis_history(env.signal.session_id, env.lab.principal)

    async def change_authority(event, context):
        if change == "malformed":
            env.path.write_text('{"partial":')
        else:
            field, value = {
                "disabled": ("enabled", False),
                "role": ("roles", ["viewer"]),
                "tenant": ("tenant_id", "other-tenant"),
                "subject": ("subject", "other-operator"),
            }[change]
            env.save(env.account | {field: value})
        return original

    env.analyzer.analyze_with_evidence.side_effect = change_authority
    response = env.client.post(
        env.route, json=env.signal.model_dump(mode="json"), headers={"X-API-Key": env.key}
    )
    assert response.status_code == 502
    assert env.analyzer.analyze_with_evidence.await_count == 1
    assert env.audit.metrics("local-lab").total_analyses == 0
    assert env.audit.get(env.signal.event.event_id, "local-lab") is None
    assert env.lab.service.analysis_history(env.signal.session_id, env.lab.principal) == journal
    assert env.key not in response.text and sha(env.key) not in response.text


def test_semantically_unchanged_registry_and_new_request_recover(verified_api_key_route):
    env = verified_api_key_route
    original = env.analyzer.analyze_with_evidence.return_value

    async def rewrite_unchanged(event, context):
        env.path.write_text(
            json.dumps({"accounts": [env.account], "schema": "api-key-accounts-1"}, indent=2)
        )
        return original

    env.analyzer.analyze_with_evidence.side_effect = rewrite_unchanged
    response = env.client.post(
        env.route, json=env.signal.model_dump(mode="json"), headers={"X-API-Key": env.key}
    )
    assert response.status_code == 200
    assert env.audit.get(env.signal.event.event_id, "local-lab") is not None
    env.save(env.account | {"enabled": False})
    calls = env.analyzer.analyze_with_evidence.await_count
    denied = env.client.post(
        env.route, json=env.signal.model_dump(mode="json"), headers={"X-API-Key": env.key}
    )
    assert denied.status_code == 401 and env.analyzer.analyze_with_evidence.await_count == calls


def test_revocation_after_audit_commit_refuses_delivery_but_preserves_committed_history(
    verified_api_key_route, monkeypatch
):
    env = verified_api_key_route
    save = env.audit.save

    async def commit_then_withdraw(record):
        await save(record)
        env.save(env.account | {"enabled": False})

    monkeypatch.setattr(env.audit, "save", commit_then_withdraw)
    response = env.client.post(
        env.route, json=env.signal.model_dump(mode="json"), headers={"X-API-Key": env.key}
    )
    assert response.status_code == 502
    # A committed analysis is historical evidence, not proof HTTP was delivered.
    # Never erase/rewrite the chain to make it look as if the analysis did not occur.
    assert env.audit.get(env.signal.event.event_id, "local-lab") is not None
    restored = AuditStore(env.audit._path)
    assert restored.integrity()["ok"] and restored.metrics("local-lab").total_analyses == 1
    assert restored.get(env.signal.event.event_id, "local-lab") is not None


@pytest.mark.parametrize("verified_api_key_route", ["/analysis/evidence-review"], indirect=True)
def test_revocation_in_tool_round_stops_before_history_read_or_second_provider_request(
    verified_api_key_route, monkeypatch
):
    env = verified_api_key_route
    history = Mock(wraps=env.lab.service.analysis_history)
    monkeypatch.setattr(env.lab.service, "analysis_history", history)
    received, history_at_response = [], []

    async def transport(request):
        received.append(json.loads(request.content))
        assert len(received) == 1, "revoked caller reached a second provider request"
        history_at_response.append(history.call_count)
        env.save(env.account | {"enabled": False})
        return httpx.Response(
            200,
            json=envelope(
                output=[
                    {
                        "type": "function_call",
                        "name": "read_current_session_history",
                        "arguments": "{}",
                        "call_id": "local-call",
                        "id": "local-function",
                        "status": "completed",
                    }
                ]
            ),
        )

    provider = AsyncOpenAI(
        api_key="local-test-placeholder",
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(transport)),
    )
    agent = EvidenceReviewAgent(env.settings, client=provider)
    monkeypatch.setattr(main, "get_evidence_agent", lambda: agent)
    try:
        response = env.client.post(
            env.route, json=env.signal.model_dump(mode="json"), headers={"X-API-Key": env.key}
        )
    finally:
        env.client.portal.call(agent.close)
    assert response.status_code == 502 and len(received) == 1
    assert history.call_count == history_at_response[0]
    assert env.audit.get(env.signal.event.event_id, "local-lab") is None
