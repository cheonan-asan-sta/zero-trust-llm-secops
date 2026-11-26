"""Bound source collection before any provider call, using real local authority."""

import asyncio
import hashlib
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi.testclient import TestClient
from test_execution_analysis_evidence import execution_lab as execution_lab  # noqa: PLC0414
from test_execution_analysis_evidence import execution_route as execution_route  # noqa: PLC0414
from test_session_analysis_evidence import assessment, scenario
from test_session_analysis_evidence import lab as lab  # noqa: PLC0414

from app import main, security
from app.config import Settings
from app.services.sqlite_audit import SQLiteAuditStore


@pytest.fixture(params=["/analysis/verified-session", "/analysis/evidence-review"])
def route(lab, tmp_path, monkeypatch, request):
    key = "local-source-admission-test-placeholder"
    config = Settings(
        _env_file=None,
        app_environment="test",
        auth_mode="api_key",
        api_key_sha256=hashlib.sha256(key.encode()).hexdigest(),
        api_key_subject=lab.principal.subject,
        api_key_tenant_id=lab.principal.tenant_id,
        api_key_roles="analyst",
        analyzer_mode="openai",
        openai_prompt_mode="grounded",
        openai_evidence_agent_enabled=True,
        analysis_queue_timeout_seconds=0.01,
    )
    signal, _ = lab.create(scenario("permitted_team"))
    provider = Mock(name="free-source-admission-provider")
    provider.name = "openai"
    provider.analyze_with_evidence = AsyncMock(return_value=assessment())

    class Agent:
        async def review(self, event, context, _history):
            result = await provider.analyze_with_evidence(event, context)
            return result, context, {"provider_calls": 0, "mode": "free-test-double"}

    audit = SQLiteAuditStore(tmp_path / "source-admission.sqlite3")
    monkeypatch.setattr(main, "get_settings", lambda: config)
    monkeypatch.setattr(security, "get_settings", lambda: config)
    monkeypatch.setattr(main, "settings", config)
    monkeypatch.setattr(main, "zero_trust_operations", lab.service)
    monkeypatch.setattr(main, "audit_store", audit)
    monkeypatch.setattr(main, "get_analyzer", lambda: provider)
    monkeypatch.setattr(main, "get_evidence_agent", Agent)
    monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(1))
    with TestClient(main.app) as client:
        yield SimpleNamespace(
            client=client,
            url=request.param,
            signal=signal,
            lab=lab,
            audit=audit,
            provider=provider,
            headers={"X-API-Key": key},
            body=signal.model_dump(mode="json"),
        )


def test_saturated_route_does_not_collect_source_evidence(route, monkeypatch):
    collect = Mock(wraps=main.collect_session_evidence)
    monkeypatch.setattr(main, "collect_session_evidence", collect)
    monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(0))
    response = route.client.post(route.url, json=route.body, headers=route.headers)
    assert response.status_code == 429
    collect.assert_not_called()
    route.provider.analyze_with_evidence.assert_not_awaited()
    assert route.audit.metrics(route.lab.principal.tenant_id).total_analyses == 0


def test_cancelled_source_collection_keeps_slot_without_blocking_loop(route, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    capacity = main.analysis_capacity
    original = main.collect_session_evidence
    calls = 0

    def blocked(*args, **kwargs):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(main, "collect_session_evidence", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:

            async def post():
                return await client.post(route.url, json=route.body, headers=route.headers)

            task = asyncio.create_task(post())
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert not task.done()
                assert (await client.get("/health/live")).status_code == 200
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and capacity._value == 0
                assert (await post()).status_code == 429 and calls == 1
                route.provider.analyze_with_evidence.assert_not_awaited()
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert capacity._value == 1
            assert route.audit.metrics(route.lab.principal.tenant_id).total_analyses == 0
            assert (await post()).status_code == 200
            assert route.provider.analyze_with_evidence.await_count == 1
            assert route.audit.metrics(route.lab.principal.tenant_id).total_analyses == 1

    asyncio.run(run())


def test_serving_store_replaced_during_initial_collection_never_calls_provider(route, monkeypatch):
    original = main.collect_session_evidence

    def swapped(*args, **kwargs):
        context = original(*args, **kwargs)
        monkeypatch.setattr(main, "zero_trust_operations", object())
        return context

    monkeypatch.setattr(main, "collect_session_evidence", swapped)
    response = route.client.post(route.url, json=route.body, headers=route.headers)
    assert response.status_code == 401
    route.provider.analyze_with_evidence.assert_not_awaited()
    assert route.audit.metrics(route.lab.principal.tenant_id).total_analyses == 0
    assert main.analysis_capacity._value == 1


def test_source_withdrawn_while_queued_is_rejected_before_collection_completes(route, monkeypatch):
    async def acquire():
        route.lab.registry["sources"][0]["enabled"] = False
        route.lab.save_registry()
        return True

    gate = SimpleNamespace(acquire=acquire, release=Mock())
    monkeypatch.setattr(main, "analysis_capacity", gate)
    response = route.client.post(route.url, json=route.body, headers=route.headers)
    assert response.status_code == 401
    route.provider.analyze_with_evidence.assert_not_awaited()
    assert route.audit.metrics(route.lab.principal.tenant_id).total_analyses == 0
    gate.release.assert_called_once()


@pytest.mark.parametrize("store", ["zero_trust_operations", "behavior_context_service"])
def test_execution_capture_store_swap_during_collection_blocks_provider(
    execution_route, monkeypatch, store
):
    lab, target, client, analyzer, audit = execution_route
    signal = lab.signals[target.session.session.session_id]
    original = main.collect_session_execution_evidence

    def changed(*args, **kwargs):
        context = original(*args, **kwargs)
        monkeypatch.setattr(main, store, object())
        return context

    monkeypatch.setattr(main, "collect_session_execution_evidence", changed)
    response = client.post(
        "/analysis/verified-session",
        params={"behavior_capture_id": target.id},
        json=signal.model_dump(mode="json"),
    )
    assert response.status_code == 401
    analyzer.analyze_with_evidence.assert_not_awaited()
    audit.save.assert_not_awaited()
