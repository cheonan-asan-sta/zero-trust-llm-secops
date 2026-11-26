"""Bounded cached provider initialization, without paid provider requests."""

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_session_analysis_evidence import assessment, scenario
from test_session_analysis_evidence import lab as lab  # noqa: PLC0414

from app import main
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.scenarios import synthetic_events


@pytest.mark.parametrize("batch", [False, True])
def test_cached_provider_setup_does_not_block_http_liveness(api, monkeypatch, batch):
    entered, heartbeat, missed = threading.Event(), threading.Event(), threading.Event()

    def get():
        entered.set()
        if not heartbeat.wait(1):
            missed.set()
        return RuleBasedAnalyzer()

    monkeypatch.setattr(main, "get_analyzer", get)

    async def run():
        event = synthetic_events()[0].model_dump(mode="json")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.post(
                    "/analysis/batch" if batch else "/analysis",
                    headers=api.headers,
                    json={"events": [event]} if batch else event,
                )
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert (await client.get("/health/live")).status_code == 200
            finally:
                heartbeat.set()
                response = await task
        assert response.status_code == 200 and not missed.is_set()

    asyncio.run(run())


@pytest.mark.parametrize("kind", ["analyzer", "agent"])
def test_concurrent_first_cached_provider_use_constructs_exactly_once(monkeypatch, kind):
    entered, release = threading.Event(), threading.Event()
    built = []
    cached = main.get_analyzer if kind == "analyzer" else main.get_evidence_agent
    cached.cache_clear()

    def construct(_):
        value = object()
        built.append(value)
        entered.set()
        assert release.wait(3)
        return value

    monkeypatch.setattr(
        main, "build_analyzer" if kind == "analyzer" else "EvidenceReviewAgent", construct
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(cached)
            try:
                assert entered.wait(2)
                second = pool.submit(cached)
                time.sleep(0.03)
                before_release = len(built)
            finally:
                release.set()
            one, two = first.result(timeout=3), second.result(timeout=3)
        assert before_release == 1 and len(built) == 1 and one is two
    finally:
        release.set()
        cached.cache_clear()


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("failed", [False, True])
def test_cancelled_cached_setup_retains_slot_and_success_remains_owned_by_cache(
    api, monkeypatch, batch, failed
):
    entered, release = threading.Event(), threading.Event()
    cached = main.get_analyzer
    cached.cache_clear()
    built, model_calls = [], []

    async def analyze(event):
        model_calls.append(event.event_id)
        return await RuleBasedAnalyzer().analyze(event)

    provider = SimpleNamespace(name="rule", analyze=analyze)

    def build(_):
        built.append(True)
        entered.set()
        assert release.wait(3)
        if failed and len(built) == 1:
            raise RuntimeError("controlled cached setup failure")
        return provider

    monkeypatch.setattr(main, "build_analyzer", build)
    main.settings.analysis_queue_timeout_seconds = 0.02

    async def run():
        capacity = asyncio.Semaphore(1)
        monkeypatch.setattr(main, "analysis_capacity", capacity)
        event = synthetic_events()[0].model_dump(mode="json")
        url = "/analysis/batch" if batch else "/analysis"
        payload = {"events": [event]} if batch else event
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.post(url, headers=api.headers, json=payload))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
                busy = await client.post(url, headers=api.headers, json=payload)
                assert busy.status_code == 429 and busy.headers["Retry-After"] == "1"
                assert not task.done() and capacity._value == 0 and len(built) == 1
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert capacity._value == 1 and not model_calls and len(api.store._records()) == 2
            response = await client.post(url, headers=api.headers, json=payload)
            assert response.status_code == 200 and len(model_calls) == 1
            assert len(built) == (2 if failed else 1)

    try:
        asyncio.run(run())
    finally:
        release.set()
        cached.cache_clear()


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("failed", [False, True])
def test_caller_revocation_during_cached_setup_denies_model_even_when_setup_fails(
    api, monkeypatch, batch, failed
):
    calls = []

    async def analyze(_):
        calls.append(True)

    def get():
        api.withdraw()
        if failed:
            raise ValueError("local setup private error")
        return SimpleNamespace(name="rule", analyze=analyze)

    monkeypatch.setattr(main, "get_analyzer", get)
    event = synthetic_events()[0].model_dump(mode="json")
    response = api.client.post(
        "/analysis/batch" if batch else "/analysis",
        headers=api.headers,
        json={"events": [event]} if batch else event,
    )
    assert response.status_code == 401 and not calls and len(api.store._records()) == 2


@pytest.mark.parametrize("batch", [False, True])
def test_full_analysis_capacity_never_enters_provider_constructor(api, monkeypatch, batch):
    built = []
    monkeypatch.setattr(main, "get_analyzer", lambda: built.append(True))

    async def run():
        monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(0))
        main.settings.analysis_queue_timeout_seconds = 0.01
        event = synthetic_events()[0].model_dump(mode="json")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/analysis/batch" if batch else "/analysis",
                headers=api.headers,
                json={"events": [event]} if batch else event,
            )
        assert response.status_code == 429 and not built

    asyncio.run(run())


@pytest.mark.parametrize("kind", ["analyzer", "agent"])
@pytest.mark.parametrize("error_type", [ValueError, RuntimeError])
def test_failed_cached_factory_is_not_cached_and_next_call_can_recover(
    monkeypatch, kind, error_type
):
    cached = main.get_analyzer if kind == "analyzer" else main.get_evidence_agent
    cached.cache_clear()
    calls = []
    result = object()

    def construct(_):
        calls.append(True)
        if len(calls) == 1:
            raise error_type("local controlled setup failure")
        return result

    monkeypatch.setattr(
        main, "build_analyzer" if kind == "analyzer" else "EvidenceReviewAgent", construct
    )
    try:
        with pytest.raises(error_type):
            cached()
        assert cached() is result and cached() is result and len(calls) == 2
    finally:
        cached.cache_clear()


@pytest.mark.parametrize("agent", [False, True])
def test_verified_session_and_agent_setup_keep_liveness_responsive(api, lab, monkeypatch, agent):
    signal, _ = lab.create(scenario("permitted_team"))
    main.settings.api_key_subject = lab.principal.subject
    main.settings.api_key_tenant_id = lab.principal.tenant_id
    main.settings.api_key_roles = "admin"
    main.settings.openai_prompt_mode = "grounded"
    main.settings.analyzer_mode = "openai"
    main.settings.openai_evidence_agent_enabled = True
    monkeypatch.setattr(main, "get_settings", lambda: main.settings)
    monkeypatch.setattr(main, "zero_trust_operations", lab.service)
    entered, heartbeat, missed = threading.Event(), threading.Event(), threading.Event()

    async def analyze_with_evidence(event, context):
        return assessment()

    async def review(event, context, history_getter):
        return assessment(), context, {}

    provider = SimpleNamespace(
        name="openai", analyze_with_evidence=analyze_with_evidence, review=review
    )

    def get():
        entered.set()
        if not heartbeat.wait(1):
            missed.set()
        return provider

    monkeypatch.setattr(main, "get_evidence_agent" if agent else "get_analyzer", get)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.post(
                    "/analysis/evidence-review" if agent else "/analysis/verified-session",
                    headers=api.headers,
                    json=signal.model_dump(mode="json"),
                )
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert (await client.get("/health/live")).status_code == 200
            finally:
                heartbeat.set()
                response = await task
        assert response.status_code == 200 and not missed.is_set(), response.text

    asyncio.run(run())
