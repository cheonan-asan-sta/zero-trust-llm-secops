"""Request-owned evaluation setup and client cleanup, local only."""

import asyncio
import threading
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_caller_sdk_retry import local_adapter
from test_openai_incomplete_retry import valid_body

from app import main
from app.analyzers import hybrid
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.config import Settings
from app.services.work_admission import WorkAdmission


def single_job(monkeypatch):
    main.settings.api_key_roles = "admin"
    main.settings.evaluation_max_concurrency = 1
    main.settings.evaluation_queue_timeout_seconds = 0.02
    capacity = WorkAdmission(1)
    monkeypatch.setattr(main.app.state, "_evaluation_admission", capacity, raising=False)
    return capacity


def test_evaluation_setup_io_does_not_block_liveness(api, monkeypatch):
    main.settings.api_key_roles = "admin"
    entered, heartbeat, missed = threading.Event(), threading.Event(), threading.Event()

    def build(_):
        entered.set()
        if not heartbeat.wait(1):
            missed.set()
        return RuleBasedAnalyzer()

    monkeypatch.setattr(main, "build_analyzer", build)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert (await client.get("/health/live")).status_code == 200
            finally:
                heartbeat.set()
                response = await task
        assert response.status_code == 200 and not missed.is_set()

    asyncio.run(run())


def test_evaluation_closes_its_owned_analyzer_once_after_cases_finish(api, monkeypatch):
    main.settings.api_key_roles = "admin"
    calls, closed = [], []

    async def analyze(event):
        assert not closed
        calls.append(event.event_id)
        return await RuleBasedAnalyzer().analyze(event)

    async def close():
        assert len(calls) == 8
        closed.append(True)

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze, close=close)
    )
    response = api.client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
    assert response.status_code == 200 and len(calls) == 8 and closed == [True]


@pytest.mark.parametrize("failed", [False, True])
def test_cancelled_setup_retains_job_capacity_and_disposes_created_client(api, monkeypatch, failed):
    capacity = single_job(monkeypatch)
    entered, release = threading.Event(), threading.Event()
    built, closed, model_calls = [], [], []

    async def analyze(event):
        model_calls.append(event.event_id)
        return await RuleBasedAnalyzer().analyze(event)

    async def close():
        closed.append(True)

    def build(_):
        built.append(True)
        entered.set()
        assert release.wait(3)
        if failed:
            raise RuntimeError("local controlled setup failure")
        return SimpleNamespace(name="rule", analyze=analyze, close=close)

    monkeypatch.setattr(main, "build_analyzer", build)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.post("/evaluation/run", headers=api.headers, json={}))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
                busy = await client.post("/evaluation/run", headers=api.headers, json={})
                assert busy.status_code == 503 and busy.headers["Retry-After"] == "1"
                assert not task.done() and capacity.snapshot()["active"] == 1 and len(built) == 1
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert capacity.snapshot()["available"] == 1 and not model_calls
            assert closed == ([] if failed else [True])
            monkeypatch.setattr(main, "build_analyzer", lambda _: RuleBasedAnalyzer())
            recovered = await client.post("/evaluation/run", headers=api.headers, json={})
            assert recovered.status_code == 200

    asyncio.run(run())


def test_repeated_cancellation_waits_for_owned_async_client_close(api, monkeypatch):
    capacity = single_job(monkeypatch)
    built, closed = [], []

    async def run():
        closing, release = asyncio.Event(), asyncio.Event()

        async def close():
            closing.set()
            await release.wait()
            closed.append(True)

        def build(_):
            built.append(True)
            return SimpleNamespace(name="rule", analyze=RuleBasedAnalyzer().analyze, close=close)

        monkeypatch.setattr(main, "build_analyzer", build)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.post("/evaluation/run", headers=api.headers, json={}))
            try:
                await asyncio.wait_for(closing.wait(), 2)
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
                assert not task.done() and not closed and capacity.snapshot()["active"] == 1
                busy = await client.post("/evaluation/run", headers=api.headers, json={})
                assert busy.status_code == 503 and len(built) == 1
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert closed == [True] and capacity.snapshot()["available"] == 1

    asyncio.run(run())


def test_cancelled_job_waiter_does_not_construct_or_release_anothers_capacity(api, monkeypatch):
    capacity = single_job(monkeypatch)
    main.settings.evaluation_queue_timeout_seconds = 1
    built = []
    assert capacity.acquire_nowait()
    monkeypatch.setattr(main, "build_analyzer", lambda _: built.append(True))

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.post("/evaluation/run", headers=api.headers, json={}))
            await asyncio.sleep(0.03)
            assert not task.done()
            task.cancel()
            outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
        assert capacity.snapshot()["active"] == 1 and not built

    try:
        asyncio.run(run())
    finally:
        capacity.release()


@pytest.mark.parametrize("error_type", [ValueError, RuntimeError])
def test_setup_failure_is_sanitized_and_releases_job_capacity(api, monkeypatch, error_type):
    capacity = single_job(monkeypatch)
    marker = "local-secret-marker-never-expose"

    def build(_):
        raise error_type(marker)

    monkeypatch.setattr(main, "build_analyzer", build)
    response = api.client.post("/evaluation/run", headers=api.headers, json={})
    assert response.status_code == 503 and marker not in response.text
    assert capacity.snapshot()["available"] == 1


def test_cleanup_failure_is_sanitized_and_does_not_deliver_summary(api, monkeypatch):
    capacity = single_job(monkeypatch)

    async def close():
        raise RuntimeError("local-transport-private-detail")

    monkeypatch.setattr(
        main,
        "build_analyzer",
        lambda _: SimpleNamespace(
            name="rule",
            analyze=RuleBasedAnalyzer().analyze,
            close=close,
        ),
    )
    response = api.client.post("/evaluation/run", headers=api.headers, json={})
    assert response.status_code == 503 and "local-transport-private-detail" not in response.text
    assert "cases" not in response.json() and capacity.snapshot()["available"] == 1


def test_authority_withdrawal_during_cleanup_is_checked_before_summary_delivery(api, monkeypatch):
    capacity = single_job(monkeypatch)
    closed = []

    async def close():
        api.withdraw()
        closed.append(True)

    monkeypatch.setattr(
        main,
        "build_analyzer",
        lambda _: SimpleNamespace(
            name="rule",
            analyze=RuleBasedAnalyzer().analyze,
            close=close,
        ),
    )
    response = api.client.post("/evaluation/run", headers=api.headers, json={})
    assert response.status_code == 401 and closed == [True]
    assert capacity.snapshot()["available"] == 1 and "cases" not in response.json()


def test_authority_revoked_during_setup_disposes_client_without_model_use(api, monkeypatch):
    capacity = single_job(monkeypatch)
    closed, calls = [], []

    async def analyze(_):
        calls.append(True)

    async def close():
        closed.append(True)

    def build(_):
        api.withdraw()
        return SimpleNamespace(name="rule", analyze=analyze, close=close)

    monkeypatch.setattr(main, "build_analyzer", build)
    response = api.client.post("/evaluation/run", headers=api.headers, json={})
    assert response.status_code == 401 and not calls and closed == [True]
    assert capacity.snapshot()["available"] == 1


def test_limiter_replacement_releases_only_original_owned_job_capacity(api, monkeypatch):
    original = single_job(monkeypatch)
    replacement = WorkAdmission(1)
    assert replacement.acquire_nowait()

    async def close():
        main.app.state._evaluation_admission = replacement

    monkeypatch.setattr(
        main,
        "build_analyzer",
        lambda _: SimpleNamespace(
            name="rule",
            analyze=RuleBasedAnalyzer().analyze,
            close=close,
        ),
    )
    try:
        response = api.client.post("/evaluation/run", headers=api.headers, json={})
        assert response.status_code == 200
        assert original.snapshot()["available"] == 1 and replacement.snapshot()["active"] == 1
    finally:
        replacement.release()


@pytest.mark.parametrize(
    "options",
    [
        {"evaluation_max_concurrency": 0},
        {"evaluation_max_concurrency": 5},
        {"evaluation_queue_timeout_seconds": 0},
        {"evaluation_queue_timeout_seconds": 2.1},
        {"evaluation_queue_timeout_seconds": float("nan")},
        {"evaluation_queue_timeout_seconds": float("inf")},
    ],
)
def test_evaluation_resource_settings_are_bounded(options):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **options)


@pytest.mark.parametrize(
    "field,value",
    [
        ("evaluation_queue_timeout_seconds", float("nan")),
        ("evaluation_max_concurrency", True),
    ],
)
def test_invalid_runtime_job_configuration_fails_closed_before_factory(
    api, monkeypatch, field, value
):
    single_job(monkeypatch)
    setattr(main.settings, field, value)
    calls = []
    monkeypatch.setattr(main, "build_analyzer", lambda _: calls.append(True))
    response = api.client.post("/evaluation/run", headers=api.headers, json={})
    assert response.status_code == 503 and not calls


@pytest.mark.parametrize("mode", ["openai", "hybrid"])
def test_request_owned_actual_sdk_client_is_closed_for_both_provider_modes(api, monkeypatch, mode):
    single_job(monkeypatch)
    requests = []

    async def run():
        async def handle(request):
            requests.append(request)
            return httpx.Response(200, json=valid_body())

        async with local_adapter(handle) as (adapter, sdk):
            if mode == "hybrid":
                monkeypatch.setattr(hybrid, "OpenAIAnalyzer", lambda _: adapter)
                owned = hybrid.HybridAnalyzer(Settings(_env_file=None, hybrid_review_all=True))
            else:
                owned = adapter
            monkeypatch.setattr(main, "build_analyzer", lambda _: owned)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
            ) as client:
                response = await client.post(
                    "/evaluation/run",
                    headers=api.headers,
                    json={"analyzer": mode, "concurrency": 1},
                )
            assert response.status_code == 200 and response.json()["total_cases"] == 8
            assert len(requests) == 8 and sdk.is_closed()

    asyncio.run(run())


def test_hybrid_close_does_not_take_ownership_of_injected_shared_adapter():
    closed = []

    async def close():
        closed.append(True)

    injected = SimpleNamespace(name="openai", analyze=RuleBasedAnalyzer().analyze, close=close)
    model = hybrid.HybridAnalyzer(Settings(_env_file=None), llm=injected)
    asyncio.run(model.close())
    assert not closed


def test_authority_failure_closes_client_after_all_started_case_tasks_settle(api, monkeypatch):
    single_job(monkeypatch)
    active, closed = 0, []

    async def run():
        sibling_started = asyncio.Event()

        async def analyze(event):
            nonlocal active
            active += 1
            try:
                if active == 1:
                    await sibling_started.wait()
                    api.withdraw()
                    return await RuleBasedAnalyzer().analyze(event)
                sibling_started.set()
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0.01)
                active -= 1

        async def close():
            assert active == 0
            closed.append(True)

        monkeypatch.setattr(
            main,
            "build_analyzer",
            lambda _: SimpleNamespace(
                name="rule",
                analyze=analyze,
                close=close,
            ),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/evaluation/run",
                headers=api.headers,
                json={"concurrency": 2},
            )
        assert response.status_code == 401 and closed == [True] and active == 0

    asyncio.run(run())
