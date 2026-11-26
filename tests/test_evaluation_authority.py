"""Evaluation work must remain within current administrator authority and capacity."""

import asyncio
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_caller_sdk_retry import local_adapter
from test_openai_incomplete_retry import truncated_body, valid_body

from app import main, security
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.config import Settings
from app.services.analysis_authority import AnalysisAuthorityClosed, current_analysis_authority
from app.services.evaluation import run_evaluation
from app.services.settled_io import settled_io
from scripts.local_oidc_authority import LocalOIDCAuthority


def make_admin():
    main.settings.api_key_roles = "admin"


def test_evaluation_stops_after_current_administrator_is_revoked(api, monkeypatch):
    make_admin()
    calls = []

    async def analyze(event):
        calls.append(event.event_id)
        api.withdraw()
        return await RuleBasedAnalyzer().analyze(event)

    model = SimpleNamespace(name="rule", analyze=analyze)
    monkeypatch.setattr(main, "build_analyzer", lambda _: model)
    response = api.client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
    assert response.status_code == 401 and len(calls) == 1
    assert len(api.store._records()) == 2


def test_evaluation_cannot_bypass_shared_analysis_capacity(api, monkeypatch):
    make_admin()
    calls = []

    async def analyze(event):
        calls.append(event.event_id)
        return await RuleBasedAnalyzer().analyze(event)

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )

    async def run():
        monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(0))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/evaluation/run", headers=api.headers, json={"concurrency": 2}
            )
        assert response.status_code == 429 and response.headers["Retry-After"] == "1"
        assert not calls

    asyncio.run(run())


def test_evaluation_fatal_error_cancels_and_settles_other_case_tasks():
    async def run():
        sibling_started, sibling_stopped = asyncio.Event(), asyncio.Event()
        tasks = []

        async def analyze(event):
            tasks.append(asyncio.current_task())
            if len(tasks) == 1:
                await sibling_started.wait()
                raise HTTPException(401, "local authority revoked")
            sibling_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0.01)
                sibling_stopped.set()

        try:
            with pytest.raises(HTTPException):
                await run_evaluation(SimpleNamespace(name="rule", analyze=analyze), concurrency=2)
            assert sibling_stopped.is_set() and all(task.done() for task in tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(run())


@pytest.mark.parametrize("change", ["role", "tenant", "subject", "mode"])
def test_evaluation_rechecks_authority_after_each_case(api, monkeypatch, change):
    make_admin()
    calls = []

    async def analyze(event):
        calls.append(event.event_id)
        field, value = {
            "role": ("api_key_roles", "analyst"),
            "tenant": ("api_key_tenant_id", "other"),
            "subject": ("api_key_subject", "other"),
            "mode": ("auth_mode", "disabled"),
        }[change]
        setattr(main.settings, field, value)
        return await RuleBasedAnalyzer().analyze(event)

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )
    response = api.client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
    assert response.status_code == 401 and len(calls) == 1


def test_evaluation_rejects_authority_revoked_while_waiting_for_case_capacity(api, monkeypatch):
    make_admin()
    calls = []
    original = main._analysis_slot

    async def analyze(event):
        calls.append(event.event_id)
        return await RuleBasedAnalyzer().analyze(event)

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )

    async def run():
        queued = asyncio.Event()
        capacity = asyncio.Semaphore(0)
        monkeypatch.setattr(main, "analysis_capacity", capacity)
        main.settings.analysis_queue_timeout_seconds = 1

        @asynccontextmanager
        async def observed():
            queued.set()
            async with original():
                yield

        monkeypatch.setattr(main, "_analysis_slot", observed)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
            )
            await queued.wait()
            api.withdraw()
            capacity.release()
            response = await task
        assert response.status_code == 401 and not calls
        assert capacity._value == 1

    asyncio.run(run())


def test_evaluation_capacity_failure_is_not_scored_as_a_runtime_model_error(api, monkeypatch):
    make_admin()
    calls = []
    attempts = 0

    async def analyze(event):
        calls.append(event.event_id)
        return await RuleBasedAnalyzer().analyze(event)

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )

    @asynccontextmanager
    async def once_full():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise main.AnalysisCapacityExceeded
        yield

    monkeypatch.setattr(main, "_analysis_slot", once_full)
    response = api.client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
    assert response.status_code == 429 and attempts >= 1 and not calls


def test_evaluation_final_delivery_rechecks_current_admin(api, monkeypatch):
    make_admin()
    original = main.run_evaluation
    monkeypatch.setattr(main, "build_analyzer", lambda _: RuleBasedAnalyzer())

    async def revoke_after_summary(*args):
        result = await original(*args)
        assert result.total_cases == 8
        api.withdraw()
        return result

    monkeypatch.setattr(main, "run_evaluation", revoke_after_summary)
    response = api.client.post("/evaluation/run", headers=api.headers, json={"concurrency": 2})
    assert response.status_code == 401 and "cases" not in response.json()


def test_evaluation_has_global_and_request_concurrency_limits_without_audit_pollution(
    api, monkeypatch
):
    make_admin()
    active, peak = 0, 0

    async def analyze(event):
        nonlocal active, peak
        active += 1
        peak = max(active, peak)
        try:
            await asyncio.sleep(0.01)
            return await RuleBasedAnalyzer().analyze(event)
        finally:
            active -= 1

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )

    async def run():
        capacity = asyncio.Semaphore(2)
        monkeypatch.setattr(main, "analysis_capacity", capacity)
        main.settings.analysis_queue_timeout_seconds = 1
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            responses = await asyncio.gather(
                *(
                    client.post("/evaluation/run", headers=api.headers, json={"concurrency": 3})
                    for _ in range(2)
                )
            )
        assert all(response.status_code == 200 for response in responses)
        for response in responses:
            assert response.json()["total_cases"] == 8
            assert response.json()["error_count"] == 0
        assert peak == 2 and active == 0 and capacity._value == 2

    asyncio.run(run())
    assert len(api.store._records()) == 2


def test_evaluation_cancellation_settles_non_cancellable_case_io_even_when_cancelled_twice(
    api, monkeypatch
):
    make_admin()
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    scopes = []

    def slow():
        entered.set()
        assert release.wait(3)
        finished.set()

    async def analyze(event):
        scopes.append(current_analysis_authority())
        await settled_io(slow)
        return await RuleBasedAnalyzer().analyze(event)

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )

    async def run():
        capacity = asyncio.Semaphore(1)
        monkeypatch.setattr(main, "analysis_capacity", capacity)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
                await asyncio.sleep(0.01)
                assert not task.done() and not finished.is_set() and capacity._value == 0
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert finished.is_set() and capacity._value == 1 and len(scopes) == 1
            with pytest.raises(AnalysisAuthorityClosed):
                await scopes[0].revalidate()
            assert current_analysis_authority() is None

    asyncio.run(run())


def test_evaluation_oidc_expiry_after_first_case_prevents_more_work(api, monkeypatch):
    now = datetime.now(UTC)
    expiry = now + timedelta(seconds=60)
    clock = {"now": now}
    calls = []

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"].astimezone(tz) if tz else clock["now"].replace(tzinfo=None)

    async def analyze(event):
        calls.append(event.event_id)
        clock["now"] = expiry + timedelta(seconds=1)
        return await RuleBasedAnalyzer().analyze(event)

    monkeypatch.setattr(main, "datetime", Clock)
    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )
    security._jwks_client.cache_clear()
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
        )
        monkeypatch.setattr(security, "get_settings", lambda: config)
        headers = {
            "Authorization": "Bearer "
            + authority.issue(
                tenant_id="local",
                roles=["admin"],
                exp=expiry,
            )
        }
        response = api.client.post("/evaluation/run", headers=headers, json={"concurrency": 1})
    assert response.status_code == 401 and len(calls) == 1


@pytest.mark.parametrize("status", [401, 403, 503])
def test_evaluation_authority_errors_remain_fatal_instead_of_model_scores(api, monkeypatch, status):
    make_admin()
    calls = []

    async def analyze(event):
        calls.append(event.event_id)
        raise HTTPException(status, "local authority/source unavailable")

    monkeypatch.setattr(
        main, "build_analyzer", lambda _: SimpleNamespace(name="rule", analyze=analyze)
    )
    response = api.client.post("/evaluation/run", headers=api.headers, json={"concurrency": 1})
    assert response.status_code == status and len(calls) == 1


@pytest.mark.parametrize("failure", ["transient", "truncated"])
def test_evaluation_real_sdk_cannot_retry_after_admin_withdrawal(api, monkeypatch, failure):
    make_admin()
    calls = []

    async def run():
        async def handle(request):
            calls.append(request)
            api.withdraw()
            if failure == "transient":
                return httpx.Response(500, json={"error": {"message": "local"}})
            return httpx.Response(200, json=truncated_body())

        async with local_adapter(handle, openai_incomplete_retries=1) as (adapter, sdk):
            # Keep automatic retries enabled on the shared SDK to verify that
            # the evaluation scope selects a request-local zero-retry client.
            sdk.max_retries = 2
            monkeypatch.setattr(main, "build_analyzer", lambda _: adapter)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
            ) as client:
                response = await client.post(
                    "/evaluation/run",
                    headers=api.headers,
                    json={"analyzer": "openai", "concurrency": 1},
                )
            assert response.status_code == 401 and len(calls) == 1
            assert sdk.max_retries == 2 and current_analysis_authority() is None

    asyncio.run(run())


def test_evaluation_current_admin_retains_explicit_token_retry_and_original_case_count(
    api, monkeypatch
):
    make_admin()
    calls = []

    async def run():
        async def handle(request):
            calls.append(request)
            return httpx.Response(200, json=truncated_body() if len(calls) == 1 else valid_body())

        async with local_adapter(handle, openai_incomplete_retries=1) as (adapter, _):
            monkeypatch.setattr(main, "build_analyzer", lambda _: adapter)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
            ) as client:
                response = await client.post(
                    "/evaluation/run",
                    headers=api.headers,
                    json={"analyzer": "openai", "concurrency": 1},
                )
            assert response.status_code == 200
            assert response.json()["total_cases"] == 8 and len(calls) == 9
            assert current_analysis_authority() is None

    asyncio.run(run())
    assert len(api.store._records()) == 2
