"""Real SDK/local transport checks; no paid provider calls or network transport."""

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import HTTPException
from openai import AsyncOpenAI
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_openai_incomplete_retry import truncated_body, valid_body
from test_session_analysis_evidence import lab as lab  # noqa: PLC0414
from test_session_analysis_evidence import scenario

from app import main, security
from app.analyzers.hybrid import HybridAnalyzer
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.scenarios import synthetic_events
from app.services.analysis_authority import (
    AnalysisAuthorityClosed,
    bind_analysis_authority,
    current_analysis_authority,
)
from app.services.trusted_signals import SignalRejected
from scripts.local_oidc_authority import LocalOIDCAuthority


@asynccontextmanager
async def local_adapter(handle, **options):
    adapter = OpenAIAnalyzer(
        Settings(
            _env_file=None,
            openai_api_key="local-caller-sdk-placeholder",
            openai_prompt_mode="grounded",
            **options,
        )
    )
    await adapter._client.close()
    async with AsyncOpenAI(
        api_key="local-caller-sdk-placeholder",
        max_retries=2,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    ) as sdk:
        adapter._client = sdk
        yield adapter, sdk


async def post_analysis(api, analyzer, monkeypatch, headers=None):
    monkeypatch.setattr(main, "get_analyzer", lambda: analyzer)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
    ) as client:
        return await client.post(
            "/analysis",
            headers=headers or api.headers,
            json=synthetic_events()[0].model_dump(mode="json"),
        )


@pytest.mark.parametrize("failure", [408, 409, 429, 500, 502, "timeout", "connection"])
def test_server_caller_withdrawal_never_allows_hidden_sdk_retry(api, monkeypatch, failure):
    requests = []

    async def run():
        async def handle(request):
            requests.append(request)
            if len(requests) == 1:
                api.withdraw()
                if failure == "timeout":
                    raise httpx.ReadTimeout("local controlled timeout", request=request)
                if failure == "connection":
                    raise httpx.ConnectError("local controlled connection failure", request=request)
                return httpx.Response(
                    failure,
                    json={"error": {"message": "local", "type": "test"}},
                    headers={"retry-after-ms": "1"},
                )
            return httpx.Response(200, json=valid_body())

        adapter = OpenAIAnalyzer(
            Settings(
                _env_file=None,
                openai_api_key="local-caller-sdk-placeholder",
                openai_prompt_mode="grounded",
            )
        )
        await adapter._client.close()
        async with AsyncOpenAI(
            api_key="local-caller-sdk-placeholder",
            max_retries=2,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ) as sdk:
            adapter._client = sdk
            monkeypatch.setattr(main, "get_analyzer", lambda: adapter)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
            ) as client:
                response = await client.post(
                    "/analysis",
                    headers=api.headers,
                    json=synthetic_events()[0].model_dump(mode="json"),
                )
            assert response.status_code == 401
            assert len(requests) == 1 and sdk.max_retries == 2

    asyncio.run(run())
    assert len(api.store._records()) == 2


@pytest.mark.parametrize("withdrawn", [False, True])
def test_explicit_output_token_retry_requires_current_caller(api, monkeypatch, withdrawn):
    requests = []

    async def run():
        async def handle(request):
            requests.append(json.loads(request.content))
            if len(requests) == 1:
                if withdrawn:
                    api.withdraw()
                return httpx.Response(200, json=truncated_body())
            return httpx.Response(200, json=valid_body())

        async with local_adapter(
            handle,
            openai_incomplete_retries=1,
            openai_max_output_tokens=800,
            openai_retry_max_output_tokens=4000,
        ) as (adapter, sdk):
            response = await post_analysis(api, adapter, monkeypatch)
            assert response.status_code == (401 if withdrawn else 200)
            assert [r["max_output_tokens"] for r in requests] == (
                [800] if withdrawn else [800, 4000]
            )
            assert sdk.max_retries == 2

    asyncio.run(run())
    assert len(api.store._records()) == (2 if withdrawn else 3)


@pytest.mark.parametrize("withdrawn", [False, True])
def test_hybrid_keeps_fallback_for_valid_caller_but_never_hides_revocation(
    api, monkeypatch, withdrawn
):
    calls = []

    async def run():
        async def handle(request):
            calls.append(request)
            if withdrawn:
                api.withdraw()
            return httpx.Response(
                500, json={"error": {"message": "local transient"}}, headers={"retry-after-ms": "1"}
            )

        async with local_adapter(handle) as (adapter, sdk):
            hybrid = HybridAnalyzer(Settings(_env_file=None, hybrid_review_all=True), llm=adapter)
            response = await post_analysis(api, hybrid, monkeypatch)
            assert response.status_code == (401 if withdrawn else 200)
            if not withdrawn:
                assert response.json()["assessment"]["requires_human_review"] is True
            assert len(calls) == 1 and sdk.max_retries == 2

    asyncio.run(run())
    assert len(api.store._records()) == (2 if withdrawn else 3)


def test_successful_provider_reply_is_not_returned_after_guard_withdrawal():
    calls = []
    revoked = False

    async def check():
        if revoked:
            raise HTTPException(401, "controlled local revocation")

    async def run():
        async def handle(request):
            nonlocal revoked
            calls.append(request)
            revoked = True
            return httpx.Response(200, json=valid_body())

        async with local_adapter(handle) as (adapter, sdk):
            with bind_analysis_authority(check), pytest.raises(HTTPException) as caught:
                await adapter.analyze(synthetic_events()[0])
            assert caught.value.status_code == 401 and len(calls) == 1 and sdk.max_retries == 2
            assert current_analysis_authority() is None

    asyncio.run(run())


def test_guarded_and_standalone_calls_share_client_without_sharing_retry_policy():
    counts = {"guarded": 0, "standalone": 0}
    revoked = False

    async def run():
        started = asyncio.Event()

        async def handle(request):
            nonlocal revoked
            name = "guarded" if current_analysis_authority() is not None else "standalone"
            counts[name] += 1
            if all(counts.values()):
                started.set()
            await started.wait()
            if counts[name] == 1:
                if name == "guarded":
                    revoked = True
                return httpx.Response(
                    500, json={"error": {"message": "local"}}, headers={"retry-after-ms": "1"}
                )
            return httpx.Response(200, json=valid_body())

        async def check():
            if revoked:
                raise HTTPException(401, "controlled local revocation")

        async with local_adapter(handle) as (adapter, sdk):

            async def guarded():
                with bind_analysis_authority(check):
                    return await adapter.analyze(synthetic_events()[0])

            protected, standalone = await asyncio.gather(
                guarded(), adapter.analyze(synthetic_events()[0]), return_exceptions=True
            )
            assert isinstance(protected, HTTPException) and protected.status_code == 401
            assert standalone.violation_type == "NORMAL"
            assert counts == {"guarded": 1, "standalone": 2} and sdk.max_retries == 2
            assert current_analysis_authority() is None

    asyncio.run(run())


def test_two_guarded_callers_keep_their_own_revalidation_closures():
    counts, scopes = {"A": 0, "B": 0}, {}
    revoked = False

    async def run():
        started = asyncio.Event()

        async def handle(request):
            nonlocal revoked
            name = scopes[id(current_analysis_authority())]
            counts[name] += 1
            if all(counts.values()):
                started.set()
            await started.wait()
            if name == "A":
                revoked = True
                return httpx.Response(500, json={"error": {"message": "local"}})
            return httpx.Response(200, json=valid_body())

        async def check_a():
            if revoked:
                raise HTTPException(401, "controlled A revocation")

        async def check_b():
            pass

        async with local_adapter(handle) as (adapter, sdk):

            async def invoke(name, check):
                with bind_analysis_authority(check) as scope:
                    scopes[id(scope)] = name
                    return await adapter.analyze(synthetic_events()[0])

            first, second = await asyncio.gather(
                invoke("A", check_a), invoke("B", check_b), return_exceptions=True
            )
            assert isinstance(first, HTTPException) and first.status_code == 401
            assert second.violation_type == "NORMAL" and counts == {"A": 1, "B": 1}
            assert sdk.max_retries == 2 and current_analysis_authority() is None

    asyncio.run(run())


def test_child_cannot_send_after_its_analyzer_owner_scope_closed():
    calls = []

    async def run():
        release = asyncio.Event()

        async def check():
            pass

        async def handle(request):
            calls.append(request)
            return httpx.Response(200, json=valid_body())

        async with local_adapter(handle) as (adapter, _):

            async def late():
                await release.wait()
                return await adapter.analyze(synthetic_events()[0])

            with bind_analysis_authority(check):
                child = asyncio.create_task(late())
            release.set()
            with pytest.raises(AnalysisAuthorityClosed):
                await child
            assert not calls and current_analysis_authority() is None

    asyncio.run(run())


def test_scope_close_during_validation_prevents_dispatch_after_callback_finishes():
    calls = []

    async def run():
        entered, release = asyncio.Event(), asyncio.Event()

        async def check():
            entered.set()
            await release.wait()

        async def handle(request):
            calls.append(request)
            return httpx.Response(200, json=valid_body())

        async with local_adapter(handle) as (adapter, _):
            with bind_analysis_authority(check):
                child = asyncio.create_task(adapter.analyze(synthetic_events()[0]))
                await entered.wait()
            release.set()
            with pytest.raises(AnalysisAuthorityClosed):
                await child
            assert not calls and current_analysis_authority() is None

    asyncio.run(run())


def test_error_resets_scope_and_standalone_sdk_policy_is_restored():
    calls = []

    async def run():
        async def check():
            raise HTTPException(401, "controlled local denial")

        async def handle(request):
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(
                    500, json={"error": {"message": "local"}}, headers={"retry-after-ms": "1"}
                )
            return httpx.Response(200, json=valid_body())

        async with local_adapter(handle) as (adapter, sdk):
            with bind_analysis_authority(check), pytest.raises(HTTPException):
                await adapter.analyze(synthetic_events()[0])
            assert not calls and current_analysis_authority() is None
            assert (await adapter.analyze(synthetic_events()[0])).violation_type == "NORMAL"
            assert len(calls) == 2 and sdk.max_retries == 2

    asyncio.run(run())


def test_cancellation_closes_scope_and_does_not_leak_to_parent_task():
    calls, captured = [], []

    async def run():
        entered = asyncio.Event()

        async def check():
            entered.set()
            await asyncio.Event().wait()

        async def handle(request):
            calls.append(request)
            return httpx.Response(200, json=valid_body())

        async with local_adapter(handle) as (adapter, _):

            async def invoke():
                with bind_analysis_authority(check) as scope:
                    captured.append(scope)
                    return await adapter.analyze(synthetic_events()[0])

            task = asyncio.create_task(invoke())
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(AnalysisAuthorityClosed):
                await captured[0].revalidate()
            assert not calls and current_analysis_authority() is None

    asyncio.run(run())


def test_added_caller_io_is_followed_by_fresh_verified_source_check(lab):
    signal, context = lab.create(scenario("permitted_team"))
    valid, calls = True, []

    def verify_source():
        if not valid:
            raise SignalRejected("controlled source withdrawal during caller I/O")

    context = replace(context, verify_current=verify_source)

    async def check():
        nonlocal valid
        valid = False

    async def run():
        async def handle(request):
            calls.append(request)
            return httpx.Response(200, json=valid_body())

        async with local_adapter(handle) as (adapter, _):
            with bind_analysis_authority(check), pytest.raises(SignalRejected):
                await adapter.analyze_with_evidence(signal.event, context)
            assert not calls

    asyncio.run(run())


def test_oidc_expiry_after_truncation_blocks_the_explicit_second_request(api, monkeypatch):
    now, calls = datetime.now(UTC), []
    expiry = now + timedelta(seconds=60)
    clock = {"now": now}

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"].astimezone(tz) if tz else clock["now"].replace(tzinfo=None)

    monkeypatch.setattr(main, "datetime", Clock)

    async def run(headers):
        async def handle(request):
            calls.append(request)
            clock["now"] = expiry + timedelta(seconds=1)
            return httpx.Response(200, json=truncated_body() if len(calls) == 1 else valid_body())

        async with local_adapter(handle, openai_incomplete_retries=1) as (adapter, _):
            response = await post_analysis(api, adapter, monkeypatch, headers)
            assert response.status_code == 401 and len(calls) == 1

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
        asyncio.run(
            run(
                {
                    "Authorization": "Bearer "
                    + authority.issue(tenant_id="local", roles=["analyst"], exp=expiry)
                }
            )
        )
    assert len(api.store._records()) == 2
