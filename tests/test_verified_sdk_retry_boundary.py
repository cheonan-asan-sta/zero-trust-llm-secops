"""SDK retries must not bypass verification for server-bound evidence."""

import asyncio
import json
from dataclasses import replace

import httpx
import pytest
from openai import APIError, AsyncOpenAI
from test_openai_incomplete_retry import valid_body
from test_session_analysis_evidence import lab as lab  # noqa: PLC0414
from test_session_analysis_evidence import scenario

from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.scenarios import synthetic_events
from app.services.trusted_signals import SignalRejected


@pytest.mark.parametrize("failure", [408, 409, 429, 500, 502, "timeout", "connection"])
def test_verified_context_never_uses_unchecked_automatic_sdk_retry(lab, failure):
    signal, context = lab.create(scenario("permitted_team"))
    requests, checks = [], []
    withdrawn = False

    def check():
        checks.append(True)
        if withdrawn:
            raise SignalRejected("source withdrawn after ambiguous provider failure")

    context = replace(context, verify_current=check)

    async def run():
        async def handle(request):
            nonlocal withdrawn
            requests.append(request)
            if len(requests) == 1:
                withdrawn = True
                if failure == "timeout":
                    raise httpx.ReadTimeout("local timeout", request=request)
                if failure == "connection":
                    raise httpx.ConnectError("local connection failure", request=request)
                return httpx.Response(
                    failure,
                    json={"error": {"message": "local transient failure", "type": "test"}},
                    headers={"retry-after-ms": "1"},
                )
            return httpx.Response(200, json=valid_body())

        adapter = OpenAIAnalyzer(
            Settings(
                _env_file=None,
                openai_api_key="local-retry-boundary-placeholder",
                openai_prompt_mode="grounded",
            )
        )
        await adapter._client.close()
        async with AsyncOpenAI(
            api_key="local-retry-boundary-placeholder",
            max_retries=2,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ) as client:
            adapter._client = client
            with pytest.raises(APIError):
                await adapter.analyze_with_evidence(signal.event, context)
            assert len(requests) == len(checks) == 1
            assert client.max_retries == 2  # No mutation of the cached client.

    asyncio.run(run())


def test_ordinary_analysis_preserves_configured_sdk_retry_policy():
    requests = []

    async def run():
        async def handle(request):
            requests.append(request)
            if len(requests) == 1:
                return httpx.Response(
                    500, json={"error": {"message": "local"}}, headers={"retry-after-ms": "1"}
                )
            return httpx.Response(200, json=valid_body())

        adapter = OpenAIAnalyzer(
            Settings(
                _env_file=None,
                openai_api_key="local-retry-boundary-placeholder",
                openai_prompt_mode="grounded",
            )
        )
        await adapter._client.close()
        async with AsyncOpenAI(
            api_key="local-retry-boundary-placeholder",
            max_retries=2,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ) as client:
            adapter._client = client
            result = await adapter.analyze(synthetic_events()[0])
            assert result.violation_type == "NORMAL"
            assert len(requests) == 2 and client.max_retries == 2

    asyncio.run(run())


def test_concurrent_verified_and_ordinary_calls_do_not_mutate_each_others_retry_policy(lab):
    signal, context = lab.create(scenario("permitted_team"))
    counts = {"verified": 0, "ordinary": 0}

    async def run():
        both_started = asyncio.Event()

        async def handle(request):
            body = json.loads(request.content)
            catalog = json.loads(body["input"][1]["content"])["evidence_catalog"]
            mode = (
                "verified"
                if any(k.startswith("verified_session.") for k in catalog)
                else "ordinary"
            )
            counts[mode] += 1
            if counts[mode] == 1:
                if all(counts.values()):
                    both_started.set()
                await asyncio.wait_for(both_started.wait(), 3)
                return httpx.Response(
                    500, json={"error": {"message": "local"}}, headers={"retry-after-ms": "1"}
                )
            return httpx.Response(200, json=valid_body())

        adapter = OpenAIAnalyzer(
            Settings(
                _env_file=None,
                openai_api_key="local-retry-boundary-placeholder",
                openai_prompt_mode="grounded",
            )
        )
        await adapter._client.close()
        async with AsyncOpenAI(
            api_key="local-retry-boundary-placeholder",
            max_retries=2,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ) as client:
            adapter._client = client
            verified, ordinary = await asyncio.gather(
                adapter.analyze_with_evidence(signal.event, context),
                adapter.analyze(synthetic_events()[0]),
                return_exceptions=True,
            )
            assert isinstance(verified, APIError)
            assert ordinary.violation_type == "NORMAL"
            assert counts == {"verified": 1, "ordinary": 2}
            assert client.max_retries == 2 and not client.is_closed()

    asyncio.run(run())
