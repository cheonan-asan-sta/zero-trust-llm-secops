"""Real SDK parsing with a local transport: no provider network or paid calls."""

import asyncio
import threading
from contextlib import asynccontextmanager
from dataclasses import replace

import httpx
import pytest
from openai import AsyncOpenAI
from test_evidence_review_agent import final_response, tool_response
from test_openai_incomplete_retry import truncated_body, valid_body
from test_session_analysis_evidence import lab as lab  # noqa: PLC0414
from test_session_analysis_evidence import scenario

from app import main
from app.analyzers.evidence_agent import EvidenceReviewAgent
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.services.sqlite_audit import SQLiteAuditStore
from app.services.trusted_signals import SignalRejected


@asynccontextmanager
async def sdk(responses, *, first_response_delay=0):
    requests = []

    async def handle(request):
        requests.append(request)
        if len(requests) == 1 and first_response_delay:
            await asyncio.sleep(first_response_delay)
        assert responses, "unexpected paid-provider-shaped request"
        return httpx.Response(200, json=responses.pop(0))

    async with AsyncOpenAI(
        api_key="local-evidence-io-placeholder",
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    ) as client:
        yield client, requests


@pytest.mark.parametrize(
    "mode,first_response_delay", [
        pytest.param("adapter_initial", 0, id="adapter_initial"),
        pytest.param("adapter_retry", 0, id="adapter_retry"),
        pytest.param("agent_initial", 0, id="agent_initial"),
        pytest.param("agent_final", 0, id="agent_final"),
        pytest.param("adapter_retry", 2.2, id="adapter_retry_slow_local_response"),
        pytest.param("adapter_retry", 12, id="adapter_retry_response_exceeds_old_watchdog"),
    ]
)
def test_cancelled_sdk_source_check_settles_without_blocking_event_loop(lab, mode, first_response_delay):
    signal, context = lab.create(scenario("permitted_team"))
    release = threading.Event()
    notify_entered = None
    checks = 0
    blocking_check = 2 if mode.endswith(("retry", "final")) else 1

    def check():
        nonlocal checks
        checks += 1
        if checks == blocking_check:
            notify_entered()
            assert release.wait(3)

    context = replace(context, verify_current=check)
    config = Settings(
        _env_file=None,
        openai_api_key="local-evidence-io-placeholder",
        openai_prompt_mode="grounded",
        openai_max_output_tokens=2400,
        openai_incomplete_retries=1,
    )

    async def run():
        nonlocal notify_entered
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        notify_entered = lambda: loop.call_soon_threadsafe(entered.set)
        responses = (
            [truncated_body(), valid_body()] if mode == "adapter_retry" else [final_response()]
        )
        async with sdk(responses, first_response_delay=first_response_delay) as (client, requests):
            if mode.startswith("adapter"):
                adapter = OpenAIAnalyzer(config)
                await adapter._client.close()
                adapter._client = client
                task = asyncio.create_task(adapter.analyze_with_evidence(signal.event, context))
            else:
                agent = EvidenceReviewAgent(config, client=client)
                task = asyncio.create_task(agent.review(signal.event, context, dict))
            try:
                # Allow transport/parsing to finish before the callback whose
                # responsiveness is under test. A controlled 12s response must
                # not fail a cancellation test before that callback is reached.
                # The callback's unchanged 3s release watchdog still makes a
                # synchronous event-loop implementation fail, even with this
                # longer outer synchronization bound. No API SLA is measured.
                await asyncio.wait_for(entered.wait(), 30)
                # This only runs before release if the callback leaves the loop responsive.
                assert not task.done()
                assert len(requests) == (blocking_check - 1)
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert len(requests) == (blocking_check - 1)

    asyncio.run(run())


def test_cancelled_agent_history_read_settles_before_review_finishes(lab):
    signal, context = lab.create(scenario("permitted_team"))
    entered, release = threading.Event(), threading.Event()

    def history():
        entered.set()
        assert release.wait(3)
        return {"decisions": []}

    async def run():
        async with sdk([tool_response("read_current_session_history"), final_response()]) as (
            client,
            requests,
        ):
            agent = EvidenceReviewAgent(Settings(_env_file=None), client=client)
            task = asyncio.create_task(agent.review(signal.event, context, history))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert not task.done() and len(requests) == 1
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert len(requests) == 1

    asyncio.run(run())


def test_authority_withdrawn_during_history_read_stops_next_sdk_call(lab):
    signal, context = lab.create(scenario("permitted_team"))
    withdrawn = threading.Event()

    def check():
        if withdrawn.is_set():
            raise SignalRejected("authority withdrawn during local history read")

    def history():
        withdrawn.set()
        return {"decisions": []}

    context = replace(context, verify_current=check)

    async def run():
        async with sdk([tool_response("read_current_session_history"), final_response()]) as (
            client,
            requests,
        ):
            agent = EvidenceReviewAgent(Settings(_env_file=None), client=client)
            with pytest.raises(SignalRejected):
                await agent.review(signal.event, context, history)
            assert len(requests) == 1

    asyncio.run(run())


@pytest.mark.parametrize("failed_read", [False, True])
def test_sdk_source_cancellation_retains_real_analysis_slot_until_settled(
    lab, tmp_path, monkeypatch, failed_read
):
    signal, context = lab.create(scenario("permitted_team"))
    entered, release = threading.Event(), threading.Event()
    finished = threading.Event()
    capacity = asyncio.Semaphore(1)
    audit = SQLiteAuditStore(tmp_path / "sdk-audit.sqlite3")
    monkeypatch.setattr(main, "analysis_capacity", capacity)
    monkeypatch.setattr(main, "audit_store", audit)
    monkeypatch.setattr(
        main, "settings", main.settings.model_copy(update={"analysis_queue_timeout_seconds": 0.01})
    )

    def check():
        entered.set()
        assert release.wait(3)
        finished.set()
        if failed_read:
            raise OSError("controlled local source read failure")

    context = replace(context, verify_current=check)

    async def run():
        async with sdk([valid_body()]) as (client, requests):
            adapter = OpenAIAnalyzer(
                Settings(
                    _env_file=None,
                    openai_api_key="local-evidence-io-placeholder",
                    openai_prompt_mode="grounded",
                )
            )
            await adapter._client.close()
            adapter._client = client

            class Bound:
                name = "openai"

                async def analyze(self, event):
                    return await adapter.analyze_with_evidence(event, context)

            task = asyncio.create_task(
                main._analyze_event(signal.event, Bound(), lab.principal, "sdk-io-cancel", context)
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and capacity._value == 0
                with pytest.raises(main.AnalysisCapacityExceeded):
                    await main._analyze_event(signal.event, Bound(), lab.principal, "sdk-io-full")
                assert not requests and audit.metrics(lab.principal.tenant_id).total_analyses == 0
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert finished.is_set() and capacity._value == 1 and not requests
            assert audit.integrity()["ok"]
            assert audit.metrics(lab.principal.tenant_id).total_analyses == 0
            if not failed_read:
                result = await main._analyze_event(
                    signal.event, Bound(), lab.principal, "sdk-io-recovered", context
                )
                assert result.assessment.requires_human_review
                assert (
                    audit.metrics(lab.principal.tenant_id).total_analyses == 1
                    and len(requests) == 1
                )

    asyncio.run(run())
