import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime

import httpx
import pytest
from openai import AsyncOpenAI

from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.analyzers.structured_response import StructuredResponseFailure
from app.config import Settings
from app.models import SecurityAssessment
from app.scenarios import synthetic_events
from app.services.trusted_signals import SignalRejected
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab
from tests.test_structured_response import envelope


def valid_body():
    assessment = SecurityAssessment(
        risk_score=0,
        risk_level="LOW",
        violation_type="NORMAL",
        rationale="로컬 응답 시험",
        evidence=["device.managed"],
        confidence=0.8,
        recommended_action="HOLD_FOR_REVIEW",
        requires_human_review=True,
    )
    return envelope(assessment.model_dump_json())


def truncated_body():
    return envelope(
        '{"risk_score":', status="incomplete", incomplete_details={"reason": "max_output_tokens"}
    )


async def invoke(bodies, requests, *, retries=1):
    def handle(request):
        requests.append(json.loads(request.content))
        body = bodies[min(len(requests) - 1, len(bodies) - 1)]
        return httpx.Response(200, json=body)

    adapter = OpenAIAnalyzer(
        Settings(
            openai_api_key="local-test-placeholder",
            openai_prompt_mode="grounded",
            openai_max_output_tokens=2400,
            openai_incomplete_retries=retries,
            openai_retry_max_output_tokens=4000,
        )
    )
    await adapter._client.close()
    async with AsyncOpenAI(
        api_key="local-test-placeholder",
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    ) as client:
        adapter._client = client
        return await adapter.analyze(synthetic_events()[0])


def test_opt_in_retries_once_with_identical_prompt_and_schema(caplog):
    requests = []
    result = asyncio.run(invoke([truncated_body(), valid_body()], requests))
    assert result.violation_type.value == "NORMAL"
    assert len(requests) == 2
    assert [r.pop("max_output_tokens") for r in requests] == [2400, 4000]
    assert requests[0] == requests[1]
    assert "max_output_tokens" in caplog.text and "input_tokens" in caplog.text
    assert "local-test-placeholder" not in caplog.text


def test_default_off_never_adds_a_billed_call():
    requests = []
    with pytest.raises(StructuredResponseFailure):
        asyncio.run(invoke([truncated_body(), valid_body()], requests, retries=0))
    assert len(requests) == 1
    assert Settings().openai_incomplete_retries == 0


def test_second_incomplete_is_preserved_instead_of_retrying_forever(caplog):
    requests = []
    with pytest.raises(StructuredResponseFailure):
        asyncio.run(invoke([truncated_body()], requests))
    assert len(requests) == 2
    assert len([r for r in caplog.records if "response rejected" in r.message]) == 2


@pytest.mark.parametrize(
    "body",
    [
        envelope("broken"),
        envelope(status="incomplete", incomplete_details={"reason": "content_filter"}),
        envelope(output=[]),
    ],
)
def test_schema_refusal_or_other_failure_does_not_trigger_token_retry(body):
    requests = []
    with pytest.raises(StructuredResponseFailure):
        asyncio.run(invoke([body, valid_body()], requests))
    assert len(requests) == 1


def test_valid_first_response_is_never_reselected_for_a_more_favorable_result():
    requests = []
    asyncio.run(invoke([valid_body(), truncated_body()], requests))
    assert len(requests) == 1


@pytest.mark.parametrize(
    "options",
    [
        {"openai_incomplete_retries": 2},
        {"openai_incomplete_retries": 1, "openai_retry_max_output_tokens": 2400},
        {"openai_incomplete_retries": 1, "openai_retry_max_output_tokens": 2000},
    ],
)
def test_unbounded_or_nonincreasing_retry_configuration_is_rejected(options):
    with pytest.raises(ValueError):
        Settings(openai_max_output_tokens=2400, **options)


def test_concurrent_calls_keep_their_own_output_limit():
    requests = []
    counts = {}

    async def run():
        async def handle(request):
            body = json.loads(request.content)
            role = json.loads(body["input"][1]["content"])["evidence_catalog"]["user.role"]
            counts[role] = counts.get(role, 0) + 1
            requests.append((role, body["max_output_tokens"]))
            await asyncio.sleep(0)
            return httpx.Response(
                200,
                json=truncated_body() if role == "employee" and counts[role] == 1 else valid_body(),
            )

        adapter = OpenAIAnalyzer(
            Settings(
                openai_api_key="local-test-placeholder",
                openai_prompt_mode="grounded",
                openai_max_output_tokens=2400,
                openai_incomplete_retries=1,
            )
        )
        await adapter._client.close()
        async with AsyncOpenAI(
            api_key="local-test-placeholder",
            max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ) as client:
            adapter._client = client
            first = synthetic_events()[0].model_copy(deep=True)
            second = first.model_copy(deep=True)
            first.user.role, second.user.role = "employee", "administrator"
            return await asyncio.gather(adapter.analyze(first), adapter.analyze(second))

    results = asyncio.run(run())
    assert len(results) == 2
    assert ("employee", 4000) in requests and ("administrator", 4000) not in requests
    assert counts == {"employee": 2, "administrator": 1}


@pytest.mark.parametrize("change", ["expired", "authority_withdrawn"])
def test_expired_or_withdrawn_evidence_stops_before_a_second_http_request(
    tmp_path, monkeypatch, change
):
    lab = LocalSessionAnalysisLab(tmp_path / "authority")
    signal, context = lab.create(next(s for s in SCENARIOS if s[0] == "read_over_vpn"))
    clock = {"now": datetime.now(UTC), "withdrawn": False}
    requests = []

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            value = clock["now"]
            return value.astimezone(tz) if tz else value.replace(tzinfo=None)

    def validate_current():
        if clock["withdrawn"]:
            raise SignalRejected("local authority withdrawn")

    context = replace(context, verify_current=validate_current)
    monkeypatch.setattr("app.services.session_analysis_evidence.datetime", Clock)

    async def run():
        def handle(request):
            requests.append(json.loads(request.content))
            if change == "expired":
                clock["now"] = context.expires_at
            else:
                clock["withdrawn"] = True
            return httpx.Response(200, json=truncated_body())

        adapter = OpenAIAnalyzer(
            Settings(
                openai_api_key="local-test-placeholder",
                openai_prompt_mode="grounded",
                openai_max_output_tokens=2400,
                openai_incomplete_retries=1,
            )
        )
        assert adapter._client.max_retries == 0
        await adapter._client.close()
        async with AsyncOpenAI(
            api_key="local-test-placeholder",
            max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        ) as client:
            adapter._client = client
            return await adapter.analyze_with_evidence(signal.event, context)

    with pytest.raises(SignalRejected):
        asyncio.run(run())
    assert len(requests) == 1
