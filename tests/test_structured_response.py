import asyncio
import json

import httpx
import pytest
from openai import AsyncOpenAI, AuthenticationError
from prometheus_client import REGISTRY
from pydantic import BaseModel

from app.analyzers.structured_response import (
    StructuredResponseFailure,
    parse_single_structured_response,
    parse_structured_response,
)


class ExampleOutput(BaseModel):
    value: int


def envelope(text='{"value": 7}', *, status="completed", usage=None, **changes):
    return {
        "id": "resp_local",
        "object": "response",
        "created_at": 1,
        "model": "local-test",
        "status": status,
        "output": [
            {
                "id": "msg_local",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            }
        ],
        "usage": usage or {"input_tokens": 37, "output_tokens": 11, "total_tokens": 48},
        **changes,
    }


async def call(body, *, http_status=200, parser=parse_structured_response):
    requests = []

    async def handle(request):
        requests.append(json.loads(request.content))
        return httpx.Response(http_status, json=body)

    async with AsyncOpenAI(
        api_key="test-placeholder",
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    ) as client:
        result = await parser(
            client,
            model="local-test",
            store=False,
            input=[{"role": "user", "content": "local synthetic observation"}],
            text_format=ExampleOutput,
        )
    assert len(requests) == 1
    assert requests[0]["store"] is False
    assert requests[0]["text"]["format"]["strict"] is True
    return result


def test_success_preserves_sdk_schema_and_usage_without_extra_calls():
    name = "secops_analysis_phase_duration_seconds_count"
    phases = ("provider_request", "structured_validation")
    before = {phase: REGISTRY.get_sample_value(name, {"phase": phase}) or 0 for phase in phases}
    response, diagnostics = asyncio.run(call(envelope()))
    assert response.output_parsed == ExampleOutput(value=7)
    assert diagnostics.as_dict() == {
        "status": "completed",
        "incomplete_reason": None,
        "input_tokens": 37,
        "output_tokens": 11,
        "refusal": False,
    }
    for phase in phases:
        assert REGISTRY.get_sample_value(name, {"phase": phase}) == before[phase] + 1


@pytest.mark.parametrize("text", ['{"value":', '{"value": 7}'])
def test_incomplete_even_parseable_prefix_is_never_success(text):
    with pytest.raises(StructuredResponseFailure) as failure:
        asyncio.run(
            call(
                envelope(
                    text,
                    status="incomplete",
                    incomplete_details={"reason": "max_output_tokens"},
                )
            )
        )
    assert failure.value.code == "response_not_completed"
    assert failure.value.diagnostics.incomplete_reason == "max_output_tokens"
    assert failure.value.diagnostics.output_tokens == 11


@pytest.mark.parametrize("text", ['{"value":', '{"value":"secret-provider-text"}'])
def test_invalid_completed_output_keeps_usage_but_never_error_input(text):
    with pytest.raises(StructuredResponseFailure) as failure:
        asyncio.run(call(envelope(text)))
    assert failure.value.code == "structured_output_invalid"
    assert failure.value.diagnostics.input_tokens == 37
    assert "secret-provider-text" not in str(failure.value)
    assert "secret-provider-text" not in repr(failure.value.diagnostics)


def test_refusal_has_bounded_diagnostics_without_refusal_text():
    body = envelope(
        output=[
            {
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "id": "m",
                "content": [{"type": "refusal", "refusal": "secret-refusal-text"}],
            }
        ]
    )
    with pytest.raises(StructuredResponseFailure) as failure:
        asyncio.run(call(body))
    assert failure.value.code == "response_refused"
    assert failure.value.diagnostics.refusal
    assert "secret-refusal-text" not in repr(failure.value.diagnostics)


def test_no_output_is_distinct_from_invalid_output():
    with pytest.raises(StructuredResponseFailure, match="structured_output_missing"):
        asyncio.run(call(envelope(output=[])))


@pytest.mark.parametrize("status", ["failed", "cancelled", "queued", "in_progress", None])
def test_noncompleted_provider_state_is_rejected(status):
    with pytest.raises(StructuredResponseFailure, match="response_not_completed"):
        asyncio.run(call(envelope(status=status)))


def test_authentication_exception_is_preserved_for_runner_stop():
    name = "secops_analysis_phase_duration_seconds_count"
    request = {"phase": "provider_request"}
    validation = {"phase": "structured_validation"}
    requests_before = REGISTRY.get_sample_value(name, request) or 0
    validations_before = REGISTRY.get_sample_value(name, validation)
    with pytest.raises(AuthenticationError):
        asyncio.run(
            call({"error": {"message": "test", "type": "invalid_api_key"}}, http_status=401)
        )
    assert REGISTRY.get_sample_value(name, request) == requests_before + 1
    assert REGISTRY.get_sample_value(name, validation) == validations_before


def test_concurrent_calls_do_not_share_usage_or_failure_state():
    async def run():
        return await asyncio.gather(
            call(envelope(usage={"input_tokens": 5, "output_tokens": 2, "total_tokens": 7})),
            call(
                envelope(
                    "broken", usage={"input_tokens": 91, "output_tokens": 4, "total_tokens": 95}
                )
            ),
            return_exceptions=True,
        )

    good, bad = asyncio.run(run())
    assert good[1].input_tokens == 5
    assert isinstance(bad, StructuredResponseFailure)
    assert bad.diagnostics.input_tokens == 91


def test_invalid_envelope_has_safe_error():
    with pytest.raises(StructuredResponseFailure, match="invalid_response_envelope"):
        asyncio.run(call(["secret-provider-text"]))


def test_missing_usage_does_not_discard_a_valid_assessment():
    response, diagnostics = asyncio.run(call(envelope(usage=None) | {"usage": None}))
    assert response.output_parsed.value == 7
    assert diagnostics.input_tokens is diagnostics.output_tokens is None


def test_unsafe_reason_and_token_shapes_cannot_become_diagnostic_labels():
    body = envelope(
        status="incomplete",
        incomplete_details={"reason": "secret-provider-text"},
        usage={"input_tokens": True, "output_tokens": -1},
    )
    with pytest.raises(StructuredResponseFailure) as failure:
        asyncio.run(call(body))
    assert failure.value.diagnostics.incomplete_reason == "other"
    assert failure.value.diagnostics.input_tokens is None
    assert failure.value.diagnostics.output_tokens is None


def test_single_assessment_uses_strict_schema_and_keeps_usage():
    assessment, diagnostics = asyncio.run(call(envelope(), parser=parse_single_structured_response))
    assert assessment == ExampleOutput(value=7)
    assert diagnostics.input_tokens == 37


@pytest.mark.parametrize(("body", "code"), [
    (envelope(status="incomplete"), "response_not_completed"),
    (envelope(output=[]), "structured_output_missing"),
    (envelope(output=[*envelope()["output"], {"type": "function_call"}]), "unexpected_tool_output"),
    (envelope(output=envelope()["output"] * 2), "structured_output_invalid"),
    (envelope(output=[envelope()["output"][0] | {"role": "user"}]), "structured_output_invalid"),
    (envelope(output=[envelope()["output"][0] | {"status": "in_progress"}]), "structured_output_invalid"),
    (envelope(output=[{"type": "message", "content": [{"type": "refusal"}]}]), "response_refused"),
    (envelope('{"value":"invalid"}'), "structured_output_invalid"),
])
def test_single_assessment_rejects_nonfinal_or_invalid_output(body, code):
    with pytest.raises(StructuredResponseFailure, match=code):
        asyncio.run(call(body, parser=parse_single_structured_response))
