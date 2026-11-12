import asyncio
import json

import httpx
import pytest
from pydantic import ValidationError

from scripts import m6_shadow_assist as assist


def example_request():
    return assist.make_request("case-001", "unknown", [
        {"id": "e1", "kind": "missing_approval", "detail": "No approval was visible."},
    ])


@pytest.mark.parametrize("scope", ["request", "evidence"])
def test_scoring_fields_cannot_be_serialized(scope):
    request = example_request()
    target = request if scope == "request" else request["evidence"][0]
    target["expected_label"] = "threat"

    with pytest.raises(ValidationError):
        assist.request_body(request, count=False)


def test_token_count_and_generation_use_same_evidence_without_storing_or_tools():
    request = example_request()
    bodies = []

    def respond(wire_request):
        assert wire_request.url.host == "api.openai.com"
        body = json.loads(wire_request.content)
        bodies.append(body)
        assert json.loads(body["input"][0]["content"]) == request
        assert "tools" not in body
        if wire_request.url.path.endswith("/input_tokens"):
            return httpx.Response(200, json={"input_tokens": 121})
        assert wire_request.url.path == "/v1/responses"
        answer = {"priority": "medium", "claims": [
            {"evidence_id": "e1", "fact_code": "missing_approval"},
        ]}
        return httpx.Response(200, headers={"x-request-id": "mock-run-1"}, json={
            "model": "gpt-5.4-mini-2026-03-17", "status": "completed",
            "usage": {"input_tokens": 121, "output_tokens": 18},
            "output": [{"type": "message", "role": "assistant", "content": [
                {"type": "output_text", "text": json.dumps(answer)},
            ]}],
        })

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            count = await assist.count_input(client, "dummy", request)
            receipt = await assist.infer(client, "dummy", request)
        return count, receipt

    count, receipt = asyncio.run(run())
    assert count == 121
    assert receipt["status"] == "completed"
    assert receipt["answer"]["priority"] == "medium"
    assert receipt["request_id"] == "mock-run-1"
    assert bodies[1] == bodies[0] | {
        "store": False, "service_tier": "default", "max_output_tokens": assist.OUTPUT_LIMIT,
    }


@pytest.mark.parametrize(("answer", "status"), [
    ({"priority": "medium", "claims": [], "rule_verdict": "normal"}, "response_error"),
    ({"priority": "medium", "claims": [{"evidence_id": "invented", "fact_code": "x"}]}, "completed"),
])
def test_model_cannot_change_verdict_and_invented_claims_reach_grounding_scorer(answer, status):
    def respond(_):
        return httpx.Response(200, json={
            "model": assist.MODEL, "status": "completed",
            "output": [{"type": "message", "role": "assistant", "content": [
                {"type": "output_text", "text": json.dumps(answer)},
            ]}],
        })

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await assist.infer(client, "dummy", example_request())

    receipt = asyncio.run(run())
    assert receipt["status"] == status
    assert receipt["answer"] == (answer if status == "completed" else None)
