"""Invocation isolation only; contexts here are test doubles, not provenance proof."""

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
from openai import AsyncOpenAI

from app.analyzers.evidence_agent import EvidenceReviewAgent
from app.config import Settings
from app.models import SecurityAssessment
from app.scenarios import synthetic_events
from app.services.session_analysis_evidence import VerifiedSessionContext, event_digest
from tests.test_evidence_review_agent import tool_response
from tests.test_structured_response import envelope


def test_one_cached_agent_keeps_simultaneous_evidence_histories_and_receipts_separate():
    async def run():
        arrived = set()
        both = asyncio.Event()
        requests = []

        async def handle(request):
            payload = json.loads(request.content)
            requests.append(payload)
            catalog = json.loads(payload["input"][1]["content"])["evidence_catalog"]
            marker = catalog["verified_session.session.marker"]
            other = "isolation-b" if marker == "isolation-a" else "isolation-a"
            assert other not in json.dumps(payload)
            output = next(
                (i for i in payload["input"] if i.get("type") == "function_call_output"), None
            )
            if output is None:
                arrived.add(marker)
                if len(arrived) == 2:
                    both.set()
                await asyncio.wait_for(both.wait(), timeout=5)
                body = tool_response()
            else:
                revealed = json.loads(output["output"])["evidence_catalog"]
                assert revealed["verified_session.execution.marker"] == marker
                assessment = SecurityAssessment(
                    risk_score=0,
                    risk_level="LOW",
                    violation_type="NORMAL",
                    rationale="Isolation transport test",
                    confidence=0.8,
                    recommended_action="HOLD_FOR_REVIEW",
                    requires_human_review=True,
                    evidence=["verified_session.execution.marker"],
                )
                body = envelope(assessment.model_dump_json())
            return httpx.Response(200, json=body)

        provider = AsyncOpenAI(
            api_key="local-mock-placeholder",
            max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        )
        agent = EvidenceReviewAgent(Settings(_env_file=None), client=provider)
        event = synthetic_events()[0]

        async def review(marker):
            context = VerifiedSessionContext(
                event_digest(event),
                datetime.now(UTC) + timedelta(seconds=30),
                json.dumps(
                    {"session": {"marker": marker}, "execution": {"marker": marker}}
                ).encode(),
            )
            return await agent.review(event, context, lambda: {"marker": marker})

        try:
            results = await asyncio.gather(review("isolation-a"), review("isolation-b"))
        finally:
            await agent.close()
        assert len(requests) == 4
        for index, marker in enumerate(("isolation-a", "isolation-b")):
            _, context, trace = results[index]
            assert context.for_event(event)["execution"]["marker"] == marker
            assert trace["provider_calls"] == 2
            assert trace["tools_executed"] == ["read_bound_execution_evidence"]
            assert len(trace["receipts"]) == len(trace["tool_results"]) + 1 == 2
        assert (
            results[0][2]["tool_results"][0]["result_sha256"]
            != results[1][2]["tool_results"][0]["result_sha256"]
        )

    asyncio.run(run())
