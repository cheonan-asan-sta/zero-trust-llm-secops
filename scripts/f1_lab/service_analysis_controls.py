"""Free contract controls reusable with a real managed systemd execution.

Uses the real OpenAI adapter/prompt/schema code with an explicitly stubbed
structured response boundary. It never measures model quality or calls an API.
"""

import asyncio
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.models import SecurityAssessment
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.service_analysis_evidence import (
    collect_service_analysis_evidence,
    review_service_execution,
)


def run(lab, request, access, receipt, event, proofs, passed):
    before = hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest()
    journal_before = lab.operations.journal_status()
    signal = lab.signals[access.session_id]
    context = collect_service_analysis_evidence(
        lab.operations,
        signal,
        lab.principal,
        lab.broker.joiner,
        lab.broker.registry,
        request,
        event,
        proofs,
        receipt,
    )
    facts = context.for_event(signal.event)
    require(
        facts["native_execution"]["app_access"]["session_version"] == 1
        and facts["native_execution"]["invocation_id"] == event.invocation_id
        and facts["session"]["approval_currently_usable"] is False,
        "native_analysis_exact_session_and_consumed_grant",
    )
    passed("native_llm_context_binds_actual_exec_and_consumed_app_grant")
    reply = SecurityAssessment(
        risk_score=10,
        risk_level="LOW",
        violation_type="NORMAL",
        confidence=0.8,
        rationale="연결된 실행 관측의 범위를 확인했습니다. 후속 행위는 확인하지 못했습니다.",
        evidence=["verified_session.native_execution.process.executable_sha256"],
        recommended_action="ALLOW",
        requires_human_review=False,
    )
    with patch(
        "app.analyzers.openai_analyzer.parse_structured_response", new_callable=AsyncMock
    ) as parse:
        parse.return_value = (SimpleNamespace(output_parsed=reply), None)
        adapter = OpenAIAnalyzer(
            Settings(
                openai_api_key="local-contract-stub-not-a-key",
                openai_prompt_mode="grounded",
            )
        )

        async def review():
            try:
                return await review_service_execution(adapter, signal, context)
            finally:
                await adapter._client.close()

        result = asyncio.run(review())
        require(
            parse.await_count == 1
            and "native_execution" in str(parse.call_args.kwargs["input"])
            and parse.call_args.kwargs["store"] is False,
            "native_analysis_existing_adapter_prompt_contract",
        )
        passed("native_llm_existing_openai_adapter_stubbed_without_api")
    require(
        result.violation_type == "NORMAL"
        and result.recommended_action == "HOLD_FOR_REVIEW"
        and result.requires_human_review,
        "native_analysis_advisory_guard",
    )
    passed("native_llm_preserves_classification_and_cannot_reissue_consumed_grant")
    context.verify_current()
    require(
        before == hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest()
        and journal_before == lab.operations.journal_status(),
        "native_analysis_read_only",
    )
    passed("native_llm_review_does_not_modify_evidence_clock_or_app_history")
