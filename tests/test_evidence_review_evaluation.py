import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from openai.types.responses.response_function_tool_call import ResponseFunctionToolCall

from app.analyzers.structured_response import ResponseDiagnostics
from app.models import SecurityAssessment
from scripts import bounded_llm_requests as bounded
from scripts import evaluate_evidence_review_llm as evaluation


@pytest.mark.parametrize("suite", ["execution", "session"])
def test_actual_oidc_paired_runner_reads_tools_and_retains_complete_denominators(
    tmp_path, monkeypatch, suite
):
    monkeypatch.setattr(
        evaluation, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-test-placeholder"}
    )
    calls = []

    async def fake(client, **kwargs):
        calls.append(kwargs)
        is_agent = "allow_tool_calls" in kwargs
        tool_seen = any(i.get("type") == "function_call_output" for i in kwargs["input"])
        if is_agent and not tool_seen:
            result = SimpleNamespace(
                output=[
                    ResponseFunctionToolCall(
                        type="function_call",
                        name="read_bound_execution_evidence"
                        if suite == "execution"
                        else "read_current_session_history",
                        arguments="{}",
                        call_id="local-call",
                        id="local-function",
                        status="completed",
                    )
                ],
                output_parsed=None,
            )
        else:
            data = json.loads(kwargs["input"][1]["content"])
            assert "truth" not in data and "ground_truth" not in data
            result = SimpleNamespace(
                output=[],
                output_parsed=SecurityAssessment(
                    risk_score=0,
                    risk_level="LOW",
                    violation_type="NORMAL",
                    rationale="Mocked provider validates plumbing only",
                    evidence=["device.managed"],
                    recommended_action="HOLD_FOR_REVIEW",
                    confidence=0.8,
                    requires_human_review=True,
                ),
                model="local-mock",
            )
        return result, ResponseDiagnostics("completed", input_tokens=100, output_tokens=100)

    monkeypatch.setattr(bounded, "parse_structured_response", fake)
    result = evaluation.run(
        tmp_path / "run",
        "unused",
        stop_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        suite=suite,
    )
    assert result["completed"] and result["attempts"] == len(calls) == 36
    assert result["real_loopback_jwks_fetches"] >= 1
    assert result["principal_injected"] is False and result["all_state_reads_unchanged"]
    assert all(r["snapshot_audited"] and r["trace_audited"] for r in result["rows"])
    assert all(
        r["response"]["llm_trace"]["provider_calls"] == 2
        for r in result["rows"]
        if r["arm"] == "agent"
    )
    for path in (tmp_path / "run").rglob("*.json*"):
        assert "Bearer " not in path.read_text(encoding="utf-8")


def test_budget_stop_attempts_nothing_and_preserves_all_24_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(
        evaluation, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-test-placeholder"}
    )

    async def forbidden(*args, **kwargs):
        raise AssertionError("paid request forbidden")

    monkeypatch.setattr(bounded, "parse_structured_response", forbidden)
    result = evaluation.run(
        tmp_path / "run",
        "unused",
        max_budget=0.00001,
        stop_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    )
    assert not result["completed"] and result["attempts"] == 0
    for group in result["metrics"].values():
        assert group["FP"] == 4 and group["FN"] == 8 and group["unknown_or_error"] == 12
