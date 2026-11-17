import asyncio
import hashlib
import json
from contextlib import contextmanager
from dataclasses import replace

import httpx
import pytest
from openai import AsyncOpenAI

from app import main
from app.analyzers.evidence_agent import EvidenceReviewAgent
from app.config import Settings
from app.models import SecurityAssessment
from app.security import Role, get_principal
from tests import test_execution_analysis_evidence as execution_cases
from tests.test_structured_response import envelope


def tool_response(name="read_bound_execution_evidence", arguments="{}", call_id="call-local"):
    return envelope(
        output=[
            {
                "type": "function_call",
                "name": name,
                "arguments": arguments,
                "call_id": call_id,
                "id": "fc-local",
                "status": "completed",
            }
        ]
    )


def final_response():
    assessment = SecurityAssessment(
        risk_score=0,
        risk_level="LOW",
        violation_type="NORMAL",
        rationale="가짜 제공자 경로 시험",
        evidence=["device.managed"],
        recommended_action="HOLD_FOR_REVIEW",
        confidence=0.8,
        requires_human_review=True,
    )
    return envelope(assessment.model_dump_json())


@pytest.fixture
def agent_route(tmp_path, monkeypatch):
    lab = execution_cases.execution_lab.__wrapped__(tmp_path, monkeypatch)
    wrapped = contextmanager(execution_cases.execution_route.__wrapped__)
    with wrapped(lab, monkeypatch) as values:
        _, target, client, _, audit = values
        requests, responses = [], []

        async def handle(request):
            requests.append(json.loads(request.content))
            if not responses:
                raise AssertionError("unexpected_provider_request")
            body = responses.pop(0)
            if callable(body):
                body = body()
            return httpx.Response(200, json=body)

        config = Settings(
            _env_file=None,
            analyzer_mode="openai",
            openai_api_key="local-test-placeholder",
            openai_prompt_mode="grounded",
            openai_evidence_agent_enabled=True,
            openai_reasoning_effort="low",
            openai_max_output_tokens=2400,
        )
        provider = AsyncOpenAI(
            api_key="local-test-placeholder",
            max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
        )
        agent = EvidenceReviewAgent(config, client=provider)
        monkeypatch.setattr(main, "get_settings", lambda: config)
        monkeypatch.setattr(main, "get_evidence_agent", lambda: agent)
        try:
            yield lab, target, client, audit, requests, responses, config
        finally:
            client.portal.call(agent.close)


def post(fixture, *, capture=True, signature=None):
    lab, target, client, _, _, _, _ = fixture
    signal = lab.signals[target.session.session.session_id]
    if signature:
        signal = signal.model_copy(update={"signature": signature})
    return client.post(
        "/analysis/evidence-review",
        json=signal.model_dump(mode="json"),
        params={"behavior_capture_id": target.id} if capture else {},
    )


def test_tool_choice_retrieves_only_bound_read_data_and_audits_trace(agent_route):
    lab, _, _, audit, requests, responses, _ = agent_route
    before, journal = lab.store.read(lab.operator.tenant_id), lab.operations.journal_status()
    responses[:] = [tool_response(), final_response()]
    response = post(agent_route)
    assert response.status_code == 200, response.json()
    trace = response.json()["llm_trace"]
    assert trace["provider_calls"] == len(requests) == 2
    assert trace["tools_executed"] == ["read_bound_execution_evidence"]
    assert trace["write_tools_available"] is False
    initial_catalog = json.loads(requests[0]["input"][1]["content"])["evidence_catalog"]
    assert not any(k.startswith("verified_session.execution.") for k in initial_catalog)
    result = next(i for i in requests[1]["input"] if i.get("type") == "function_call_output")
    assert (
        "verified_session.execution.observed_actor.workload_id"
        in json.loads(result["output"])["evidence_catalog"]
    )
    assert (
        trace["tool_results"][0]["result_sha256"]
        == hashlib.sha256(result["output"].encode()).hexdigest()
    )
    assert "parsed_arguments" not in json.dumps(requests[1]["input"])
    assert all(r["store"] is False and r["parallel_tool_calls"] is False for r in requests)
    assert audit.save.call_args.args[0].llm_trace == trace
    assert "execution" in response.json()["verification_context"]
    assert lab.store.read(lab.operator.tenant_id) == before
    assert lab.operations.journal_status() == journal


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("revoke_session", "{}"),
        ("read_bound_execution_evidence", '{"session_id":"other"}'),
        ("read_current_session_history", '{"tenant":"other"}'),
        ("read_bound_execution_evidence", "[]"),
    ],
)
def test_unapproved_tool_or_arguments_never_read_or_write_a_foreign_target(
    agent_route, name, arguments
):
    lab, _, _, audit, requests, responses, _ = agent_route
    before = lab.store.read(lab.operator.tenant_id)
    responses[:] = [tool_response(name, arguments)]
    assert post(agent_route).status_code == 502
    assert len(requests) == 1
    audit.save.assert_not_awaited()
    assert lab.store.read(lab.operator.tenant_id) == before


def test_unseen_execution_cannot_be_published_as_a_successful_review(agent_route):
    _, _, _, audit, requests, responses, _ = agent_route
    responses[:] = [final_response()]
    assert post(agent_route).status_code == 502
    assert len(requests) == 1
    audit.save.assert_not_awaited()


def test_two_distinct_reads_then_one_final_response_is_the_hard_limit(agent_route):
    _, _, _, _, requests, responses, _ = agent_route
    responses[:] = [
        tool_response(),
        tool_response("read_current_session_history", call_id="call-history"),
        final_response(),
    ]
    response = post(agent_route)
    assert response.status_code == 200
    assert len(requests) == response.json()["llm_trace"]["provider_calls"] == 3
    assert requests[-1]["tool_choice"] == "none"
    history = response.json()["verification_context"]["history"]
    assert history["total_records"] >= 1
    assert "grant_token" not in json.dumps(history)


def test_repeat_request_stops_without_another_provider_round(agent_route):
    _, _, _, audit, requests, responses, _ = agent_route
    responses[:] = [tool_response(), tool_response(call_id="repeat-call")]
    assert post(agent_route).status_code == 502
    assert len(requests) == 2
    audit.save.assert_not_awaited()


def test_authority_withdrawn_during_tool_proposal_never_reaches_tool_output(agent_route):
    lab, _, _, audit, requests, responses, _ = agent_route

    def withdraw():
        next(s for s in lab.registry["sources"] if s["source_id"] == "execution")["enabled"] = False
        lab.save()
        return tool_response()

    responses[:] = [withdraw]
    assert post(agent_route).status_code == 502
    assert len(requests) == 1
    audit.save.assert_not_awaited()


def test_bad_signature_and_disabled_feature_spend_no_provider_calls(agent_route):
    _, _, _, audit, requests, _, config = agent_route
    assert post(agent_route, signature="A" * 86).status_code == 401
    assert not requests
    config.openai_evidence_agent_enabled = False
    assert post(agent_route).status_code == 503
    assert not requests
    audit.save.assert_not_awaited()


def test_no_optional_execution_can_finish_without_any_retrieval(agent_route):
    _, _, _, _, requests, responses, _ = agent_route
    responses[:] = [final_response()]
    result = post(agent_route, capture=False)
    assert result.status_code == 200
    assert result.json()["llm_trace"]["tools_executed"] == []
    assert len(requests) == 1


def test_hybrid_mode_cannot_clear_existing_rule_detection(agent_route, monkeypatch):
    _, _, _, _, _, responses, config = agent_route
    config.analyzer_mode = "hybrid"
    baseline = SecurityAssessment(
        risk_score=80,
        risk_level="HIGH",
        violation_type="ACCESS_POLICY_VIOLATION",
        rationale="Existing independent rule observation",
        evidence=["device.managed"],
        recommended_action="HOLD_FOR_REVIEW",
        confidence=0.9,
        requires_human_review=True,
    )
    monkeypatch.setattr(main.RuleBasedAnalyzer, "assess", lambda *_: baseline)
    responses[:] = [tool_response(), final_response()]
    response = post(agent_route)
    assert response.status_code == 200
    body = response.json()
    assert body["assessment"]["violation_type"] == "ACCESS_POLICY_VIOLATION"
    assert body["assessment"]["risk_score"] >= 80
    assert body["llm_trace"]["model_assessment_before_rule_merge"]["violation_type"] == "NORMAL"
    assert body["llm_trace"]["rule_baseline_preserved"] is True
    assert body["assessment"]["requires_human_review"] is True


def test_production_disabled_route_cannot_initialize_a_paid_agent(agent_route, monkeypatch):
    _, _, _, audit, requests, _, _ = agent_route
    monkeypatch.setattr(main, "zero_trust_operations", None)
    monkeypatch.setattr(main, "get_evidence_agent", lambda: pytest.fail("paid factory forbidden"))
    assert post(agent_route).status_code == 404
    assert not requests
    audit.save.assert_not_awaited()


def test_model_cannot_cite_a_field_that_was_not_disclosed(agent_route):
    _, _, _, audit, requests, responses, _ = agent_route
    assessment = SecurityAssessment(
        risk_score=0,
        risk_level="LOW",
        violation_type="NORMAL",
        rationale="Undisclosed citation",
        evidence=["verified_session.execution.observed_actor.workload_id"],
        recommended_action="HOLD_FOR_REVIEW",
        confidence=0.8,
        requires_human_review=True,
    )
    responses[:] = [envelope(assessment.model_dump_json())]
    assert post(agent_route, capture=False).status_code == 502
    assert len(requests) == 1
    audit.save.assert_not_awaited()


def test_total_deadline_cancels_review_and_releases_capacity_without_audit(
    agent_route, monkeypatch
):
    _, _, _, audit, requests, _, config = agent_route
    config.openai_evidence_review_timeout_seconds = 0.02  # Test-only short assignment.
    cancelled = []

    async def blocked(*_):
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.append(True)

    agent = main.get_evidence_agent()
    monkeypatch.setattr(agent, "review", blocked)
    capacity = main.analysis_capacity._value
    assert post(agent_route).status_code == 502
    assert cancelled == [True] and not requests
    assert main.analysis_capacity._value == capacity
    audit.save.assert_not_awaited()


def test_viewer_role_cannot_reach_paid_factory(agent_route, monkeypatch):
    lab, _, _, audit, requests, _, _ = agent_route
    viewer = replace(lab.operator, roles=frozenset({Role.VIEWER}))
    with monkeypatch.context() as local_patch:
        local_patch.setitem(main.app.dependency_overrides, get_principal, lambda: viewer)
        local_patch.setattr(main, "get_evidence_agent", lambda: pytest.fail("paid factory forbidden"))
        assert post(agent_route).status_code == 403
    assert not requests
    audit.save.assert_not_awaited()


def test_foreign_capture_never_reaches_model_or_discloses_context(agent_route, monkeypatch):
    lab, target, client, audit, requests, _, _ = agent_route
    foreign = lab.capture("other-session-capture", 5)
    signal = lab.signals[target.session.session.session_id]
    monkeypatch.setattr(main, "get_evidence_agent", lambda: pytest.fail("paid factory forbidden"))
    response = client.post(
        "/analysis/evidence-review",
        json=signal.model_dump(mode="json"),
        params={"behavior_capture_id": foreign.id},
    )
    assert response.status_code == 401 and not requests
    assert foreign.id not in response.text
    audit.save.assert_not_awaited()
