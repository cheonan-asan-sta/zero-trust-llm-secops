import json
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from app import main
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.behavior_context_models import ApprovalCreate, ContextRevocation
from app.config import Settings
from app.models import SecurityAssessment
from app.security import get_principal
from app.services.execution_analysis_evidence import collect_session_execution_evidence
from app.services.trusted_signals import SignalRejected
from tests import test_behavior_context_integration as context_cases


@pytest.fixture
def execution_lab(tmp_path, monkeypatch):
    lab = context_cases.context_lab.__wrapped__(tmp_path, monkeypatch)
    signals = {}
    evaluate = lab.operations.evaluate_signed

    def record(signal, *args, **kwargs):
        signals[signal.session_id] = signal
        return evaluate(signal, *args, **kwargs)

    monkeypatch.setattr(lab.operations, "evaluate_signed", record)
    lab.signals = signals
    return lab


def collect(lab, target, offset=6):
    signal = lab.signals[target.session.session.session_id]
    result = collect_session_execution_evidence(
        lab.operations,
        lab.service,
        signal,
        lab.operator,
        target.id,
        now=lab.at(offset),
    )
    return result, result.for_event(signal.event, now=lab.at(offset))


def test_reads_real_verified_execution_and_policy_without_admitting_capture(execution_lab):
    lab = execution_lab
    lab.baseline()
    target = lab.capture("review-target", 4)
    before = lab.store.read(lab.operator.tenant_id)
    journal = lab.operations.journal_status()
    context, facts = collect(lab, target)
    execution = facts["execution"]
    assert execution["observation_status"] == "complete"
    assert execution["observed_actor"] == lab.policy()["actor"]
    assert execution["observed_destinations"] == lab.policy()["destinations"]
    assert execution["policy_count"] == 1 and execution["unresolved_execution_policy_count"] == 0
    assert execution["exact_field_comparisons"][0]["one_coherent_policy_matches"]
    assert execution["comparison_scope_complete"]
    assert execution["reviewed_execution_policies"][0]["execution_policy"] == lab.policy()
    assert context.expires_at == lab.at(60)  # approval expires before session proof
    assert "verdict" not in json.dumps(facts)
    assert "signature" not in execution
    assert "grant_token" not in json.dumps(facts)
    assert lab.store.read(lab.operator.tenant_id) == before
    assert lab.operations.journal_status() == journal
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "normal"


@pytest.mark.parametrize("missing", ["actor", "destinations", "all"])
def test_missing_execution_facts_stay_unknown_not_invented_from_policy(execution_lab, missing):
    lab = execution_lab
    lab.baseline()
    target = lab.capture("missing-" + missing, 4, execution=False)
    if missing != "all":
        lab.service.accept_execution_evidence(
            lab.evidence(target, **{missing: None}), lab.analyst, now=lab.at(4)
        )
    _, facts = collect(lab, target)
    observed = facts["execution"]
    assert observed["observation_status"] == ("missing" if missing == "all" else "incomplete")
    assert observed["observed_actor"] is observed["observed_destinations"] is None
    assert observed["policy_count"] == 1


def test_conflicting_signed_reports_never_choose_a_favorable_actor(execution_lab):
    lab = execution_lab
    lab.baseline()
    target = lab.capture("conflict-target", 4)
    lab.service.accept_execution_evidence(
        lab.evidence(
            target,
            evidence_id="other-proof",
            actor=lab.policy()["actor"] | {"workload_id": "different-job"},
        ),
        lab.analyst,
        now=lab.at(4),
    )
    _, facts = collect(lab, target)
    assert facts["execution"]["observation_status"] == "conflict"
    assert facts["execution"]["observed_actor"] is None


@pytest.mark.parametrize("kind", ["approval", "baseline"])
def test_revoked_reviewed_context_is_not_forwarded_as_approved_policy(execution_lab, kind):
    lab = execution_lab
    lab.baseline()
    target = lab.capture("revoked-review", 4)
    identifier = "approval-a" if kind == "approval" else "baseline-a"
    lab.service.revoke(
        kind,
        identifier,
        ContextRevocation(reason="Withdraw local review"),
        lab.operator,
        now=lab.at(5),
    )
    _, facts = collect(lab, target)
    assert facts["execution"]["policy_count"] == 0
    assert facts["execution"]["observation_status"] == "complete"


def test_legacy_alternative_policy_remains_explicitly_unresolved(execution_lab):
    lab = execution_lab
    lab.baseline()
    lab.service.create_approval(
        ApprovalCreate(
            approval_id="legacy-alternative",
            baseline_id="baseline-a",
            valid_from=lab.at(3),
            valid_until=lab.at(60),
            note="Legacy review with unknown executable policy",
        ),
        lab.operator,
        now=lab.at(3),
    )
    target = lab.capture("legacy-target", 4)
    _, facts = collect(lab, target)
    assert facts["execution"]["policy_count"] == 1
    assert facts["execution"]["unresolved_execution_policy_count"] == 1
    assert facts["execution"]["comparison_scope_complete"] is False


def test_reading_does_not_consume_approval_quota_for_another_capture(execution_lab):
    lab = execution_lab
    lab.baseline()
    target = lab.capture("read-only", 4)
    collect(lab, target)
    collect(lab, target)
    other = lab.capture("other-candidate", 5)
    assert lab.service.evaluate(other.id, lab.analyst, now=lab.at(6))["verdict"] == "normal"
    _, facts = collect(lab, target)
    assert facts["execution"]["policy_count"] == 0  # only an actual evaluation used the quota


def test_capture_cannot_be_reused_for_a_different_current_session(execution_lab):
    lab = execution_lab
    lab.baseline()
    first, second = lab.capture("first-target", 4), lab.capture("second-target", 5)
    with pytest.raises(SignalRejected):
        collect_session_execution_evidence(
            lab.operations,
            lab.service,
            lab.signals[second.session.session.session_id],
            lab.operator,
            first.id,
            now=lab.at(6),
        )


@pytest.mark.parametrize("source", ["behavior", "execution"])
def test_withdrawn_collectors_cannot_keep_positive_execution_facts(execution_lab, source):
    lab = execution_lab
    lab.baseline()
    target = lab.capture("withdrawn-target", 4)
    next(s for s in lab.registry["sources"] if s["source_id"] == source)["enabled"] = False
    lab.save()
    if source == "behavior":
        with pytest.raises(SignalRejected):
            collect(lab, target)
    else:
        _, facts = collect(lab, target)
        assert facts["execution"]["observation_status"] == "stale"
        assert facts["execution"]["observed_actor"] is None


def local_assessment():
    return SecurityAssessment(
        risk_score=0,
        risk_level="LOW",
        violation_type="NORMAL",
        rationale="검증된 실행 관측 비교 시험",
        recommended_action="HOLD_FOR_REVIEW",
        confidence=0.8,
        evidence=["verified_session.execution.observed_actor.workload_id"],
        requires_human_review=False,
    )


@pytest.fixture
def execution_route(execution_lab, monkeypatch):
    lab = execution_lab
    lab.baseline()
    target = lab.capture("http-target", 4)
    lab.clock.now = lab.at(6)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return lab.clock.now.astimezone(tz) if tz else lab.clock.now.replace(tzinfo=None)

    monkeypatch.setattr("app.services.session_analysis_evidence.datetime", Clock)
    monkeypatch.setattr("app.services.execution_analysis_evidence.datetime", Clock)
    analyzer = Mock()
    analyzer.name = "openai"
    analyzer.analyze_with_evidence = AsyncMock(return_value=local_assessment())
    audit = Mock()
    audit.save = AsyncMock()
    monkeypatch.setattr(main, "zero_trust_operations", lab.operations)
    monkeypatch.setattr(main, "behavior_context_service", lab.service)
    monkeypatch.setattr(main, "get_analyzer", lambda: analyzer)
    monkeypatch.setattr(main, "get_settings", lambda: Settings(openai_prompt_mode="grounded"))
    monkeypatch.setattr(main, "audit_store", audit)
    assert get_principal not in main.app.dependency_overrides
    main.app.dependency_overrides[get_principal] = lambda: lab.operator
    try:
        with TestClient(main.app) as client:
            yield lab, target, client, analyzer, audit
    finally:
        main.app.dependency_overrides.pop(get_principal, None)


def post_route(fixture, capture_id=None):
    lab, target, client, _, _ = fixture
    signal = lab.signals[target.session.session.session_id]
    return client.post(
        "/analysis/verified-session",
        params={"behavior_capture_id": capture_id or target.id},
        json=signal.model_dump(mode="json"),
    )


def test_execution_query_audits_exact_read_only_server_facts(execution_route):
    lab, _, _, analyzer, audit = execution_route
    before, journal = lab.store.read(lab.operator.tenant_id), lab.operations.journal_status()
    response = post_route(execution_route)
    assert response.status_code == 200
    facts = response.json()["verification_context"]
    assert facts["execution"]["observation_status"] == "complete"
    assert response.json()["assessment"]["requires_human_review"]
    analyzer.analyze_with_evidence.assert_awaited_once()
    assert audit.save.call_args.args[0].verification_context == facts
    assert lab.store.read(lab.operator.tenant_id) == before
    assert lab.operations.journal_status() == journal


@pytest.mark.parametrize("change", ["approval", "execution_key", "conflicting_report", "quota"])
def test_changed_execution_authority_during_provider_call_cannot_publish_success(
    execution_route, change
):
    lab, target, _, analyzer, audit = execution_route
    other = lab.capture("quota-other", 5) if change == "quota" else None

    async def change_state(event, context):
        if change == "approval":
            lab.service.revoke(
                "approval",
                "approval-a",
                ContextRevocation(reason="Withdraw during model request"),
                lab.operator,
                now=lab.at(6),
            )
        elif change == "execution_key":
            next(s for s in lab.registry["sources"] if s["source_id"] == "execution")["enabled"] = (
                False
            )
            lab.save()
        elif change == "conflicting_report":
            lab.service.accept_execution_evidence(
                lab.evidence(
                    target,
                    evidence_id="mid-call-report",
                    actor=lab.policy()["actor"] | {"workload_id": "different-job"},
                ),
                lab.analyst,
                now=lab.at(6),
            )
        else:
            assert lab.service.evaluate(other.id, lab.analyst, now=lab.at(6))["verdict"] == "normal"
        return local_assessment()

    analyzer.analyze_with_evidence.side_effect = change_state
    response = post_route(execution_route)
    assert response.status_code == 502
    analyzer.analyze_with_evidence.assert_awaited_once()
    audit.save.assert_not_awaited()


def test_foreign_capture_query_never_reaches_provider(execution_route):
    lab, _, _, analyzer, audit = execution_route
    other = lab.capture("foreign-http-target", 5)
    response = post_route(execution_route, other.id)
    assert response.status_code == 401
    analyzer.analyze_with_evidence.assert_not_awaited()
    audit.save.assert_not_awaited()


def test_adapter_adds_execution_contract_and_uses_exact_observation_paths(execution_route):
    lab, target, _, _, _ = execution_route
    context, _ = collect(lab, target)
    signal = lab.signals[target.session.session.session_id]
    import asyncio

    with patch(
        "app.analyzers.openai_analyzer.parse_structured_response", new_callable=AsyncMock
    ) as parse:
        parse.return_value = (Mock(output_parsed=local_assessment()), None)
        adapter = OpenAIAnalyzer(
            Settings(openai_api_key="local-test-placeholder", openai_prompt_mode="grounded")
        )
        result = asyncio.run(adapter.analyze_with_evidence(signal.event, context))
        kwargs = parse.call_args.kwargs
        assert "ONE coherent reviewed policy" in kwargs["input"][0]["content"]
        catalog = json.loads(kwargs["input"][1]["content"])["evidence_catalog"]
        assert catalog["verified_session.execution.observed_actor.workload_id"] == "reviewed-job"
        assert "signature" not in json.dumps(
            catalog["verified_session.execution.reviewed_execution_policies"]
        )
        assert result.requires_human_review
