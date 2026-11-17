import json

from app.services.execution_analysis_evidence import collect_session_execution_evidence
from scripts.local_execution_analysis_lab import (
    EXECUTION_SCENARIOS,
    GROUNDING_SCENARIOS,
    LocalExecutionAnalysisLab,
)


def test_current_time_lab_uses_predeclared_scope_cases_and_keeps_labels_out_of_facts(tmp_path):
    lab = LocalExecutionAnalysisLab(tmp_path / "lab")
    lab.prepare()
    assert len(EXECUTION_SCENARIOS) == 12
    assert sum(truth for _, truth in EXECUTION_SCENARIOS) == 8
    for name, threat in EXECUTION_SCENARIOS:
        signal, capture, context = lab.create_execution_case(name)
        facts = context.for_event(signal.event)
        assert facts["execution"]["policy_count"] == 2
        assert facts["execution"]["observation_status"] == "complete"
        assert facts["execution"]["approval_quota_consumed_by_this_read"] is False
        assert facts["execution"]["comparison_scope_complete"]
        assert any(
            c["one_coherent_policy_matches"] for c in facts["execution"]["exact_field_comparisons"]
        ) is (not threat)
        assert "verdict" not in json.dumps(facts)
        assert "truth" not in json.dumps(facts)
        assert name not in capture.capture_id  # Opaque random IDs never encode case outcomes.
        assert (
            capture.activity.events[0].timestamp
            >= lab.service.history(signal.session_id, lab.principal)[-1].evaluated_at
        )
        result = lab.behavior.evaluate(capture.capture_id, lab.principal)
        assert result["verdict"] == ("threat" if threat else "normal"), name


def test_grounding_cases_keep_missing_conflicting_and_unresolved_facts_separate(tmp_path):
    lab = LocalExecutionAnalysisLab(tmp_path / "lab")
    lab.prepare()
    statuses = ["missing", "incomplete", "incomplete", "conflict", "complete", "complete"]
    for (name, label), status in zip(GROUNDING_SCENARIOS, statuses, strict=True):
        assert label is None  # These are uncertainty cases, not binary threat labels.
        signal, capture, context = lab.create_grounding_case(name)
        execution = context.for_event(signal.event)["execution"]
        assert execution["observation_status"] == status
        assert execution["comparison_scope_complete"] is False
        if status != "complete":
            assert execution["observed_actor"] is execution["observed_destinations"] is None
        if name == "unresolved_legacy_scope":
            assert execution["unresolved_execution_policy_count"] == 1
        if name == "no_active_reviewed_policy":
            assert execution["policy_count"] == execution["unresolved_execution_policy_count"] == 0
        before, journal = (
            lab.behavior.store.read(lab.principal.tenant_id),
            lab.service.journal_status(),
        )
        collect_session_execution_evidence(
            lab.service, lab.behavior, signal, lab.principal, capture.capture_id
        )
        assert lab.behavior.store.read(lab.principal.tenant_id) == before
        assert lab.service.journal_status() == journal
