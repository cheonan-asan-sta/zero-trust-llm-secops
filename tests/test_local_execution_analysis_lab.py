import json

from scripts.local_execution_analysis_lab import EXECUTION_SCENARIOS, LocalExecutionAnalysisLab


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
