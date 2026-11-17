import json
from types import SimpleNamespace

from app.analyzers.structured_response import ResponseDiagnostics
from app.models import SecurityAssessment
from scripts import evaluate_execution_analysis_llm as evaluation


def test_runner_exercises_real_oidc_and_gateway_without_labels_in_model_input(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        evaluation, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-test-placeholder"}
    )
    attempts = []

    async def fake(client, **kwargs):
        attempts.append(kwargs)
        data = json.loads(kwargs["input"][1]["content"])
        catalog = data["evidence_catalog"]
        assert "truth" not in catalog and "ground_truth" not in catalog
        root = "verified_session.execution."
        violation = False
        if root + "observation_status" in catalog:
            actor = {
                name: catalog[root + "observed_actor." + name]
                for name in ("principal_id", "workload_id", "executable_sha256")
            }
            observed = {
                json.dumps(d, sort_keys=True) for d in catalog[root + "observed_destinations"]
            }
            policies = catalog[root + "reviewed_execution_policies"]
            violation = not any(
                actor == p["execution_policy"]["actor"]
                and observed
                <= {json.dumps(d, sort_keys=True) for d in p["execution_policy"]["destinations"]}
                for p in policies
            )
        assessment = SecurityAssessment(
            risk_score=35 if violation else 0,
            risk_level="MEDIUM" if violation else "LOW",
            violation_type="ACCESS_POLICY_VIOLATION" if violation else "NORMAL",
            rationale="가짜 제공자를 사용한 로컬 실행 경로 검증",
            evidence=["device.managed"],
            recommended_action="HOLD_FOR_REVIEW",
            confidence=0.8,
            requires_human_review=True,
        )
        return SimpleNamespace(output_parsed=assessment, model="local-test"), ResponseDiagnostics(
            "completed", input_tokens=100, output_tokens=100
        )

    monkeypatch.setattr(evaluation, "parse_structured_response", fake)
    result = evaluation.run(tmp_path / "run", "unused")
    assert result["completed"] and result["attempts"] == len(attempts) == 48
    assert result["real_loopback_jwks_fetches"] >= 1
    assert result["principal_injected"] is False
    assert result["all_state_reads_unchanged"]
    for repeat in result["by_repeat"].values():
        assert repeat["metrics"]["execution"]["TP"] == 8
        assert repeat["metrics"]["execution"]["TN"] == 4
        assert repeat["metrics"]["session"]["FN"] == 8
    for path in (tmp_path / "run").rglob("*.json*"):
        assert "Bearer " not in path.read_text(encoding="utf-8")


def test_budget_stop_has_no_paid_call_and_keeps_entire_cohort(tmp_path, monkeypatch):
    monkeypatch.setattr(
        evaluation, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-test-placeholder"}
    )

    async def forbidden(*args, **kwargs):
        raise AssertionError("provider must not be called")

    monkeypatch.setattr(evaluation, "parse_structured_response", forbidden)
    result = evaluation.run(tmp_path / "run", "unused", max_budget=0.0001)
    assert not result["completed"] and result["fatal"] == "budget_or_request_limit"
    assert result["attempts"] == 0 and result["known_usage_estimated_usd"] == 0
    for repeat in result["by_repeat"].values():
        for metrics in repeat["metrics"].values():
            assert metrics["unknown_or_error"] == 12
            assert metrics["FP"] == 4 and metrics["FN"] == 8
