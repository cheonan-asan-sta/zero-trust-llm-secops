import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import SecurityEvent
from app.scenarios import SCENARIOS, synthetic_events
from app.services.policy import response_preview
from app.services.scenario_evaluator import evaluate_scenarios


def test_structured_conditions_identify_each_synthetic_scenario() -> None:
    for event in synthetic_events():
        assert event.ground_truth is not None
        evaluation = evaluate_scenarios(event, SCENARIOS)
        exact_ids = {match.scenario_id for match in evaluation.matches if match.matched}
        assert event.ground_truth.scenario_id in exact_ids
        assert evaluation.best_match == event.ground_truth.scenario_id


def test_approved_exception_has_auditable_scope() -> None:
    event = synthetic_events()[2]
    exception = event.behavior.policy_exception

    assert event.behavior.policy_exception_approved is True
    assert exception is not None
    assert exception.exception_id == "EXC-BACKUP-01"
    assert exception.approved_by == "security-manager"
    assert exception.scope.max_download_volume_mb == 1000


def test_expired_policy_exception_is_rejected() -> None:
    event_data = synthetic_events()[2].model_dump(mode="json")
    exception = event_data["behavior"]["policy_exception"]
    exception["valid_from"] = "2026-08-01T00:00:00+09:00"
    exception["valid_until"] = "2026-08-31T23:59:59+09:00"

    with pytest.raises(ValidationError, match="does not apply"):
        SecurityEvent.model_validate(event_data)


def test_download_volume_on_non_download_event_is_rejected() -> None:
    event_data = synthetic_events()[0].model_dump(mode="json")
    event_data["behavior"]["download_volume_mb"] = 10

    with pytest.raises(ValidationError, match="must be zero"):
        SecurityEvent.model_validate(event_data)


def test_policy_preview_reports_validated_exception() -> None:
    event = synthetic_events()[2]
    assessment = asyncio.run(RuleBasedAnalyzer().analyze(event))
    decision = response_preview(assessment, event)

    assert decision.exception_id == "EXC-BACKUP-01"
    assert "scoped-exception-validated" in decision.controls_applied


def test_lambda_template_avoids_reserved_environment_variables() -> None:
    template = Path("infra/lambda.yaml").read_text(encoding="utf-8")

    assert "AWS_REGION:" not in template


def test_deployment_builds_lambda_compatible_image_and_stops_on_native_errors() -> None:
    script = Path("scripts/deploy-aws.ps1").read_text(encoding="utf-8")

    assert "$PSNativeCommandUseErrorActionPreference = $true" in script
    assert "--platform linux/amd64" in script
    assert "--provenance=false" in script
