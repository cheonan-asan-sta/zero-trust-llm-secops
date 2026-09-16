import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.models import PublicReplayDataset
from app.services.correlation import get_correlation_engine
from app.services.detection_quality import DetectionQualityService, get_detection_quality_service
from app.services.ocsf import get_ocsf_normalizer
from app.services.public_replay import PublicReplayService, get_public_replay_service
from app.services.sigma import get_sigma_engine

client = TestClient(app)


def test_detection_quality_report_meets_fail_closed_targets() -> None:
    report = get_detection_quality_service().evaluate("local")

    assert report.dataset_count == 3
    assert report.declared_record_count == 12
    assert report.parsed_record_count == 12
    assert report.parse_failure_count == 0
    assert report.parse_success_rate == 1.0
    assert report.mapping_completeness == 1.0
    assert report.confusion.model_dump() == {
        "true_positive": 8,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 4,
    }
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.f1 == 1.0
    assert report.false_positive_rate == 0.0
    assert report.gate_passed is True
    assert all(report.targets_met.values())


def test_rule_quality_separates_evaluated_and_unsupported_rules() -> None:
    report = get_detection_quality_service().evaluate("local")
    evaluated = [rule for rule in report.rules if rule.evaluation_status == "evaluated"]
    unsupported = [
        rule for rule in report.rules if rule.evaluation_status == "no_positive_support"
    ]

    assert report.approved_rule_count == 6
    assert report.supported_rule_count == 2
    assert report.rule_coverage_rate == 0.3333
    assert {rule.title for rule in evaluated} == {
        "Zero Trust Credential Anomaly",
        "Zero Trust Remote Desktop Logon",
    }
    assert all(rule.positive_support == 4 for rule in evaluated)
    assert all(rule.precision == 1.0 and rule.recall == 1.0 for rule in evaluated)
    assert all(rule.targets_met is True for rule in evaluated)
    assert len(unsupported) == 4
    assert all(rule.precision is None and rule.targets_met is None for rule in unsupported)


def test_detection_quality_fingerprint_is_reproducible() -> None:
    service = get_detection_quality_service()

    first = service.evaluate("local")
    second = service.evaluate("local")

    assert len(first.evaluation_fingerprint_sha256) == 64
    assert first.evaluation_fingerprint_sha256 == second.evaluation_fingerprint_sha256
    assert first.manifest_digest_sha256 == second.manifest_digest_sha256
    assert first.ruleset_digest_sha256 == second.ruleset_digest_sha256


def test_detection_quality_api_exposes_metrics_and_rule_coverage() -> None:
    response = client.get("/evaluation/detection-quality")
    payload = response.json()

    assert response.status_code == 200
    assert payload["evaluation_version"] == "0.14.0"
    assert payload["gate_passed"] is True
    assert payload["supported_rule_count"] == 2
    assert payload["approved_rule_count"] == 6
    assert payload["targets_met"]["dataset_expectations"] is True


def test_stricter_public_rule_coverage_target_fails_closed() -> None:
    replay = PublicReplayService(
        get_ocsf_normalizer(),
        get_sigma_engine(),
        get_correlation_engine(),
    )
    replay.quality_targets = replay.quality_targets.model_copy(
        update={"minimum_rule_coverage_rate": 0.5}
    )

    report = DetectionQualityService(replay, get_sigma_engine()).evaluate("local")

    assert report.rule_coverage_rate == 0.3333
    assert report.targets_met["rule_coverage_rate"] is False
    assert report.gate_passed is False


def test_threat_dataset_requires_explicit_expected_rules() -> None:
    source = get_public_replay_service().datasets()[0].model_dump(mode="json")
    source["expected_rule_ids"] = []

    with pytest.raises(ValidationError, match="threat datasets require expected rules"):
        PublicReplayDataset.model_validate(source)
