import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.models import PublicReplayDataset
from app.services.correlation import get_correlation_engine
from app.services.incident_quality import IncidentQualityService, get_incident_quality_service
from app.services.ocsf import get_ocsf_normalizer
from app.services.public_replay import PublicReplayService, get_public_replay_service
from app.services.sigma import get_sigma_engine

client = TestClient(app)


def _replay_service() -> PublicReplayService:
    return PublicReplayService(
        get_ocsf_normalizer(),
        get_sigma_engine(),
        get_correlation_engine(),
    )


def test_incident_quality_report_meets_fail_closed_targets() -> None:
    report = get_incident_quality_service().evaluate("local")

    assert report.dataset_count == 3
    assert report.positive_dataset_support == 1
    assert report.negative_dataset_support == 2
    assert report.confusion.model_dump() == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 2,
    }
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.f1 == 1.0
    assert report.false_positive_rate == 0.0
    assert report.window_accuracy == 1.0
    assert report.graph_structure_accuracy == 1.0
    assert report.deduplication_accuracy == 1.0
    assert report.gate_passed is True
    assert all(report.targets_met.values())


def test_incident_quality_exposes_dataset_level_evidence() -> None:
    report = get_incident_quality_service().evaluate("local")
    by_id = {result.dataset_id: result for result in report.datasets}
    attack = by_id["splunk-rdp-session-established"]
    credential_attack = by_id["splunk-aws-console-login-failures"]
    benign = by_id["microsoft-sentinel-wiz-audit"]

    assert attack.expected_incident_count == 1
    assert attack.observed_incident_count == 1
    assert attack.observed_windows_minutes == [5]
    assert attack.observed_entity_node_count == 6
    assert attack.observed_entity_edge_count == 6
    assert attack.observed_deduplicated_count == 2
    assert attack.window_match is True
    assert attack.graph_structure_match is True
    assert attack.deduplication_match is True
    assert credential_attack.observed_incident_count == 0
    assert credential_attack.graph_structure_match is True
    assert benign.observed_entity_node_count == 0
    assert benign.incident_classification_correct is True


def test_incident_quality_fingerprint_is_reproducible_and_tenant_independent() -> None:
    service = get_incident_quality_service()

    tenant_a = service.evaluate("tenant-a")
    tenant_b = service.evaluate("tenant-b")

    assert len(tenant_a.evaluation_fingerprint_sha256) == 64
    assert tenant_a.evaluation_fingerprint_sha256 == tenant_b.evaluation_fingerprint_sha256
    assert tenant_a.manifest_digest_sha256 == tenant_b.manifest_digest_sha256
    assert tenant_a.correlation_version == "0.13.0"


def test_incident_quality_api_and_readiness_expose_gate() -> None:
    response = client.get("/evaluation/incident-quality")
    readiness = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["evaluation_version"] == "0.13.0"
    assert response.json()["gate_passed"] is True
    assert response.json()["positive_dataset_support"] == 1
    assert readiness.status_code == 200
    assert readiness.json()["incident_quality"]["valid"] is True
    assert readiness.json()["incident_quality"]["window_accuracy"] == 1.0
    assert readiness.json()["incident_quality"]["graph_structure_accuracy"] == 1.0


def test_insufficient_positive_incident_support_fails_closed() -> None:
    replay = _replay_service()
    replay.incident_quality_targets = replay.incident_quality_targets.model_copy(
        update={"minimum_positive_dataset_support": 2}
    )

    report = IncidentQualityService(replay, get_correlation_engine()).evaluate("local")

    assert report.positive_dataset_support == 1
    assert report.targets_met["positive_dataset_support"] is False
    assert report.gate_passed is False


def test_graph_expectation_regression_fails_closed() -> None:
    replay = _replay_service()
    source = replay._datasets[0]
    replay._datasets[0] = source.model_copy(
        update={"expected_entity_node_count": source.expected_entity_node_count + 1}
    )

    report = IncidentQualityService(replay, get_correlation_engine()).evaluate("local")

    assert report.graph_structure_accuracy < 1.0
    assert report.targets_met["graph_structure_accuracy"] is False
    assert report.targets_met["dataset_expectations"] is False
    assert report.gate_passed is False


def test_incident_windows_must_match_expected_incident_count() -> None:
    source = get_public_replay_service().datasets()[0].model_dump(mode="json")
    source["expected_incident_windows_minutes"] = []

    with pytest.raises(ValidationError, match="expected incident windows"):
        PublicReplayDataset.model_validate(source)
