from datetime import timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.models import CorrelationPolicy, DetectionPipelineResult
from app.scenarios import synthetic_events
from app.services.correlation import get_correlation_engine
from app.services.ocsf import get_ocsf_normalizer
from app.services.public_replay import get_public_replay_service
from app.services.sigma import get_sigma_engine

client = TestClient(app)


def _threat_events():
    return [event for event in synthetic_events() if event.ground_truth.scenario_id.startswith("ZT-")]


def _pipeline(event):
    normalized = get_ocsf_normalizer().normalize(event)
    return DetectionPipelineResult(
        normalized=normalized,
        detection=get_sigma_engine().evaluate(normalized),
    )


def test_public_replay_manifest_and_fixtures_are_integrity_checked() -> None:
    service = get_public_replay_service()
    datasets = service.datasets()

    assert service.valid is True
    assert service.validation_issues == []
    assert len(service.manifest_digest_sha256) == 64
    assert len(datasets) == 2
    assert {dataset.license for dataset in datasets} == {"Apache-2.0", "MIT"}
    assert all(len(dataset.source_revision) == 40 for dataset in datasets)
    assert all(len(dataset.source_artifact_sha256) == 64 for dataset in datasets)
    assert all(len(dataset.fixture_sha256) == 64 for dataset in datasets)


def test_public_attack_and_benign_replays_meet_regression_expectations() -> None:
    suite = get_public_replay_service().run_all("local")
    by_id = {result.dataset.dataset_id: result for result in suite.results}
    attack = by_id["splunk-rdp-session-established"]
    benign = by_id["microsoft-sentinel-wiz-audit"]

    assert suite.dataset_count == 2
    assert suite.event_count == 8
    assert suite.finding_count == 4
    assert suite.incident_count == 1
    assert suite.expectations_met is True
    assert attack.expectation_met is True
    assert attack.finding_count == 4
    assert len(attack.incidents) == 1
    assert attack.incidents[0].class_uid == 2005
    assert attack.incidents[0].type_uid == 200501
    assert "repeated_detection_across_resources" in attack.incidents[0].correlation_reasons
    assert "attack.t1021.001" in attack.incidents[0].attack_tags
    assert benign.expectation_met is True
    assert benign.finding_count == 0
    assert benign.incidents == []


def test_multi_rule_attack_chain_correlation_is_deterministic() -> None:
    pipelines = [_pipeline(event) for event in _threat_events()]
    engine = get_correlation_engine()

    forward = engine.correlate(pipelines, "local")
    reversed_result = engine.correlate(list(reversed(pipelines)), "local")

    assert forward.incident_count == 1
    assert forward.finding_count == 8
    assert forward.incidents[0].incident_uid == reversed_result.incidents[0].incident_uid
    assert len(forward.incidents[0].event_ids) == 5
    assert forward.incidents[0].severity_id == 5
    assert "multi_rule_attack_chain" in forward.incidents[0].correlation_reasons
    assert forward.incidents[0].requires_human_review is True


def test_repeated_detection_requires_multiple_resources() -> None:
    source = _threat_events()[1]
    events = [
        source.model_copy(
            update={
                "event_id": f"same-resource-{index}",
                "timestamp": source.timestamp + timedelta(minutes=index),
            }
        )
        for index in range(3)
    ]
    result = get_correlation_engine().correlate(
        [_pipeline(event) for event in events],
        "local",
        CorrelationPolicy(),
    )

    assert result.finding_count == 3
    assert result.incident_count == 0


def test_correlation_and_public_replay_apis() -> None:
    payload = {"events": [event.model_dump(mode="json") for event in _threat_events()]}
    correlation = client.post("/incidents/correlate", json=payload)
    datasets = client.get("/replay/public/datasets")
    suite = client.post("/replay/public/run")
    missing = client.post("/replay/public/not-a-dataset")

    assert correlation.status_code == 200
    assert correlation.json()["incident_count"] == 1
    assert correlation.json()["incidents"][0]["class_uid"] == 2005
    assert datasets.status_code == 200
    assert len(datasets.json()) == 2
    assert suite.status_code == 200
    assert suite.json()["expectations_met"] is True
    assert missing.status_code == 404


def test_readiness_includes_correlation_and_public_replay_integrity() -> None:
    response = client.get("/health/ready")
    payload = response.json()

    assert response.status_code == 200
    assert payload["correlation"]["version"] == "0.10.0"
    assert payload["correlation"]["output_class_uid"] == 2005
    assert payload["public_replay"]["valid"] is True
    assert payload["public_replay"]["dataset_count"] == 2
    assert payload["public_replay"]["validation_issue_count"] == 0
