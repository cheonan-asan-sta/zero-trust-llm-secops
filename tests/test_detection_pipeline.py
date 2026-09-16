from copy import deepcopy

from fastapi.testclient import TestClient

from app.main import app
from app.models import EventAction
from app.scenarios import synthetic_events
from app.services.ocsf import get_ocsf_normalizer
from app.services.sigma import SigmaEngine, get_sigma_engine

client = TestClient(app)


def _event(scenario_id: str):
    return next(
        event
        for event in synthetic_events()
        if event.ground_truth and event.ground_truth.scenario_id == scenario_id
    )


def _approved_rule_document() -> dict:
    return {
        "title": "Test OCSF Rule",
        "id": "df607182-93a4-4fb0-912c-3d4e5f607182",
        "status": "test",
        "description": "Detects a test OCSF event.",
        "taxonomy": "ocsf",
        "logsource": {"category": "api", "product": "zero_trust_secops"},
        "detection": {"selection": {"class_uid": 6003}, "condition": "selection"},
        "level": "medium",
        "tags": ["detection.test"],
        "x_secops": {
            "lifecycle": "approved",
            "version": "1.0.0",
            "approved_by": "security-owner",
            "approved_on": "2026-09-16",
            "test_case_ids": ["TEST-01"],
        },
    }


def test_ocsf_normalizer_maps_authentication_and_api_classes() -> None:
    normalizer = get_ocsf_normalizer()
    login_event = _event("NORMAL-01").model_copy(update={"action": EventAction.LOGIN})
    authentication = normalizer.normalize(login_event)
    api_activity = normalizer.normalize(_event("ZT-S05"))

    assert authentication.event.class_uid == 3002
    assert authentication.event.category_uid == 3
    assert authentication.event.type_uid == 300201
    assert authentication.event.user is not None
    assert authentication.event.service is not None
    assert api_activity.event.class_uid == 6003
    assert api_activity.event.category_uid == 6
    assert api_activity.event.type_uid == 600302
    assert api_activity.event.api is not None
    assert api_activity.provenance.schema_version == "1.9.0"


def test_normalization_is_deterministic_and_excludes_ground_truth() -> None:
    normalizer = get_ocsf_normalizer()
    source = _event("ZT-S03")
    without_truth = source.model_copy(update={"ground_truth": None})

    first = normalizer.normalize(source)
    second = normalizer.normalize(without_truth)
    serialized = first.model_dump(mode="json")

    assert first == second
    assert first.provenance.source_sha256 == first.event.raw_data_hash.value
    assert len(first.provenance.mapping_digest_sha256) == 64
    assert "ground_truth" not in str(serialized)
    assert "raw_data" not in serialized["event"]


def test_packaged_sigma_rules_are_valid_versioned_and_approved() -> None:
    engine = get_sigma_engine()
    summaries = engine.summaries()

    assert engine.valid is True
    assert engine.validation_issues == []
    assert len(summaries) == 5
    assert len(engine.approved_rules) == 5
    assert all(rule.version == "1.0.0" for rule in summaries)
    assert all(rule.test_case_ids for rule in summaries)
    assert len(engine.ruleset_digest_sha256) == 64


def test_sigma_replay_detects_each_threat_and_suppresses_normal_events() -> None:
    normalizer = get_ocsf_normalizer()
    engine = get_sigma_engine()
    expected_tags = {
        "ZT-S01": "attack.t1110",
        "ZT-S02": "attack.t1133",
        "ZT-S03": "attack.t1098",
        "ZT-S04": "attack.t1021",
        "ZT-S05": "attack.t1020",
    }

    for scenario_id, expected_tag in expected_tags.items():
        result = engine.evaluate(normalizer.normalize(_event(scenario_id)))
        assert expected_tag in {tag for match in result.matches for tag in match.tags}

    for scenario_id in ("NORMAL-01", "NORMAL-02", "NORMAL-03"):
        result = engine.evaluate(normalizer.normalize(_event(scenario_id)))
        assert result.matches == []
        assert result.highest_level is None


def test_sigma_loader_fails_closed_for_unproved_or_unsupported_rules() -> None:
    missing_tests = _approved_rule_document()
    missing_tests["x_secops"]["test_case_ids"] = []
    unsupported = deepcopy(_approved_rule_document())
    unsupported["id"] = "e0718293-a4b5-40c1-a23d-4e5f60718293"
    unsupported["detection"]["selection"] = {"message|base64": "unsafe"}

    engine = SigmaEngine.from_documents(
        [("missing_tests.yml", missing_tests), ("unsupported.yml", unsupported)]
    )

    assert engine.valid is False
    assert engine.approved_rules == []
    assert len(engine.validation_issues) == 2
    assert "test_case_ids" in engine.validation_issues[0]
    assert "unsupported Sigma modifier" in engine.validation_issues[1]


def test_pipeline_apis_and_analysis_return_versioned_detection_evidence() -> None:
    source = _event("ZT-S05").model_dump(mode="json")
    normalized = client.post("/events/normalize", json=source)
    detection = client.post("/detections/evaluate", json=source)
    rules = client.get("/detections/rules")
    analysis = client.post("/analysis", json=source)

    assert normalized.status_code == 200
    assert normalized.json()["event"]["class_uid"] == 6003
    assert detection.status_code == 200
    assert detection.json()["detection"]["matches"][0]["version"] == "1.0.0"
    assert rules.status_code == 200
    assert len(rules.json()) == 5
    assert analysis.status_code == 200
    assert analysis.json()["normalized_event"]["provenance"]["schema_version"] == "1.9.0"
    assert analysis.json()["detection"]["evaluated_rule_count"] == 5


def test_readiness_includes_normalization_and_detection_integrity() -> None:
    response = client.get("/health/ready")
    payload = response.json()

    assert response.status_code == 200
    assert payload["normalization"]["schema_version"] == "1.9.0"
    assert len(payload["normalization"]["mapping_digest_sha256"]) == 64
    assert payload["detection"]["valid"] is True
    assert payload["detection"]["approved_rule_count"] == 5
    assert payload["detection"]["validation_issue_count"] == 0
