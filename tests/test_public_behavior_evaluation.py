import json
from copy import deepcopy

import pytest

from scripts import evaluate_m6_public_behavior as evaluation
from scripts.evaluate_m6 import canonical, digest
from scripts.prepare_m7_local import jsonl


def sample_row(group="new-group", event="new-event", credential="new-credential"):
    observed = {
        "source": "cloudtrail", "original_group_id": group,
        "events": [{
            "id": digest(event.encode()), "timestamp": "2025-01-01T00:00:00Z",
            "kind": "AwsApiCall", "connection_id": credential,
            "principal_hash": "account-scoped-actor", "api_service": "sts.amazonaws.com",
            "api_action": "GetCallerIdentity", "outcome": "success",
        }],
    }
    return {"source": "cloudtrail", "original_group_id": group, "observation": observed,
            "event_hashes": [observed["events"][0]["id"]],
            "expected_label": "normal", "families": []}


def fixture_evidence_truth():
    from scripts.m6_public_evidence_scoring import observation_event_hash

    row = sample_row()
    return {row["event_hashes"][0]: {
        "source": "cloudtrail", "original_group_id": row["original_group_id"],
        "event_label": "normal", "label_granularity": "event", "group_label": "normal",
        "observed_event_sha256": observation_event_hash(row["observation"]["events"][0]),
    }}, {"fixture": True}


@pytest.fixture
def isolated_bundle(monkeypatch, tmp_path):
    # No original archives, private labels or previous project results are needed.
    monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"detector.py": "frozen"})
    monkeypatch.setattr(evaluation, "verify_overlap", lambda *args, **kwargs: {})
    monkeypatch.setattr(evaluation, "overlap_with_shadow", lambda *args: {})
    monkeypatch.setattr(evaluation, "check_previous_device", lambda *args: {})
    monkeypatch.setattr(evaluation, "load_evidence_references", lambda _: fixture_evidence_truth())
    root = tmp_path / "development"
    evaluation.write_bundle(root, [sample_row()], {}, cohort="fixture-development")
    return root


@pytest.mark.parametrize("location", ["session", "event"])
def test_reference_labels_cannot_be_written_in_detector_inputs(isolated_bundle, tmp_path, location):
    row = sample_row()
    target = row["observation"] if location == "session" else row["observation"]["events"][0]
    target["expected_label"] = "threat"
    with pytest.raises(ValueError, match="reference_leak"):
        evaluation.write_bundle(tmp_path / "invalid", [row], {}, cohort="fixture")


@pytest.mark.parametrize(("key", "value"), [
    ("source", "cowrie"), ("original_group_id", "other-group"),
    ("event_hashes", ["wrong-hash"]), ("expected_label", "unrecognized"),
    ("families", "not-a-list"),
])
def test_outer_scoring_metadata_must_match_observed_session(isolated_bundle, tmp_path, key, value):
    row = sample_row() | {key: value}
    with pytest.raises(ValueError, match="reference_mismatch"):
        evaluation.write_bundle(tmp_path / "invalid", [row], {}, cohort="fixture")


def test_bundle_rejects_frozen_code_and_data_changes(isolated_bundle, monkeypatch):
    evaluation.checked_bundle(isolated_bundle)
    monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"detector.py": "modified"})
    with pytest.raises(ValueError, match="frozen_implementation_changed"):
        evaluation.checked_bundle(isolated_bundle)
    monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"detector.py": "frozen"})
    input_path = isolated_bundle / "dataset" / evaluation.INPUTS
    input_path.write_bytes(input_path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="bundle_changed"):
        evaluation.checked_bundle(isolated_bundle)


def test_detector_sees_no_labels_and_all_predictions_precede_reference_parsing(isolated_bundle, monkeypatch):
    original_read = evaluation.read_rows
    scoring_parsed = False
    predictions = []
    detector = evaluation.PublicDetectionService()

    def read_rows(raw):
        nonlocal scoring_parsed
        if b"expected_label" in raw:
            assert len(predictions) == 1
            scoring_parsed = True
        return original_read(raw)

    class Detector:
        def evaluate(self, observed):
            assert scoring_parsed is False
            assert not evaluation.contains_reference_field(observed.model_dump())
            predictions.append(observed)
            return detector.evaluate(observed)

    def load_references(_manifest):
        assert scoring_parsed is True
        assert len(predictions) == 1
        return fixture_evidence_truth()

    monkeypatch.setattr(evaluation, "read_rows", read_rows)
    monkeypatch.setattr(evaluation, "PublicDetectionService", Detector)
    monkeypatch.setattr(evaluation, "load_evidence_references", load_references)
    report = evaluation.evaluate(isolated_bundle)
    assert scoring_parsed
    assert report["external_model_requests"] == report["automatic_access_mutations"] == 0
    assert report["summary"]["held_total"] == 0
    assert report["summary"]["all_targets_met"] is False


@pytest.mark.parametrize(("key", "value"), [
    ("source", "cowrie"), ("original_group_id", "missing-group"),
    ("case_id", "wrong-case"), ("expected_label", "invalid"),
])
def test_evaluation_rejects_wrong_scoring_reference(isolated_bundle, monkeypatch, key, value):
    manifest, files, manifest_hash = evaluation.checked_bundle(isolated_bundle)
    references = evaluation.read_rows(files[evaluation.SCORING])
    references[0][key] = value
    changed = files | {evaluation.SCORING: jsonl(references)}
    monkeypatch.setattr(evaluation, "checked_bundle", lambda _root: (manifest, changed, manifest_hash))
    with pytest.raises(ValueError, match="reference_mismatch"):
        evaluation.evaluate(isolated_bundle)


@pytest.mark.parametrize("overlap", ["event", "credential", "session", "raw_source_audit"])
def test_overlap_removes_entire_group_without_selecting_clean_events(overlap):
    prior = sample_row("prior-group", "prior-event", "prior-credential")["observation"]
    candidate = sample_row()
    external = []
    if overlap == "event":
        candidate["observation"]["events"].append(deepcopy(prior["events"][0]))
    elif overlap == "credential":
        candidate["observation"]["events"][0]["connection_id"] = "prior-credential"
    elif overlap == "session":
        candidate["observation"]["original_group_id"] = candidate["original_group_id"] = "prior-group"
    else:
        external.append("new-group")
    clean = sample_row("clean-group", "clean-event", None)
    retained, excluded = evaluation.partition_overlap([candidate, clean], [prior], external)
    assert retained == [clean]
    assert excluded[0]["group_id"] == candidate["original_group_id"]
    assert overlap in excluded[0]["reasons"]
    # Reference relabeling cannot change the partition.
    candidate["expected_label"] = "threat"
    assert evaluation.partition_overlap([candidate, clean], [prior], external) == (retained, excluded)


def make_freeze(root, path):
    evaluation.evaluate(root)
    evaluation.freeze(root, path)
    return json.loads(path.read_text())


@pytest.mark.parametrize("tamper", ["implementation", "archive", "development_report"])
def test_holdout_cannot_open_after_freeze_tampering(isolated_bundle, tmp_path, monkeypatch, tamper):
    freeze_path = tmp_path / "freeze.json"
    value = make_freeze(isolated_bundle, freeze_path)
    if tamper == "implementation":
        value["implementation_sha256"] = {"detector.py": "other"}
    elif tamper == "archive":
        value["holdout_archive_sha256"] = "0" * 64
    else:
        (isolated_bundle / "report.json").write_text("modified report")
    freeze_path.write_text(json.dumps(value))

    def forbidden_loader(*args, **kwargs):
        pytest.fail("holdout archive must not be opened after a frozen dependency changes")

    monkeypatch.setattr(evaluation, "load_cloudtrail_behavior", forbidden_loader)
    with pytest.raises(ValueError, match="changed"):
        evaluation.prepare_holdout(tmp_path / "holdout", isolated_bundle, freeze_path,
                                   tmp_path / "missing.zip", tmp_path / "missing-audit.json")


@pytest.mark.parametrize("excluded", ["not-a-list", ["foreign-group"], ["new-group", "new-group"]])
def test_raw_overlap_audit_rejects_invalid_or_non_candidate_groups(
    isolated_bundle, tmp_path, monkeypatch, excluded,
):
    freeze_path = tmp_path / "freeze.json"
    make_freeze(isolated_bundle, freeze_path)
    audit = {"freeze_sha256": digest(freeze_path.read_bytes()),
             "holdout_archive_sha256": evaluation.HOLDOUT_SHA, "excluded_group_ids": excluded}
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit))
    monkeypatch.setattr(evaluation, "load_cloudtrail_behavior", lambda *args, **kwargs: ([sample_row()], {}))
    with pytest.raises(ValueError, match="overlap_audit_groups"):
        evaluation.prepare_holdout(tmp_path / "holdout", isolated_bundle, freeze_path,
                                   tmp_path / "fixture.zip", audit_path)


def test_conservative_metrics_count_held_threats_as_missed_and_report_held_normals():
    rows = [{"expected_label": label, "rule_verdict": verdict} for label, verdict in [
        ("threat", "threat"), ("threat", "normal"), ("threat", "unknown"),
        ("normal", "threat"), ("normal", "normal"), ("normal", "unknown"),
    ]]
    result = evaluation.summarize(rows)
    assert result["missed_threats"] == 2
    assert result["false_alarms"] == 1
    assert result["held_known_by_label"] == {"threat": 1, "normal": 1}
    assert result["metrics"] == {"precision": .5, "recall": 1 / 3, "f1": .4,
                                 "false_positive_rate": 1 / 3}
    assert result["all_targets_met"] is False


def test_case_id_derives_only_from_source_and_group(isolated_bundle):
    _, files, _ = evaluation.checked_bundle(isolated_bundle)
    reference = evaluation.read_rows(files[evaluation.SCORING])[0]
    assert reference["case_id"] == "behavior-" + digest(canonical(["cloudtrail", "new-group"]))
