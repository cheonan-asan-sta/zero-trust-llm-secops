"""Reject reused evaluation material and leaked labels before any detector is called."""

import copy
import json

import pytest

from scripts import m7_context_dataset as dataset


@pytest.fixture(scope="module")
def cohort():
    return dataset.build_dataset(1)


def test_authored_cohort_keeps_hard_cases_and_separates_truth(cohort):
    inputs, labels = cohort
    report = dataset.audit_inputs(inputs, labels)
    assert report["label_counts"] == {"normal": 10, "threat": 6, "unknown": 8}
    assert report["baseline_sessions"] == 72
    assert report["prior_use_sessions"] == 1
    assert report["target_baseline_identity_overlap"] == 0
    assert dataset.audit_inputs(inputs)["label_counts"] is None
    by_family = {row["family"]: row for row in labels}
    for name in ("hidden_bulk_exfiltration", "hidden_low_volume_theft"):
        assert by_family[name]["label"] == "threat"
        assert by_family[name]["expected_support"] == ["none"]
    for name in ("benign_missing_approval", "benign_expired_approval", "maintenance_isolation"):
        assert by_family[name]["label"] == "normal"
    assert all(row["reference_kind"] == "authored_controlled_lab_ground_truth" for row in labels)


def test_new_draw_contains_fresh_sessions_not_renamed_previous_rows(cohort):
    prior, _ = cohort
    fresh, _ = dataset.build_dataset(1)
    old_ids = dataset._fingerprints(prior)["identifiers"]
    new_ids = dataset._fingerprints(fresh)["identifiers"]
    assert not old_ids & new_ids
    assert not dataset._fingerprints(prior)["observations"] & dataset._fingerprints(fresh)["observations"]


@pytest.mark.parametrize("field", ["label", "ground_truth", "family", "expected_support", "support_event_sha256"])
def test_label_injection_rejected_at_input_boundary(cohort, field):
    spec = copy.deepcopy(cohort[0][0])
    spec["target"]["activity"]["events"][0][field] = "threat"
    with pytest.raises(ValueError):
        dataset.validate_input(spec)


def test_case_identity_cannot_encode_answer(cohort):
    spec = copy.deepcopy(cohort[0][0])
    spec["case_id"] = "threat-device-01"
    with pytest.raises(ValueError, match="opaque_id"):
        dataset.validate_input(spec)


@pytest.mark.parametrize("field", ["session_id", "capture_id"])
def test_target_cannot_reuse_baseline_identity(cohort, field):
    spec = copy.deepcopy(cohort[0][0])
    spec["target"][field] = spec["baseline_samples"][0][field]
    with pytest.raises(ValueError, match="duplicate_identity"):
        dataset.validate_input(spec)


@pytest.mark.parametrize("field", ["id", "connection_id"])
def test_target_cannot_reuse_training_event_or_connection(cohort, field):
    spec = copy.deepcopy(cohort[0][0])
    spec["target"]["activity"]["events"][0][field] = spec["baseline_samples"][0]["activity"]["events"][0][field]
    with pytest.raises(ValueError, match="overlap"):
        dataset.validate_input(spec)


def test_duplicate_group_and_cross_case_session_rejected(cohort):
    one, two = copy.deepcopy(cohort[0][:2])
    two["target"]["session_id"] = one["target"]["session_id"]
    with pytest.raises(ValueError, match="duplicate_identity"):
        dataset.audit_inputs([one, two])
    one["target"]["activity"]["original_group_id"] = one["baseline_samples"][0]["activity"]["original_group_id"]
    with pytest.raises(ValueError, match="group_overlap"):
        dataset.validate_input(one)


def test_baseline_must_precede_target(cohort):
    spec = copy.deepcopy(cohort[0][0])
    spec["baseline_samples"][0]["activity"]["events"][0]["timestamp"] = spec["target"]["activity"]["events"][0]["timestamp"]
    with pytest.raises(ValueError, match="event_time"):
        dataset.validate_input(spec)


def test_private_remote_shell_reference_is_content_bound(cohort):
    inputs, labels = copy.deepcopy(cohort)
    reference = next(row for row in labels if row["family"] == "remote_shell_attempt")
    reference["support_event_sha256"][reference["support_event_ids"][0]] = "0" * 64
    with pytest.raises(ValueError, match="label_event_hash"):
        dataset.audit_inputs(inputs, labels)


def test_scoring_label_swap_or_duplicate_rejected(cohort):
    inputs, labels = copy.deepcopy(cohort)
    labels[1]["case_id"] = labels[0]["case_id"]
    with pytest.raises(ValueError, match="label_identity"):
        dataset.audit_inputs(inputs, labels)


def _prior_file(tmp_path, name, value):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")
    return path


def test_prior_overlap_rejects_session_even_when_entire_wrapper_changes(tmp_path, cohort):
    inputs, _ = cohort
    _prior_file(tmp_path, "old.jsonl", {"case_id": "other", "capture": {"session_id": inputs[0]["target"]["session_id"]}})
    with pytest.raises(ValueError, match="prior_overlap"):
        dataset.audit_prior_overlap(inputs, root=tmp_path, required_files=["old.jsonl"], optional_files=[])


def test_prior_request_hash_reuse_rejected(tmp_path, cohort):
    inputs, _ = cohort
    _prior_file(tmp_path, "old.jsonl", {"input_sha256": dataset.digest(inputs[0])})
    with pytest.raises(ValueError, match="prior_overlap"):
        dataset.audit_prior_overlap(inputs, root=tmp_path, required_files=["old.jsonl"], optional_files=[])


def test_prior_missing_and_changed_hash_fail_closed(tmp_path, cohort):
    inputs, _ = cohort
    with pytest.raises(ValueError, match="missing_prior"):
        dataset.audit_prior_overlap(inputs, root=tmp_path, required_files=["old.jsonl"], optional_files=[])
    path = _prior_file(tmp_path, "old.jsonl", {"session_id": "old-only"})
    first = dataset.audit_prior_overlap(inputs, root=tmp_path, required_files=["old.jsonl"], optional_files=["optional.jsonl"])
    assert first["missing_optional"] == ["optional.jsonl"]
    assert dataset.audit_prior_overlap(inputs, root=tmp_path, pinned=first) == first
    path.write_text('{"session_id":"other-only"}\n')
    with pytest.raises(ValueError, match="prior_changed"):
        dataset.audit_prior_overlap(inputs, root=tmp_path, pinned=first)


def test_pinned_prior_paths_cannot_escape_repository(tmp_path, cohort):
    with pytest.raises(ValueError, match="prior_path"):
        dataset.audit_prior_overlap(cohort[0], root=tmp_path, pinned={"sources": {"../outside.json": {"sha256": "0" * 64}}})


def test_duplicate_json_keys_in_prior_rejected(tmp_path, cohort):
    path = tmp_path / "old.jsonl"
    path.write_text('{"session_id":"a","session_id":"b"}\n')
    with pytest.raises(ValueError):
        dataset.audit_prior_overlap(cohort[0], root=tmp_path, required_files=["old.jsonl"], optional_files=[])


def test_previous_context_bundle_is_discovered_on_new_prepare(tmp_path, cohort, monkeypatch):
    inputs, _ = cohort
    monkeypatch.setattr(dataset, "REQUIRED", {})
    monkeypatch.setattr(dataset, "ADDITIONAL_PRIOR", ())
    monkeypatch.setattr(dataset, "OPTIONAL", {})
    directory = tmp_path / "runtime/m7/context-earlier"
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_text(json.dumps({"schema": "m7-context-comparison-dataset-1"}))
    (directory / "inputs.jsonl").write_text(json.dumps(inputs[0]) + "\n")
    with pytest.raises(ValueError, match="prior_overlap"):
        dataset.audit_prior_overlap(inputs, root=tmp_path)


def test_prior_manifest_content_mismatch_is_not_silently_accepted(tmp_path, cohort):
    _prior_file(tmp_path, "old/observations.jsonl", {"session_id": "old-only"})
    _prior_file(tmp_path, "old/manifest.json", {"files": {"observations.jsonl": "0" * 64}})
    with pytest.raises(ValueError, match="prior_manifest_mismatch"):
        dataset.audit_prior_overlap(cohort[0], root=tmp_path, required_files=["old/observations.jsonl"], optional_files=[])


def test_pinned_manifest_changes_are_detected_even_when_data_unchanged(tmp_path, cohort):
    old = _prior_file(tmp_path, "old/observations.jsonl", {"session_id": "old-only"})
    manifest = _prior_file(tmp_path, "old/manifest.json", {"files": {"observations.jsonl": dataset.digest(old.read_bytes())}})
    pinned = dataset.audit_prior_overlap(cohort[0], root=tmp_path, required_files=["old/observations.jsonl"], optional_files=[])
    body = json.loads(manifest.read_text())
    body["new_annotation"] = "changed"
    manifest.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="prior_manifest_changed"):
        dataset.audit_prior_overlap(cohort[0], root=tmp_path, pinned=pinned)
