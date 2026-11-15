import json

import pytest

from scripts import evaluate_m6_public_behavior as behavior
from scripts import evaluate_m6_public_regression as regression
from scripts.evaluate_m6 import canonical, digest, write_report
from scripts.prepare_m7_local import jsonl


@pytest.fixture
def previous(tmp_path, monkeypatch):
    root = tmp_path / "previous"
    group = "old-group"
    inputs = [{"source": "cloudtrail", "original_group_id": group, "events": [
        {"id": "old-event", "kind": "AwsApiCall", "timestamp": "2025-01-01T00:00:00Z"},
    ]}]
    scoring = [{"case_id": "behavior-" + digest(canonical(["cloudtrail", group])),
                "source": "cloudtrail", "original_group_id": group,
                "expected_label": "threat", "families": ["fixture"]}]
    files = {behavior.INPUTS: jsonl(inputs), behavior.SCORING: jsonl(scoring)}
    for name, content in files.items():
        target = root / "dataset" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    manifest = {"schema": "m6-public-behavior-bundle-1", "units": 1,
                "files": {name: digest(content) for name, content in files.items()},
                "cohort": "previously_unseen", "implementation_sha256": {"detector": "old"},
                "freeze_sha256": "previous-freeze"}
    write_report(root / "dataset/manifest.json", manifest)
    write_report(root / "report.json", {
        "manifest_sha256": digest((root / "dataset/manifest.json").read_bytes()),
        "rows": [scoring[0] | {"rule_verdict": "threat"}],
    })
    monkeypatch.setattr(behavior, "implementation_hashes", lambda: {"detector": "new"})
    return root


def test_revision_preserves_inputs_labels_and_prior_freeze(previous, tmp_path):
    original = {path.relative_to(previous): path.read_bytes()
                for path in previous.rglob("*") if path.is_file()}
    destination = tmp_path / "replay"
    manifest = regression.prepare(previous, destination)
    assert manifest["independent_evaluation"] is False
    assert manifest["cohort"] == "exposed_public_regression"
    assert manifest["implementation_sha256"] == {"detector": "new"}
    assert manifest["previous_implementation_sha256"] == {"detector": "old"}
    assert manifest["freeze_sha256"] is None
    for name in (behavior.INPUTS, behavior.SCORING):
        assert (destination / "dataset" / name).read_bytes() == (previous / "dataset" / name).read_bytes()
    assert {path.relative_to(previous): path.read_bytes()
            for path in previous.rglob("*") if path.is_file()} == original
    with pytest.raises(ValueError, match="destination_exists"):
        regression.prepare(previous, destination)


@pytest.mark.parametrize("name", [behavior.INPUTS, behavior.SCORING, "manifest.json"])
def test_changed_previous_evidence_cannot_be_rebased_as_fresh(previous, tmp_path, name):
    path = previous / "dataset" / name
    path.write_bytes(path.read_bytes() + b"\n")
    destination = tmp_path / "replay"
    with pytest.raises(ValueError, match="previous_artifact_changed"):
        regression.prepare(previous, destination)
    assert not destination.exists()


def test_previous_directory_cannot_be_overwritten(previous):
    with pytest.raises(ValueError, match="destination_exists"):
        regression.prepare(previous, previous)


def test_changed_previous_prediction_is_rejected_against_pinned_baseline(previous, tmp_path):
    pinned = regression.read_previous(previous)[3]
    path = previous / "report.json"
    report = json.loads(path.read_text())
    report["rows"][0]["rule_verdict"] = "normal"
    write_report(path, report)
    with pytest.raises(ValueError, match="pinned_hash_changed"):
        regression.prepare(previous, tmp_path / "replay", pinned)


def test_comparison_refuses_changed_truth(previous):
    old = json.loads((previous / "report.json").read_text())
    new = {"rows": [old["rows"][0] | {"expected_label": "normal"}]}
    with pytest.raises(ValueError, match="reference_changed"):
        regression.compare(old, new)
