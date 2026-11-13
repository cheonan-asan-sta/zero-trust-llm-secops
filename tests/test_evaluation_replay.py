"""A current-source regression copy must never overwrite historical source pins."""

import json

import pytest

from scripts.evaluate_m6 import digest
from scripts.replay_evaluation_evidence import FILES, prepare


@pytest.mark.parametrize("schema", FILES)
def test_replay_preserves_original_bytes_and_records_exposed_case_lineage(tmp_path, schema):
    source, target = tmp_path / "original", tmp_path / "replay"
    source.mkdir()
    files = {name: b'{"fixture":true}\n' for name in FILES[schema]}
    for name, raw in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    original = {"schema": schema, "implementation_sha256": {"historical.py": "old-pin"},
                "files": {name: digest(raw) for name, raw in files.items()}}
    raw = json.dumps(original).encode()
    (source / "manifest.json").write_bytes(raw)
    report = prepare(source, target)
    assert report["new_independent_evaluation"] is False
    assert report["external_model_requests"] == 0
    assert (source / "manifest.json").read_bytes() == raw
    assert (target / "origin-manifest.json").read_bytes() == raw
    manifest = json.loads((target / "manifest.json").read_bytes())
    assert manifest["regression_replay"]["original_implementation_sha256"] == original["implementation_sha256"]
    assert manifest["regression_replay"]["original_manifest_sha256"] == digest(raw)
    assert manifest["regression_replay"]["exposed_cases"] is True
    for name, contents in files.items():
        assert (source / name).read_bytes() == (target / name).read_bytes() == contents
    with pytest.raises(ValueError):
        prepare(source, target)


def test_changed_original_input_is_rejected_before_publication(tmp_path):
    source, target = tmp_path / "original", tmp_path / "replay"
    (source / "private").mkdir(parents=True)
    (source / "inputs.jsonl").write_text("changed")
    (source / "private/scoring.jsonl").write_text("private")
    (source / "manifest.json").write_text(json.dumps({
        "schema": "m7-context-comparison-dataset-1", "implementation_sha256": {},
        "files": {"inputs.jsonl": "original-digest", "private/scoring.jsonl": "private-digest"},
    }))
    with pytest.raises(ValueError, match="source changed"):
        prepare(source, target)
    assert not target.exists()


def test_relocated_previous_bundle_must_keep_every_original_artifact_hash(tmp_path):
    source, previous = tmp_path / "execution", tmp_path / "relocated-context"
    (previous / "private").mkdir(parents=True)
    files = {
        "inputs.jsonl": b"".join(json.dumps({"case_id": f"case-{i}"}).encode() + b"\n" for i in range(240)),
        "private/scoring.jsonl": b"".join(json.dumps({"case_id": f"case-{i}", "label": "normal"}).encode() + b"\n" for i in range(240)),
        "predictions.jsonl": b"".join(json.dumps({"case_id": f"case-{i}", "fixture": True}).encode() + b"\n" for i in range(240)),
    }
    previous_manifest = {"sessions": 240, "files": {name: digest(files[name]) for name in ("inputs.jsonl", "private/scoring.jsonl")}}
    files["manifest.json"] = json.dumps(previous_manifest).encode()
    files["report.json"] = json.dumps({"sessions": 240, "manifest_sha256": digest(files["manifest.json"]),
                                       "predictions_sha256": digest(files["predictions.jsonl"])}).encode()
    for name, contents in files.items():
        (previous / name).write_bytes(contents)
    names = FILES["m7-execution-evaluation-1"]
    for name in names:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"fixture":true}\n')
    original = {"schema": "m7-execution-evaluation-1", "implementation_sha256": {"historical.py": "old"},
                "files": {name: digest((source / name).read_bytes()) for name in names},
                "previous_directory": "/original/host/unavailable/context",
                "previous_artifact_sha256": {name: digest(raw) for name, raw in files.items()}}
    original_raw = json.dumps(original).encode()
    (source / "manifest.json").write_bytes(original_raw)
    target = tmp_path / "replay"
    prepare(source, target, previous_directory=previous)
    copied = json.loads((target / "manifest.json").read_bytes())
    assert copied["previous_directory"] == str(previous.resolve())
    assert copied["previous_artifact_sha256"] == original["previous_artifact_sha256"]
    assert copied["regression_replay"]["original_previous_directory"] == original["previous_directory"]
    assert (source / "manifest.json").read_bytes() == original_raw
    (previous / "private/scoring.jsonl").write_text("different labels")
    with pytest.raises(ValueError, match="prior_changed"):
        prepare(source, tmp_path / "rejected", previous_directory=previous)
    assert not (tmp_path / "rejected").exists()
