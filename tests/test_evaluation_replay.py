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
