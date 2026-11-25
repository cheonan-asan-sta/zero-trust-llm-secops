import json
from pathlib import Path

import pytest

from scripts import evaluate_public_fpad_crs as evaluator
from scripts.evaluate_local_remote_holdout import fingerprint, read, write


def staged(tmp_path, monkeypatch):
    source = tmp_path / "source.jsonl"
    rows = [
        {"method": "GET", "url": "/a", "label": 0, "body": "unused", "location": []},
        {"method": "GET", "url": "/b", "label": 1, "body": "", "location": ["test-only"]},
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    monkeypatch.setattr(evaluator, "DATASETS", {"fpad": (fingerprint(source), 2)})
    output = tmp_path / "output"
    evaluator.prepare(source, output, "fpad")
    return source, output


def test_prepare_exposes_only_request_target_and_method(tmp_path, monkeypatch):
    _, output = staged(tmp_path, monkeypatch)
    assert evaluator.observations(output) == [
        {"ordinal": 1, "method": "GET", "target": "/a"},
        {"ordinal": 2, "method": "GET", "target": "/b"},
    ]


def test_score_retains_unknowns_and_checks_priority_fingerprint(tmp_path, monkeypatch):
    source, output = staged(tmp_path, monkeypatch)
    predictions, priorities = output / "predictions.jsonl", output / "priorities.jsonl"
    predictions.write_text('{"ordinal":1,"alert":null}\n{"ordinal":2,"alert":true}\n', encoding="utf-8")
    priorities.write_text('{"ordinal":1,"alert":null}\n{"ordinal":2,"alert":false}\n', encoding="utf-8")
    script = Path(evaluator.__file__)
    seal = output / "seal.json"
    write(seal, {"binary_sha256": evaluator.BINARY_SHA, "predictions_sha256": fingerprint(predictions),
                 "priorities_sha256": fingerprint(priorities), "plan_sha256": fingerprint(output / "plan.json"),
                 "evaluator_sha256": fingerprint(script),
                 "priority_evaluator_sha256": fingerprint(script.with_name("evaluate_public_web_crs_priority.py"))})

    evaluator.score(source, output, fingerprint(seal))
    result = read(output / "report.json")
    assert result["crs_target_only"]["tp"] == 1
    assert result["corroborated_subset"]["fn"] == 1
    assert result["crs_target_only"]["inference_errors"] == result["corroborated_subset"]["inference_errors"] == 1

    priorities.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="prediction seal does not match"):
        evaluator.score(source, output, fingerprint(seal))
