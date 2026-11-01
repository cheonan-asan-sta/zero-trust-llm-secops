import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security import Principal, get_principal
from app.services.detection_benchmark import (
    BenchmarkUnavailable,
    DetectionBenchmark,
    confusion,
    family_intervals,
    metrics,
)
from scripts import build_detection_benchmark, evaluate_detection_benchmark

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "app/data/benchmark"


@pytest.fixture(scope="module")
def benchmark():
    return DetectionBenchmark()


@pytest.fixture(scope="module")
def reports(benchmark):
    return {split: benchmark.evaluate(split) for split in ("development", "holdout")}


def test_frozen_corpus_has_balanced_labels_and_family_separated_splits(benchmark):
    assert len(benchmark.cases) == 720 and len(benchmark.families) == 72
    assert all(value == 0 for value in benchmark.overlap.values())
    for split in ("development", "holdout"):
        cases = [case for case in benchmark.cases if case.split == split]
        assert len(cases) == 360
        assert sum(case.threat for case in cases) == 180
        assert len({case.family_id for case in cases}) == 36
        assert len({case.domain for case in cases}) == 6
        assert all(case.event.ground_truth is None for case in cases)
        assert all(case.family_id not in case.event.event_id for case in cases)


def test_secondary_variations_preserve_the_declared_scenario_mechanism(benchmark):
    for case in benchmark.cases:
        if case.family_id == "lateral-slow-fanout":
            assert case.event.behavior.request_rate == "normal"
        elif case.family_id == "exfiltration-internal-report-export":
            assert case.event.resource.sensitivity == "internal"
        elif case.family_id == "credential-typing-errors":
            assert case.event.behavior.request_rate == "normal"


@pytest.mark.parametrize("split", ["development", "holdout"])
def test_metrics_match_independently_counted_case_outcomes(reports, split):
    report = reports[split]
    rows = report["cases"]
    tp = sum(row["outcome"] == "TP" for row in rows)
    fp = sum(row["outcome"] == "FP" for row in rows)
    fn = sum(row["outcome"] == "FN" for row in rows)
    tn = sum(row["outcome"] == "TN" for row in rows)
    assert report["confusion"] == {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
    assert report["metrics"]["precision"] == pytest.approx(tp / (tp + fp))
    assert report["metrics"]["recall"] == pytest.approx(tp / (tp + fn))
    assert report["metrics"]["f1"] == pytest.approx(2 * tp / (2 * tp + fp + fn))
    assert report["metrics"]["false_positive_rate"] == pytest.approx(fp / (fp + tn))
    assert tp + fp + fn + tn == 360
    assert report["evaluation_error_count"] == 0
    assert report["gate_passed"] == all(report["targets_met"].values())
    assert 300 <= report["unique_signal_pattern_count"] <= 360


@pytest.mark.parametrize("split", ["development", "holdout"])
def test_every_rule_has_positive_family_support_and_separate_error_counts(reports, split):
    report = reports[split]
    assert report["rule_coverage_rate"] == 1.0
    for rule in report["rules"]:
        expected = [rule["rule_id"] in row["expected_rule_ids"] for row in report["cases"]]
        observed = [rule["rule_id"] in row["predicted_rule_ids"] for row in report["cases"]]
        assert rule["confusion"] == confusion(expected, observed)
        assert rule["positive_family_count"] >= 3
        assert rule["negative_count"] > 0
        assert rule["support_sufficient"]


def test_another_rules_alert_does_not_hide_a_lateral_rule_miss(reports):
    report = reports["holdout"]
    row = next(row for row in report["cases"] if row["family_id"] == "lateral-slow-fanout")
    lateral = next(rule for rule in report["rules"] if "Lateral" in rule["title"])
    assert row["outcome"] == "TP"
    assert lateral["rule_id"] in row["expected_rule_ids"]
    assert lateral["rule_id"] not in row["predicted_rule_ids"]
    assert lateral["confusion"]["fn"] > 0


def test_family_bootstrap_does_not_treat_repeated_rows_as_independent_samples(reports):
    rows = reports["holdout"]["cases"]
    first = family_intervals(rows, repetitions=150)
    repeated = family_intervals(rows * 7, repetitions=150)
    assert first == repeated
    assert first["family_count"] == 36
    for interval in first["intervals"].values():
        assert 0 <= interval["lower"] <= interval["upper"] <= 1


@pytest.mark.parametrize("counts,expected", [
    ({"tp": 1, "fp": 1, "fn": 1, "tn": 1}, (.5, .5, .5, .5)),
    ({"tp": 0, "fp": 0, "fn": 2, "tn": 3}, (None, 0, 0, 0)),
    ({"tp": 0, "fp": 0, "fn": 0, "tn": 0}, (None, None, None, None)),
    ({"tp": 9, "fp": 1, "fn": 3, "tn": 19}, (.9, .75, 18 / 22, .05)),
])
def test_metric_denominators_and_undefined_values(counts, expected):
    assert tuple(metrics(counts).values()) == expected


def test_mismatched_label_vectors_are_rejected():
    with pytest.raises(ValueError, match="lengths"):
        confusion([True], [])


@pytest.fixture
def corpus_copy(tmp_path):
    for name in ("manifest.json", "families.json", "cases.jsonl"):
        shutil.copyfile(DATA / name, tmp_path / name)
    return tmp_path


def rewrite_cases(root, rows):
    raw = ("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n").encode()
    (root / "cases.jsonl").write_bytes(raw)
    manifest = json.loads((root / "manifest.json").read_bytes())
    manifest["cases_sha256"] = hashlib.sha256(raw).hexdigest()
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


@pytest.mark.parametrize("damage", ["missing-file", "bad-hash", "wrong-count", "bad-manifest"])
def test_corrupt_or_incomplete_frozen_inputs_fail_validation(corpus_copy, damage):
    if damage == "missing-file":
        (corpus_copy / "cases.jsonl").unlink()
    elif damage == "bad-hash":
        with (corpus_copy / "cases.jsonl").open("ab") as output:
            output.write(b" ")
    else:
        manifest = json.loads((corpus_copy / "manifest.json").read_bytes())
        if damage == "wrong-count":
            manifest["case_count"] += 1
        else:
            manifest["source_kind"] = "public_real_world"
        (corpus_copy / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BenchmarkUnavailable):
        DetectionBenchmark(corpus_copy)


@pytest.mark.parametrize("field,value", [
    ("minimum_precision", .94), ("minimum_recall", .94), ("minimum_f1", .94),
    ("maximum_false_positive_rate", .06), ("minimum_positive_families_per_rule", 1),
])
def test_relaxing_the_declared_quality_gate_is_rejected(corpus_copy, field, value):
    manifest = json.loads((corpus_copy / "manifest.json").read_bytes())
    manifest["targets"][field] = value
    (corpus_copy / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BenchmarkUnavailable):
        DetectionBenchmark(corpus_copy)


@pytest.mark.parametrize("damage", [
    "duplicate-id", "changed-label", "changed-split", "unknown-rule", "invalid-event",
    "cross-split-user", "cross-split-device", "cross-split-pattern", "time-overlap",
])
def test_semantic_data_errors_are_rejected_even_after_rehashing(corpus_copy, damage):
    rows = [json.loads(line) for line in (corpus_copy / "cases.jsonl").read_bytes().splitlines()]
    first = next(row for row in rows if row["split"] == "development")
    target = next(row for row in rows if row["split"] == "holdout")
    if damage == "duplicate-id":
        target["case_id"] = first["case_id"]
    elif damage == "changed-label":
        target["threat"] = not target["threat"]
    elif damage == "changed-split":
        target["split"] = "development"
    elif damage == "unknown-rule":
        target["expected_rule_ids"] = ["unknown-rule"]
    elif damage == "invalid-event":
        target["event"]["action"] = "DELETE"
    elif damage == "cross-split-user":
        target["event"]["user"]["user_id"] = first["event"]["user"]["user_id"]
    elif damage == "cross-split-device":
        target["event"]["device"]["device_id"] = first["event"]["device"]["device_id"]
    elif damage == "cross-split-pattern":
        old = target["event"]
        target["event"] = json.loads(json.dumps(first["event"]))
        for group, field in (("user", "user_id"), ("device", "device_id"), ("resource", "resource_id")):
            target["event"][group][field] = old[group][field]
        target["event"]["event_id"] = old["event_id"]
        target["event"]["timestamp"] = old["timestamp"]
    else:
        target["event"]["timestamp"] = first["event"]["timestamp"]
    rewrite_cases(corpus_copy, rows)
    with pytest.raises(BenchmarkUnavailable):
        DetectionBenchmark(corpus_copy)


@pytest.mark.parametrize("split", ["development", "holdout"])
def test_checked_in_report_can_be_reproduced_exactly(reports, split):
    stored = json.loads((ROOT / f"docs/benchmark-results/{split}.json").read_bytes())
    assert reports[split] == stored


@pytest.mark.parametrize("failure", ["no-alerts", "runtime-error"])
def test_broken_detector_cannot_pass_a_benchmark(benchmark, failure):
    class BrokenDetector:
        valid = True
        ruleset_digest_sha256 = benchmark.engine.ruleset_digest_sha256

        def summaries(self):
            return benchmark.engine.summaries()

        def evaluate(self, _):
            if failure == "runtime-error":
                raise RuntimeError("controlled evaluation failure")
            return SimpleNamespace(matches=[])

    report = DetectionBenchmark(engine=BrokenDetector()).evaluate()
    assert report["confusion"]["fn"] == 180
    assert report["metrics"]["recall"] == 0
    assert report["metrics"]["precision"] is None
    assert not report["gate_passed"]
    assert report["evaluation_error_count"] == (360 if failure == "runtime-error" else 0)


def test_generator_reproduces_frozen_artifacts_without_reading_detector_output(tmp_path, monkeypatch):
    monkeypatch.setattr(build_detection_benchmark, "OUTPUT", tmp_path)
    build_detection_benchmark.build()
    for name in ("manifest.json", "families.json", "cases.jsonl"):
        assert (tmp_path / name).read_bytes() == (DATA / name).read_bytes()


def test_api_returns_holdout_by_default_and_rejects_unknown_splits(reports):
    with TestClient(app) as client:
        response = client.get("/evaluation/detection-benchmark")
        assert response.status_code == 200
        assert response.json() == reports["holdout"]
        assert client.get("/evaluation/detection-benchmark?split=all").status_code == 422


def test_api_does_not_bypass_authorization(monkeypatch):
    principal = Principal("no-role", "test", frozenset(), "api_key")
    monkeypatch.setitem(app.dependency_overrides, get_principal, lambda: principal)
    with TestClient(app) as client:
        assert client.get("/evaluation/detection-benchmark").status_code == 403


def test_api_reports_invalid_input_as_unavailable(monkeypatch):
    def broken():
        raise BenchmarkUnavailable("internal fixture location")

    monkeypatch.setattr("app.main.get_detection_benchmark", broken)
    with TestClient(app) as client:
        response = client.get("/evaluation/detection-benchmark")
        assert response.status_code == 503
        assert response.json() == {"detail": "Detection benchmark inputs failed validation"}


def test_cli_can_fail_the_quality_gate_without_hiding_its_reports(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["benchmark", "--require-targets", "--output-dir", str(tmp_path)])
    assert evaluate_detection_benchmark.main() == 1
    report = json.loads((tmp_path / "holdout.json").read_bytes())
    assert not report["gate_passed"] and report["evaluation_error_count"] == 0
