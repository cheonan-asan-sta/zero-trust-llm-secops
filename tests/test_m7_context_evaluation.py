"""Freeze, label separation and immutable evaluation artifact contracts."""

import json
import subprocess

import pytest

from scripts import evaluate_m7_context as evaluation


@pytest.mark.parametrize('failure', ['missing', 'not-checkout', 'timeout'])
def test_prepare_without_git_keeps_unknown_revision_and_required_hashes(bundle, tmp_path, monkeypatch, failure):
    def unavailable(*args, **kwargs):
        if failure == 'missing':
            raise FileNotFoundError('git')
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(['git'], 5)
        return subprocess.CompletedProcess(['git'], 128, stdout='', stderr='not a repository')

    monkeypatch.setattr(evaluation.subprocess, 'run', unavailable)
    directory = tmp_path / 'portable-archive'
    manifest = evaluation.prepare(directory, repetitions=1)
    assert manifest['source_commit'] is None and manifest['source_dirty'] is None
    assert manifest['implementation_sha256'] == {'frozen-source': 'v1'}
    assert evaluation.checked_bundle(directory)[0] == manifest


@pytest.mark.parametrize('dirty', [False, True])
def test_known_revision_records_actual_git_status(monkeypatch, dirty):
    monkeypatch.setattr(evaluation, 'source_commit', lambda: 'a' * 40)
    monkeypatch.setattr(evaluation.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(
        ['git'], 0, stdout=' M source.py\n' if dirty else '', stderr='',
    ))
    assert evaluation.source_revision() == ('a' * 40, dirty)


@pytest.mark.parametrize('failure', ['status-error', 'timeout'])
def test_failed_status_lookup_is_never_recorded_as_clean(monkeypatch, failure):
    monkeypatch.setattr(evaluation, 'source_commit', lambda: 'a' * 40)

    def unavailable(*args, **kwargs):
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(['git'], 5)
        return subprocess.CompletedProcess(['git'], 128, stdout='', stderr='unavailable')

    monkeypatch.setattr(evaluation.subprocess, 'run', unavailable)
    assert evaluation.source_revision() == ('a' * 40, None)


def test_source_change_while_reading_revision_cannot_publish_bundle(bundle, tmp_path, monkeypatch):
    def changed():
        monkeypatch.setattr(evaluation, 'implementation_hashes', lambda: {'frozen-source': 'v2'})
        return 'a' * 40, True

    monkeypatch.setattr(evaluation, 'source_revision', changed)
    directory = tmp_path / 'changed-during-metadata'
    with pytest.raises(ValueError, match='implementation_changed_during_prepare'):
        evaluation.prepare(directory, repetitions=1)
    assert not directory.exists()


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    from scripts import m7_context_dataset as dataset
    from scripts import m7_context_provenance as provenance

    build = dataset.build_dataset

    def one_case(repetitions=1):
        inputs, labels = build(repetitions=1)
        item = inputs[0]
        return [item], [row for row in labels if row["case_id"] == item["case_id"]]

    monkeypatch.setattr(dataset, "build_dataset", one_case)
    monkeypatch.setattr(dataset, "audit_prior_overlap", lambda *a, **k: {"sources": {}})
    # These tests exercise publication order with fake rows; real evidence has a separate suite.
    monkeypatch.setattr(provenance, "validate_provenance", lambda *a: None)
    monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"frozen-source": "v1"})
    directory = tmp_path / "evaluation"
    evaluation.prepare(directory, repetitions=1)
    return directory


def test_changed_source_refuses_evaluation(bundle, monkeypatch):
    monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"frozen-source": "v2"})
    with pytest.raises(ValueError, match="frozen_implementation_changed"):
        evaluation.evaluate(bundle)
    assert not (bundle / evaluation.PREDICTIONS).exists()


@pytest.mark.parametrize("name", [evaluation.INPUTS, evaluation.LABELS])
def test_changed_dataset_refuses_evaluation(bundle, name):
    path = bundle / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="dataset_changed"):
        evaluation.evaluate(bundle)
    assert not (bundle / evaluation.PREDICTIONS).exists()


def test_prepare_cannot_replace_previous_bundle(bundle):
    before = (bundle / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="directory_exists"):
        evaluation.prepare(bundle)
    assert (bundle / "manifest.json").read_bytes() == before


def fake_case(spec, directory):
    assert "label" not in spec and "family" not in spec
    activity = evaluation.PublicSession.model_validate(spec["target"]["activity"]).model_dump(mode="json")
    fingerprint = evaluation.digest(evaluation.canonical(activity))
    return {"case_id": spec["case_id"], "session_id": spec["target"]["session_id"],
            "input_sha256": evaluation.digest(evaluation.canonical(spec)),
            "rule_only": {"verdict": "unknown"}, "with_context": {"verdict": "unknown"},
            "activity_sha256": fingerprint, "rule_input_sha256": fingerprint,
            "context_activity_sha256": fingerprint, "paired_input_identical": True,
            "policy_journal_unchanged_by_evaluation": True,
            "provenance": {"capture": spec["target"] | {
                "activity": activity, "scope": spec["scope"], "tenant_id": spec["tenant_id"],
            }}}


def test_labels_decoded_only_after_predictions_are_written(bundle, monkeypatch):
    from scripts import m7_context_runtime as runtime
    from scripts import m7_context_scoring as scoring

    monkeypatch.setattr(runtime, "run_case", fake_case)
    original = evaluation.read_rows
    label_bytes = (bundle / evaluation.LABELS).read_bytes()
    label_read = []

    def guarded_read(raw):
        if raw == label_bytes:
            assert (bundle / evaluation.PREDICTIONS).is_file()
            label_read.append(True)
        return original(raw)

    def score(predictions, labels):
        assert label_read and len(predictions) == len(labels) == 1
        return {"sessions": len(predictions)}

    monkeypatch.setattr(evaluation, "read_rows", guarded_read)
    monkeypatch.setattr(scoring, "score_comparison", score)
    result = evaluation.evaluate(bundle)
    assert result["scoring_labels_decoded_after_predictions_saved"]
    assert result["project_goals_met"] is False
    assert len(label_read) == 1
    report_before = (bundle / "report.json").read_bytes()
    with pytest.raises(ValueError, match="results_exist"):
        evaluation.evaluate(bundle)
    assert (bundle / "report.json").read_bytes() == report_before


def test_runtime_failure_is_recorded_without_raw_error_or_false_normal(bundle, monkeypatch):
    from scripts import m7_context_runtime as runtime

    def fail(spec, directory):
        raise RuntimeError("private token must never appear")

    monkeypatch.setattr(runtime, "run_case", fail)
    _, inputs, _ = evaluation.checked_bundle(bundle)
    rows = evaluation.predict(inputs, bundle)
    assert rows[0]["error_type"] == "RuntimeError"
    assert rows[0]["rule_only"] == {"status": "error", "verdict": "unknown"}
    assert "private token" not in json.dumps(rows)


def test_source_changed_during_prediction_never_publishes_scored_report(bundle, monkeypatch):
    from scripts import m7_context_runtime as runtime

    def change(spec, directory):
        result = fake_case(spec, directory)
        monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"frozen-source": "v2"})
        return result

    monkeypatch.setattr(runtime, "run_case", change)
    with pytest.raises(ValueError, match="frozen_implementation_changed"):
        evaluation.evaluate(bundle)
    assert (bundle / evaluation.PREDICTIONS).exists()
    assert not (bundle / "report.json").exists()


def test_actual_capture_tamper_rejected_even_if_runtime_recomputes_its_hashes(bundle, monkeypatch):
    from scripts import m7_context_runtime as runtime

    def change(spec, directory):
        result = fake_case(spec, directory)
        result["provenance"]["capture"]["activity"]["events"][0]["outcome"] = "failure"
        fingerprint = evaluation.digest(evaluation.canonical(result["provenance"]["capture"]["activity"]))
        for key in ("activity_sha256", "rule_input_sha256", "context_activity_sha256"):
            result[key] = fingerprint
        return result

    monkeypatch.setattr(runtime, "run_case", change)
    with pytest.raises(ValueError, match="observed_input_mismatch"):
        evaluation.evaluate(bundle)
    assert not (bundle / "report.json").exists()


def test_coherent_label_and_manifest_change_during_run_is_rejected(bundle, monkeypatch):
    from scripts import m7_context_runtime as runtime

    def change(spec, directory):
        path = bundle / evaluation.LABELS
        labels = evaluation.read_rows(path.read_bytes())
        labels[0]["rationale"] += " changed after freeze"
        path.write_bytes(evaluation.jsonl(labels))
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][evaluation.LABELS] = evaluation.digest(path.read_bytes())
        manifest_path.write_bytes(evaluation.canonical(manifest) + b"\n")
        return fake_case(spec, directory)

    monkeypatch.setattr(runtime, "run_case", change)
    with pytest.raises(ValueError, match="manifest_changed_during_run"):
        evaluation.evaluate(bundle)
    assert not (bundle / "report.json").exists()
