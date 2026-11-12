"""Immutable regression and fresh execution evidence evaluation contracts."""

import copy
import json
from pathlib import Path

import pytest

from scripts import evaluate_m7_execution_context as evaluation


@pytest.fixture(scope="module")
def experiment(tmp_path_factory):
    inputs, labels = evaluation.build_fresh(1)
    location = tmp_path_factory.mktemp("execution-evaluation")
    records = [evaluation.run_case(item["context"], location / str(index), execution=item["execution"])
               for index, item in enumerate(inputs)]
    by_case = {row["case_id"]: row for row in records}
    by_input = {row["case_id"]: row for row in inputs}
    return inputs, labels, records, {
        reference["family"]: (by_input[reference["case_id"]], by_case[reference["case_id"]], reference)
        for reference in labels
    }


def test_new_dataset_keeps_hidden_threats_and_known_benign_missing_information():
    inputs, labels = evaluation.build_fresh(1)
    result = evaluation.audit_fresh(inputs, labels)
    assert result["target_sessions"] == 17
    assert result["label_counts"] == {"normal": 7, "threat": 7, "unknown": 3}
    assert result["execution_labels_in_inputs"] == 0
    assert all("family" not in row and "label" not in row for row in inputs)
    assert next(row for row in labels if row["family"] == "hidden_abuse_same_actor_destination")["label"] == "threat"
    assert next(row for row in labels if row["family"] == "benign_binary_update_stale_approval")["label"] == "normal"


@pytest.mark.parametrize("location", ["top", "execution", "actor", "policy"])
def test_reference_fields_cannot_enter_operational_inputs(location):
    inputs, _ = evaluation.build_fresh(1)
    item = copy.deepcopy(next(row for row in inputs if row["execution"]["actor"] is not None and row["execution"]["policy"] is not None))
    target = item if location == "top" else item["execution"]
    if location == "actor": target = target["actor"]
    if location == "policy": target = target["policy"]
    target["label"] = "normal"
    with pytest.raises(ValueError): evaluation.audit_fresh([item])


def test_fresh_real_collector_and_api_cases_keep_all_outcomes(experiment):
    inputs, labels, records, _ = experiment
    report = evaluation.score(records, labels, inputs=inputs)
    current = report["arms"]["with_context"]
    assert current["confusion_classified_known"] == {"tp": 4, "fp": 1, "fn": 1, "tn": 3}
    assert current["missed_threats_including_abstentions_and_errors"] == 3
    assert current["held_by_label"] == {"normal": 3, "threat": 2, "unknown": 3}
    assert current["errors_total"] == 0
    assert current["metrics"] == {"precision": 0.8, "recall": 4 / 7,
                                  "f1": 8 / 12, "false_positive_rate": 1 / 7}
    assert current["evidence_alignment"]["provenance_aligned"] == 17
    assert current["evidence_alignment"]["reference_supported"] == 10


@pytest.mark.parametrize("family,status,state", [
    ("approved_exact_execution", 201, "acknowledged"),
    ("attack_with_corrupted_report", 403, "rejected"),
    ("attack_with_unbound_capture_report", 404, "pending"),
    ("unresolved_stale_evidence", 201, "acknowledged"),
])
def test_actual_api_intake_and_collector_receipt_are_recorded(experiment, family, status, state):
    item, row, _ = experiment[3][family]
    assert row["execution_trace"]["http_status"] == status
    assert row["execution_trace"]["state"] == state
    evaluation.validate_run(item["context"], row, item["execution"])


def test_changed_endpoint_rejected_even_when_runtime_rehashes_committed_record(experiment):
    item, original, _ = experiment[3]["approved_exact_execution"]
    row = copy.deepcopy(original)
    row["execution_trace"]["request"]["destinations"][0]["host"] = "other.example.invalid"
    request = row["execution_trace"]["request"]
    entry = next(entry for entry in row["provenance"]["context_records"] if entry["kind"] == "execution")
    entry["payload"]["evidence"] = copy.deepcopy(request)
    entry["payload"]["input_digest"] = evaluation.digest(evaluation.canonical(request))
    row["execution_trace"]["receipt"]["input_digest"] = entry["payload"]["input_digest"]
    with pytest.raises(ValueError, match="materialized_evidence_changed"):
        evaluation.validate_run(item["context"], row, item["execution"])


def test_changed_approval_policy_rejected(experiment):
    item, original, _ = experiment[3]["unauthorized_workload"]
    row = copy.deepcopy(original)
    entry = next(entry for entry in row["provenance"]["context_records"] if entry["kind"] == "approval")
    entry["payload"]["request"]["execution_policy"]["actor"] = item["execution"]["actor"]
    with pytest.raises(ValueError, match="materialized_policy_changed"):
        evaluation.validate_run(item["context"], row, item["execution"])


def test_evidence_alignment_is_not_label_accuracy(experiment):
    item, row, reference = experiment[3]["benign_binary_update_stale_approval"]
    alignment = evaluation._execution_alignment(row, reference, item)
    assert row["with_context"]["verdict"] == "threat"
    assert alignment["provenance_aligned"] is True
    assert alignment["reference_supported"] is False
    item, row, reference = experiment[3]["hidden_abuse_same_actor_destination"]
    alignment = evaluation._execution_alignment(row, reference, item)
    assert row["with_context"]["verdict"] == "normal"
    assert alignment["provenance_aligned"] is True
    assert alignment["reference_supported"] is False


def test_previous_archive_hash_contract_is_read_only(tmp_path):
    # This is a small synthetic archive for the hash contract. Acceptance of the
    # real240 artifacts runs separately with scripts.verify_m7_historical_quota.
    previous = tmp_path / 'prior-archive'
    (previous / 'private').mkdir(parents=True)
    for name in ('inputs.jsonl', 'private/scoring.jsonl', 'predictions.jsonl'):
        (previous / name).write_text(''.join(json.dumps({'case_id': str(i)}) + '\n' for i in range(240)))
    manifest = {'sessions': 240, 'files': {name: evaluation._hash(previous / name)
                for name in ('inputs.jsonl', 'private/scoring.jsonl')}}
    (previous / 'manifest.json').write_text(json.dumps(manifest))
    (previous / 'report.json').write_text(json.dumps({
        'sessions': 240, 'manifest_sha256': evaluation._hash(previous / 'manifest.json'),
        'predictions_sha256': evaluation._hash(previous / 'predictions.jsonl'),
    }))
    original = {p.relative_to(previous).as_posix(): p.read_bytes() for p in previous.rglob('*') if p.is_file()}
    before = evaluation.prior_artifacts(previous)
    assert evaluation.prior_artifacts(previous, pinned=before) == before
    changed = dict(before)
    changed["report.json"] = "0" * 64
    with pytest.raises(ValueError, match="prior_changed"):
        evaluation.prior_artifacts(previous, pinned=changed)
    assert {p.relative_to(previous).as_posix(): p.read_bytes() for p in previous.rglob('*') if p.is_file()} == original


def test_legacy_quota_uses_only_saved_original_evaluation(tmp_path):
    raw = (Path(__file__).parent / 'fixtures/behavior_context/historical-approval.json').read_bytes()
    assert evaluation.digest(raw) == '12cf6f71ef3e8ce07ac9adf1f8272b555ec795b5e413a0b4c61329bda9c721c2'
    fixture = json.loads(raw)
    spec, archived = fixture['spec'], fixture['archived_evaluation']
    row = evaluation.run_case(spec, tmp_path / "historical", historical_prior=archived)
    assert row["historical_quota_replayed"] is True
    assert row["with_context"]["verdict"] == "unknown"
    assert row["execution_trace"]["state"] == "not_supplied"
    used = [entry for entry in row["provenance"]["context_records"] if entry["kind"] == "evaluation"]
    assert used == [archived]
    with pytest.raises(ValueError, match="missing_original_prior_use"):
        evaluation.run_case(spec, tmp_path / "missing")


@pytest.fixture
def fake_bundle(tmp_path, monkeypatch):
    previous = tmp_path / "previous"
    (previous / "private").mkdir(parents=True)
    (previous / "inputs.jsonl").write_text('{"case_id":"old"}\n')
    (previous / "private/scoring.jsonl").write_text('{"case_id":"old","label":"unknown"}\n')
    monkeypatch.setattr(evaluation, "prior_artifacts", lambda *a, **k: {"saved": "unchanged"})
    monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"source": "frozen"})
    monkeypatch.setattr(evaluation, "audit_prior_overlap", lambda *a, **k: {"sources": {}})
    directory = tmp_path / "output"
    evaluation.prepare(directory, previous=previous, repetitions=1)
    return directory


def test_frozen_input_and_source_changes_refuse_evaluation(fake_bundle, monkeypatch):
    evaluation.checked(fake_bundle)
    monkeypatch.setattr(evaluation, "implementation_hashes", lambda: {"source": "changed"})
    with pytest.raises(ValueError, match="source_changed"): evaluation.checked(fake_bundle)


def test_coherently_changed_labels_and_manifest_do_not_change_frozen_identity(fake_bundle):
    _, frozen = evaluation.checked(fake_bundle)
    path = fake_bundle / "fresh/private/scoring.jsonl"
    path.write_bytes(path.read_bytes() + b"\n")
    manifest_path = fake_bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["fresh/private/scoring.jsonl"] = evaluation._hash(path)
    manifest_path.write_bytes(evaluation.canonical(manifest))
    with pytest.raises(ValueError, match="manifest_changed"): evaluation.checked(fake_bundle, frozen)


def test_existing_result_directory_is_never_replaced(fake_bundle):
    before = (fake_bundle / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="directory_exists"): evaluation.prepare(fake_bundle)
    assert (fake_bundle / "manifest.json").read_bytes() == before
