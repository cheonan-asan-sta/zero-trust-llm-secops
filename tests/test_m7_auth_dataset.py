import hashlib
import json
import shutil

import pytest

from scripts.prepare_m7 import SOURCE, prepare, verify

PILOT = SOURCE.parent / "pilot"
SPLITS = ("development", "evaluation")
EVENT_FIELDS = {"evidence_id", "module", "http_method", "http_status", "level", "duration_ms"}


def read_jsonl(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


@pytest.fixture
def contract():
    return json.loads(SOURCE.read_bytes())


@pytest.fixture
def bundle(tmp_path):
    return shutil.copytree(PILOT, tmp_path / "pilot")


def rewrite_bundle_file(bundle, name, rows):
    data = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    ).encode("utf-8")
    (bundle / name).write_bytes(data)
    manifest_file = bundle / "manifest.json"
    manifest = json.loads(manifest_file.read_bytes())
    manifest["files"][name] = hashlib.sha256(data).hexdigest()
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")


def test_published_pilot_verifies_and_keeps_ground_truth_out_of_inputs(contract):
    manifest = verify(PILOT, contract)
    assert manifest == json.loads((PILOT / "manifest.json").read_bytes())
    assert manifest["source_sha256"] == contract["sha256"]
    assert manifest["cross_split_overlap"] == dict.fromkeys(
        ("subjects", "clients", "families", "sessions", "records", "signal_patterns"), 0
    )
    labels = read_jsonl(PILOT / "labels.jsonl")
    assert len({row["session_id"] for row in labels}) == len(labels)

    sessions = set()
    evidence = set()
    split_identities = {}
    for split in SPLITS:
        cases = read_jsonl(PILOT / f"{split}.jsonl")
        split_labels = {row["session_id"]: row for row in labels if row["split"] == split}
        assert cases and set(split_labels) == {row["session_id"] for row in cases}
        assert len(split_labels) == len(cases)
        assert {row["expected_label"] for row in split_labels.values()} == {"normal", "threat"}
        split_identities[split] = {
            key: {identity for row in split_labels.values() for identity in row[key]}
            for key in ("subjects", "clients")
        }
        for case in cases:
            assert set(case) == {"session_id", "events"}
            assert case["session_id"] not in sessions
            sessions.add(case["session_id"])
            records = split_labels[case["session_id"]]["records"]
            assert case["events"]
            assert [event["evidence_id"] for event in case["events"]] == [
                record["evidence_id"] for record in records
            ]
            for event, record in zip(case["events"], records, strict=True):
                assert set(event) == EVENT_FIELDS
                assert record["sha256"] not in event["evidence_id"]
                assert event["evidence_id"] not in evidence
                evidence.add(event["evidence_id"])
    assert len(sessions) == len(labels)
    for key in ("subjects", "clients"):
        assert split_identities["development"][key].isdisjoint(split_identities["evaluation"][key])


@pytest.mark.parametrize("name", ["development.jsonl", "evaluation.jsonl", "labels.jsonl"])
def test_artifact_hash_detects_changed_bytes(bundle, contract, name):
    path = bundle / name
    path.write_bytes(path.read_bytes().rstrip(b"\n") + b" \n")
    with pytest.raises(ValueError, match="m7_manifest_mismatch"):
        verify(bundle, contract)


def test_manifest_cannot_replace_the_pinned_source_digest(bundle, contract):
    path = bundle / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["source_sha256"] = "0" * 64
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="m7_manifest_mismatch"):
        verify(bundle, contract)


def test_prepare_rejects_a_substitute_for_the_pinned_raw_log(tmp_path, contract):
    source = tmp_path / "iam.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    output = tmp_path / "pilot"
    with pytest.raises(ValueError, match="m7_source_size"):
        prepare(source, output, contract)
    assert not (output / "manifest.json").exists()


@pytest.fixture
def source_record():
    return {
        "trace_id": "fixture", "label": "benign", "category": "login", "subcategory": None,
        "module": "auth", "http_method": "POST", "http_status": 200, "level": "INFO",
        "duration_ms": 12, "timestamp": "2026-02-01T00:00:00+09:00",
        "user_id": "test-user", "action_by": None, "client_ip": "192.0.2.1",
    }


def write_source(tmp_path, contract, rows):
    data = "".join(json.dumps(row) + "\n" for row in rows).encode("utf-8")
    source = tmp_path / "iam.jsonl"
    source.write_bytes(data)
    contract["bytes"] = len(data)
    contract["sha256"] = hashlib.sha256(data).hexdigest()
    return source


def test_prepare_checks_raw_digest_after_size_matches(tmp_path, contract, source_record):
    source = write_source(tmp_path, contract, [source_record])
    data = source.read_bytes()
    source.write_bytes(data.replace(b'"duration_ms": 12', b'"duration_ms": 13'))
    assert source.stat().st_size == contract["bytes"]
    assert source.read_bytes() != data
    with pytest.raises(ValueError, match="m7_source_digest"):
        prepare(source, tmp_path / "pilot", contract)


def test_prepare_rejects_duplicate_raw_rows(tmp_path, contract, source_record):
    source = write_source(tmp_path, contract, [source_record, source_record])
    with pytest.raises(ValueError, match="m7_duplicate_raw_record"):
        prepare(source, tmp_path / "pilot", contract)


def test_prepare_rejects_conflicting_labels_within_one_trace(tmp_path, contract, source_record):
    conflicting = source_record | {"label": "attack", "subcategory": "credential_stuffing"}
    source = write_source(tmp_path, contract, [source_record, conflicting])
    with pytest.raises(ValueError, match="m7_conflicting_session_labels"):
        prepare(source, tmp_path / "pilot", contract)


@pytest.mark.parametrize("identity", ["subjects", "clients"])
def test_cross_split_identity_is_rejected_even_after_rehashing(bundle, contract, identity):
    labels = read_jsonl(bundle / "labels.jsonl")
    development = next(row for row in labels if row["split"] == "development" and row[identity])
    evaluation = next(row for row in labels if row["split"] == "evaluation" and row[identity])
    evaluation[identity] = development[identity][:]
    rewrite_bundle_file(bundle, "labels.jsonl", labels)
    with pytest.raises(ValueError, match="m7_cross_split_identity_or_family_overlap"):
        verify(bundle, contract)


def test_same_session_cannot_be_assigned_to_both_splits(bundle, contract):
    development = read_jsonl(bundle / "development.jsonl")
    evaluation = read_jsonl(bundle / "evaluation.jsonl")
    labels = read_jsonl(bundle / "labels.jsonl")
    session = evaluation[0]["session_id"]
    reused = development[0]["session_id"]
    evaluation[0]["session_id"] = reused
    next(row for row in labels if row["session_id"] == session)["session_id"] = reused
    rewrite_bundle_file(bundle, "evaluation.jsonl", evaluation)
    rewrite_bundle_file(bundle, "labels.jsonl", labels)
    with pytest.raises(ValueError, match="m7_duplicate_session"):
        verify(bundle, contract)


def test_duplicate_event_is_rejected_even_with_matching_evidence_sidecar(bundle, contract):
    evaluation = read_jsonl(bundle / "evaluation.jsonl")
    labels = read_jsonl(bundle / "labels.jsonl")
    session = next(row for row in evaluation if len(row["events"]) >= 2)
    records = next(row for row in labels if row["session_id"] == session["session_id"])["records"]
    session["events"][1] = session["events"][0].copy()
    records[1] = records[0].copy()
    rewrite_bundle_file(bundle, "evaluation.jsonl", evaluation)
    rewrite_bundle_file(bundle, "labels.jsonl", labels)
    with pytest.raises(ValueError, match="m7_duplicate_or_out_of_range_record"):
        verify(bundle, contract)


def test_duplicate_raw_digest_is_rejected_even_with_distinct_evidence_ids(bundle, contract):
    labels = read_jsonl(bundle / "labels.jsonl")
    development = next(row for row in labels if row["split"] == "development")
    evaluation = next(row for row in labels if row["split"] == "evaluation")
    evaluation["records"][0]["sha256"] = development["records"][0]["sha256"]
    rewrite_bundle_file(bundle, "labels.jsonl", labels)
    with pytest.raises(ValueError, match="duplicate"):
        verify(bundle, contract)


def test_same_signal_pattern_with_different_ids_and_duration_is_rejected(bundle, contract):
    development = read_jsonl(bundle / "development.jsonl")
    evaluation = read_jsonl(bundle / "evaluation.jsonl")
    by_length = {len(row["events"]): row for row in development}
    target = next(row for row in evaluation if len(row["events"]) in by_length)
    copied = by_length[len(target["events"])]["events"]
    target["events"] = [
        source | {"evidence_id": previous["evidence_id"], "duration_ms": source["duration_ms"] + 1}
        for source, previous in zip(copied, target["events"], strict=True)
    ]
    rewrite_bundle_file(bundle, "evaluation.jsonl", evaluation)
    with pytest.raises(ValueError, match="m7_duplicate_signal_pattern"):
        verify(bundle, contract)


def test_changed_label_is_rejected_even_after_rehashing(bundle, contract):
    labels = read_jsonl(bundle / "labels.jsonl")
    different = next(row for row in labels if row["expected_label"] != labels[0]["expected_label"])
    labels[0]["expected_label"] = different["expected_label"]
    rewrite_bundle_file(bundle, "labels.jsonl", labels)
    with pytest.raises(ValueError, match="m7_label_or_family_split_mismatch"):
        verify(bundle, contract)


def test_training_attack_family_cannot_be_relabelled_as_evaluation(bundle, contract):
    labels = read_jsonl(bundle / "labels.jsonl")
    development = next(row for row in labels
                       if row["split"] == "development" and row["expected_label"] == "threat")
    evaluation = next(row for row in labels
                      if row["split"] == "evaluation" and row["expected_label"] == "threat")
    evaluation["category"] = development["category"]
    evaluation["subcategory"] = development["subcategory"]
    rewrite_bundle_file(bundle, "labels.jsonl", labels)
    with pytest.raises(ValueError, match="m7_label_or_family_split_mismatch"):
        verify(bundle, contract)


def test_evaluation_evidence_cannot_precede_training_boundary(bundle, contract):
    labels = read_jsonl(bundle / "labels.jsonl")
    development = next(row for row in labels if row["split"] == "development")
    evaluation = next(row for row in labels if row["split"] == "evaluation")
    evaluation["records"][0]["timestamp"] = development["records"][0]["timestamp"]
    rewrite_bundle_file(bundle, "labels.jsonl", labels)
    with pytest.raises(ValueError, match="m7_event_order_or_time_split"):
        verify(bundle, contract)


def test_labels_cannot_be_embedded_in_model_inputs(bundle, contract):
    evaluation = read_jsonl(bundle / "evaluation.jsonl")
    evaluation[0]["events"][0]["source_label"] = "benign"
    rewrite_bundle_file(bundle, "evaluation.jsonl", evaluation)
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        verify(bundle, contract)
