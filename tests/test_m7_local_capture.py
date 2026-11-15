import hashlib
import json
from collections import Counter

import pytest

from scripts import prepare_m7, prepare_m7_local
from scripts.prepare_m7_holdout import verify_requests


def read_jsonl(data):
    return [json.loads(line) for line in data.splitlines()]


def jsonl(rows):
    return b"".join(prepare_m7.canonical(row) + b"\n" for row in rows)


def write_bundle(directory, files):
    for name, data in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def declared_captures(plan):
    """Construct test evidence without re-running the HTTP lab for every mutation."""
    return [
        {
            "case_id": case["case_id"],
            "policy_digest_sha256": "0" * 64,
            "grant": {
                "http_status": 200,
                "duration_ms": 3,
                "since_previous_ms": None,
                "authenticated_subject": case["owner_id"],
                "authenticated_tenant": case["tenant_id"],
                "content_present": False,
                "reason_code": None,
                "grant_issued": True,
                "journal_matches": None,
            },
            "attempts": [
                {
                    "http_status": attempt["expected_status"],
                    "duration_ms": 2,
                    "since_previous_ms": 0,
                    "authenticated_subject": attempt["expected_subject"],
                    "authenticated_tenant": attempt["expected_tenant"],
                    "content_present": attempt["expected_status"] == 200,
                    "reason_code": attempt["expected_reason"],
                    "journal_matches": True,
                }
                for attempt in case["attempts"]
            ],
        }
        for case in plan
    ]


@pytest.fixture
def capture():
    plan = prepare_m7_local.create_plan()
    return plan, declared_captures(plan)


def test_plan_keeps_normal_denials_and_successful_threats():
    plan = prepare_m7_local.create_plan()
    assert Counter(case["expected_label"] for case in plan) == {"normal": 100, "threat": 100}
    assert (
        len({case["case_id"] for case in plan}) == len({case["session_id"] for case in plan}) == 200
    )
    statuses = {
        label: {
            case["attempts"][-1]["expected_status"]
            for case in plan
            if case["expected_label"] == label
        }
        for label in ("normal", "threat")
    }
    assert {200, 401} <= statuses["normal"] & statuses["threat"]
    assert all(case["owner_id"] != case["attacker_id"] for case in plan)


def test_local_bundle_separates_scoring_labels_from_model_inputs(capture, tmp_path):
    plan, captures = capture
    files, manifest = prepare_m7_local.build_bundle(plan, captures, ())
    assert json.loads(files["manifest.json"]) == manifest
    assert {
        "private/plan.jsonl",
        "private/scoring-labels.jsonl",
        "private/evidence.jsonl",
    } <= files.keys()
    observations = read_jsonl(files["observations.jsonl"])
    scoring = read_jsonl(files["private/scoring-labels.jsonl"])
    assert len(observations) == len(scoring) == 200
    assert {row["session_id"]: row["expected_label"] for row in scoring} == {
        case["session_id"]: case["expected_label"] for case in plan
    }
    assert {row["session_id"] for row in observations} == {row["session_id"] for row in scoring}
    assert all(set(row) == {"session_id", "events"} for row in observations)
    evidence = [event["evidence_id"] for row in observations for event in row["events"]]
    assert len(evidence) == len(set(evidence))
    assert all(
        event["since_previous_ms"] is None for row in observations for event in row["events"]
    )
    assert all(case["owner_id"].encode() not in files["observations.jsonl"] for case in plan)
    assert all(case["attacker_id"].encode() not in files["observations.jsonl"] for case in plan)
    assert verify_requests(files["observations.jsonl"])["answer_fields"] == 0
    directory = tmp_path / "bundle"
    write_bundle(directory, files)
    assert prepare_m7_local.verify_bundle(directory, ()) == manifest


@pytest.mark.parametrize("mutation", ["status", "principal", "content", "journal", "missing"])
def test_build_refuses_unverified_terminal_outcomes(capture, mutation):
    plan, captures = capture
    matching = next(row for row in captures if row["attempts"][-1]["http_status"] == 200)
    attempt = matching["attempts"][-1]
    if mutation == "status":
        attempt["http_status"] = 500
    elif mutation == "principal":
        attempt["authenticated_subject"] = "unrelated-account"
    elif mutation == "content":
        attempt["content_present"] = False
    elif mutation == "journal":
        attempt["journal_matches"] = False
    else:
        captures.remove(matching)

    error = {"journal": "m7_local_capture_journal", "missing": "m7_local_capture_count"}.get(
        mutation, "m7_local_capture_outcome"
    )
    with pytest.raises(ValueError, match=error):
        prepare_m7_local.build_bundle(plan, captures, ())


def test_build_refuses_session_overlap_with_prior_observations(capture, tmp_path):
    plan, captures = capture
    files, _ = prepare_m7_local.build_bundle(plan, captures, ())
    prior_path = tmp_path / "observations.jsonl"
    prior_path.write_bytes(files["observations.jsonl"].splitlines()[0] + b"\n")

    with pytest.raises(ValueError, match="overlap"):
        prepare_m7_local.build_bundle(plan, captures, (prior_path,))


@pytest.mark.parametrize("target", ["extra_label_field", "forged_observation", "swapped_labels"])
def test_verification_rejects_rehashed_tampering(capture, tmp_path, target):
    plan, captures = capture
    files, manifest = prepare_m7_local.build_bundle(plan, captures, ())
    name = "private/scoring-labels.jsonl" if target == "swapped_labels" else "observations.jsonl"
    rows = read_jsonl(files[name])
    if target == "swapped_labels":
        first = next(row for row in rows if row["expected_label"] == "normal")
        second = next(row for row in rows if row["expected_label"] == "threat")
        first["expected_label"], second["expected_label"] = (
            second["expected_label"],
            first["expected_label"],
        )
    elif target == "extra_label_field":
        rows[0]["events"][0]["expected_label"] = "threat"
    else:
        event = rows[0]["events"][0]
        event["http_status"] = 418
    files[name] = jsonl(rows)
    manifest["files"][name] = hashlib.sha256(files[name]).hexdigest()
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode() + b"\n"
    directory = tmp_path / "forged"
    write_bundle(directory, files)

    with pytest.raises(ValueError, match="m7_local_bundle_mismatch"):
        prepare_m7_local.verify_bundle(directory, ())
