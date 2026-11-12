import hashlib
import json

import pytest

from scripts import prepare_m7, prepare_m7_holdout


def read_jsonl(data):
    return [json.loads(line) for line in data.splitlines()]


@pytest.fixture
def bundle(tmp_path):
    contract = json.loads(prepare_m7.SOURCE.read_bytes())
    contract["pilot"]["sessions_per_label_per_split"] = 1
    development_attack = ("attack", "protocol_fixture", "scenario-0")
    prior_attack = ("attack", "protocol_fixture", "scenario-4")
    fresh_attack = next(
        family for n in range(1, 20)
        if (family := ("attack", "protocol_fixture", f"scenario-{n}")) != prior_attack
        and prepare_m7.split_for(family, contract["pilot"]) == "development"
    )
    sessions = (
        ("dev-normal", "02-01", ("benign", "login", None)),
        ("dev-attack", "02-01", development_attack),
        ("prior-normal", "03-02", ("benign", "account", None)),
        ("prior-attack", "03-02", prior_attack),
        ("fresh-normal", "03-03", ("benign", "login", None)),
        ("fresh-attack", "03-03", fresh_attack),
    )
    rows = []
    for index, (trace, date, (label, category, subcategory)) in enumerate(sessions):
        base = {
            "trace_id": trace,
            "label": label,
            "category": category,
            "subcategory": subcategory,
            "module": "auth",
            "http_method": "POST",
            "level": "INFO",
            "duration_ms": 10,
            "user_id": f"private-account-{index}",
            "action_by": f"private-actor-{index}",
            "client_ip": f"198.51.100.{index + 1}",
            "message": "private-message",
            "uri": "/private-uri",
            "payload": {"token": "private-payload"},
        }
        # Write the later event first so the bundle must restore chronological order.
        rows.extend((
            base | {
                "timestamp": f"2026-{date}T09:00:00.003+09:00",
                "http_status": 401,
                "event_type": "auth_login_failed_user_not_found",
            },
            base | {
                "timestamp": f"2026-{date}T09:00:00+09:00",
                "http_status": 200 + index,
                "event_type": "private-event-type",
            },
        ))

    raw = "".join(json.dumps(row) + "\n" for row in rows).encode()
    source = tmp_path / "publisher.jsonl"
    source.write_bytes(raw)
    contract.update(
        bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        source_counts={"rows": len(rows), "sessions": {"benign": 3, "attack": 3}},
    )
    pilot = tmp_path / "pilot"
    prepare_m7.prepare(source, pilot, contract)
    return source, pilot, contract


def write_bundle(directory, files):
    directory.mkdir()
    for name, data in files.items():
        (directory / name).write_bytes(data)


def test_holdout_reproduces_enriched_observations_and_separate_labels(bundle, tmp_path):
    source, pilot, contract = bundle
    files, manifest = prepare_m7_holdout.build_holdout(source, pilot, contract)
    assert set(files) == {"observations.jsonl", "scoring-labels.jsonl", "manifest.json", "NOTICE.md"}
    assert json.loads(files["manifest.json"]) == manifest
    assert manifest["files"] == {
        name: hashlib.sha256(data).hexdigest()
        for name, data in files.items() if name != "manifest.json"
    }
    observations = read_jsonl(files["observations.jsonl"])
    labels = {row["session_id"]: row for row in read_jsonl(files["scoring-labels.jsonl"])}
    holdout_ids = [row["session_id"] for row in observations]
    assert holdout_ids == sorted(prepare_m7.session_id_for(trace)
                                 for trace in ("fresh-normal", "fresh-attack"))
    assert set(holdout_ids) == set(labels)
    assert {row["expected_label"] for row in labels.values()} == {"normal", "threat"}
    old = read_jsonl((pilot / "development.jsonl").read_bytes()) + read_jsonl(
        (pilot / "evaluation.jsonl").read_bytes()
    )
    assert set(holdout_ids).isdisjoint(row["session_id"] for row in old)
    for row in observations:
        assert set(row) == {"session_id", "events"}
        assert all(set(event) == {
            "evidence_id", "module", "http_method", "http_status", "level", "duration_ms",
            "auth_stage", "failure_reason", "since_previous_ms",
        } for event in row["events"])
        assert [event["auth_stage"] for event in row["events"]] == ["unknown", "login"]
        assert [event["failure_reason"] for event in row["events"]] == [None, "user_not_found"]
        assert [event["since_previous_ms"] for event in row["events"]] == [None, 3]
    assert b"private-" not in files["observations.jsonl"]
    assert b"198.51.100." not in files["observations.jsonl"]
    assert b"auth_login_failed_user_not_found" not in files["observations.jsonl"]

    directory = tmp_path / "holdout"
    assert prepare_m7_holdout.prepare_holdout(source, pilot, directory, contract) == manifest
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == files
    assert prepare_m7_holdout.verify_holdout(source, pilot, directory, contract) == manifest
    with pytest.raises(ValueError, match="m7_holdout_output_requires_fresh_directory"):
        prepare_m7_holdout.prepare_holdout(source, pilot, directory, contract)


@pytest.mark.parametrize("target", ["extra_key", "label_in_stage", "scoring_label"])
def test_holdout_rejects_forged_files_even_after_rehash(bundle, tmp_path, target):
    source, pilot, contract = bundle
    files, manifest = prepare_m7_holdout.build_holdout(source, pilot, contract)
    filename = "scoring-labels.jsonl" if target == "scoring_label" else "observations.jsonl"
    rows = read_jsonl(files[filename])
    if target == "scoring_label":
        rows[0]["expected_label"], rows[1]["expected_label"] = (
            rows[1]["expected_label"], rows[0]["expected_label"],
        )
    elif target == "extra_key":
        rows[0]["events"][0]["expected_label"] = "threat"
    else:
        rows[0]["events"][0]["auth_stage"] = "threat"
    files[filename] = b"".join(prepare_m7.canonical(row) + b"\n" for row in rows)
    manifest["files"][filename] = hashlib.sha256(files[filename]).hexdigest()
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode() + b"\n"
    directory = tmp_path / "forged"
    write_bundle(directory, files)

    with pytest.raises(ValueError, match="m7_holdout_reproduction_mismatch"):
        prepare_m7_holdout.verify_holdout(source, pilot, directory, contract)


def test_holdout_rejects_same_size_change_to_pinned_source(bundle):
    source, pilot, contract = bundle
    raw = source.read_bytes()
    changed = raw.replace(b"private-message", b"PRIVATE-MESSAGE", 1)
    assert len(raw) == len(changed) and raw != changed
    source.write_bytes(changed)

    with pytest.raises(ValueError, match="m7_source_digest"):
        prepare_m7_holdout.build_holdout(source, pilot, contract)


@pytest.mark.parametrize("field", ["auth_stage", "failure_reason"])
def test_request_check_rejects_labels_in_allowed_observation_fields(bundle, field):
    source, pilot, contract = bundle
    files, _ = prepare_m7_holdout.build_holdout(source, pilot, contract)
    rows = read_jsonl(files["observations.jsonl"])
    rows[0]["events"][0][field] = "threat"
    observations = b"".join(prepare_m7.canonical(row) + b"\n" for row in rows)

    with pytest.raises(ValueError, match="m7_holdout_request_values"):
        prepare_m7_holdout.verify_requests(observations)


@pytest.mark.parametrize("conflict", ["session", "actor", "client", "pattern", "record", "threat_family"])
def test_selector_rejects_known_split_overlap(bundle, conflict):
    source, _, contract = bundle
    sessions = prepare_m7.read_source(source, contract)
    old = prepare_m7.select_sessions(sessions, contract["pilot"])
    if conflict == "threat_family":
        known = sessions["dev-attack"]
        fresh_trace = "fresh-attack"
    else:
        known = sessions["prior-normal"]
        fresh_trace = "fresh-normal"

    changed = []
    for row, previous in zip(sessions[fresh_trace], known, strict=True):
        when, event, record, family, actors, client = row
        if conflict == "actor":
            actors = (previous[4][-1],)
        elif conflict == "client":
            client = previous[5]
        elif conflict == "pattern":
            event = event.model_copy(update={"http_status": previous[1].http_status})
        elif conflict == "record":
            record = record.model_copy(update={"sha256": previous[2].sha256})
        elif conflict == "threat_family":
            family = previous[3]
        changed.append((when, event, record, family, actors, client))
    del sessions[fresh_trace]
    sessions["prior-normal" if conflict == "session" else fresh_trace] = changed

    with pytest.raises(ValueError, match="insufficient"):
        prepare_m7_holdout.select_holdout(sessions, old, contract)
