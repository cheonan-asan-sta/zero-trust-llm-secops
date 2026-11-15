"""Bind runtime evidence to frozen operational inputs, independently of scoring labels."""

import hashlib
import json
from datetime import datetime, timedelta

from app.services.public_detection import PublicSession


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _require(condition, code):
    if not condition:
        raise ValueError("context_provenance_" + code)


def _date(value):
    instant = datetime.fromisoformat(value)
    _require(instant.utcoffset() is not None, "clock")
    return instant


def _window_request(actual, expected):
    expected = dict(expected)
    for key in ("valid_from", "valid_until"):
        _require(_date(actual[key]) == _date(expected[key]), "window_time")
        expected[key] = actual[key]
    return actual == expected


def _capture(spec, sample, captured):
    activity = PublicSession.model_validate(sample["activity"]).model_dump(mode="json")
    issued = max(_date(event["timestamp"]) for event in activity["events"])
    _require(captured["activity"] == activity, "sample_activity")
    _require(captured["capture_id"] == sample["capture_id"]
             and captured["session_id"] == sample["session_id"]
             and captured["tenant_id"] == spec["tenant_id"]
             and captured["scope"] == spec["scope"], "sample_binding")
    _require(captured["schema_version"] == "zt-behavior-1"
             and captured["algorithm"] == "Ed25519"
             and captured["source_id"] == "behavior" and captured["key_id"] == "key"
             and captured["session_version"] == 1 and "signature" not in captured,
             "sample_source")
    _require(_date(captured["issued_at"]) == issued
             and _date(captured["expires_at"]) == issued + timedelta(seconds=90), "sample_time")
    _require(set(captured["connection_ids"]) == {
        event["connection_id"] for event in activity["events"]
    }, "sample_connections")


def _context_records(spec, provenance, at):
    samples = spec["baseline_samples"]
    captured_samples = provenance["baseline_sample_captures"]
    _require(len(captured_samples) == len(samples), "sample_count")
    for sample, captured in zip(samples, captured_samples, strict=True):
        _capture(spec, sample, captured)
    target = provenance["capture"]
    _capture(spec, spec["target"], target)
    captures = captured_samples + [target]
    prior = spec["prior_use"]
    if prior is None:
        _require(provenance["prior_use_capture"] is None, "unexpected_prior_use")
    else:
        _capture(spec, prior, provenance["prior_use_capture"])
        captures.append(provenance["prior_use_capture"])
    records = provenance["context_records"]
    index = {(entry["kind"], entry["record_id"]): entry for entry in records}
    _require(len(index) == len(records), "duplicate_record")
    expected_keys = {("capture", item["capture_id"]) for item in captures}
    for capture in captures:
        entry = index.get(("capture", capture["capture_id"]))
        _require(entry is not None, "missing_capture_record")
        _require(entry["payload"]["capture"] == capture
                 and entry["payload"]["input_digest"] == _digest(capture), "capture_record_content")
        _require(_date(entry["created_at"]) == _date(capture["issued_at"])
                 and entry["actor"] == "lab-reader", "capture_record_time")
    baseline, approval = spec["baseline"], spec["approval"]
    if baseline["enabled"]:
        expected_keys.add(("baseline", baseline["id"]))
        entry = index.get(("baseline", baseline["id"]))
        _require(entry is not None, "missing_baseline")
        payload = entry["payload"]
        request = payload["request"]
        _require(_window_request(request, {
            "baseline_id": baseline["id"], "capture_ids": [item["capture_id"] for item in samples],
            "valid_from": at(3).isoformat(), "valid_until": at(300).isoformat(),
            "note": "Reviewed earlier local operation samples",
        }), "baseline_request")
        _require(payload["scope"] == spec["scope"]
                 and _date(entry["created_at"]) == at(3) and entry["actor"] == "lab-operator",
                 "baseline_scope_time")
        _require(set(payload["training_event_ids"]) == {
            event["id"] for sample in samples for event in sample["activity"]["events"]
        } and set(payload["training_groups"]) == {
            sample["activity"]["original_group_id"] for sample in samples
        }, "baseline_samples")
    if approval["mode"] != "missing":
        expected_keys.add(("approval", approval["id"]))
        entry = index.get(("approval", approval["id"]))
        _require(entry is not None, "missing_approval")
        start, end = (20 if approval["mode"] == "future" else 3), (9 if approval["mode"] == "expired" else 60)
        _require(_window_request(entry["payload"]["request"], {
            "approval_id": approval["id"], "baseline_id": baseline["id"],
            "max_uses": approval["max_uses"], "valid_from": at(start).isoformat(),
            "valid_until": at(end).isoformat(), "note": "Bounded local operation window",
        }), "approval_request")
        _require(entry["payload"]["scope"] == spec["scope"]
                 and entry["payload"]["baseline_digest"] == _digest(index["baseline", baseline["id"]]["payload"])
                 and _date(entry["created_at"]) == at(3) and entry["actor"] == "lab-operator",
                 "approval_scope_time")
    revocations = []
    if approval["mode"] == "revoked":
        revocations.append(("approval", approval["id"], "Operation window cancelled"))
    if baseline["revoked"]:
        revocations.append(("baseline", baseline["id"], "Reviewed operation profile withdrawn"))
    for kind, identifier, reason in revocations:
        record_id = _digest([kind, identifier])
        expected_keys.add(("revocation", record_id))
        entry = index.get(("revocation", record_id))
        _require(entry is not None and entry["payload"] == {
            "target_kind": kind, "target_id": identifier, "reason": reason,
        } and _date(entry["created_at"]) == at(8) and entry["actor"] == "lab-operator",
            "revocation")
    evaluations = [entry for entry in records if entry["kind"] == "evaluation"]
    _require(len(evaluations) == (1 if prior else 0), "prior_use_count")
    if prior:
        entry = evaluations[0]
        payload = entry["payload"]
        expected_keys.add(("evaluation", entry["record_id"]))
        _require(payload["capture_id"] == prior["capture_id"]
                 and payload["approval_id"] == approval["id"]
                 and payload["baseline_id"] == baseline["id"]
                 and payload["verdict"] == "normal"
                 and payload["reason"] == "APPROVED_BASELINE_MATCH"
                 and _date(entry["created_at"]) == at(6) and entry["actor"] == "lab-reader",
                 "prior_use_record")
    _require(set(index) == expected_keys, "unexpected_context_record")
    _require(all(entry["tenant_id"] == spec["tenant_id"] for entry in records), "context_tenant")


def _observation(spec, provenance, at):
    config, scope = spec["observation"], spec["scope"]
    intake, markers = provenance["observation_intake"], provenance["observations"]
    _require(intake["event_id"] == config["id"], "observation_id")
    if config["kind"] == "none":
        _require(intake == {"accepted": False, "state": "not_supplied", "event_id": config["id"]}
                 and markers == [], "unexpected_observation")
        return
    if config["kind"] == "device":
        subject = (scope["device_id"] if config["scope"] == "same"
                   else "d-" + _digest([spec["case_id"], "other-device"])[:32])
        observed = {"kind": "device", "managed": True,
                    "security_posture": config["posture"], "subject_id": subject}
    else:
        resource = (scope["resource_id"] if config["scope"] == "same" else
                    ("zt-demo-vault" if scope["resource_id"] == "zt-demo-documents" else "zt-demo-documents"))
        observed = {"kind": "guardduty", "subject_id": scope["user_id"], "resource_id": resource,
                    "finding_sha256": _digest([config["id"], "local-simulated-finding"])}
    request = {
        "schema_version": "zt-observation-1", "algorithm": "Ed25519", "tenant_id": spec["tenant_id"],
        "source_id": config["kind"], "key_id": "key", "event_id": config["id"],
        "issued_at": at(11).isoformat(), "observed_at": at(11).isoformat(),
        "expires_at": at(101).isoformat(), "observation": observed,
    }
    actual = intake["request"]
    # Pydantic emits UTC as Z; compare timestamp instants, then content canonically.
    for key in ("issued_at", "observed_at", "expires_at"):
        _require(_date(actual[key]) == _date(request[key]), "observation_time")
        request[key] = actual[key]
    _require(actual == request and intake["observation"] == observed
             and intake["input_sha256"] == _digest(actual), "observation_request")
    accepted = config["signature"] == "valid"
    _require(intake["accepted"] is accepted
             and intake["state"] == ("completed" if accepted else "rejected"), "observation_acceptance")
    _require(len(markers) == (1 if accepted else 0), "observation_count")
    if markers:
        marker = markers[0]
        _require(marker["observation"] == observed
                 and marker["input_digest_sha256"] == intake["input_sha256"]
                 and all(marker[key] == request[key] for key in (
                     "tenant_id", "event_id", "source_id", "key_id",
                 )) and _date(marker["observed_at"]) == at(11)
                 and _date(marker["recorded_at"]) == at(11), "observation_marker")


def validate_provenance(spec, row):
    """Reject a runtime that substituted operational context, without consulting truth."""
    try:
        provenance = row["provenance"]
        base = _date(spec["base_time"])

        def at(seconds):
            return base + timedelta(seconds=seconds)

        _require(row["case_id"] == spec["case_id"]
                 and row["session_id"] == spec["target"]["session_id"]
                 and row["input_sha256"] == _digest(spec), "input_identity")
        _require(_date(provenance["evaluation_at"]) == at(12), "evaluation_clock")
        _context_records(spec, provenance, at)
        _observation(spec, provenance, at)
        history = provenance["session_history"]
        _require(bool(history), "session_history")
        _require(all(item["tenant_id"] == spec["tenant_id"]
                     and item["session_id"] == spec["target"]["session_id"]
                     and all(item[key] == spec["scope"][key]
                             for key in ("user_id", "device_id", "resource_id", "action"))
                     for item in history), "session_scope")
        previous = history[0]
        _require(previous["version"] == 1 and previous["status"] == "ACTIVE"
                 and previous["signal_trust"] == "verified_source"
                 and previous["input_digest_sha256"] == provenance["capture"]["session_input_sha256"]
                 and _date(previous["evaluated_at"]) == at(10), "initial_session")
        revoked = [item for item in history if "OPERATOR_REVOKED" in item["reason_codes"]]
        _require(len(revoked) == (1 if spec["session_revoke"] else 0), "manual_revoke_count")
        if revoked:
            _require(_date(revoked[0]["evaluated_at"]) == at(11)
                     and revoked[0]["status"] == "REVOKED"
                     and revoked[0]["decision"] == "DENY", "manual_revoke_state")
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("context_provenance_missing_or_malformed") from error
    return {"passed": True, "frozen_operational_context_matched": True}
