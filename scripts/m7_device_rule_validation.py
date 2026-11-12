"""Verify trusted device detection against fresh signed lab sessions."""

import argparse
import json
import secrets
import tempfile
from collections import Counter
from pathlib import Path

from app.continuous_signal_models import ObservationApplication
from scripts import evaluate_m6 as m6
from scripts import m7_shadow_capture as lab
from scripts.evaluate_m6_shadow import CAPTURES, REQUESTS, SCORES, read_rows, rule_answer
from scripts.m7_shadow_overlap import ROOT, verify_overlap

PREVIOUS_SHADOW = ROOT / "runtime/m7/shadow-assist"
CONTROLS = {
    "compromise": ("confirmed_endpoint_compromise", "threat", 202, 403, "REVOKED", 1),
    "approved_isolation": ("approved_endpoint_isolation", "normal", 202, 403, "HELD", 1),
    "unverified_report": ("untrusted_endpoint_claim", "unknown", 401, 200, "ACTIVE", 0),
    "duplicate_unknown_posture": ("duplicate_endpoint_uncertainty", "unknown", 202, 403, "HELD", 1),
    "other_device": ("confirmed_endpoint_compromise", "unknown", 202, 200, "ACTIVE", 0),
}


def create_cases():
    cases = {}
    for control, (family, *_expectations) in CONTROLS.items():
        for resource, action, role in lab.CONTEXTS:
            case_id = "case-" + secrets.token_hex(16)
            setup = {
                "case_id": case_id, "session_id": "sess-" + secrets.token_hex(16),
                "family": family, "resource_id": resource, "action": action, "account_role": role,
            }
            if control == "other_device":
                setup["observation_subject"] = "other_device"
            cases[case_id] = control, setup
    return cases


def read_provenance(directory, session_id):
    entries = lab._journal(directory / session_id / "journal.sqlite3")
    latest = next(
        entry["session"] for entry in reversed(entries)
        if entry["kind"] == "decision" and entry["session"]["session_id"] == session_id
    )
    markers = [entry for entry in entries if entry["kind"] == "observation"]
    if len(markers) > 1:
        raise ValueError("device_lab_duplicate_marker")
    return {
        "session": {key: latest[key] for key in (
            "session_id", "tenant_id", "device_id", "version", "signal_trust", "reason_codes",
        )},
        "committed_observation": (
            ObservationApplication.model_validate(markers[0]).model_dump(mode="json")
            if markers else None
        ),
    }


def compare_case(control, setup, captured, provenance):
    _, expected_label, intake, access, state, matched = CONTROLS[control]
    observed = captured["capture"]
    session = provenance["session"]
    marker = provenance["committed_observation"]
    if session["signal_trust"] != "verified_source":
        raise ValueError("device_lab_session_not_verified")
    if (
        (marker is None) != (control == "unverified_report")
        or marker is not None and (
            marker["tenant_id"] != session["tenant_id"] or marker["source_id"] != lab.COLLECTOR
            or marker["event_id"] != setup["case_id"] + "-observation"
            or marker["observation"] != observed["observation"]
            or marker["matched_sessions"] != observed["matched_sessions"]
            or marker["changed_sessions"] != observed["changed_sessions"]
        )
    ):
        raise ValueError(f"device_lab_observation_provenance: {control}")
    expected_subject_match = control not in {"unverified_report", "other_device"}
    subject_matches = bool(marker and marker["observation"]["subject_id"] == session["device_id"])
    if (
        observed["intake_status"], observed["final_access"]["status"],
        observed["final_session_status"], observed["matched_sessions"], observed["changed_sessions"],
        observed["duplicate_delivery"], subject_matches,
    ) != (intake, access, state, matched, matched, control == "duplicate_unknown_posture",
          expected_subject_match):
        raise ValueError(f"device_lab_capture_mismatch: {control}")
    baseline = rule_answer(captured | {"rule_evidence": {
        key: value for key, value in captured["rule_evidence"].items()
        if key != "verified_device_compromise"
    }})
    revised = rule_answer(captured)
    expected_baseline = "unknown" if control == "compromise" else expected_label
    passed = (
        baseline["verdict"] == expected_baseline and revised["verdict"] == expected_label
        and (revised["reason"] == "verified_device_compromise") == (control == "compromise")
    )
    evidence = sorted(captured["evidence"], key=lambda fact: fact["id"])
    legacy_request = {
        "case_id": setup["case_id"], "rule_verdict": baseline["verdict"], "evidence": evidence,
    }
    return {
        "case_id": setup["case_id"], "session_id": setup["session_id"], "control": control,
        "resource_id": setup["resource_id"], "action": setup["action"],
        "expected_verdict": expected_label, "baseline": baseline, "revised": revised,
        "rule_evidence": captured["rule_evidence"], "capture": observed, "passed": passed,
        "provenance": provenance,
        "evidence_ids": [fact["id"] for fact in evidence],
        "request_sha256": m6.digest(m6.canonical(legacy_request)),
        "capture_sha256": m6.digest(m6.canonical(captured)),
    }


def overlap_with_shadow(rows, directory):
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes, object_pairs_hook=m6.unique_fields)
    sources = {}
    for filename in (SCORES, CAPTURES, REQUESTS):
        raw = (directory / filename).read_bytes()
        if m6.digest(raw) != manifest["files"][filename]:
            raise ValueError(f"device_lab_prior_shadow_changed: {filename}")
        sources[filename] = read_rows(raw)
    if manifest["sessions"] != 24 or any(len(items) != 24 for items in sources.values()):
        raise ValueError("device_lab_prior_shadow_count")

    prior_ids = {
        row[key] for items in sources.values() for row in items
        for key in ("session_id", "case_id") if key in row
    }
    prior_evidence_ids = {
        fact["id"] for row in sources[REQUESTS] for fact in row["evidence"]
    }
    prior_requests = {m6.digest(m6.canonical(row)) for row in sources[REQUESTS]}
    prior_captures = {m6.digest(m6.canonical(row)) for row in sources[CAPTURES]}
    new_ids = {row[key] for row in rows for key in ("session_id", "case_id")}
    new_evidence = {item for row in rows for item in row["evidence_ids"]}
    overlaps = {
        "session_or_case_ids": len(new_ids & prior_ids),
        "evidence_ids": len(new_evidence & prior_evidence_ids),
        "request_hashes": sum(row["request_sha256"] in prior_requests for row in rows),
        "capture_hashes": sum(row["capture_sha256"] in prior_captures for row in rows),
    }
    if any(overlaps.values()):
        raise ValueError(f"device_lab_prior_shadow_overlap: {overlaps}")
    return {"manifest_sha256": m6.digest(manifest_bytes), "sessions": 24, "overlaps": overlaps}


def run_validation(previous_shadow=PREVIOUS_SHADOW):
    cases = create_cases()
    with tempfile.TemporaryDirectory(prefix="device-rule-") as directory:
        scratch = Path(directory)
        captures = lab.capture_cases([setup for _, setup in cases.values()], scratch)
        if {row["case_id"] for row in captures} != cases.keys() or len(captures) != len(cases):
            raise ValueError("device_lab_incomplete_captures")
        rows = [
            compare_case(*cases[row["case_id"]], row, read_provenance(scratch, row["session_id"]))
            for row in captures
        ]
    prior_shadow = overlap_with_shadow(rows, previous_shadow)
    prior_cohorts = verify_overlap(
        [row["session_id"] for row in rows],
        [fact for row in rows for fact in row["evidence_ids"]],
        [row["request_sha256"] for row in rows],
        new_related_ids=[row["case_id"] for row in rows],
        new_source_hashes=[row["capture_sha256"] for row in rows],
    )
    return {
        "schema": "m7-device-rule-validation-1", "scope": lab.SCOPE,
        "sessions": len(rows), "passed": sum(row["passed"] for row in rows),
        "controls": dict(Counter(row["control"] for row in rows)),
        "baseline_verdicts": dict(Counter(row["baseline"]["verdict"] for row in rows)),
        "revised_verdicts": dict(Counter(row["revised"]["verdict"] for row in rows)),
        "external_model_requests": 0, "prior_shadow": prior_shadow,
        "prior_cohorts": prior_cohorts, "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous-shadow", type=Path, default=PREVIOUS_SHADOW)
    args = parser.parse_args()
    result = run_validation(args.previous_shadow)
    m6.write_report(args.output, result)
    print(json.dumps({key: result[key] for key in (
        "sessions", "passed", "controls", "baseline_verdicts", "revised_verdicts",
    )}))
    return int(result["sessions"] != result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
