"""Score frozen, paired local observations only after both arms have produced predictions.

Reference labels never enter either detector. Evidence checks inspect recorded events and
committed operational history independently; they do not call the detector under evaluation.
These checks establish local provenance consistency, not independent real-world ground truth.
"""

import hashlib
import json
from collections import Counter
from datetime import datetime

ARMS = ("rule_only", "with_context")
LABELS = {"normal", "threat", "unknown"}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _instant(value):
    result = datetime.fromisoformat(value)
    if result.utcoffset() is None:
        raise ValueError("context_score_timestamp_timezone")
    return result


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _prediction(row, arm):
    answer = row.get(arm)
    if (row.get("error") or row.get("error_type") or not isinstance(answer, dict)
            or answer.get("error") or answer.get("status", "success") != "success"):
        return "error"
    return answer.get("verdict") if answer.get("verdict") in LABELS else "error"


def _scope_matches(session, capture):
    return (session.get("tenant_id") == capture["tenant_id"]
            and session.get("session_id") == capture["session_id"]
            and all(session.get(key) == capture["scope"][key]
                    for key in ("user_id", "device_id", "resource_id", "action")))


def _bound_sessions(provenance):
    capture = provenance["capture"]
    sessions = [item for item in provenance["session_history"] if _scope_matches(item, capture)]
    prior = [item for item in sessions if item["version"] == capture["session_version"]]
    if len(prior) != 1 or not sessions:
        return None, None
    previous, latest = prior[0], max(sessions, key=lambda item: item["version"])
    if (previous["signal_trust"] != "verified_source"
            or previous["input_digest_sha256"] != capture["session_input_sha256"]
            or _instant(previous["evaluated_at"]) > _instant(capture["issued_at"])
            or any(_instant(event["timestamp"]) < _instant(previous["evaluated_at"])
                   for event in capture["activity"]["events"])):
        return None, None
    return previous, latest


def _normal_session(provenance):
    previous, latest = _bound_sessions(provenance)
    if previous is None:
        return False
    capture, now = provenance["capture"], _instant(provenance["evaluation_at"])
    return (latest["version"] == capture["session_version"]
            and latest["status"] == "ACTIVE" and latest["decision"] == "ALLOW"
            and latest["signal_trust"] == "verified_source"
            and latest["input_digest_sha256"] == capture["session_input_sha256"]
            and all(latest.get(key) and _instant(latest[key]) > now
                    for key in ("grant_expires_at", "signal_expires_at"))
            and _instant(capture["expires_at"]) > now)


def _profile(events):
    """Recompute bounds from raw events without the production profile helper."""
    times = sorted(_instant(item["timestamp"]) for item in events)
    operations = Counter()
    for event in events:
        fields = {key: value for key, value in event.items()
                  if key not in {"id", "timestamp", "connection_id", "principal_hash"}}
        fields["resource_hashes"] = sorted(fields["resource_hashes"])
        operations[_digest(fields)] += 1
    peak = max(sum(0 <= (right - left).total_seconds() < 1 for left in times)
               for right in times)
    return {"event_limits": dict(operations), "max_events": len(events),
            "max_span_seconds": (times[-1] - times[0]).total_seconds(),
            "max_events_per_second": peak}


def _within_window(entry, now, start, end):
    request = entry["payload"]["request"]
    left, right = _instant(request["valid_from"]), _instant(request["valid_until"])
    return (left <= start <= end < right and left <= now < right
            and _instant(entry["created_at"]) <= start)


def _approval_supported(provenance, baseline_id, approval_id):
    capture = provenance["capture"]
    now = _instant(provenance["evaluation_at"])
    records = [item for item in provenance["context_records"]
               if item["tenant_id"] == capture["tenant_id"]
               and _instant(item["created_at"]) <= now]
    index = {(item["kind"], item["record_id"]): item for item in records}
    if len(index) != len(records):
        return False
    baseline = index.get(("baseline", baseline_id))
    approval = index.get(("approval", approval_id))
    if not baseline or not approval or not _normal_session(provenance):
        return False
    payload = baseline["payload"]
    approved = approval["payload"]
    if (payload["scope"] != capture["scope"] or approved["scope"] != capture["scope"]
            or approved["request"]["baseline_id"] != baseline_id
            or approved["baseline_digest"] != _digest(payload)):
        return False
    for entry in records:
        if entry["kind"] == "revocation" and (
            entry["payload"]["target_kind"], entry["payload"]["target_id"]
        ) in {("baseline", baseline_id), ("approval", approval_id)}:
            return False
    events = capture["activity"]["events"]
    times = [_instant(event["timestamp"]) for event in events]
    if not all(_within_window(item, now, min(times), max(times)) for item in (baseline, approval)):
        return False
    sample_ids = payload["request"]["capture_ids"]
    samples = [index.get(("capture", identifier)) for identifier in sample_ids]
    if len(set(sample_ids)) < 3 or not all(samples):
        return False
    sample_captures = [entry["payload"]["capture"] for entry in samples]
    training_ids = [event["id"] for item in sample_captures for event in item["activity"]["events"]]
    training_groups = [item["activity"]["original_group_id"] for item in sample_captures]
    if (len(set(training_ids)) != len(training_ids)
            or len(set(training_groups)) != len(training_groups)
            or set(training_ids) != set(payload["training_event_ids"])
            or set(training_groups) != set(payload["training_groups"])
            or any(item["scope"] != capture["scope"] for item in sample_captures)
            or any(not entry["payload"]["normal_session_at_acceptance"] for entry in samples)
            or any(_instant(event["timestamp"]) >= _instant(baseline["created_at"])
                   for item in sample_captures for event in item["activity"]["events"])
            or {event["id"] for event in events} & set(training_ids)
            or capture["activity"]["original_group_id"] in training_groups):
        return False
    computed_limits = {"event_limits": {}, "max_events": 0, "max_span_seconds": 0,
                       "max_events_per_second": 0}
    for item in sample_captures:
        profile = _profile(item["activity"]["events"])
        for key in ("max_events", "max_span_seconds", "max_events_per_second"):
            computed_limits[key] = max(computed_limits[key], profile[key])
        for key, count in profile["event_limits"].items():
            computed_limits["event_limits"][key] = max(
                computed_limits["event_limits"].get(key, 0), count,
            )
    if computed_limits != payload["profile"]:
        return False
    candidate = _profile(events)
    if (any(candidate[key] > computed_limits[key] for key in (
        "max_events", "max_span_seconds", "max_events_per_second",
    )) or any(count > computed_limits["event_limits"].get(key, 0)
              for key, count in candidate["event_limits"].items())):
        return False
    uses = {item["payload"]["capture_id"] for item in records
            if item["kind"] == "evaluation" and item["payload"].get("verdict") == "normal"
            and item["payload"].get("approval_id") == approval_id}
    return (capture["capture_id"] in uses
            or len(uses) < approved["request"].get("max_uses", 1))


def _committed_request_matches(provenance, marker):
    intake = provenance["observation_intake"]
    request = intake["request"]
    return (intake["accepted"] is True and intake["state"] == "completed"
            and intake["event_id"] == marker["event_id"]
            and request["schema_version"] == "zt-observation-1"
            and request["algorithm"] == "Ed25519" and "signature" not in request
            and intake["input_sha256"] == _digest(request) == marker["input_digest_sha256"]
            and intake["observation"] == request["observation"] == marker["observation"]
            and all(request[key] == marker[key]
                    for key in ("tenant_id", "event_id", "source_id", "key_id"))
            and _instant(request["observed_at"]) == _instant(marker["observed_at"])
            and _instant(request["observed_at"]) <= _instant(request["issued_at"])
            <= _instant(marker["recorded_at"]) < _instant(request["expires_at"]))


def _trusted_supported(provenance, evidence):
    capture = provenance["capture"]
    historical, _ = _bound_sessions(provenance)
    now = _instant(provenance["evaluation_at"])
    markers = [item for item in provenance["observations"]
               if item["event_id"] == evidence.get("event_id")]
    if historical is None or len(markers) != 1:
        return False
    marker = markers[0]
    if (not _committed_request_matches(provenance, marker)
            or marker["tenant_id"] != capture["tenant_id"] or marker["restriction"] != "DENY"
            or _instant(marker["observed_at"]) > now or _instant(marker["recorded_at"]) > now
            or evidence.get("historically_committed") is not True
            or any(evidence.get(key) != marker[key] for key in (
                "event_id", "source_id", "key_id", "input_digest_sha256",
            ))
            or any(_instant(evidence[key]) != _instant(marker[key])
                   for key in ("observed_at", "recorded_at"))):
        return False
    observed, scope = marker["observation"], capture["scope"]
    kind = observed["kind"]
    if evidence.get("kind") != kind:
        return False
    if kind == "device":
        return (observed["subject_id"] == scope["device_id"]
                and observed["security_posture"] == "compromised"
                and evidence.get("reason") == "trusted_device_compromise")
    if kind == "guardduty":
        return (observed["subject_id"] == scope["user_id"]
                and observed["resource_id"] == scope["resource_id"]
                and evidence.get("reason") == "trusted_guardduty_finding")
    if kind == "session_proof":
        return (marker["matched_sessions"] > 0
                and observed["subject_id"] == scope["user_id"]
                and observed["device_id"] == scope["device_id"]
                and observed["resource_id"] == scope["resource_id"]
                and observed["action"] == scope["action"]
                and all(observed[key] == capture[key] for key in (
                    "session_id", "session_version", "session_input_sha256",
                ))
                and _instant(marker["observed_at"]) >= _instant(historical["evaluated_at"])
                and evidence.get("reason") == "trusted_session_proof_violation")
    return False


def _any_scoped_adverse(provenance):
    reasons = {"device": "trusted_device_compromise", "guardduty": "trusted_guardduty_finding",
               "session_proof": "trusted_session_proof_violation"}
    for marker in provenance["observations"]:
        kind = marker["observation"]["kind"]
        if kind not in reasons:
            continue
        evidence = {key: marker[key] for key in (
            "event_id", "source_id", "key_id", "input_digest_sha256", "observed_at", "recorded_at",
        )}
        evidence.update(kind=kind, reason=reasons[kind], historically_committed=True)
        if _trusted_supported(provenance, evidence):
            return True
    return False


def _rule_citations(answer, capture, label):
    events = {item["id"]: item for item in capture["activity"]["events"]}
    cited = answer.get("evidence_ids", [])
    findings = [item for item in answer.get("findings", []) if item.get("disposition") == "threat"]
    finding_ids = {identifier for item in findings for identifier in item.get("evidence_ids", [])}
    # Event IDs alone are not attack evidence: the pre-frozen reference must identify
    # those exact records as the observed attempt, and every threat citation must agree.
    support = set(label.get("support_event_ids", []))
    frozen_hashes = label.get("support_event_sha256", {})
    return (bool(cited) and len(set(cited)) == len(cited)
            and set(cited) == finding_ids and set(cited) <= events.keys()
            and set(cited) <= support and "remote_shell" in label.get("expected_support", [])
            and all(frozen_hashes.get(identifier) == _digest(events[identifier])
                    for identifier in cited)
            and all(item.get("feature") == "ssh_reverse_shell" for item in findings))


def evidence_alignment(row, label, arm):
    """Separate factual provenance, reference support, and expected abstention."""
    prediction = _prediction(row, arm)
    result = {"provenance_aligned": False, "reference_supported": False,
              "expected_abstention": prediction == "unknown" and label["label"] == "unknown",
              "status": "error" if prediction == "error" else "unsupported"}
    if prediction == "error":
        return result
    try:
        provenance, answer = row["provenance"], row[arm]
        capture = provenance["capture"]
        activity_digest = _digest(capture["activity"])
        if (row["session_id"] != capture["session_id"]
                or row["activity_sha256"] != activity_digest
                or row["rule_input_sha256"] != activity_digest
                or row["context_activity_sha256"] != activity_digest):
            return result | {"status": "input_provenance_mismatch"}
        if arm == "rule_only":
            if prediction == "threat":
                factual = _rule_citations(answer, capture, label)
            elif prediction == "normal":
                # Absence of a match is not proof of authorization or of benign intent.
                # Retain the traceable observation, but score correctness separately.
                factual = (answer.get("reason") == "supported_observed_activity_without_match"
                           and answer.get("normal_profile_supported") is True
                           and not answer.get("missing_fields") and not answer.get("evidence_ids")
                           and not any(item.get("disposition") == "threat"
                                       for item in answer.get("findings", [])))
            else:
                cited = answer.get("candidate_evidence_ids", [])
                identifiers = {item["id"] for item in capture["activity"]["events"]}
                factual = set(cited) <= identifiers and answer.get("reason") in {
                    "observed_activity_requires_context", "missing_or_unsupported_observed_activity",
                }
        elif prediction == "threat":
            if answer.get("reason") == "TRUSTED_ADVERSE_EVIDENCE":
                cited = answer.get("trusted_evidence", [])
                factual = (bool(cited) and len({item["event_id"] for item in cited}) == len(cited)
                           and all(_trusted_supported(provenance, item) for item in cited))
            elif answer.get("reason") == "EXPLICIT_REMOTE_SHELL_ATTEMPT":
                factual = _rule_citations(answer["base_detection"], capture, label)
            else:
                factual = False
        elif prediction == "normal":
            factual = (not _any_scoped_adverse(provenance)
                       and answer.get("reason") == "APPROVED_BASELINE_MATCH"
                       and not answer.get("trusted_evidence")
                       and _approval_supported(provenance, answer.get("baseline_id"),
                                               answer.get("approval_id")))
        else:
            if answer.get("reason") == "SESSION_NOT_ELIGIBLE":
                factual = not _normal_session(provenance)
            elif answer.get("reason") == "SESSION_BINDING_INVALID":
                factual = _bound_sessions(provenance)[0] is None
            elif answer.get("reason") == "CONTEXT_REQUIRED":
                approvals = [entry for entry in provenance["context_records"]
                             if entry["kind"] == "approval"]
                factual = not any(_approval_supported(
                    provenance, entry["payload"]["request"]["baseline_id"], entry["record_id"],
                ) for entry in approvals)
            else:
                factual = False
        if arm == "with_context" and prediction == "unknown" and _any_scoped_adverse(provenance):
            factual = False
        supported = factual and prediction == label["label"]
        if prediction == "threat" and arm == "with_context" and answer.get("trusted_evidence"):
            supported &= all(item["kind"] in label.get("expected_support", [])
                             for item in answer["trusted_evidence"])
        if prediction == "normal" and arm == "with_context":
            supported &= "approved_baseline" in label.get("expected_support", [])
        return result | {"provenance_aligned": bool(factual), "reference_supported": bool(supported),
                         "status": "aligned" if factual else "unsupported"}
    except (KeyError, TypeError, ValueError, IndexError):
        return result | {"status": "malformed_provenance"}


def summarize(rows, arm):
    counts = Counter((row["label"], row[arm]["prediction"]) for row in rows)
    normals = sum(count for (truth, _), count in counts.items() if truth == "normal")
    threats = sum(count for (truth, _), count in counts.items() if truth == "threat")
    unknowns = len(rows) - normals - threats
    tp, fp = counts["threat", "threat"], counts["normal", "threat"]
    fn_classified, tn = counts["threat", "normal"], counts["normal", "normal"]
    missed = threats - tp
    held = {truth: counts[truth, "unknown"] for truth in sorted(LABELS)}
    errors = {truth: counts[truth, "error"] for truth in sorted(LABELS)}
    classified = tp + fp + fn_classified + tn
    evidence = [row[arm]["evidence_alignment"] for row in rows]
    claims = [row for row in rows if row[arm]["prediction"] in {"normal", "threat"}]
    unsupported = Counter(row[arm]["prediction"] for row in claims
                          if not row[arm]["evidence_alignment"]["provenance_aligned"])
    grounded_tp = sum(row["label"] == "threat" and row[arm]["prediction"] == "threat"
                      and row[arm]["evidence_alignment"]["reference_supported"] for row in rows)
    threat_claims = sum(row[arm]["prediction"] == "threat" for row in rows)
    return {
        "sessions": len(rows), "known_normals": normals, "known_threats": threats,
        "reference_unknown": unknowns,
        "prediction_counts": dict(Counter(row[arm]["prediction"] for row in rows)),
        "confusion_classified_known": {"tp": tp, "fp": fp, "fn": fn_classified, "tn": tn},
        "missed_threats_including_abstentions_and_errors": missed, "false_alarms": fp,
        "held_total": sum(held.values()), "held_by_label": held,
        "errors_total": sum(errors.values()), "errors_by_label": errors,
        "metrics": {"precision": _ratio(tp, tp + fp), "recall": _ratio(tp, threats),
                    "f1": _ratio(2 * tp, 2 * tp + fp + missed),
                    "false_positive_rate": _ratio(fp, normals)},
        "classified_coverage_known": _ratio(classified, normals + threats),
        "classified_coverage_all": _ratio(sum(row[arm]["prediction"] in {"normal", "threat"}
                                             for row in rows), len(rows)),
        "accuracy_all_known": _ratio(tp + tn, normals + threats),
        "conditional_metrics": {"precision": _ratio(tp, tp + fp),
                                "recall": _ratio(tp, tp + fn_classified),
                                "f1": _ratio(2 * tp, 2 * tp + fp + fn_classified),
                                "false_positive_rate": _ratio(fp, fp + tn)},
        "unknown_reference": {"correctly_held": held["unknown"],
                              "unsupported_normal_claims": counts["unknown", "normal"],
                              "unsupported_threat_claims": counts["unknown", "threat"],
                              "execution_errors": errors["unknown"]},
        "evidence_alignment": {
            "statuses": dict(Counter(item["status"] for item in evidence)),
            "provenance_aligned": sum(item["provenance_aligned"] for item in evidence),
            "reference_supported": sum(item["reference_supported"] for item in evidence),
            "unsupported_normal_claims": unsupported["normal"],
            "unsupported_threat_claims": unsupported["threat"],
            "expected_abstentions": sum(item["expected_abstention"] for item in evidence),
        },
        "evidence_supported_detection": {
            "true_positives": grounded_tp, "all_threat_claims": threat_claims,
            "precision": _ratio(grounded_tp, threat_claims), "recall": _ratio(grounded_tp, threats),
            "f1": _ratio(2 * grounded_tp, threat_claims + threats),
            "note": "All threat claims include unresolved-reference and unsupported claims; not a conventional confusion matrix.",
        },
    }


def score_comparison(predictions, labels):
    references = {row["case_id"]: row for row in labels}
    records = {row["case_id"]: row for row in predictions}
    if (not references or len(references) != len(labels) or len(records) != len(predictions)
            or references.keys() != records.keys()
            or any(row.get("label") not in LABELS or not row.get("family")
                   for row in labels)):
        raise ValueError("context_score_reference_alignment")
    rows = []
    for identifier in sorted(references):
        label, record = references[identifier], records[identifier]
        item = {"case_id": identifier, "session_id": record.get("session_id"),
                "label": label["label"], "family": label["family"]}
        for arm in ARMS:
            item[arm] = {"prediction": _prediction(record, arm),
                         "evidence_alignment": evidence_alignment(record, label, arm)}
        rows.append(item)
    paired = Counter(row["rule_only"]["prediction"] + "->" + row["with_context"]["prediction"]
                     for row in rows)
    return {
        "schema": "m7-context-comparison-score-1", "sessions": len(rows),
        "cohort": "fresh_controlled_local_sessions",
        "independent_generalization_verified": False, "independent_human_label_review": False,
        "project_goals_met": False,
        "scope": "Synthetic local operational context; no public-log accuracy or production prevalence claim.",
        "metric_contract": {
            "positive": "threat", "negative": "normal",
            "known_threat_abstentions_and_errors": "Counted as missed threats in recall and F1",
            "known_normal_abstentions_and_errors": "Separate from TN; included in all-normal FPR denominator and coverage",
            "unknown_references": "Excluded from binary metrics; claims and abstentions counted separately",
            "no_positive_predictions": "Precision is null; no pass inferred from zero false alarms",
            "reference_support": "Pre-frozen scenario references and local recorded evidence, not independent external attribution",
        },
        "arms": {arm: summarize(rows, arm) for arm in ARMS},
        "by_family": {family: {arm: summarize([row for row in rows if row["family"] == family], arm)
                                for arm in ARMS} for family in sorted({row["family"] for row in rows})},
        "paired_transitions": dict(paired),
        "both_correct_known": sum(row["label"] in {"normal", "threat"}
                                  and row["rule_only"]["prediction"] == row["label"]
                                  and row["with_context"]["prediction"] == row["label"] for row in rows),
        "rows": rows,
    }
