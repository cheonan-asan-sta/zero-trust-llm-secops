"""Score public detections against separate, source-bound publisher evidence labels.

This module is an offline scoring boundary. Publisher labels never become detector
input, authorization evidence, or proof that a recorded attack succeeded.
"""

import json
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from scripts import m7_public_cloudtrail as cloudtrail
from scripts import m7_public_cowrie as cowrie
from scripts.audit_m7_public_holdout import read_pinned_records
from scripts.evaluate_m6 import canonical, digest, unique_fields
from scripts.evaluate_m6_public_independent import contains_reference_field, summarize
from scripts.m7_public_behavior_inputs import cloudtrail_event, cowrie_event


def observation_event_hash(event):
    """Bind normalized values, including defaults, to the actual source projection."""
    from app.services.public_detection import PublicActivity

    normalized = PublicActivity.model_validate(event).model_dump(mode="json")
    return digest(canonical(normalized))


def cloudtrail_event_truth(records):
    """Validate annotations and bind event truth to exactly the existing grouping."""
    references, metadata = cloudtrail.normalize_records(records)
    groups = {row["original_group_id"]: row for row in references}
    index = {}
    for raw in records:
        record = {key: value for key, value in raw.items() if key not in cloudtrail.ANNOTATIONS}
        event_hash = digest(canonical(record))
        group = cloudtrail.credential_group(record, event_hash)
        group_id = digest(canonical(("cloudtrail", group))) if group[0] != "event_only" else None
        index[event_hash] = {
            "source": "cloudtrail", "original_group_id": group_id,
            "event_label": "threat" if raw["should_sample"] else "normal",
            "label_granularity": "event",
            "group_label": groups[group_id]["expected_label"] if group_id else None,
            "observed_event_sha256": observation_event_hash(cloudtrail_event(raw)),
        }
    return index, metadata


def load_cloudtrail_event_truth(path: Path, *, expected_sha256: str):
    records, member_sha = read_pinned_records(path, expected_sha256)
    index, metadata = cloudtrail_event_truth(records)
    return index, metadata | {
        "archive_sha256": expected_sha256, "json_member_sha256": member_sha,
        "label_granularity": "event",
    }


def load_cowrie_event_truth(path: Path):
    references, metadata = cowrie.load_cowrie(path)
    index = {}
    for row in references:
        for event_hash in row["event_hashes"]:
            # The publisher labels an actor-round, not each command or login event.
            index[event_hash] = {
                "source": "cowrie", "original_group_id": row["original_group_id"],
                "event_label": None, "label_granularity": "group",
                "group_label": row["expected_label"],
            }
    with ZipFile(path) as archive:
        for round_number in range(1, 25):
            raw = archive.read(cowrie.PREFIX + f"r{round_number:02}_cowrie.json")
            for line in raw.splitlines():
                record = json.loads(line, object_pairs_hook=unique_fields)
                identifier = digest(canonical(record))
                index[identifier]["observed_event_sha256"] = observation_event_hash(cowrie_event(record))
    if any("observed_event_sha256" not in reference for reference in index.values()):
        raise ValueError("public_evidence_cowrie_projection_missing")
    return index, metadata | {"label_granularity": "group"}


def merge_event_truth(*indices):
    merged = {}
    for index in indices:
        for identifier, reference in index.items():
            if identifier in merged and merged[identifier] != reference:
                raise ValueError("public_evidence_conflicting_reference")
            merged[identifier] = reference
    return merged


def _identifiers(value):
    return (isinstance(value, list) and all(isinstance(item, str) and item for item in value)
            and len(set(value)) == len(value))


def _labels(ids, observed, event_truth):
    counts = Counter()
    errors = []
    observed_ids = {event["id"] for event in observed["events"]}
    for identifier in ids:
        reference = event_truth.get(identifier)
        if identifier not in observed_ids:
            errors.append("evidence_outside_observed_group")
        if reference is None:
            counts["unresolved"] += 1
            errors.append("evidence_reference_missing")
        elif (reference.get("source") != observed["source"]
              or reference.get("original_group_id") != observed["original_group_id"]):
            counts["wrong_group"] += 1
            errors.append("evidence_reference_wrong_group")
        elif reference.get("label_granularity") == "group" and reference.get("event_label") is None:
            counts["unverifiable"] += 1
        elif (reference.get("label_granularity") == "event"
              and reference.get("event_label") in {"normal", "threat"}):
            counts[reference["event_label"]] += 1
        else:
            counts["unverifiable"] += 1
            errors.append("evidence_reference_invalid_label")
    return dict(counts), sorted(set(errors))


def qualify_prediction(observed, prediction, event_truth, *, rule_policies=None):
    """Validate exact rule evidence before consulting separate event labels.

    Local deterministic recomputation binds each finding to its real selector output;
    a caller cannot replace a benign cited event with an unrelated attack event.
    """
    from app.services.public_detection import PublicDetectionService, public_rule_policies

    if contains_reference_field(observed):
        raise ValueError("public_evidence_label_in_observation")
    policies = public_rule_policies() if rule_policies is None else rule_policies
    expected = PublicDetectionService().evaluate(observed)
    errors = []
    for event in observed["events"]:
        reference = event_truth.get(event["id"])
        if (reference is None
                or reference.get("observed_event_sha256") != observation_event_hash(event)):
            errors.append("source_event_projection_mismatch")
    for key in ("verdict", "findings", "evidence_ids", "candidate_evidence_ids",
                "investigation_required", "features", "sigma"):
        if key not in prediction or prediction[key] != expected[key]:
            errors.append("detector_contract_mismatch:" + key)
    if prediction.get("enforcement_eligible") is not False:
        errors.append("enforcement_authority_not_denied")
    findings = prediction.get("findings")
    if not isinstance(findings, list):
        findings = []
        errors.append("findings_missing_or_invalid")
    audits = []
    seen_rules, threat_ids, candidate_ids = set(), set(), set()
    for finding in findings:
        if not isinstance(finding, dict):
            errors.append("finding_invalid_shape")
            continue
        rule_id = finding.get("rule_id")
        policy = policies.get(rule_id) if isinstance(rule_id, str) else None
        disposition = finding.get("disposition")
        finding_errors = []
        if (not policy or finding.get("feature") != policy["feature"]
                or disposition != policy["disposition"]):
            finding_errors.append("finding_rule_policy_mismatch")
        if isinstance(rule_id, str) and rule_id in seen_rules:
            finding_errors.append("finding_rule_repeated")
        if isinstance(rule_id, str):
            seen_rules.add(rule_id)
        ids = finding.get("evidence_ids")
        if not _identifiers(ids) or not ids:
            finding_errors.append("finding_evidence_missing_or_duplicate")
            ids = []
        label_counts, reference_errors = _labels(ids, observed, event_truth)
        finding_errors.extend(reference_errors)
        if disposition == "threat":
            threat_ids.update(ids)
        elif disposition == "investigate":
            candidate_ids.update(ids)
        if finding_errors:
            alignment = "invalid"
        elif disposition != "threat":
            alignment = "investigation_only"
        elif label_counts.get("unverifiable", 0):
            alignment = "unverifiable"
        elif label_counts.get("threat", 0):
            alignment = "publisher_attack_evidence_present"
        else:
            alignment = "publisher_attack_evidence_absent"
        audits.append({
            "rule_id": rule_id, "feature": finding.get("feature"), "disposition": disposition,
            "evidence_ids": ids, "label_counts": label_counts,
            "alignment": alignment, "errors": sorted(set(finding_errors)),
        })
        errors.extend(finding_errors)
    for key, union in (("evidence_ids", threat_ids), ("candidate_evidence_ids", candidate_ids)):
        if not _identifiers(prediction.get(key)) or set(prediction.get(key, [])) != union:
            errors.append("aggregate_evidence_mismatch:" + key)
    threat_findings = [row for row in audits if row["disposition"] == "threat"]
    if prediction.get("verdict") != "threat":
        status = "not_a_threat_claim"
    elif errors or not threat_findings:
        status = "invalid"
    elif any(row["alignment"] == "unverifiable" for row in threat_findings):
        status = "unverifiable"
    elif all(row["alignment"] == "publisher_attack_evidence_present" for row in threat_findings):
        status = "supported"
    else:
        status = "unsupported"
    threat_labels, _ = _labels(sorted(threat_ids), observed, event_truth)
    candidate_labels, _ = _labels(sorted(candidate_ids), observed, event_truth)
    return {
        "evidence_status": status,
        "supported_threat_claim": status == "supported" and not errors,
        "contract_valid": not errors, "errors": sorted(set(errors)), "findings": audits,
        "threat_evidence_labels": threat_labels, "candidate_evidence_labels": candidate_labels,
    }


def score_predictions(observations, references, decisions, event_truth, *, rule_policies=None):
    """Keep ordinary group metrics separate from evidence-qualified claim metrics."""
    observed_by_group = {row["original_group_id"]: row for row in observations}
    reference_by_group = {row["original_group_id"]: row for row in references}
    if (not observations or len(observed_by_group) != len(observations)
            or len(reference_by_group) != len(references)
            or observed_by_group.keys() != reference_by_group.keys()
            or observed_by_group.keys() != decisions.keys()):
        raise ValueError("public_evidence_group_join")
    rows = []
    for group, observed in observed_by_group.items():
        reference = reference_by_group[group]
        if (reference["source"] != observed["source"]
                or reference["expected_label"] not in {"normal", "threat", "unknown"}):
            raise ValueError("public_evidence_scoring_reference")
        for event in observed["events"]:
            truth = event_truth.get(event["id"])
            if truth is None:
                raise ValueError("public_evidence_source_reference_missing")
            if (
                truth.get("source") != observed["source"]
                or truth.get("original_group_id") != group
                or truth.get("group_label") != reference["expected_label"]
                or truth.get("observed_event_sha256") != observation_event_hash(event)
            ):
                raise ValueError("public_evidence_source_reference_join")
        prediction = decisions[group]
        audit = qualify_prediction(observed, prediction, event_truth, rule_policies=rule_policies)
        rows.append({
            "original_group_id": group, "source": observed["source"],
            "expected_label": reference["expected_label"], "rule_verdict": prediction["verdict"],
            "investigation_required": prediction.get("investigation_required") is True,
            "qualified_true_positive": reference["expected_label"] == "threat"
            and audit["supported_threat_claim"],
            **audit,
        })
    group_summary = summarize(rows)
    group_summary["group_label_targets_met"] = group_summary.pop("all_targets_met")
    group_summary["group_label_thresholds"] = group_summary.pop("target_verified")
    threat_claims = sum(row["rule_verdict"] == "threat" for row in rows)
    qualified_tp = sum(row["qualified_true_positive"] for row in rows)
    missed = group_summary["known_threats"] - qualified_tp
    unsubstantiated = threat_claims - qualified_tp
    precision = qualified_tp / threat_claims if threat_claims else None
    recall = qualified_tp / group_summary["known_threats"] if group_summary["known_threats"] else None
    f1_denominator = 2 * qualified_tp + unsubstantiated + missed
    f1 = 2 * qualified_tp / f1_denominator if f1_denominator else None
    qualified = {
        "supported_true_positives": qualified_tp, "threat_claims": threat_claims,
        "unsubstantiated_positive_claims": unsubstantiated, "missed_threats": missed,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": group_summary["false_positive_rate_all_normals"],
        "precision_denominator": "All threat claims, including unsupported and unverifiable ones",
        "recall_denominator": "All publisher-labeled threat groups, including abstentions",
        "counts_are_not_a_conventional_confusion_matrix": True,
    }
    evidence_summary = {
        "status_counts": dict(Counter(row["evidence_status"] for row in rows)),
        "investigation_groups": sum(row["investigation_required"] for row in rows),
        "group_true_positives_without_supported_evidence": sum(
            row["expected_label"] == "threat" and row["rule_verdict"] == "threat"
            and not row["supported_threat_claim"] for row in rows
        ),
        "threat_evidence_labels": dict(sum((Counter(row["threat_evidence_labels"]) for row in rows), Counter())),
        "candidate_evidence_labels": dict(sum((Counter(row["candidate_evidence_labels"]) for row in rows), Counter())),
    }
    gates = {name: qualified[name] is not None and qualified[name] >= .95
             for name in ("precision", "recall", "f1")}
    counts = group_summary["conditional_confusion"]
    gates["false_positive_rate"] = bool(
        counts["tn"] + counts["fp"] and qualified["false_positive_rate"] <= .05
    )
    gates["evidence_support"] = bool(
        threat_claims and all(row["supported_threat_claim"] for row in rows
                             if row["rule_verdict"] == "threat")
    )
    gates["prediction_contract_integrity"] = all(row["contract_valid"] for row in rows)
    return {
        "schema": "m6-public-evidence-score-1", "group_summary": group_summary,
        "evidence_summary": evidence_summary, "grounded_metrics": qualified,
        "acceptance": {"passed": all(gates.values()), "gates": gates,
                       "thresholds": {"precision": .95, "recall": .95, "f1": .95,
                                      "false_positive_rate": .05},
                       "classified_coverage": group_summary["classified_coverage"],
                       "independent_generalization_verified": False,
                       "scope": "Publisher evidence alignment and observed cohort metrics only"},
        "rows": rows,
    }
