"""Evaluate observed public behavior, keeping exposed development and frozen holdout apart."""

import argparse
import json
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.services.public_detection import PublicDetectionService, PublicSession
from scripts import evaluate_m6 as m6
from scripts.evaluate_m6_public_independent import (
    SOURCES,
    check_previous_device,
    contains_reference_field,
    summarize,
)
from scripts.evaluate_m6_shadow import read_rows
from scripts.m7_device_rule_validation import PREVIOUS_SHADOW, overlap_with_shadow
from scripts.m7_public_behavior_inputs import load_cloudtrail_behavior, load_cowrie_behavior
from scripts.m7_shadow_overlap import ROOT, verify_overlap
from scripts.prepare_m7_local import jsonl

DEFAULT_ROOT = ROOT / "runtime/m7/public-behavior-development"
HOLDOUT_SHA = "09694486a5336f6771b8062e9fe269779bb91ec100214ba5f40b31f5c49b8183"
INPUTS = "observations.jsonl"
SCORING = "private/scoring.jsonl"


def implementation_hashes():
    names = [
        "app/services/public_detection.py", "app/services/sigma.py", "app/models.py", "app/main.py",
        "app/services/detection_benchmark.py", "scripts/m7_public_behavior_inputs.py",
        "scripts/m7_public_cloudtrail.py", "scripts/m7_public_cowrie.py",
        "scripts/evaluate_m6_public_behavior.py", "scripts/evaluate_m6_public_independent.py",
        "scripts/evaluate_m6_shadow.py", "scripts/evaluate_m6.py",
        "scripts/m7_shadow_overlap.py", "scripts/m7_device_rule_validation.py",
        "scripts/prepare_m7_local.py",
        "scripts/audit_m7_public_holdout.py",
        "scripts/m6_public_evidence_scoring.py", "scripts/evaluate_m6_public_regression.py",
    ]
    names += [str(path.relative_to(ROOT)) for path in sorted((ROOT / "app/data/public_sigma").glob("*.yml"))]
    if not any(name.endswith(".yml") for name in names):
        raise ValueError("public_behavior_no_rules")
    return {name: m6.digest((ROOT / name).read_bytes()) for name in names}


def partition_overlap(rows, prior_inputs, excluded_group_ids=()):
    """Drop whole sessions if any prior event or credential appears, independent of labels."""
    groups = {row["original_group_id"] for row in prior_inputs}
    events = {event["id"] for row in prior_inputs for event in row["events"]}
    credentials = {event["connection_id"] for row in prior_inputs for event in row["events"]
                   if event.get("connection_id")}
    external = set(excluded_group_ids)
    retained, excluded = [], []
    for row in rows:
        observed = row["observation"]
        reasons = []
        if observed["original_group_id"] in groups:
            reasons.append("session")
        if any(event["id"] in events for event in observed["events"]):
            reasons.append("event")
        if any(event.get("connection_id") in credentials for event in observed["events"]):
            reasons.append("credential")
        if observed["original_group_id"] in external:
            reasons.append("raw_source_audit")
        if reasons:
            excluded.append({"source": row["source"], "group_id": row["original_group_id"],
                             "reasons": reasons})
        else:
            retained.append(row)
    return retained, excluded


def checked_bundle(root):
    manifest_raw = (root / "dataset/manifest.json").read_bytes()
    manifest = json.loads(manifest_raw, object_pairs_hook=m6.unique_fields)
    if manifest["implementation_sha256"] != implementation_hashes():
        raise ValueError("public_behavior_frozen_implementation_changed")
    files = {name: (root / "dataset" / name).read_bytes() for name in (INPUTS, SCORING)}
    if manifest["files"] != {name: m6.digest(raw) for name, raw in files.items()}:
        raise ValueError("public_behavior_bundle_changed")
    return manifest, files, m6.digest(manifest_raw)


def write_bundle(root, rows, metadata, *, cohort, overlap=None, freeze_sha256=None):
    if (root / "dataset").exists():
        raise ValueError("public_behavior_dataset_exists")
    inputs, scoring, audit = [], [], []
    for row in sorted(rows, key=lambda row: (row["source"], row["original_group_id"])):
        observed = row["observation"]
        if contains_reference_field(observed):
            raise ValueError("public_behavior_reference_leak")
        # The strict API model validates exactly the object used by the detector.
        PublicSession.model_validate(observed)
        if (row["source"] != observed["source"]
                or row["original_group_id"] != observed["original_group_id"]
                or row["event_hashes"] != sorted(event["id"] for event in observed["events"])
                or row["expected_label"] not in {"normal", "threat"}
                or not isinstance(row["families"], list)
                or any(not isinstance(family, str) or not family for family in row["families"])):
            raise ValueError("public_behavior_reference_mismatch")
        case_id = "behavior-" + m6.digest(m6.canonical([row["source"], row["original_group_id"]]))
        inputs.append(observed)
        scoring.append({"case_id": case_id, "source": row["source"],
                        "original_group_id": row["original_group_id"],
                        "expected_label": row["expected_label"], "families": row["families"]})
        audit.append({"case_id": case_id, "session_id": row["original_group_id"],
                      "evidence_ids": [event["id"] for event in observed["events"]],
                      "request_sha256": m6.digest(m6.canonical(observed)),
                      "capture_sha256": m6.digest(m6.canonical(observed))})
    ids = [row["session_id"] for row in audit]
    events = [event for row in audit for event in row["evidence_ids"]]
    if not rows or len(set(ids)) != len(ids) or len(set(events)) != len(events):
        raise ValueError("public_behavior_duplicate_or_empty")
    prior = verify_overlap(ids, events, [row["request_sha256"] for row in audit],
                           new_related_ids=[row["case_id"] for row in audit], new_source_hashes=events)
    files = {INPUTS: jsonl(inputs), SCORING: jsonl(scoring)}
    manifest = {
        "schema": "m6-public-behavior-bundle-1", "cohort": cohort,
        "units": len(inputs), "events": len(events), "sources": metadata,
        "implementation_sha256": implementation_hashes(), "freeze_sha256": freeze_sha256,
        "files": {name: m6.digest(raw) for name, raw in files.items()},
        "prior_local_cohorts": prior,
        "prior_24_shadow": overlap_with_shadow(audit, PREVIOUS_SHADOW),
        "prior_15_device": check_previous_device(audit),
        "public_overlap": overlap,
        "label_fields_in_inputs": False, "publisher_labels_are_enforcement_evidence": False,
    }
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".behavior-", dir=root) as temp:
        stage = Path(temp) / "dataset"
        (stage / "private").mkdir(parents=True, mode=0o700)
        for name, raw in files.items():
            (stage / name).write_bytes(raw)
            (stage / name).chmod(0o600)
        m6.write_report(stage / "manifest.json", manifest)
        stage.rename(root / "dataset")
    return manifest


def prepare_development(root, source_root):
    rows, metadata = [], {}
    for name, loader in (("cowrie", load_cowrie_behavior), ("cloudtrail", load_cloudtrail_behavior)):
        loaded, detail = loader(source_root / SOURCES[name]["archive"])
        rows.extend(loaded)
        metadata[name] = SOURCES[name] | {"selection": detail}
    return write_bundle(root, rows, metadata, cohort="exposed_public_development")


def freeze(development, destination):
    manifest, _, manifest_sha = checked_bundle(development)
    report_raw = (development / "report.json").read_bytes()
    report = json.loads(report_raw, object_pairs_hook=m6.unique_fields)
    if report["manifest_sha256"] != manifest_sha:
        raise ValueError("public_behavior_development_not_evaluated")
    if destination.exists():
        raise ValueError("public_behavior_freeze_exists")
    value = {"schema": "m6-public-behavior-freeze-1", "frozen_at": datetime.now(UTC).isoformat(),
             "implementation_sha256": implementation_hashes(),
             "development_manifest_sha256": manifest_sha,
             "development_report_sha256": m6.digest(report_raw),
             "development_units": manifest["units"], "holdout_archive_sha256": HOLDOUT_SHA,
             "holdout_scope": "New records from same publisher; not independent sources or new attack families"}
    m6.write_report(destination, value)
    return value


def prepare_holdout(root, development, freeze_path, archive, overlap_audit):
    frozen_raw = freeze_path.read_bytes()
    frozen = json.loads(frozen_raw, object_pairs_hook=m6.unique_fields)
    if frozen["implementation_sha256"] != implementation_hashes():
        raise ValueError("public_behavior_freeze_changed")
    if frozen["holdout_archive_sha256"] != HOLDOUT_SHA:
        raise ValueError("public_behavior_frozen_holdout_changed")
    _, dev_files, dev_sha = checked_bundle(development)
    if frozen["development_manifest_sha256"] != dev_sha:
        raise ValueError("public_behavior_development_changed")
    if frozen["development_report_sha256"] != m6.digest((development / "report.json").read_bytes()):
        raise ValueError("public_behavior_development_report_changed")
    audit_raw = overlap_audit.read_bytes()
    audit = json.loads(audit_raw, object_pairs_hook=m6.unique_fields)
    if (audit["freeze_sha256"] != m6.digest(frozen_raw)
            or audit["holdout_archive_sha256"] != HOLDOUT_SHA):
        raise ValueError("public_behavior_overlap_audit_mismatch")
    rows, metadata = load_cloudtrail_behavior(archive, expected_sha256=HOLDOUT_SHA)
    excluded_ids = audit["excluded_group_ids"]
    if (not isinstance(excluded_ids, list)
            or any(not isinstance(group, str) or not group for group in excluded_ids)
            or len(set(excluded_ids)) != len(excluded_ids)
            or not set(excluded_ids) <= {row["original_group_id"] for row in rows}):
        raise ValueError("public_behavior_overlap_audit_groups")
    retained, excluded = partition_overlap(
        rows, read_rows(dev_files[INPUTS]), excluded_ids,
    )
    provenance_path = archive.with_suffix(".provenance.json")
    provenance = json.loads(provenance_path.read_bytes(), object_pairs_hook=m6.unique_fields)
    return write_bundle(
        root, retained, {"cloudtrail": {"selection": metadata, "provenance": provenance}},
        cohort="frozen_new_record_holdout_same_publisher", freeze_sha256=m6.digest(frozen_raw),
        overlap={"candidate_units": len(rows), "retained_units": len(retained),
                 "excluded_units": excluded, "raw_audit_sha256": m6.digest(audit_raw),
                 "actor_disjoint": False, "novel_attack_families_claimed": False},
    )


def load_evidence_references(manifest):
    """Read pinned publisher references only after all input-only predictions exist."""
    from scripts.m6_public_evidence_scoring import (
        load_cloudtrail_event_truth,
        load_cowrie_event_truth,
        merge_event_truth,
    )

    indices, metadata = [], {}
    for source, details in manifest["sources"].items():
        if source == "cowrie":
            if details.get("archive_sha256") != SOURCES["cowrie"]["archive_sha256"]:
                raise ValueError("public_behavior_unknown_reference_archive")
            index, meta = load_cowrie_event_truth(
                ROOT / "runtime/m7/public-independent/source/cowrie.zip",
            )
        elif source == "cloudtrail":
            sha = details.get("archive_sha256", details.get("selection", {}).get("archive_sha256"))
            archives = {
                SOURCES["cloudtrail"]["archive_sha256"]:
                    ROOT / "runtime/m7/public-independent/source/cloudtrail-a.zip",
                HOLDOUT_SHA:
                    ROOT / "runtime/m7/public-behavior-holdout/source/cloudtrail-train-labeled.zip",
            }
            if sha not in archives:
                raise ValueError("public_behavior_unknown_reference_archive")
            index, meta = load_cloudtrail_event_truth(archives[sha], expected_sha256=sha)
        else:
            raise ValueError("public_behavior_unknown_reference_source")
        indices.append(index)
        metadata[source] = meta
    return merge_event_truth(*indices), metadata


def group_label_summary(rows):
    result = summarize(rows)
    result["group_label_targets_met"] = result.pop("all_targets_met")
    result["group_label_thresholds"] = result.pop("target_verified")
    return result


def evaluate_files(manifest, files, manifest_sha):
    from scripts.m6_public_evidence_scoring import score_predictions

    service = PublicDetectionService()
    decisions = {}
    observed_sources = {}
    observations = read_rows(files[INPUTS])
    # Reference bytes were hashed for integrity; none are parsed or used for predictions.
    for observed in observations:
        if contains_reference_field(observed):
            raise ValueError("public_behavior_reference_leak")
        group = observed["original_group_id"]
        if group in decisions:
            raise ValueError("public_behavior_duplicate_decision")
        result = service.evaluate(PublicSession.model_validate(observed))
        if result["enforcement_eligible"] is not False:
            raise ValueError("public_behavior_authority_escalation")
        decisions[group] = result
        observed_sources[group] = observed["source"]
    references = read_rows(files[SCORING])
    if len(references) != len(decisions) or {row["original_group_id"] for row in references} != decisions.keys():
        raise ValueError("public_behavior_reference_mismatch")
    for reference in references:
        group, source = reference["original_group_id"], reference["source"]
        expected_id = "behavior-" + m6.digest(m6.canonical([source, group]))
        if (source != observed_sources[group] or reference["case_id"] != expected_id
                or reference["expected_label"] not in {"normal", "threat"}
                or not isinstance(reference["families"], list)
                or any(not isinstance(family, str) or not family for family in reference["families"])):
            raise ValueError("public_behavior_reference_mismatch")
    rows = [reference | {"rule_verdict": decisions[reference["original_group_id"]]["verdict"],
                         "detection": decisions[reference["original_group_id"]]}
            for reference in references]
    families = sorted({family for row in rows for family in row["families"]})
    event_truth, evidence_sources = load_evidence_references(manifest)
    evidence_score = score_predictions(observations, references, decisions, event_truth)
    report = {
        "schema": "m6-public-behavior-report-2", "cohort": manifest["cohort"],
        "manifest_sha256": manifest_sha, "freeze_sha256": manifest["freeze_sha256"],
        "external_model_requests": 0, "automatic_access_mutations": 0,
        "target_thresholds": {"precision": .95, "recall": .95, "f1": .95, "false_positive_rate": .05},
        "summary": group_label_summary(rows),
        "by_source": {source: group_label_summary([row for row in rows if row["source"] == source])
                      for source in sorted({row["source"] for row in rows})},
        "by_threat_family": {family: group_label_summary([row for row in rows if family in row["families"]])
                             for family in families},
        "reasons": dict(Counter(row["detection"]["reason"] for row in rows)),
        "investigation_candidates": sum(bool(row["detection"].get("investigation_required")) for row in rows),
        "evidence_validation": evidence_score,
        "evidence_reference_sources": evidence_sources,
        "acceptance": evidence_score["acceptance"],
        "generalization_claim": False,
        "rows": rows,
    }
    # Group-label metrics remain descriptive; they cannot grant project acceptance.
    report["summary"]["all_targets_met"] = evidence_score["acceptance"]["passed"]
    return report


def evaluate(root):
    manifest, files, manifest_sha = checked_bundle(root)
    if (root / "report.json").exists():
        raise ValueError("public_behavior_report_exists")
    report = evaluate_files(manifest, files, manifest_sha)
    if manifest["implementation_sha256"] != implementation_hashes():
        raise ValueError("public_behavior_implementation_changed_during_evaluation")
    if (root / "report.json").exists():
        raise ValueError("public_behavior_report_exists")
    m6.write_report(root / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare-development", "freeze", "prepare-holdout", "evaluate"))
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--source-root", type=Path, default=ROOT / "runtime/m7/public-independent/source")
    parser.add_argument("--development", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--freeze", type=Path, default=ROOT / "runtime/m7/public-behavior-holdout/freeze.json")
    parser.add_argument("--archive", type=Path,
                        default=ROOT / "runtime/m7/public-behavior-holdout/source/cloudtrail-train-labeled.zip")
    parser.add_argument("--overlap-audit", type=Path,
                        default=ROOT / "runtime/m7/public-behavior-holdout/holdout-overlap-audit.json")
    args = parser.parse_args()
    if args.mode == "prepare-development":
        result = prepare_development(args.root, args.source_root)
    elif args.mode == "freeze":
        result = freeze(args.development, args.freeze)
    elif args.mode == "prepare-holdout":
        result = prepare_holdout(args.root, args.development, args.freeze, args.archive, args.overlap_audit)
    else:
        result = evaluate(args.root)
    print(json.dumps(result.get("summary", {"units": result.get("units"), "cohort": result.get("cohort")}),
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
