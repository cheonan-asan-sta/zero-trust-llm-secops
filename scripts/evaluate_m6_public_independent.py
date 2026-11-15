"""Evaluate the frozen M6 rules on independent public system logs."""

import argparse
import json
import tempfile
from collections import Counter
from pathlib import Path

from scripts import evaluate_m6 as m6
from scripts.evaluate_m6_proof_policy import VerifiedEvidence, assess
from scripts.evaluate_m6_shadow import detection_summary, read_rows
from scripts.m7_device_rule_validation import PREVIOUS_SHADOW, overlap_with_shadow
from scripts.m7_shadow_overlap import ROOT, verify_overlap
from scripts.prepare_m7_local import jsonl

RULE = Path(__file__).with_name("evaluate_m6_proof_policy.py")
DEFAULT_ROOT = ROOT / "runtime/m7/public-independent"
PRIOR_DEVICE = ROOT / "runtime/m7/device-rule-validation/report.json"
INPUTS = "rule-inputs.jsonl"
OBSERVATIONS = "public-observations.jsonl"
SCORING = "private/scoring.jsonl"
SOURCES = {
    "cowrie": {
        "archive": "cowrie.zip",
        "archive_sha256": "5da1df26decc9077ee6afd0b983b990bf64a4cb9798ebdaca871aed7217b88fc",
        "revision": "441729542d953f920d4cd0ec7139ee655a5a3154",
        "publisher_url": "https://github.com/danirzkpinho/cowrie-honeypot-llm-sentinel",
        "license": "CC BY-NC 4.0",
        "scope": "Cowrie SSH records captured during benign and attack activity in a research lab",
    },
    "cloudtrail": {
        "archive": "cloudtrail-a.zip",
        "archive_sha256": "d5dce3dbdb61ffb935e16cb4728aaca933daa42201a672dfad7387fd168f6eb0",
        "revision": "18d3f248f4def592f4e86152c3fcb54506fbcbf6",
        "publisher_url": "https://github.com/ArielCyber/cloud_log_sampling",
        "license": "Released for research; no explicit repository license found. Local analysis only.",
        "scope": "System-generated CloudTrail records of benign and attack activity in a controlled AWS deployment",
    },
}
LABEL_FIELDS = {"label", "labels", "expected_label", "attack_name", "should_sample", "families"}


def public_rule_evidence() -> VerifiedEvidence:
    # AWS and Cowrie report their own observations. Neither source supplies this
    # framework's tenant policy, enrolled device binding or signed verifier findings.
    return VerifiedEvidence(
        proof_requirement="unknown", proof_state="absent", identity_binding="unconfirmed",
        endpoint_scope="unconfirmed", verified_violation=None,
    )


def contains_reference_field(value):
    if isinstance(value, dict):
        return bool(value.keys() & LABEL_FIELDS) or any(map(contains_reference_field, value.values()))
    if isinstance(value, list):
        return any(map(contains_reference_field, value))
    return False


def check_previous_device(audit_rows):
    raw = PRIOR_DEVICE.read_bytes()
    prior = json.loads(raw, object_pairs_hook=m6.unique_fields)
    if prior["sessions"] != 15 or len(prior["rows"]) != 15:
        raise ValueError("m6_public_prior_device_count")
    overlaps = {
        name: len({item[name] for item in audit_rows} & {item[name] for item in prior["rows"]})
        for name in ("case_id", "session_id", "request_sha256", "capture_sha256")
    }
    overlaps["evidence_ids"] = len(
        {fact for item in audit_rows for fact in item["evidence_ids"]}
        & {fact for item in prior["rows"] for fact in item["evidence_ids"]}
    )
    if any(overlaps.values()):
        raise ValueError("m6_public_prior_device_overlap")
    return {"sha256": m6.digest(raw), "units": 15, "overlaps": overlaps}


def prepare(root):
    from scripts.m7_public_cloudtrail import load_cloudtrail
    from scripts.m7_public_cowrie import load_cowrie

    target = root / "dataset"
    if target.exists():
        raise ValueError("m6_public_dataset_exists")
    metadata, source_rows = {}, []
    for name, loader in (("cowrie", load_cowrie), ("cloudtrail", load_cloudtrail)):
        source = SOURCES[name]
        archive = root / "source" / source["archive"]
        if m6.digest(archive.read_bytes()) != source["archive_sha256"]:
            raise ValueError(f"m6_public_source_hash_mismatch: {name}")
        rows, detail = loader(archive)
        metadata[name] = source | {"selection": detail}
        source_rows.extend(rows)

    inputs, observations, scoring, audit_rows = [], [], [], []
    evidence = public_rule_evidence().model_dump(exclude_defaults=True)
    for row in sorted(source_rows, key=lambda item: (item["source"], item["original_group_id"])):
        source, group = row["source"], row["original_group_id"]
        if source not in SOURCES or not row["event_hashes"] or row["expected_label"] not in m6.LABELS:
            raise ValueError("m6_public_invalid_group")
        case_id = "public-" + m6.digest(m6.canonical([source, group]))
        request = {"case_id": case_id, "evidence": evidence}
        observed = {"case_id": case_id, "source": source, "original_group_id": group,
                    "event_hashes": sorted(row["event_hashes"]), "facts": row["observation"]}
        if contains_reference_field(observed):
            raise ValueError("m6_public_reference_leak")
        inputs.append(request)
        observations.append(observed)
        scoring.append({"case_id": case_id, "source": source,
                        "expected_label": row["expected_label"], "families": row["families"]})
        audit_rows.append({
            "case_id": case_id, "session_id": group, "evidence_ids": observed["event_hashes"],
            "request_sha256": m6.digest(m6.canonical(request)),
            "capture_sha256": m6.digest(m6.canonical(observed)),
        })
    event_hashes = [fact for row in audit_rows for fact in row["evidence_ids"]]
    if (not inputs or len({row["case_id"] for row in inputs}) != len(inputs)
            or len(set(event_hashes)) != len(event_hashes)):
        raise ValueError("m6_public_duplicate_unit_or_event")
    overlap = verify_overlap(
        [row["session_id"] for row in audit_rows], event_hashes,
        [row["request_sha256"] for row in audit_rows],
        new_related_ids=[row["case_id"] for row in audit_rows], new_source_hashes=event_hashes,
    )
    files = {INPUTS: jsonl(inputs), OBSERVATIONS: jsonl(observations), SCORING: jsonl(scoring)}
    manifest = {
        "schema": "m6-independent-public-logs-1", "sources": metadata,
        "rule_sha256": m6.digest(RULE.read_bytes()),
        "units": len(inputs), "included_events": len(event_hashes),
        "prior_cohorts": overlap,
        "prior_24_shadow": overlap_with_shadow(audit_rows, PREVIOUS_SHADOW),
        "prior_15_device": check_previous_device(audit_rows),
        "files": {name: m6.digest(data) for name, data in files.items()},
        "projection": {
            "native_evidence_available": [],
            "verified_compromise_promoted_from_publisher_label": False,
            "reference_labels_used_only_after_classification": True,
        },
    }
    with tempfile.TemporaryDirectory(prefix=".m6-public-", dir=root) as temp:
        stage = Path(temp) / "dataset"
        (stage / "private").mkdir(parents=True, mode=0o700)
        for name, data in files.items():
            (stage / name).write_bytes(data)
            (stage / name).chmod(0o600)
        m6.write_report(stage / "manifest.json", manifest)
        stage.rename(target)
    return manifest


def summarize(rows):
    result = detection_summary(rows)
    verdicts = Counter(row["rule_verdict"] for row in rows)
    values = {
        "precision": result["conditional_metrics"]["precision"],
        "recall": result["conservative_recall"], "f1": result["conservative_f1"],
        "false_positive_rate": result["false_positive_rate_all_normals"],
    }
    gates = {key: value is not None and value >= 0.95
             for key, value in values.items() if key != "false_positive_rate"}
    evaluated_normals = result["conditional_confusion"]["tn"] + result["conditional_confusion"]["fp"]
    gates["false_positive_rate"] = bool(evaluated_normals and values["false_positive_rate"] <= 0.05)
    return result | {
        "units": len(rows), "prediction_counts": dict(verdicts),
        "held_total": verdicts["unknown"], "metrics": values, "target_verified": gates,
        "all_targets_met": all(gates.values()),
    }


def evaluate(root):
    bundle = root / "dataset"
    raw_manifest = (bundle / "manifest.json").read_bytes()
    manifest = json.loads(raw_manifest, object_pairs_hook=m6.unique_fields)
    if manifest["rule_sha256"] != m6.digest(RULE.read_bytes()):
        raise ValueError("m6_public_frozen_rule_changed")
    files = {name: (bundle / name).read_bytes() for name in (INPUTS, OBSERVATIONS, SCORING)}
    if {name: m6.digest(data) for name, data in files.items()} != manifest["files"]:
        raise ValueError("m6_public_bundle_changed")
    inputs = read_rows(files[INPUTS])
    decisions = {}
    for row in inputs:
        if set(row) != {"case_id", "evidence"} or row["case_id"] in decisions:
            raise ValueError("m6_public_input_shape")
        facts = VerifiedEvidence.model_validate(row["evidence"], strict=True)
        if facts != public_rule_evidence():
            raise ValueError("m6_public_unverified_rule_input")
        decisions[row["case_id"]] = assess(facts)
    references = read_rows(files[SCORING])
    if len(references) != len(decisions) or decisions.keys() != {row["case_id"] for row in references}:
        raise ValueError("m6_public_reference_mismatch")
    rows = []
    for reference in references:
        verdict, next_check, reason = decisions[reference["case_id"]]
        rows.append(reference | {"rule_verdict": verdict, "next_check": next_check, "reason": reason})
    report = {
        "schema": "m6-independent-public-logs-report-1", "manifest_sha256": m6.digest(raw_manifest),
        "rule_sha256": manifest["rule_sha256"], "external_model_requests": 0,
        "target_thresholds": {"precision": .95, "recall": .95, "f1": .95, "false_positive_rate": .05},
        "summary": summarize(rows),
        "by_source": {name: summarize([row for row in rows if row["source"] == name]) for name in SOURCES},
        "verdict_reasons": dict(Counter(row["reason"] for row in rows)),
        "threat_families": dict(Counter(
            family for row in rows if row["expected_label"] == "threat" for family in row["families"]
        )),
        "rows": rows,
    }
    m6.write_report(root / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "evaluate"))
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    report = prepare(args.root) if args.mode == "prepare" else evaluate(args.root)
    print(json.dumps(report.get("summary", {"units": report.get("units")}), ensure_ascii=False))


if __name__ == "__main__":
    main()
