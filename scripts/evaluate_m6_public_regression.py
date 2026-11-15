"""Replay exposed public cohorts under a new detector without altering prior evidence."""

import argparse
import json
import tempfile
from collections import Counter
from pathlib import Path

from scripts import evaluate_m6 as m6
from scripts import evaluate_m6_public_behavior as behavior
from scripts.evaluate_m6_shadow import read_rows
from scripts.m7_shadow_overlap import ROOT

DEFAULT_ROOT = ROOT / "runtime/m7/public-behavior-v2-regression"
PREVIOUS = {
    "development": ROOT / "runtime/m7/public-behavior-development",
    "previous-holdout": ROOT / "runtime/m7/public-behavior-holdout",
}


def read_previous(root, expected_hashes=None):
    """Validate original files against their original manifest, without rewriting its freeze."""
    manifest_raw = (root / "dataset/manifest.json").read_bytes()
    report_raw = (root / "report.json").read_bytes()
    hashes = {"manifest": m6.digest(manifest_raw), "report": m6.digest(report_raw)}
    if expected_hashes is not None and hashes != expected_hashes:
        raise ValueError("public_regression_previous_pinned_hash_changed")
    manifest = json.loads(manifest_raw, object_pairs_hook=m6.unique_fields)
    report = json.loads(report_raw, object_pairs_hook=m6.unique_fields)
    manifest_sha = m6.digest(manifest_raw)
    files = {name: (root / "dataset" / name).read_bytes()
             for name in (behavior.INPUTS, behavior.SCORING)}
    if (report["manifest_sha256"] != manifest_sha
            or manifest["files"] != {name: m6.digest(data) for name, data in files.items()}):
        raise ValueError("public_regression_previous_artifact_changed")
    observed = read_rows(files[behavior.INPUTS])
    references = read_rows(files[behavior.SCORING])
    row_ids = [row["original_group_id"] for row in observed]
    prior_ids = [row["original_group_id"] for row in report["rows"]]
    if (len(row_ids) != manifest["units"] or len(set(row_ids)) != len(row_ids)
            or len(references) != len(row_ids) or len(prior_ids) != len(row_ids)
            or set(prior_ids) != set(row_ids)):
        raise ValueError("public_regression_previous_shape")
    return manifest, report, files, hashes


def prepare(previous, destination, expected_hashes=None):
    manifest, _, files, hashes = read_previous(previous, expected_hashes)
    if (destination / "dataset").exists() or destination.resolve() == previous.resolve():
        raise ValueError("public_regression_destination_exists")
    revised = manifest | {
        "schema": "m6-public-behavior-bundle-2",
        "cohort": "exposed_public_regression",
        "implementation_sha256": behavior.implementation_hashes(),
        "freeze_sha256": None,
        "previous_cohort": manifest["cohort"],
        "previous_artifact_hashes": hashes,
        "previous_implementation_sha256": manifest["implementation_sha256"],
        "independent_evaluation": False,
        "reuse_reason": "Both cohorts were examined before this detector revision.",
    }
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".regression-", dir=destination) as temp:
        stage = Path(temp) / "dataset"
        (stage / "private").mkdir(parents=True, mode=0o700)
        for name, data in files.items():
            (stage / name).write_bytes(data)
            (stage / name).chmod(0o600)
        m6.write_report(stage / "manifest.json", revised)
        stage.rename(destination / "dataset")
    return revised


def compare(old, new):
    prior = {row["original_group_id"]: row for row in old["rows"]}
    current = {row["original_group_id"]: row for row in new["rows"]}
    if prior.keys() != current.keys():
        raise ValueError("public_regression_comparison_groups")
    transitions = Counter()
    changes = []
    for group, before in prior.items():
        after = current[group]
        for field in ("source", "expected_label", "families", "case_id"):
            if before[field] != after[field]:
                raise ValueError("public_regression_reference_changed")
        transitions[f'{before["rule_verdict"]}->{after["rule_verdict"]}'] += 1
        if before["rule_verdict"] != after["rule_verdict"]:
            changes.append({
                "group_id": group, "source": after["source"],
                "expected_label": after["expected_label"],
                "before": before["rule_verdict"], "after": after["rule_verdict"],
                "investigation_required": after["detection"].get("investigation_required", False),
            })
    return {
        "before_group_summary": old["summary"], "after_group_summary": new["summary"],
        "after_evidence_summary": new["evidence_validation"]["evidence_summary"],
        "after_grounded_metrics": new["evidence_validation"]["grounded_metrics"],
        "after_acceptance": new["acceptance"],
        "investigation_candidates": new["investigation_candidates"],
        "transitions": dict(transitions), "changed_rows": changes,
    }


def run(root, previous=None, baseline_hashes=DEFAULT_ROOT / "prior-artifact-hashes.json"):
    previous = PREVIOUS if previous is None else previous
    if (root / "comparison.json").exists():
        raise ValueError("public_regression_report_exists")
    implementation = behavior.implementation_hashes()
    baseline_raw = baseline_hashes.read_bytes()
    baseline = json.loads(baseline_raw, object_pairs_hook=m6.unique_fields)
    reports, protected = {}, {}
    for name, source in previous.items():
        relative = source.resolve().relative_to(ROOT.resolve())
        pinned = {"manifest": baseline[str(relative / "dataset/manifest.json")],
                  "report": baseline[str(relative / "report.json")]}
        _, before, _, hashes = read_previous(source, pinned)
        protected[name] = hashes
        destination = root / name
        prepare(source, destination, pinned)
        after = behavior.evaluate(destination)
        reports[name] = compare(before, after)
    for name, source in previous.items():
        if read_previous(source, protected[name])[3] != protected[name]:
            raise ValueError("public_regression_previous_changed_during_run")
    if behavior.implementation_hashes() != implementation:
        raise ValueError("public_regression_implementation_changed_during_run")
    report = {
        "schema": "m6-public-behavior-regression-2",
        "implementation_sha256": implementation, "previous_artifact_hashes": protected,
        "baseline_snapshot_sha256": m6.digest(baseline_raw),
        "independent_evaluation": False, "external_model_requests": 0,
        "project_goals_met": False,
        "project_acceptance_note": "Exposed regression cohorts cannot establish final generalization.",
        "cohorts": reports,
    }
    m6.write_report(root / "comparison.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--baseline-hashes", type=Path,
                        default=DEFAULT_ROOT / "prior-artifact-hashes.json")
    args = parser.parse_args()
    report = run(args.root, baseline_hashes=args.baseline_hashes)
    print(json.dumps({name: {key: value[key] for key in (
        "after_group_summary", "after_evidence_summary", "after_grounded_metrics",
        "after_acceptance", "investigation_candidates", "transitions",
    )} for name, value in report["cohorts"].items()}, ensure_ascii=False))


if __name__ == "__main__":
    main()
