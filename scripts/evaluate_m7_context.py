"""Freeze and compare public rules with signed operational context on fresh local sessions."""

import argparse
import json
import os
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.services.public_detection import PublicSession
from scripts.evaluate_m6 import canonical, digest, source_commit, unique_fields, write_report

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIRECTORY = ROOT / "runtime/m7/behavior-context-evaluation"
INPUTS = "inputs.jsonl"
LABELS = "private/scoring.jsonl"
PREDICTIONS = "predictions.jsonl"
SCOPE = (
    "Fresh controlled local sessions with synthetic operational records and real signature, "
    "Inbox, worker and context-service execution. The two arms receive identical observed "
    "activity; only the context arm receives prior reviewed baselines, approvals and verified "
    "operational signals. This measures the value of additional evidence, not a same-information "
    "model comparison or independent public-log generalization."
)


def implementation_hashes():
    paths = set()
    for directory in (ROOT / "app", ROOT / "scripts"):
        paths.update(path for path in directory.rglob("*")
                     if path.is_file() and path.suffix in {".py", ".json", ".yml", ".yaml"})
    paths.add(ROOT / "pyproject.toml")
    return {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sorted(paths)}


def jsonl(rows):
    return b"".join(canonical(row) + b"\n" for row in rows)


def read_rows(raw):
    rows = [json.loads(line, object_pairs_hook=unique_fields) for line in raw.splitlines()]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError("context_evaluation_invalid_rows")
    return rows


def exclusive_write(path, data):
    """Publish an artifact once; never replace previous evaluation evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def source_revision():
    """Git is optional metadata; source hashes remain mandatory in archives."""
    commit = source_commit()
    if commit is None:
        return None, None
    try:
        status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                                capture_output=True, text=True, check=False, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return commit, None
    return commit, bool(status.stdout) if status.returncode == 0 else None


def prepare(directory, repetitions=10):
    from scripts.m7_context_dataset import audit_inputs, audit_prior_overlap, build_dataset

    directory = Path(directory)
    if directory.exists():
        raise ValueError("context_evaluation_directory_exists")
    before = implementation_hashes()
    inputs, labels = build_dataset(repetitions=repetitions)
    leakage = audit_inputs(inputs, labels)
    overlap = audit_prior_overlap(inputs)
    if implementation_hashes() != before:
        raise ValueError("context_evaluation_implementation_changed_during_prepare")
    files = {INPUTS: jsonl(inputs), LABELS: jsonl(labels)}
    commit, dirty = source_revision()
    if implementation_hashes() != before:
        raise ValueError("context_evaluation_implementation_changed_during_prepare")
    manifest = {
        "schema": "m7-context-comparison-dataset-1", "created_at": datetime.now(UTC).isoformat(),
        "scope": SCOPE, "sessions": len(inputs), "repetitions_per_stratum": repetitions,
        "source_commit": commit, "source_dirty": dirty,
        "implementation_sha256": before,
        "files": {name: digest(raw) for name, raw in files.items()},
        "input_label_separation": leakage, "prior_overlap": overlap,
        "data_origin": "newly generated controlled local experiment; no new public logs",
        "independent_human_label_review": False, "new_threat_family_claim": False,
        "external_model_requests": 0,
    }
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".context-prepare-", dir=directory.parent) as name:
        stage = Path(name) / "bundle"
        (stage / "private").mkdir(parents=True, mode=0o700)
        for relative, raw in files.items():
            exclusive_write(stage / relative, raw)
        exclusive_write(stage / "manifest.json", canonical(manifest) + b"\n")
        stage.rename(directory)
    return manifest


def checked_bundle(directory, *, check_prior=True):
    """Check sealed bytes without decoding scoring labels before predictions exist."""
    from scripts.m7_context_dataset import audit_inputs, audit_prior_overlap

    directory = Path(directory)
    raw = (directory / "manifest.json").read_bytes()
    manifest = json.loads(raw, object_pairs_hook=unique_fields)
    if manifest["schema"] != "m7-context-comparison-dataset-1":
        raise ValueError("context_evaluation_manifest_schema")
    if manifest["implementation_sha256"] != implementation_hashes():
        raise ValueError("context_evaluation_frozen_implementation_changed")
    if set(manifest["files"]) != {INPUTS, LABELS}:
        raise ValueError("context_evaluation_manifest_files")
    for name, expected in manifest["files"].items():
        if digest((directory / name).read_bytes()) != expected:
            raise ValueError("context_evaluation_dataset_changed")
    inputs = read_rows((directory / INPUTS).read_bytes())
    if len(inputs) != manifest["sessions"]:
        raise ValueError("context_evaluation_session_count")
    audit_inputs(inputs)
    if check_prior:
        # Recheck the exact files observed at preparation, not a later enlarged inventory.
        # New cohort discovery belongs to a new prepare operation.
        audit_prior_overlap(inputs, pinned=manifest["prior_overlap"])
    return manifest, inputs, digest(raw)


def predict(inputs, directory):
    """Execute both arms without any scoring data or expected verdict parameter."""
    from scripts.m7_context_provenance import validate_provenance
    from scripts.m7_context_runtime import run_case

    rows = []
    for spec in inputs:
        with tempfile.TemporaryDirectory(prefix="context-case-") as temporary:
            try:
                row = run_case(spec, Path(temporary) / "case")
            except (ValueError, RuntimeError, OSError, TypeError, LookupError) as error:
                row = {
                    "case_id": spec["case_id"], "session_id": spec["target"]["session_id"],
                    "input_sha256": digest(canonical(spec)),
                    "activity_sha256": digest(canonical(spec["target"]["activity"])),
                    "error_type": type(error).__name__,
                    "rule_only": {"status": "error", "verdict": "unknown"},
                    "with_context": {"status": "error", "verdict": "unknown"},
                    "provenance": {},
                }
            if row["case_id"] != spec["case_id"] or row["input_sha256"] != digest(canonical(spec)):
                raise ValueError("context_evaluation_prediction_input_mismatch")
            if not row.get("error_type"):
                expected = PublicSession.model_validate(spec["target"]["activity"]).model_dump(mode="json")
                capture = row["provenance"]["capture"]
                if (capture["activity"] != expected
                        or capture["session_id"] != spec["target"]["session_id"]
                        or capture["capture_id"] != spec["target"]["capture_id"]
                        or capture["tenant_id"] != spec["tenant_id"]
                        or capture["scope"] != spec["scope"]
                        or any(row[key] != digest(canonical(expected)) for key in (
                            "activity_sha256", "rule_input_sha256", "context_activity_sha256",
                        ))
                        or row.get("paired_input_identical") is not True
                        or row.get("policy_journal_unchanged_by_evaluation") is not True):
                    raise ValueError("context_evaluation_observed_input_mismatch")
                validate_provenance(spec, row)
            rows.append(row)
        if len(rows) % 20 == 0:
            print(json.dumps({"predicted": len(rows), "total": len(inputs)}), flush=True)
    exclusive_write(Path(directory) / PREDICTIONS, jsonl(rows))
    return rows


def evaluate(directory):
    from scripts.m7_context_scoring import score_comparison

    directory = Path(directory)
    if any((directory / name).exists() for name in (PREDICTIONS, "report.json", "execution.json")):
        raise ValueError("context_evaluation_results_exist")
    manifest, inputs, manifest_sha = checked_bundle(directory)
    started = datetime.now(UTC).isoformat()
    predictions = predict(inputs, directory)
    # Predictions are durably written before private reference labels are parsed.
    predicted_at = datetime.now(UTC).isoformat()
    prediction_raw = (directory / PREDICTIONS).read_bytes()
    if read_rows(prediction_raw) != predictions:
        raise ValueError("context_evaluation_prediction_publication_changed")
    if checked_bundle(directory)[2] != manifest_sha:
        raise ValueError("context_evaluation_manifest_changed_during_run")
    labels = read_rows((directory / LABELS).read_bytes())
    report = score_comparison(predictions, labels)
    report.update({
        "schema": "m7-context-comparison-report-1", "scope": SCOPE,
        "manifest_sha256": manifest_sha, "predictions_sha256": digest(prediction_raw),
        "dataset_files_sha256": manifest["files"],
        "implementation_sha256": manifest["implementation_sha256"],
        "scoring_labels_decoded_after_predictions_saved": True,
        "external_model_requests": 0, "independent_public_generalization_verified": False,
        "independent_human_label_review": False, "project_goals_met": False,
        "acceptance_note": "Controlled scenario results alone cannot establish final detection goals.",
        "started_at": started, "predictions_saved_at": predicted_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "input_label_separation": manifest["input_label_separation"],
        "prior_overlap": manifest["prior_overlap"],
    })
    if checked_bundle(directory)[2] != manifest_sha:
        raise ValueError("context_evaluation_manifest_changed_during_run")
    exclusive_write(directory / "report.json", json.dumps(
        report, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False,
    ).encode() + b"\n")
    write_report(directory / "execution.json", {
        "python_version": platform.python_version(), "manifest_sha256": manifest_sha,
        "report_sha256": digest((directory / "report.json").read_bytes()),
        "predictions_sha256": digest(prediction_raw), "started_at": started,
        "finished_at": report["finished_at"], "case_workspaces_cleaned": True,
        "private_keys_persisted": False, "external_model_requests": 0,
    })
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "evaluate"))
    parser.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument("--repetitions", type=int, default=10)
    args = parser.parse_args()
    if args.command == "prepare":
        report = prepare(args.directory, args.repetitions)
        summary = {"sessions": report["sessions"], "directory": str(args.directory)}
    elif args.command == "verify":
        report, _, manifest_sha = checked_bundle(args.directory)
        summary = {"verified": True, "sessions": report["sessions"], "manifest_sha256": manifest_sha}
    else:
        report = evaluate(args.directory)
        summary = {key: value for key, value in report.items() if key in {
            "schema", "sessions", "models", "arms", "summary", "comparison",
            "project_goals_met", "external_model_requests",
        }}
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
