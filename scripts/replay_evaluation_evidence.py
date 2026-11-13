"""Prepare an explicitly exposed regression replay, preserving original evidence.

Only the new copy names today's implementation. Original inputs, labels, manifests
and historical predictions are never changed. A replay is not independent accuracy.
"""

import argparse
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from scripts.evaluate_m6 import canonical, digest, unique_fields
from scripts.evaluate_m7_context import exclusive_write, implementation_hashes, source_revision

FILES = {
    "m7-context-comparison-dataset-1": {"inputs.jsonl", "private/scoring.jsonl"},
    "m7-execution-evaluation-1": {"legacy/inputs.jsonl", "legacy/private/scoring.jsonl",
                                  "fresh/inputs.jsonl", "fresh/private/scoring.jsonl"},
}


def prepare(source, target, *, previous_directory=None):
    source, target = Path(source), Path(target)
    if source.is_symlink() or not source.is_dir() or target.exists() or target.is_symlink():
        raise ValueError("regression replay requires existing source and fresh target")
    manifest_path = source / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("regression replay symlink")
    raw = manifest_path.read_bytes()
    original = json.loads(raw, object_pairs_hook=unique_fields)
    names = FILES.get(original.get("schema"))
    if names is None or set(original["files"]) != names:
        raise ValueError("regression replay manifest shape")
    files = {}
    for name in sorted(names):
        path = source / name
        if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
            raise ValueError("regression replay input path")
        files[name] = path.read_bytes()
        if digest(files[name]) != original["files"][name]:
            raise ValueError("regression replay source changed")
    implementation = implementation_hashes()
    commit, dirty = source_revision()
    manifest = original | {
        "created_at": datetime.now(UTC).isoformat(), "source_commit": commit, "source_dirty": dirty,
        "implementation_sha256": implementation,
        "regression_replay": {"original_directory": str(source.resolve()),
                              "original_manifest_sha256": digest(raw),
                              "original_implementation_sha256": original["implementation_sha256"],
                              "same_input_and_label_bytes": True,
                              "exposed_cases": True, "new_independent_evaluation": False},
    }
    if previous_directory is not None:
        if original["schema"] != "m7-execution-evaluation-1":
            raise ValueError("previous directory relocation requires execution replay")
        from scripts.evaluate_m7_execution_context import prior_artifacts
        previous_directory = Path(previous_directory)
        if previous_directory.is_symlink() or not previous_directory.is_dir():
            raise ValueError("previous replay directory must be a regular directory")
        # A path override never overrides the pinned input, labels or predictions.
        prior_artifacts(previous_directory, original["previous_artifact_sha256"])
        manifest["previous_directory"] = str(previous_directory.resolve())
        manifest["regression_replay"]["original_previous_directory"] = original["previous_directory"]
        manifest["regression_replay"]["previous_directory_relocated"] = True
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".regression-replay-", dir=target.parent) as name:
        stage = Path(name) / "bundle"
        stage.mkdir(mode=0o700)
        for relative, data in files.items():
            exclusive_write(stage / relative, data)
        for private in stage.rglob("private"):
            private.chmod(0o700)
        exclusive_write(stage / "origin-manifest.json", raw)
        exclusive_write(stage / "manifest.json", canonical(manifest) + b"\n")
        if (manifest_path.read_bytes() != raw or implementation_hashes() != implementation
                or any((source / name).read_bytes() != data for name, data in files.items())):
            raise ValueError("regression replay inputs changed during publication")
        stage.rename(target)
    return {"prepared": True, "original_manifest_sha256": digest(raw), "exposed_cases": True,
            "new_independent_evaluation": False, "external_model_requests": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--previous-directory", type=Path,
                        help="Relocated original context bundle; every historical artifact hash must match")
    args = parser.parse_args(argv)
    print(json.dumps(prepare(args.source, args.directory, previous_directory=args.previous_directory)))


if __name__ == "__main__":
    main()
