"""Evaluate frozen target-only CRS against the public FPAD test splits."""

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_web_crs_priority import corroborated
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical

DATASETS = {
    "fpad": ("674cffc945c44d0858cae4a55db658dc7f38bc64e2d9f3f4ade64da2c0e1fc61", 16_197),
    "fpad-ood": ("d690b3650e2d65a740402ae36618bb3982f27c24f785b5304fd344c5bed4c32f", 21_180),
}
BINARY_SHA = "85fa7c369711880249ae06a3f474665e6e1ba7f6aa8b11338450da8bcc00b69c"
MAX_SOURCE_BYTES = 8 * 1024**2
FIELDS = {"ordinal", "method", "target"}


def source_rows(source, split):
    if source.stat().st_size > MAX_SOURCE_BYTES or fingerprint(source) != DATASETS[split][0]:
        raise ValueError("FPAD file does not match the pinned release")
    with source.open("rb") as stream:
        yield from map(json.loads, stream)


def prepare(source, output, split):
    rows = [
        {"ordinal": ordinal, "method": row["method"], "target": row["url"]}
        for ordinal, row in enumerate(source_rows(source, split), 1)
    ]
    source_sha, population = DATASETS[split]
    if len(rows) != population or any(type(row[key]) is not str for row in rows for key in ("method", "target")):
        raise ValueError("FPAD observation population changed")
    output.mkdir()
    path = output / "observations.json"
    write(path, rows)
    write(output / "plan.json", {
        "split": split, "source_sha256": source_sha, "observations_sha256": fingerprint(path),
    })


def observations(output):
    path = output / "observations.json"
    plan = read(output / "plan.json")
    source_sha, population = DATASETS[plan["split"]]
    if plan["source_sha256"] != source_sha or plan["observations_sha256"] != fingerprint(path):
        raise ValueError("FPAD observation file changed")
    rows = read(path)
    if len(rows) != population or any(set(row) != FIELDS or row["ordinal"] != index
                                      for index, row in enumerate(rows, 1)):
        raise ValueError("FPAD observation structure changed")
    return rows


def capture(output, executable):
    rows = observations(output)
    binary = executable.resolve()
    if fingerprint(binary) != BINARY_SHA:
        raise ValueError("expected the earlier frozen target-only CRS binary")
    path = output / "predictions.jsonl"
    with (
        path.open("xb") as stream,
        subprocess.Popen([str(binary), "--target-only"], stdin=subprocess.PIPE, stdout=stream) as scanner,
    ):
        with scanner.stdin as pipe:
            for row in rows:
                pipe.write(canonical(row) + b"\n")
        if scanner.wait():
            raise ValueError("local target inspection failed")
    priority_path = output / "priorities.jsonl"
    with path.open("rb") as decisions, priority_path.open("xb") as priorities:
        for observed, decision in zip(rows, map(json.loads, decisions), strict=True):
            if decision["ordinal"] != observed["ordinal"]:
                raise ValueError("scanner changed row order")
            # Rendering for the existing target-specific helper. No response was observed.
            line = f'"{observed["method"]} {observed["target"]} HTTP/0" 000'
            alert = decision["alert"]
            elevated = alert and corroborated(line, decision.get("rule_ids", [])) if alert is not None else None
            priorities.write(canonical({"ordinal": observed["ordinal"], "alert": elevated}) + b"\n")
    write(output / "seal.json", {
        "binary_sha256": BINARY_SHA, "predictions_sha256": fingerprint(path),
        "priorities_sha256": fingerprint(priority_path),
        "plan_sha256": fingerprint(output / "plan.json"), "evaluator_sha256": fingerprint(Path(__file__)),
        "priority_evaluator_sha256": fingerprint(Path(__file__).with_name("evaluate_public_web_crs_priority.py")),
    })


def score(source, output, expected_seal):
    seal_path, prediction_path = output / "seal.json", output / "predictions.jsonl"
    priority_path = output / "priorities.jsonl"
    seal = read(seal_path)
    if (fingerprint(seal_path) != expected_seal or fingerprint(prediction_path) != seal["predictions_sha256"]
            or fingerprint(priority_path) != seal["priorities_sha256"]
            or fingerprint(output / "plan.json") != seal["plan_sha256"] or seal["binary_sha256"] != BINARY_SHA
            or fingerprint(Path(__file__)) != seal["evaluator_sha256"] or fingerprint(Path(__file__).with_name(
                "evaluate_public_web_crs_priority.py")) != seal["priority_evaluator_sha256"]):
        raise ValueError("FPAD prediction seal does not match")
    split = read(output / "plan.json")["split"]
    overall, priority = counts(), counts()
    by_body = {"absent": counts(), "present": counts()}
    labels, misses = Counter(), Counter()
    benign_targets, threat_targets = set(), Counter()
    benign_requests, threat_requests = set(), Counter()
    with prediction_path.open("rb") as stream, priority_path.open("rb") as priorities:
        for observed, row, decision, tier in zip(
            observations(output), source_rows(source, split), map(json.loads, stream),
            map(json.loads, priorities), strict=True
        ):
            if (decision["ordinal"] != observed["ordinal"] or tier["ordinal"] != observed["ordinal"]
                    or type(row["label"]) is not int or row["label"] not in range(5)
                    or (row["method"], row["url"]) != (observed["method"], observed["target"])):
                raise ValueError("FPAD predictions and labels do not align")
            label = row["label"]
            truth, alert = label != 0, decision["alert"]
            labels[label] += 1
            misses[label] += truth and alert is not True
            body = row["body"]
            if not isinstance(body, str):
                raise TypeError("FPAD body schema changed")
            target = (observed["method"], observed["target"])
            request = (*target, hashlib.sha256(body.encode()).digest())
            if truth:
                threat_targets[target] += 1
                threat_requests[request] += 1
            else:
                benign_targets.add(target)
                benign_requests.add(request)
            record(by_body["present" if body else "absent"], truth, alert)
            record(overall, truth, alert)
            record(priority, truth, tier["alert"])
    if (fingerprint(prediction_path) != seal["predictions_sha256"]
            or fingerprint(priority_path) != seal["priorities_sha256"]):
        raise ValueError("FPAD predictions changed during scoring")
    detection, elevated = metrics(overall), metrics(priority)
    if not labels[0]:
        for result in (detection, elevated):
            result.update(precision=None, f1=None, false_positive_rate=None)
    collisions = None
    if labels[0]:
        collisions = {
            "threat_rows_sharing_method_target_with_benign": sum(threat_targets[key] for key in benign_targets),
            "threat_rows_sharing_method_target_body_with_benign": sum(threat_requests[key] for key in benign_requests),
        }
    write(output / "report.json", {
        "split": split, "source_sha256": DATASETS[split][0], "seal_sha256": expected_seal, "capture": seal,
        "crs_target_only": detection, "corroborated_subset": elevated,
        "publisher_labels": dict(labels), "misses_by_positive_label": {key: misses[key] for key in labels if key},
        "distinct_method_targets": len(benign_targets.union(threat_targets)),
        "crs_confusion_by_unused_body_presence": by_body, "input_collisions": collisions,
        "scope": "offline request target only; no application response, identities or actions",
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "capture", "score"):
        action = actions.add_parser(name)
        action.add_argument("output", type=Path)
        if name in ("prepare", "score"):
            action.add_argument("source", type=Path)
        if name == "capture":
            action.add_argument("executable", type=Path)
        if name == "prepare":
            action.add_argument("split", choices=tuple(DATASETS))
        if name == "score":
            action.add_argument("expected_seal")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.source, args.output, args.split)
    elif args.action == "capture":
        capture(args.output, args.executable)
    else:
        score(args.source, args.output, args.expected_seal)


if __name__ == "__main__":
    main()
