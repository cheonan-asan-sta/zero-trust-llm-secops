"""Evaluate the frozen SR-BH POST candidate on the public crAPI/VAmPI lab capture."""

import argparse
import csv
import io
import json
import math
import subprocess
import tarfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_apache_transfer import frozen_model
from scripts.evaluate_public_post_body_shape import request_shape
from scripts.evaluate_public_post_crs import HEADER_MAP, safe_address
from scripts.evaluate_public_post_crs_rules import candidate_scores, fit_and_check
from scripts.evaluate_public_successful_post import METHODS, forecast, safe_header
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.raw_observations import REQUEST
from scripts.f1_lab.streaming_context import IncrementalHTTPWindow
from scripts.f1_lab.web_post_refinement import SuccessfulPostRefinement
from scripts.f1_lab.web_residual import WebResidualRefinement

ARCHIVE_SHA = "9126e43da413bee16cb543a8d0b9187819d312303f83c83e57d8bda3b1ecfd86"
MEMBER = "data/corpus/labelled/testbed.parquet"
OBSERVATIONS = (
    "http_method",
    "url_path_raw",
    "url_query",
    "http_version",
    "headers",
    "response_status",
    "request_body",
    "response_size",
    "src_ip",
    "timestamp",
    "app",
)
HEADER_NAMES = {name.casefold(): name for name in HEADER_MAP.values()}


def source(archive):
    from pyarrow import parquet

    if fingerprint(archive) != ARCHIVE_SHA:
        raise ValueError("publisher testbed checksum mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) != 1 or members[0].name != MEMBER or not members[0].isfile():
            raise ValueError("unexpected testbed archive member")
        with bundle.extractfile(members[0]) as stream:
            return parquet.ParquetFile(io.BytesIO(stream.read()))


def is_successful_post(row):
    status = row["response_status"]
    return row["http_method"] == "POST" and type(status) is int and 200 <= status < 300


def access_line(event, stamp, status, size):
    method, target, protocol = (event[key] for key in ("method", "target", "protocol"))
    if (
        method not in METHODS
        or not target
        or len(target) > 16_384
        or any(char in target for char in '\r\n"\x00')
        or protocol != "HTTP/1.1"
        or type(status) is not int
        or not 100 <= status < 600
    ):
        return None
    agent = safe_header(event["headers"].get("User-Agent", ""))
    referer = safe_header(event["headers"].get("Referer", ""))
    client = event["client"] or "-"
    size = size if type(size) is int and 0 <= size < 10**16 else "-"
    date = stamp.strftime("%d/%b/%Y:%H:%M:%S %z")
    line = f'{client} - - [{date}] "{method} {target} {protocol}" {status} {size} "{referer}" "{agent}"'
    return line if len(line.encode()) <= MAX_ROW and REQUEST.search(line) else None


def decode_observation(row):
    stamp = datetime.fromisoformat(row["timestamp"])
    if stamp.tzinfo is None or stamp.astimezone(UTC).year != 2026:
        raise ValueError("unexpected testbed timestamp")
    stamp = stamp.astimezone(UTC)
    headers = {
        HEADER_NAMES[key.casefold()]: value
        for key, value in json.loads(row["headers"]).items()
        if key.casefold() in HEADER_NAMES
    }
    path, query, body = row["url_path_raw"], row["url_query"], row["request_body"] or ""
    target = path + "?" + query if query else path
    if query and "?" in path:
        raise ValueError("request target contains query twice")
    if body:
        headers["Content-Length"] = str(len(body.encode()))
    event = {
        "method": row["http_method"],
        "target": target,
        "protocol": row["http_version"],
        "client": safe_address(row["src_ip"]),
        "headers": headers,
        "body": body,
    }
    line = access_line(event, stamp, row["response_status"], row["response_size"])
    return stamp.timestamp(), line, event


def capture(archive, output, exe, candidate, diagnostic_seal):
    model, vocab, threshold = candidate
    rows = source(archive).read(columns=OBSERVATIONS).to_pylist()
    observed = [(number, row, *decode_observation(row)) for number, row in enumerate(rows, 1)]
    windows = defaultdict(IncrementalHTTPWindow)
    native_model, pins = frozen_model()
    residual = WebResidualRefinement(native_model)
    post = SuccessfulPostRefinement(native_model.web_model)
    native, input_lines, feature_rows = {}, [], []
    for number, row, moment, line, event in sorted(
        observed, key=lambda entry: (entry[2], entry[0])
    ):
        window = windows[row["app"]]
        context = window.observe(line, moment) if line is not None else None
        if not is_successful_post(row):
            continue
        if context is None:
            raise ValueError("selected request lacks native observations")
        native[number], _ = forecast(
            line, moment, context, number, ARCHIVE_SHA, native_model, residual, post
        )
        input_lines.append(canonical({"ordinal": number, **event}))
        feature_rows.append(
            (number, "", request_shape(event["target"], event["body"], row["response_status"]))
        )

    outcome = subprocess.run(
        [str(exe.resolve()), "--rule-ids"],
        input=b"\n".join(input_lines) + b"\n",
        capture_output=True,
        check=True,
    )
    result = [json.loads(line) for line in outcome.stdout.splitlines()]
    if [row["ordinal"] for row in result] != list(native) or any(
        type(row["alert"]) is not bool for row in result
    ):
        raise ValueError("incomplete or invalid CRS decisions on selected requests")
    crs = {row["ordinal"]: row["alert"] for row in result}
    rules = {row["ordinal"]: frozenset(row.get("rule_ids", [])) for row in result}
    probabilities = candidate_scores(model, feature_rows, rules, vocab, crs)
    plan_file, predictions = output / "plan.json", output / "predictions.json"
    write(
        plan_file,
        {
            "archive_sha256": ARCHIVE_SHA,
            "selection": "all recorded POST with HTTP 2xx",
            "diagnostic_seal": diagnostic_seal,
            "binary_sha256": fingerprint(exe),
            "native_model_pins": pins,
            "candidate_threshold": threshold,
            "full_population": len(rows),
            "selected_rows": len(native),
            "selected_rows_with_body": sum(
                bool(event["body"]) for _, row, _, _, event in observed if is_successful_post(row)
            ),
            "skipped_history_rows": sum(line is None for _, _, _, line, _ in observed),
            "http_egress": False,
        },
    )
    write(
        predictions,
        [
            {
                "ordinal": ordinal,
                "native": native[ordinal],
                "crs": crs[ordinal],
                "candidate": score >= threshold,
            }
            for ordinal, score in zip(native, probabilities, strict=True)
        ],
    )
    write(
        output / "seal.json",
        {
            "plan_sha256": fingerprint(plan_file),
            "predictions_sha256": fingerprint(predictions),
        },
    )


def score(archive, output, expected_sha):
    plan_file, pred_file, seal_file = (
        output / name for name in ("plan.json", "predictions.json", "seal.json")
    )
    seal = read(seal_file)
    if (
        fingerprint(seal_file) != expected_sha
        or fingerprint(plan_file) != seal["plan_sha256"]
        or fingerprint(pred_file) != seal["predictions_sha256"]
        or read(plan_file)["archive_sha256"] != ARCHIVE_SHA
    ):
        raise ValueError("external testbed seal mismatch")
    saved = read(pred_file)
    predictions = {row["ordinal"]: row for row in saved}
    if len(saved) != len(predictions) or len(saved) != read(plan_file)["selected_rows"]:
        raise ValueError("external testbed prediction population changed")
    totals = defaultdict(counts)
    transitions = defaultdict(Counter)
    attack_families = defaultdict(Counter)
    labels = (
        source(archive)
        .read(columns=["http_method", "response_status", "app", "label", "attack_family"])
        .to_pylist()
    )
    for ordinal, row in enumerate(labels, 1):
        if not is_successful_post(row):
            continue
        decision = predictions.pop(ordinal)
        if row["label"] not in {"benign", "attack"}:
            raise ValueError("unknown publisher campaign label")
        expected = row["label"] == "attack"
        baseline = decision["native"] or decision["crs"]
        modes = {name: decision[name] for name in ("native", "crs", "candidate")}
        modes["native_or_crs"] = baseline
        if expected:
            family = attack_families[row["attack_family"] or "unrecorded"]
            family["population"] += 1
            family["native_or_crs_hits"] += baseline
            family["candidate_hits"] += decision["candidate"]
            family["lost_true_positives"] += baseline and not decision["candidate"]
            family["recovered_true_positives"] += not baseline and decision["candidate"]
        for cohort in ("all", row["app"]):
            for mode, prediction in modes.items():
                key = (cohort, mode)
                record(totals[key], expected, prediction)
                transitions[key]["new_false_positives"] += (
                    not expected and not baseline and prediction
                )
                transitions[key]["lost_true_positives"] += expected and baseline and not prediction
    if predictions:
        raise ValueError("unused sealed external predictions")
    grouped = defaultdict(dict)
    for (cohort, mode), result in totals.items():
        grouped[cohort][mode] = {**metrics(result), **transitions[cohort, mode]}
    candidate = grouped["all"]["candidate"]
    numerical_gate = (
        all(
            candidate[name] is not None and candidate[name] >= 0.95
            for name in ("precision", "recall", "f1")
        )
        and candidate["false_positive_rate"] is not None
        and candidate["false_positive_rate"] <= 0.05
    )
    retention_gate = candidate["new_false_positives"] == candidate["lost_true_positives"] == 0
    write(
        output / "report.json",
        {
            "seal_sha256": expected_sha,
            "groups": grouped,
            "attack_families": attack_families,
            "numerical_gate_passed": numerical_gate,
            "retention_gate_passed": retention_gate,
            "candidate_adopted": False,
            "labels": "publisher campaign labels based on source and time, not a per-request verdict",
        },
    )


def verify_reproduced_candidate(original, reproduced, expected_sha):
    reference_seal = read(original / "seal.json")
    old_plan, old_preds = original / "plan.json", original / "predictions.json"
    new_plan, new_preds = reproduced / "plan.json", reproduced / "predictions.json"
    if (
        fingerprint(original / "seal.json") != expected_sha
        or fingerprint(old_plan) != reference_seal["plan_sha256"]
        or fingerprint(old_preds) != reference_seal["predictions_sha256"]
        or fingerprint(new_plan) != reference_seal["plan_sha256"]
    ):
        raise ValueError("frozen diagnostic plan or reference seal differs")
    threshold = read(old_plan)["threshold"]
    # Parallel tree aggregation may differ in the last floating-point place.
    for old, new in zip(read(old_preds), read(new_preds), strict=True):
        if (
            old["ordinal"] != new["ordinal"]
            or not math.isclose(old["score"], new["score"], rel_tol=0, abs_tol=1e-12)
            or (old["score"] >= threshold) != (new["score"] >= threshold)
        ):
            raise ValueError("frozen diagnostic predictions did not reproduce")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    capture_cmd = sub.add_parser("capture")
    score_cmd = sub.add_parser("score")
    for cmd in (capture_cmd, score_cmd):
        cmd.add_argument("archive", type=Path)
        cmd.add_argument("output", type=Path)
    for name in ("sr_bh", "native", "original_crs", "crs_with_rules", "exe", "diagnostic"):
        capture_cmd.add_argument(name, type=Path)
    capture_cmd.add_argument("expected_diagnostic_sha")
    score_cmd.add_argument("expected_seal_sha")
    args = parser.parse_args()
    if args.mode == "score":
        score(args.archive, args.output, args.expected_seal_sha)
        return
    original = args.diagnostic / "seal.json"
    if fingerprint(original) != args.expected_diagnostic_sha:
        raise ValueError("expected frozen diagnostic seal")
    if fingerprint(args.exe) != read(args.crs_with_rules / "seal.json")["binary_sha256"]:
        raise ValueError("transfer CRS binary differs from the diagnostic binary")
    csv.field_size_limit(1_048_576)
    args.output.mkdir()
    candidate = fit_and_check(
        args.sr_bh,
        args.native,
        args.original_crs,
        args.crs_with_rules,
        args.output / "reproduced-diagnostic",
    )
    verify_reproduced_candidate(
        args.diagnostic, args.output / "reproduced-diagnostic", args.expected_diagnostic_sha
    )
    capture(args.archive, args.output, args.exe, candidate, args.expected_diagnostic_sha)


if __name__ == "__main__":
    main()
