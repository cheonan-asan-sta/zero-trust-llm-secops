"""Passively compare OWASP CRS with a sealed POST cohort. Never sends requests."""

import argparse
import csv
import ipaddress
import json
import subprocess
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_successful_post import (
    file_digests,
    published_truth,
    selected,
    source_rows,
)
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical

HEADER_MAP = {
    "request_user_agent": "User-Agent",
    "request_referer": "Referer",
    "request_host": "Host",
    "request_origin": "Origin",
    "request_cookie": "Cookie",
    "request_content_type": "Content-Type",
    "request_accept": "Accept",
    "request_accept_language": "Accept-Language",
    "request_accept_encoding": "Accept-Encoding",
    "request_do_not_track": "DNT",
    "request_connection": "Connection",
}


def safe_address(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def request_events(source):
    with source.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        fields = next(reader)
        for ordinal, cells in enumerate(reader, 1):
            if len(cells) != len(fields):
                continue
            row = dict(zip(fields[:24], cells[:24], strict=True))
            if not selected(row):
                continue
            header = {name: row[column] for column, name in HEADER_MAP.items() if row[column]}
            body = row["request_body"]
            if body:
                header["Content-Length"] = str(len(body.encode()))
            yield (
                ordinal,
                {
                    "ordinal": ordinal,
                    "target": row["request_http_request"],
                    "method": row["request_http_method"],
                    "protocol": row["request_http_protocol"],
                    "client": safe_address(row["src_ip"]),
                    "server": safe_address(row["dst_ip"]),
                    "headers": header,
                    "body": body,
                },
            )


def baseline(location):
    pred_path = location / "predictions.jsonl"
    seal_path = location / "seal.json"
    seal = read(seal_path)
    if fingerprint(pred_path) != seal["predictions_sha256"] or (
        fingerprint(location / "plan.json") != seal["plan_sha256"]
    ):
        raise ValueError("POST baseline evidence changed")
    with pred_path.open("rb") as stream:
        values = {row["ordinal"]: row for row in map(json.loads, stream)}
    if len(values) != seal["population"]["selected_post_2xx"]:
        raise ValueError("POST baseline population mismatch")
    return values, fingerprint(seal_path)


def capture(source, original, output, exe, *, rule_ids=False):
    sha = file_digests(source)
    expected, baseline_sha = baseline(original)
    if read(original / "plan.json")["source_sha256"] != sha:
        raise ValueError("source differs from baseline")
    output.mkdir()
    pred = output / "crs-predictions.jsonl"
    command = [str(exe.resolve())]
    if rule_ids:
        command.append("--rule-ids")
    with (
        pred.open("xb") as stream,
        subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stream) as proc,
    ):
        for ordinal, event in request_events(source):
            expected.pop(ordinal)
            proc.stdin.write(canonical(event) + b"\n")
        proc.stdin.close()
        if proc.wait() != 0 or expected:
            raise ValueError("CRS prediction capture did not complete")
    write(
        output / "seal.json",
        {
            "reference_sha256": baseline_sha,
            "source_sha256": sha,
            "crs_version": "4.25.0",
            "coraza_version": "3.8.1",
            "binary_sha256": fingerprint(exe),
            "predictions_sha256": fingerprint(pred),
            "attack_rule_ids": rule_ids,
            "http_egress": False,
            "representation": "publisher request columns; reconstructed Content-Length from stored body",
        },
    )


def score(source, original, output, expected_seal):
    before, baseline_sha = baseline(original)
    path = output / "crs-predictions.jsonl"
    seal_path = output / "seal.json"
    seal = read(seal_path)
    if (
        fingerprint(seal_path) != expected_seal
        or baseline_sha != seal["reference_sha256"]
        or file_digests(source) != seal["source_sha256"]
        or fingerprint(path) != seal["predictions_sha256"]
    ):
        raise ValueError("CRS prediction seal mismatch")
    with path.open("rb") as stream:
        predicted = {row["ordinal"]: row["alert"] for row in map(json.loads, stream)}
    if len(predicted) != len(before):
        raise ValueError("CRS population mismatch")
    modes = {
        name: counts()
        for name in ("native", "crs", "crs_or_post", "native_filtered_by_crs", "native_or_crs")
    }
    transitions = {name: {"new_false_positives": 0, "lost_true_positives": 0} for name in modes}
    unknown = 0
    for ordinal, row, flags in source_rows(source, include_truth=True):
        if row is None or not selected(row):
            continue
        native = before.pop(ordinal)
        crs = predicted.pop(ordinal)
        if crs is None:
            unknown += 1
        truth = published_truth(flags)
        if truth is None:
            continue
        values = {
            "native": native["before"],
            "crs": crs,
            "crs_or_post": native["after"] or crs if crs is not None else native["before"],
            "native_filtered_by_crs": native["before"] and crs
            if crs is not None
            else native["before"],
            "native_or_crs": native["before"] or crs if crs is not None else native["before"],
        }
        for name, prediction in values.items():
            record(modes[name], truth, prediction)
            transitions[name]["new_false_positives"] += (
                not truth and native["before"] is False and prediction is True
            )
            transitions[name]["lost_true_positives"] += (
                truth and native["before"] is True and prediction is not True
            )
    if predicted or before or fingerprint(path) != seal["predictions_sha256"]:
        raise ValueError("CRS rows changed or were unused")
    write(
        output / "report.json",
        {
            "seal_sha256": expected_seal,
            "source_sha256": seal["source_sha256"],
            "crs_unknown": unknown,
            "modes": {
                name: {**metrics(value), **transitions[name]} for name, value in modes.items()
            },
            "candidate_adopted": False,
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument("output", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--exe", type=Path)
    mode.add_argument("--score-seal")
    parser.add_argument("--rule-ids", action="store_true")
    args = parser.parse_args()
    csv.field_size_limit(1_048_576)
    if args.exe:
        capture(args.source, args.original, args.output, args.exe, rule_ids=args.rule_ids)
    else:
        if args.rule_ids:
            parser.error("--rule-ids requires --exe")
        score(args.source, args.original, args.output, args.score_seal)


if __name__ == "__main__":
    main()
