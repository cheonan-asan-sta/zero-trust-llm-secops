"""Compare the same passive CRS rules with and without observed POST bodies."""

import argparse
import csv
import json
import subprocess
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_api_post_transfer import ARCHIVE_SHA, is_successful_post
from scripts.evaluate_public_api_post_transfer import source as open_testbed
from scripts.evaluate_public_post_crs import baseline, request_events
from scripts.evaluate_public_successful_post import (
    file_digests,
    published_truth,
    selected,
    source_rows,
)
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical

MODES = {"target": "--target-only", "target_body": "--target-and-body"}
TESTBED_COLUMNS = ("url_path_raw", "url_query", "http_version", "headers", "request_body")


def testbed_events(source):
    columns = ["response_status", "http_method", *TESTBED_COLUMNS]
    for ordinal, row in enumerate(open_testbed(source).read(columns=columns).to_pylist(), 1):
        if not is_successful_post(row):
            continue
        header_pairs = json.loads(row["headers"], object_pairs_hook=list)
        headers = {}
        for key in ("Content-Type", "Content-Encoding"):
            observed = [value for name, value in header_pairs if name.casefold() == key.casefold()]
            if len(observed) > 1 or (observed and not isinstance(observed[0], str)):
                headers.clear()
                break
            if observed:
                headers[key] = observed[0]
        path, query = row["url_path_raw"], row["url_query"]
        if query and "?" in path:
            raise ValueError("ambiguous request target projection")
        yield ordinal, {
            "ordinal": ordinal, "method": row["http_method"], "target": f"{path}?{query}" if query else path,
            "protocol": row["http_version"], "headers": headers, "body": row["request_body"] or "",
        }


def testbed_labels(source):
    columns = ["response_status", "http_method", "label"]
    for ordinal, row in enumerate(open_testbed(source).read(columns=columns).to_pylist(), 1):
        if is_successful_post(row):
            if row["label"] not in {"benign", "attack"}:
                raise ValueError("unknown testbed campaign label")
            yield ordinal, row["label"] == "attack"


def sr_bh_labels(source):
    for ordinal, row, flags in source_rows(source, include_truth=True):
        if row is not None and selected(row):
            yield ordinal, published_truth(flags)


def project(event, include_body):
    observation = {key: event[key] for key in ("ordinal", "method", "target", "protocol")}
    if include_body and event["headers"].get("Content-Type"):
        headers = {key: event["headers"][key] for key in ("Content-Type", "Content-Encoding") if key in event["headers"]}
        observation.update(headers=headers, body=event["body"])
    return observation


def capture(source, reference, output, executable):
    if reference is None:
        corpus, reference_sha, events = "testbed", None, testbed_events
        source_sha = fingerprint(source)
        if source_sha != ARCHIVE_SHA:
            raise ValueError("testbed source changed")
        original = {ordinal for ordinal, _ in events(source)}
        if len(original) != 5_216:
            raise ValueError("testbed POST population changed")
    else:
        corpus, events = "sr-bh", request_events
        source_sha = file_digests(source)
        original, reference_sha = baseline(reference)
        if source_sha != read(reference / "plan.json")["source_sha256"]:
            raise ValueError("public POST reference source changed")
    output.mkdir()
    binary = executable.resolve()
    binary_sha = fingerprint(binary)
    paths = {}
    for name, flag in MODES.items():
        path = paths[name] = output / f"{name}.jsonl"
        with path.open("xb") as stream, subprocess.Popen(
            [str(binary), flag], stdin=subprocess.PIPE, stdout=stream
        ) as engine:
            with engine.stdin as pipe:
                remaining = set(original)
                for ordinal, row in events(source):
                    remaining.remove(ordinal)
                    pipe.write(canonical(project(row, include_body=name == "target_body")) + b"\n")
            if engine.wait() or remaining:
                raise ValueError("passive inspection did not complete")
    if fingerprint(binary) != binary_sha:
        raise ValueError("CRS executable changed")
    write(output / "seal.json", {
        "corpus": corpus, "source_sha256": source_sha, "reference_seal_sha256": reference_sha,
        "binary_sha256": binary_sha,
        "evaluator_sha256": fingerprint(Path(__file__)), "rows": len(original),
        "predictions_sha256": {name: fingerprint(path) for name, path in paths.items()},
    })


def score(source, output, expected_seal):
    seal_path = output / "seal.json"
    seal = read(seal_path)
    paths = {name: output / f"{name}.jsonl" for name in MODES}
    corpus = seal["corpus"]
    if corpus not in {"sr-bh", "testbed"}:
        raise ValueError("unknown successful POST corpus")
    source_sha = file_digests(source) if corpus == "sr-bh" else fingerprint(source)
    if (fingerprint(seal_path) != expected_seal or source_sha != seal["source_sha256"]
            or fingerprint(Path(__file__)) != seal["evaluator_sha256"]
            or any(fingerprint(path) != seal["predictions_sha256"][name] for name, path in paths.items())):
        raise ValueError("public POST body-scope seal changed")

    reports = {name: counts() for name in (*MODES, "preserve_target")}
    body_rows = body_normal = body_threat = unknown_labels = 0
    extra_threats = extra_normal = direct_losses = 0
    rows = sr_bh_labels(source) if corpus == "sr-bh" else testbed_labels(source)
    total = 0
    with paths["target"].open("rb") as earlier, paths["target_body"].open("rb") as later:
        for total, ((ordinal, truth), before, after) in enumerate(
            zip(rows, map(json.loads, earlier), map(json.loads, later), strict=True), 1
        ):
            if before["ordinal"] != ordinal or after["ordinal"] != ordinal:
                raise ValueError("public POST row order changed")
            included = after.get("body_included", False)
            old, direct = before["alert"], after["alert"]
            if not included and old != direct:
                raise ValueError("request decision changed without a body input")
            body_rows += included
            if truth is None:
                unknown_labels += 1
                continue
            body_normal += included and not truth
            body_threat += included and truth
            record(reports["target"], truth, old)
            record(reports["target_body"], truth, direct)
            record(reports["preserve_target"], truth, True if old is True else direct)
            extra_threats += truth and old is False and direct is True
            extra_normal += not truth and old is False and direct is True
            direct_losses += truth and old is True and direct is not True
    if total != seal["rows"] or any(
        fingerprint(path) != seal["predictions_sha256"][name] for name, path in paths.items()
    ):
        raise ValueError("public POST body-scope population changed")
    write(output / "report.json", {
        "seal_sha256": expected_seal, "capture": seal, "body_included": body_rows,
        "body_included_normal": body_normal, "body_included_threat": body_threat,
        "unknown_labels": unknown_labels, "additional_threats": extra_threats, "new_false_positives": extra_normal,
        "direct_lost_true_positives": direct_losses, "modes": {name: metrics(values) for name, values in reports.items()},
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for mode in ("capture", "score"):
        command = actions.add_parser(mode)
        command.add_argument("source", type=Path)
        command.add_argument("output", type=Path)
        if mode == "capture":
            command.add_argument("executable", type=Path)
            command.add_argument("--sr-bh-reference", type=Path, help="existing SR-BH POST seal directory")
        else:
            command.add_argument("expected_seal")
    args = parser.parse_args()
    csv.field_size_limit(1_048_576)
    if args.action == "capture":
        capture(args.source, args.sr_bh_reference, args.output, args.executable)
    else:
        score(args.source, args.output, args.expected_seal)


if __name__ == "__main__":
    main()
