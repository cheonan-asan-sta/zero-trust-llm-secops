"""Inspect a pinned sample of open-appsec legitimate requests, locally only."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_post_body_scope import MODES, project
from scripts.f1_lab.native_bayes import counts, record
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical

RECEIPT_SHA = "31a9256782117d36f0f7d31ba2b704a37e9fffa7fa93e680df9d1f666d637bc7"
HOLDOUT_SHA = "f4b349317bc39b6371c62242e68ce644d22415e319938f053dc89069e7721120"
BINARY_SHA = "d49a45c26270a5df2a35dbf1544de02ba46610d65c6e55b218579ce44adffebf"
ROWS = 12_887
HOLDOUT_ROWS = 15_250
BODY_HEADERS = {"content-type": "Content-Type", "content-encoding": "Content-Encoding"}


def observation(row, ordinal):
    method, target, body, raw_headers = (row[key] for key in ("method", "url", "data", "headers"))
    if any(not isinstance(item, str) for item in (method, target, body)) or not isinstance(raw_headers, dict):
        raise ValueError("legitimate request schema changed")
    if not target.startswith("/"):
        raise ValueError("expected a stored origin-form request target")
    headers = {}
    for original, value in raw_headers.items():
        key = BODY_HEADERS.get(original.casefold())
        if key is None:
            continue
        if key in headers or not isinstance(value, str):
            # Ambiguous or unavailable media metadata must not select a parser.
            headers.clear()
            break
        headers[key] = value
    return {"ordinal": ordinal, "method": method, "target": target, "protocol": "", "body": body, "headers": headers}


def request_rows(source, *, receipt_sha, expected_rows):
    receipt_path = source / "download-receipt.json"
    plan_path = source / "plan.json"
    if fingerprint(receipt_path) != receipt_sha:
        raise ValueError("legitimate sample receipt mismatch")
    receipt, plan = read(receipt_path), read(plan_path)
    if fingerprint(plan_path) != receipt["plan_sha256"]:
        raise ValueError("legitimate sample plan mismatch")
    ordinal = 0
    for index, (member, pin) in enumerate(zip(plan["members"], receipt["members"], strict=True), 1):
        path = source / f"member-{index:02}.json"
        if path.stat().st_size != member["bytes"] or path.stat().st_size > 24 * 1024**2:
            raise ValueError("legitimate sample member bound")
        body = path.read_bytes()
        if member["ordinal"] != index or pin["ordinal"] != index or hashlib.sha256(body).hexdigest() != pin["sha256"]:
            raise ValueError("legitimate sample member mismatch")
        for row in decode(body):
            ordinal += 1
            yield row
    if ordinal != expected_rows:
        raise ValueError("legitimate sample row count changed")


def request_events(source, *, receipt_sha=RECEIPT_SHA, expected_rows=ROWS):
    for ordinal, row in enumerate(request_rows(source, receipt_sha=receipt_sha, expected_rows=expected_rows), 1):
        yield observation(row, ordinal)


def evaluate(source, output, executable, *, holdout=False):
    binary = executable.resolve()
    if fingerprint(binary) != BINARY_SHA:
        raise ValueError("legitimate replay requires the frozen CRS binary")
    output.mkdir()
    receipt_sha, row_count = (HOLDOUT_SHA, HOLDOUT_ROWS) if holdout else (RECEIPT_SHA, ROWS)
    paths = {mode: output / f"{mode}.jsonl" for mode in MODES}
    for mode, flag in MODES.items():
        with paths[mode].open("xb") as sink, subprocess.Popen(
            [str(binary), flag], stdin=subprocess.PIPE, stdout=sink
        ) as engine:
            with engine.stdin as pipe:
                for event in request_events(source, receipt_sha=receipt_sha, expected_rows=row_count):
                    pipe.write(canonical(project(event, include_body=mode == "target_body")) + b"\n")
            if engine.wait():
                raise ValueError("legitimate passive inspection failed")
    predictions = {mode: fingerprint(path) for mode, path in paths.items()}
    seal = output / "seal.json"
    write(seal, {"source_receipt_sha256": receipt_sha, "binary_sha256": BINARY_SHA,
                 "predictions_sha256": predictions, "evaluator_sha256": fingerprint(Path(__file__))})

    before, after = counts(), counts()
    count = included = additional = lost = errors_added = 0
    with paths["target"].open("rb") as earlier, paths["target_body"].open("rb") as later:
        for count, (first, second) in enumerate(zip(map(json.loads, earlier), map(json.loads, later), strict=True), 1):
            if first["ordinal"] != count or second["ordinal"] != count:
                raise ValueError("legitimate prediction row order changed")
            old, new = first["alert"], second["alert"]
            has_body = second.get("body_included", False)
            if old != new and not has_body:
                raise ValueError("no body observation explains the prediction change")
            included += has_body
            additional += new is True and old is False
            lost += old is True and new is not True
            errors_added += new is None and old is not None
            record(before, False, old)
            record(after, False, True if old is True else new)
    if count != row_count or any(fingerprint(path) != predictions[mode] for mode, path in paths.items()):
        raise ValueError("legitimate prediction population changed")
    for result in (before, after):
        result["false_positive_rate"] = result["fp"] / count
    write(output / "report.json", {
        "seal_sha256": fingerprint(seal), "population": count, "body_included": included,
        "new_positive_alarms": additional, "new_inference_errors": errors_added,
        "direct_prior_alarm_losses": lost, "crs_target": before, "crs_target_or_body": after,
        "scope": "publisher legitimate traffic only; no recall, precision, F1 or runtime policy claim",
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "executable"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--holdout", action="store_true", help="check the additional site-separated sample")
    args = parser.parse_args()
    evaluate(args.source, args.output, args.executable, holdout=args.holdout)


if __name__ == "__main__":
    main()
