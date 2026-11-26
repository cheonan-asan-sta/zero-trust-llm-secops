"""Evaluate frozen successful-POST refinement on publisher-labeled SR-BH requests."""

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import sqlite3
from collections import Counter, defaultdict
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from scripts.evaluate_local_remote_holdout import fingerprint, git, read, write
from scripts.evaluate_public_apache_transfer import THRESHOLD, frozen_model
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import REQUEST, raw_features, raw_time
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.streaming_context import IncrementalHTTPWindow
from scripts.f1_lab.web_post_refinement import SuccessfulPostRefinement
from scripts.f1_lab.web_residual import WebResidualRefinement, build_evidence
from scripts.f1_lab.web_sensitive_read import evidence, refine

SOURCE = "https://doi.org/10.7910/DVN/OGOIXX"
SOURCE_MD5 = "173ec515308bdce5aec19cfd5b792596"
SOURCE_SIZE = 436_437_661
FIELDS = (
    "timestamp", "src_ip", "request_http_method", "request_http_request", "request_http_protocol",
    "request_user_agent", "request_referer", "response_http_status_code", "response_content_length",
    "request_body",
)
METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
YEAR_START, YEAR_END = 1_577_836_800, 1_609_459_200


def file_digests(path):
    with path.open("rb") as stream:
        md5 = hashlib.file_digest(stream, "md5").hexdigest()
        stream.seek(0)
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    if path.stat().st_size != SOURCE_SIZE or md5 != SOURCE_MD5:
        raise ValueError("publisher CSV checksum mismatch")
    return sha


def runner_digest():
    return hashlib.sha256(Path(__file__).read_text(encoding="utf-8").encode()).hexdigest()


def source_rows(path, *, include_truth=False):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader)
        if len(header) != 38 or len(set(header)) != len(header):
            raise ValueError("unexpected SR-BH header")
        labels = header[24:]
        if labels[0] != "000 - Normal" or not all(re.match(r"^\d{2,3} - ", name) for name in labels):
            raise ValueError("unexpected publisher label columns")
        fields = {name: header[:24].index(name) for name in FIELDS}
        for ordinal, row in enumerate(reader, 1):
            if len(row) != len(header):
                yield ordinal, None, None
                continue
            yield ordinal, {name: row[index] for name, index in fields.items()}, row[24:] if include_truth else None


def selected(row):
    return row["request_http_method"] == "POST" and re.fullmatch(
        r"2[0-9]{2}", row["response_http_status_code"]
    ) is not None


def apache_observation(row):
    """Map only publisher observation fields. Missing metadata stays unavailable."""
    method, target = row["request_http_method"], row["request_http_request"]
    protocol, status = row["request_http_protocol"], row["response_http_status_code"]
    stamp = row["timestamp"]
    if (
        method not in METHODS
        or not re.fullmatch(r"HTTP/\d(?:\.\d)?", protocol)
        or not re.fullmatch(r"[1-5][0-9]{2}", status)
        or len(target) > 16_384
        or not target
        or any(char in target for char in '\r\n"\x00')
        or not re.fullmatch(r"\d{2}/[A-Za-z]{3}/2020:\d{2}:\d{2}:\d{2} [+-]\d{4}", stamp)
    ):
        return None, None
    try:
        client = str(ipaddress.ip_address(row["src_ip"]))
    except ValueError:
        client = "-"
    size = row["response_content_length"]
    size = size if size.isascii() and size.isdecimal() and len(size) <= 16 else "-"
    referer = safe_header(row["request_referer"])
    agent = safe_header(row["request_user_agent"])
    line = f'{client} - - [{stamp}] "{method} {target} {protocol}" {status} {size} "{referer}" "{agent}"'
    if len(line.encode()) > MAX_ROW or REQUEST.search(line) is None:
        return None, None
    try:
        return raw_time(line, YEAR_START, YEAR_END, source_timezone="UTC"), line
    except ValueError:
        return None, None


def safe_header(value):
    return value if len(value) <= 4096 and not any(char in value for char in '\r\n"\x00') else "-"


def index_observations(source, db):
    db.execute("CREATE TABLE observation (ordinal INTEGER PRIMARY KEY, moment REAL, line TEXT, included INTEGER)")
    population = Counter()
    with db:
        for ordinal, row, _ in source_rows(source):
            population["physical_csv_records"] += 1
            if row is None:
                population["unclassified_csv_width"] += 1
                continue
            include = selected(row)
            moment, line = apache_observation(row)
            population["selected_post_2xx"] += include
            population["selected_with_recorded_body"] += include and bool(row["request_body"])
            population["unusable_http_context_rows"] += moment is None
            if moment is not None or include:
                db.execute("INSERT INTO observation VALUES (?, ?, ?, ?)", (ordinal, moment, line, include))
        db.execute("CREATE INDEX chronological ON observation (moment, ordinal)")
    return population


def capture(source, output, source_sha):
    start = perf_counter()
    model, pins = frozen_model()
    residual = WebResidualRefinement(model)
    candidate = SuccessfulPostRefinement(model.web_model)
    output.mkdir()
    predictions = output / "predictions.jsonl"
    write(output / "plan.json", {
        "source": SOURCE, "source_sha256": source_sha, "source_md5": SOURCE_MD5,
        "runner_sha256": runner_digest(), "git_revision": git("rev-parse", "HEAD").decode().strip(),
        "candidate": "existing v52 SuccessfulPostRefinement", "threshold": THRESHOLD,
        "model_pins": pins, "scope": "all observed POST with HTTP 2xx, label-independent selection",
        "body_inspected": False,
    })
    with TemporaryDirectory(dir=output) as scratch, closing(sqlite3.connect(Path(scratch) / "observations.sqlite")) as db:
        population = index_observations(source, db)
        window = IncrementalHTTPWindow()
        with predictions.open("xb") as stream:
            query = "SELECT ordinal, moment, line, included FROM observation ORDER BY moment, ordinal"
            for ordinal, moment, line, included in db.execute(query):
                context = window.observe(line, moment) if moment is not None else None
                if included:
                    before, after = (None, None) if context is None else forecast(
                        line, moment, context, ordinal, source_sha, model, residual, candidate
                    )
                    stream.write(canonical({"ordinal": ordinal, "before": before, "after": after}) + b"\n")
    write(output / "seal.json", {
        "plan_sha256": fingerprint(output / "plan.json"), "predictions_sha256": fingerprint(predictions),
        "population": dict(population), "elapsed_seconds": round(perf_counter() - start, 3),
    })


def forecast(line, moment, context, ordinal, source_sha, model, residual, candidate):
    features = {**raw_features(line), **extra_observations(line), **semantic_observations(line), **context}
    case = hashlib.sha256(f"{source_sha}:{ordinal}".encode()).hexdigest()
    base = model.web_model.probability(features)
    hit = base >= THRESHOLD
    decision = OperationDecision(base, base, hit, hit, "unchanged")
    metadata = build_evidence([(ordinal, moment, line)], "access", source_sha)
    decision = residual.refine(decision, features, case, metadata.get(case))
    before = refine(decision, features, case, evidence(line, source_sha, ordinal))
    return before.alert, candidate.refine(before, features).alert


def published_truth(flags):
    if any(flag not in ("0", "1") for flag in flags):
        return None
    normal, attack = flags[0] == "1", "1" in flags[1:]
    return attack if normal != attack else None


def score(source, output, source_sha, expected_seal):
    path, plan_path, seal_path = (output / name for name in ("predictions.jsonl", "plan.json", "seal.json"))
    plan, seal = read(plan_path), read(seal_path)
    if (
        fingerprint(seal_path) != expected_seal or plan["source_sha256"] != source_sha
        or plan["runner_sha256"] != runner_digest() or fingerprint(plan_path) != seal["plan_sha256"]
        or fingerprint(path) != seal["predictions_sha256"]
    ):
        raise ValueError("SR-BH evidence seal mismatch")
    with path.open("rb") as stream:
        saved = {entry["ordinal"]: entry for entry in map(json.loads, stream)}
    if len(saved) != seal["population"]["selected_post_2xx"]:
        raise ValueError("SR-BH sealed population mismatch")
    old, new = counts(), counts()
    day_support = defaultdict(Counter)
    lost_tp = new_fp = ambiguous = 0
    for ordinal, row, flags in source_rows(source, include_truth=True):
        if row is None or not selected(row):
            continue
        prediction = saved.pop(ordinal)
        truth = published_truth(flags)
        day = row["timestamp"][:11] if re.fullmatch(r"\d{2}/[A-Za-z]{3}/2020", row["timestamp"][:11]) else "unknown"
        if truth is None:
            ambiguous += 1
            day_support[day]["ambiguous"] += 1
            continue
        day_support[day]["threat" if truth else "normal"] += 1
        before, after = prediction["before"], prediction["after"]
        record(old, truth, before)
        record(new, truth, after)
        lost_tp += truth and before is True and after is not True
        new_fp += not truth and before is False and after is True
    if saved or fingerprint(path) != seal["predictions_sha256"]:
        raise ValueError("SR-BH prediction alignment changed")
    write(output / "report.json", {
        "source": SOURCE, "source_sha256": source_sha, "seal_sha256": expected_seal,
        "population": seal["population"], "ambiguous_publisher_labels": ambiguous,
        "before": metrics(old), "after": metrics(new), "lost_true_positives": lost_tp,
        "new_false_positives": new_fp, "date_support": dict(day_support),
        "capture_seconds": seal["elapsed_seconds"], "body_features_used": False,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--score-seal")
    args = parser.parse_args()
    csv.field_size_limit(1_048_576)
    digest = file_digests(args.source)
    if args.score_seal:
        score(args.source, args.output, digest, args.score_seal)
    else:
        capture(args.source, args.output, digest)


if __name__ == "__main__":
    main()
