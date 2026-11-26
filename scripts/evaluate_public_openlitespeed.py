"""Replay a fixed OpenLiteSpeed incident-window web corpus offline."""

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from time import perf_counter
from zipfile import ZipFile

import yaml

from scripts.evaluate_local_remote_holdout import fingerprint, git, read, write
from scripts.evaluate_public_apache_transfer import frozen_model, records
from scripts.evaluate_public_successful_post import forecast
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.raw_context import ordered_http_context
from scripts.f1_lab.raw_observations import REQUEST, raw_time
from scripts.f1_lab.web_post_refinement import SuccessfulPostRefinement
from scripts.f1_lab.web_residual import WebResidualRefinement

SOURCE_SHA = "4e0aa82b126ef687a967b1086f449dd4b0aaf78774197bbc4b2082a944878dcf"
SOURCE_URL = "https://zenodo.org/records/20001206"
LABEL_MEMBER = "organization-y/ground-truth/organization-y.yaml"
# Publication describes Apr 29 as incident date. Include adjacent rotations.
WINDOW_MEMBERS = re.compile(
    r"organization-y/log/home/[^/]+/logs/[^/]+\.access_log\.2025_04_(?:28|29|30)(?:\.[0-9]+)?"
)


def runner_sha():
    return hashlib.sha256(Path(__file__).read_text(encoding="utf-8").encode()).hexdigest()


def classify(method, status):
    if method == "POST" and status in range(200, 300):
        return "post_success"
    if method in {"GET", "HEAD"} and status in range(300, 400):
        return "redirect"
    return "other"


def prepare(rows):
    timed, cohorts = [], {}
    for ordinal, line in enumerate(rows, 1):
        match = REQUEST.search(line)
        try:
            moment = raw_time(line, 1735689600, 1767225600, source_timezone="UTC")
        except ValueError:
            moment = None
        if match is not None and "\ufffd" not in line and moment is not None:
            cohorts[ordinal] = classify(match[1], int(match[3]))
            timed.append((ordinal, moment, line))
    return timed, cohorts


def forecast_member(task):
    source, output, member, index = task
    with ZipFile(source) as archive:
        rows, source_sha = records(archive, member)
    timed, cohorts = prepare(rows)
    windows = ordered_http_context(timed)
    model, _ = frozen_model()
    residual = WebResidualRefinement(model)
    post = SuccessfulPostRefinement(model.web_model)
    path = output / f"predictions-{index:02d}.jsonl"
    processed = {ordinal: (moment, line) for ordinal, moment, line in timed}
    with path.open("xb") as stream:
        for ordinal in range(1, len(rows) + 1):
            if ordinal not in processed:
                old, new = None, None
            else:
                moment, line = processed[ordinal]
                old, new = forecast(
                    line, moment, windows[ordinal], ordinal, source_sha, model, residual, post
                )
            stream.write(
                canonical(
                    {
                        "ordinal": ordinal,
                        "before": old,
                        "after": new,
                        "cohort": cohorts.get(ordinal, "unparsed"),
                    }
                )
                + b"\n"
            )
    return {
        "name": member,
        "row_count": len(rows),
        "row_source_sha256": source_sha,
        "prediction_name": path.name,
        "prediction_sha256": fingerprint(path),
    }


def capture(source, output):
    start = perf_counter()
    _, pins = frozen_model()
    output.mkdir()
    with ZipFile(source) as archive:
        members = sorted(name for name in archive.namelist() if WINDOW_MEMBERS.fullmatch(name))
    if len(members) != 32 or len(members) != len(set(members)):
        raise ValueError("unexpected OpenLiteSpeed population")
    write(
        output / "plan.json",
        {
            "source": SOURCE_URL,
            "source_sha256": SOURCE_SHA,
            "runner_sha256": runner_sha(),
            "git_revision": git("rev-parse", "HEAD").decode().strip(),
            "model_pins": pins,
            "members": members,
            "purpose": "public incident window plus adjacent rotations",
            "request_body_available": False,
        },
    )
    with ProcessPoolExecutor(max_workers=3) as pool:
        arguments = ((source, output, member, index) for index, member in enumerate(members))
        receipts = list(pool.map(forecast_member, arguments))
    write(
        output / "seal.json",
        {
            "plan_sha256": fingerprint(output / "plan.json"),
            "members": receipts,
            "wall_seconds": round(perf_counter() - start, 3),
        },
    )


def score(source, output, expected):
    plan_path, seal_path = output / "plan.json", output / "seal.json"
    plan, seal = read(plan_path), read(seal_path)
    if (
        fingerprint(seal_path) != expected
        or fingerprint(plan_path) != seal["plan_sha256"]
        or plan["runner_sha256"] != runner_sha()
        or plan["source_sha256"] != SOURCE_SHA
        or [row["name"] for row in seal["members"]] != plan["members"]
    ):
        raise ValueError("OpenLiteSpeed evaluation plan is unsealed")
    for member in seal["members"]:
        if fingerprint(output / member["prediction_name"]) != member["prediction_sha256"]:
            raise ValueError("OpenLiteSpeed prediction checksum changed")
    overall = {"before": counts(), "after": counts()}
    cohorts = defaultdict(lambda: {"before": counts(), "after": counts()})
    rule_counts = Counter()
    losses = Counter()
    with ZipFile(source) as archive:
        label_data = archive.read(LABEL_MEMBER)
        rules = [(r["id"], r["filter"]) for r in yaml.safe_load(label_data)]
        if not rules or not all(
            terms and all(isinstance(term, str) and term for term in terms) for _, terms in rules
        ):
            raise ValueError("publisher labels do not have the expected literal rules")
        for member in seal["members"]:
            path = output / member["prediction_name"]
            rows, source_sha = records(archive, member["name"])
            if len(rows) != member["row_count"] or source_sha != member["row_source_sha256"]:
                raise ValueError("OpenLiteSpeed source rows changed")
            with path.open("rb") as predictions:
                for ordinal, (line, prediction) in enumerate(
                    zip(rows, map(json.loads, predictions), strict=True), 1
                ):
                    if prediction["ordinal"] != ordinal:
                        raise ValueError("OpenLiteSpeed predictions reordered")
                    labels = {rule for rule, terms in rules if all(term in line for term in terms)}
                    rule_counts.update(labels)
                    truth = bool(labels)
                    group = cohorts[prediction["cohort"]]
                    for name, tally in overall.items():
                        record(tally, truth, prediction[name])
                        record(group[name], truth, prediction[name])
                    losses["new_false_positives"] += (
                        not truth
                        and prediction["before"] is False
                        and (prediction["after"] is True)
                    )
                    losses["lost_true_positives"] += (
                        truth and prediction["before"] is True and (prediction["after"] is not True)
                    )
            if fingerprint(path) != member["prediction_sha256"]:
                raise ValueError("OpenLiteSpeed predictions changed during scoring")
    write(
        output / "report.json",
        {
            "source": SOURCE_URL,
            "source_sha256": SOURCE_SHA,
            "seal_sha256": expected,
            "wall_seconds": seal["wall_seconds"],
            "publisher_label_sha256": hashlib.sha256(label_data).hexdigest(),
            "publisher_rule_counts": dict(rule_counts),
            "transitions": dict(losses),
            "overall": {key: metrics(value) for key, value in overall.items()},
            "by_cohort": {
                key: {mode: metrics(value) for mode, value in report.items()}
                for key, report in cohorts.items()
            },
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--score-seal")
    args = parser.parse_args()
    if fingerprint(args.source) != SOURCE_SHA:
        raise ValueError("OpenLiteSpeed source checksum mismatch")
    if args.score_seal:
        score(args.source, args.output, args.score_seal)
    else:
        capture(args.source, args.output)


if __name__ == "__main__":
    main()
