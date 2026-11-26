"""Score the frozen HTTP detector against publisher-labeled synthetic access records."""

import argparse
import ipaddress
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, git, read, write
from scripts.evaluate_public_apache_transfer import THRESHOLD, frozen_model
from scripts.evaluate_public_successful_post import METHODS, forecast
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW
from scripts.f1_lab.streaming_context import IncrementalHTTPWindow
from scripts.f1_lab.web_post_refinement import SuccessfulPostRefinement
from scripts.f1_lab.web_residual import WebResidualRefinement

SOURCE = "https://databasesample.com/datasets/nginx-and-apache-access-log-tables-with-attack-annotations"
PUBLISHER_SHA = "42f840b5dfd0f92a5b6dea339bc2077927f2ac0f8bcc2a536c39c3ae95b0d0c7"
POPULATION = 791
# The publisher supplies wall-clock times without a timezone or UTC claim.
SOURCE_CLOCK_ORIGIN = datetime(1970, 1, 1)  # noqa: DTZ001
FIELDS = (
    "virtual_host_id", "client_ip", "method", "path", "status", "response_bytes", "requested_at",
)


def publisher_rows(source):
    if source.stat().st_size > 512 * 1024 or fingerprint(source) != PUBLISHER_SHA:
        raise ValueError("publisher file does not match the pinned release")
    dataset = read(source)
    rows = dataset["requests"]
    if len(rows) != POPULATION or len({row["id"] for row in rows}) != POPULATION:
        raise ValueError("publisher request population changed")
    return rows


def prepare(source, output):
    observations = [{field: row[field] for field in FIELDS} for row in publisher_rows(source)]
    output.mkdir()
    write(output / "observations.json", observations)
    write(output / "plan.json", {
        "source": SOURCE,
        "source_sha256": PUBLISHER_SHA,
        "observations_sha256": fingerprint(output / "observations.json"),
        "unit": "all publisher request rows, original physical ordinal",
        "history": "publisher wall clock and ordinal, one window per virtual host",
        "protocol": "unavailable; HTTP/0 is a rendering sentinel, not an observed version",
        "annotation": "read only by score; neither route ID nor user-agent class is projected",
        "threshold": THRESHOLD,
    })


def access_record(row):
    try:
        stamp = datetime.strptime(row["requested_at"], "%Y-%m-%d %H:%M:%S")  # noqa: DTZ007
        client = str(ipaddress.ip_address(row["client_ip"]))
        method, target, status, size = (row[k] for k in ("method", "path", "status", "response_bytes"))
        if (
            method not in METHODS
            or not 1 <= len(target) <= 16384 or re.search(r"[\x00-\x1f\x7f]", target)
            or not re.fullmatch(r"[1-5][0-9]{2}", status)
            or type(size) is not int or size < 0
        ):
            return None
    except (ValueError, TypeError):
        return None
    target = target.replace('"', "%22")
    log_time = stamp.strftime("%d/%b/%Y:%H:%M:%S")
    line = f'{client} - - [{log_time}] "{method} {target} HTTP/0" {status} {size} "-" "-"'
    moment = (stamp - SOURCE_CLOCK_ORIGIN).total_seconds()
    return (moment, line) if len(line.encode()) <= MAX_ROW else None


def capture(output, revision):
    if git("rev-parse", "HEAD").decode().strip() != revision or git(
        "status", "--porcelain", "--untracked-files=no"
    ).strip():
        raise ValueError("clean frozen revision required")
    observation_path = output / "observations.json"
    plan_path = output / "plan.json"
    plan, rows = read(plan_path), read(observation_path)
    if (
        plan["source_sha256"] != PUBLISHER_SHA or plan["threshold"] != THRESHOLD
        or len(rows) != POPULATION or fingerprint(observation_path) != plan["observations_sha256"]
        or any(set(row) != set(FIELDS) for row in rows)
    ):
        raise ValueError("observation projection does not match the frozen plan")

    model, pins = frozen_model()
    residual = WebResidualRefinement(model)
    candidate = SuccessfulPostRefinement(model.web_model)
    results = [{"ordinal": i, "before": None, "after": None} for i in range(1, POPULATION + 1)]
    timed = []
    for ordinal, row in enumerate(rows, 1):
        entry = access_record(row)
        if entry is not None:
            moment, line = entry
            timed.append((moment, ordinal, row["virtual_host_id"], line))
    if not timed:
        raise ValueError("no publisher request rows can be mapped by the input adapter")
    windows = defaultdict(IncrementalHTTPWindow)
    for moment, ordinal, host, line in sorted(timed):
        features = windows[host].observe(line, moment)
        before, after = forecast(line, moment, features, ordinal, PUBLISHER_SHA, model, residual, candidate)
        results[ordinal - 1].update(before=before, after=after)
    write(output / "predictions.json", results)
    write(output / "seal.json", {
        "candidate_commit": revision,
        "plan_sha256": fingerprint(plan_path),
        "predictions_sha256": fingerprint(output / "predictions.json"),
        "evaluator_sha256": fingerprint(Path(__file__)),
        "model_pins": pins,
        "valid_observations": len(timed),
    })


def score(source, output, expected_seal):
    seal_path = output / "seal.json"
    seal = read(seal_path)
    prediction_path = output / "predictions.json"
    if (
        fingerprint(seal_path) != expected_seal
        or fingerprint(output / "plan.json") != seal["plan_sha256"]
        or fingerprint(prediction_path) != seal["predictions_sha256"]
        or fingerprint(Path(__file__)) != seal["evaluator_sha256"]
    ):
        raise ValueError("capture seal mismatch")
    before, after = counts(), counts()
    lost_tp = new_fp = 0
    routes = {False: set(), True: set()}
    for ordinal, (source_row, prediction) in enumerate(
        zip(publisher_rows(source), read(prediction_path), strict=True), 1
    ):
        label = source_row["annotation"]
        if prediction["ordinal"] != ordinal or not isinstance(label, str) or not label:
            raise ValueError("cannot align prediction with the publisher annotation")
        truth = label != "benign"
        routes[truth].add(source_row["route_id"])
        old, new = prediction["before"], prediction["after"]
        record(before, truth, old)
        record(after, truth, new)
        lost_tp += truth and old is True and new is not True
        new_fp += not truth and old is False and new is True
    current = metrics(after)
    targets = {"precision": .95, "recall": .95, "f1": .95, "false_positive_rate": .05}
    passed = {
        key: current[key] is not None
        and (current[key] <= limit if key == "false_positive_rate" else current[key] >= limit)
        for key, limit in targets.items()
    }
    write(output / "report.json", {
        "source": SOURCE, "source_sha256": PUBLISHER_SHA,
        "seal_sha256": expected_seal, "capture": seal,
        "before": metrics(before), "after": current, "targets_met": passed,
        "goal_met_for_this_cohort": all(passed.values()),
        "route_support": {"normal": len(routes[False]), "threat": len(routes[True])},
        "lost_true_positives": lost_tp, "new_false_positives": new_fp,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "capture", "score"):
        command = commands.add_parser(name)
        command.add_argument("output", type=Path)
        if name != "capture":
            command.add_argument("source", type=Path)
        if name == "score":
            command.add_argument("seal")
        if name == "capture":
            command.add_argument("revision")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.source, args.output)
    elif args.command == "capture":
        capture(args.output, args.revision)
    else:
        score(args.source, args.output, args.seal)


if __name__ == "__main__":
    main()
