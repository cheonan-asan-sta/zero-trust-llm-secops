"""Compare a passive CRS request-target signal with sealed web predictions."""

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

import yaml

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_apache_transfer import LABEL_MEMBER, SOURCE_SHA, records
from scripts.evaluate_public_web_access import FIELDS, POPULATION, PUBLISHER_SHA, publisher_rows
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.raw_observations import REQUEST


def baseline(plan_path, prediction_path, expected_seal):
    seal_path = plan_path.parent / "seal.json"
    if fingerprint(seal_path) != expected_seal:
        raise ValueError("baseline seal does not match")
    seal = read(seal_path)
    prediction_key = "prediction_sha256" if prediction_path.suffix == ".jsonl" else "predictions_sha256"
    if (
        fingerprint(plan_path) != seal["plan_sha256"]
        or fingerprint(prediction_path) != seal[prediction_key]
    ):
        raise ValueError("baseline data changed")
    return read(plan_path), seal


def access_inputs(reference, expected_seal):
    plan, _ = baseline(reference / "plan.json", reference / "predictions.json", expected_seal)
    observed_path = reference / "observations.json"
    rows = read(observed_path)
    if (
        plan["source_sha256"] != PUBLISHER_SHA
        or fingerprint(observed_path) != plan["observations_sha256"]
        or len(rows) != POPULATION or any(set(row) != set(FIELDS) for row in rows)
    ):
        raise ValueError("web access observations changed")
    for index, row in enumerate(rows, 1):
        yield {"ordinal": index, "method": row["method"], "target": row["path"]}


def apache_logs(source, reference, expected_seal):
    plan, seal = baseline(reference / "plan.json", reference / "predictions.jsonl", expected_seal)
    if plan["archive_sha256"] != SOURCE_SHA or fingerprint(source) != SOURCE_SHA:
        raise ValueError("Apache source fingerprint mismatch")
    with ZipFile(source) as archive, (reference / "predictions.jsonl").open("rb") as predictions:
        for item in seal["media"]:
            rows, digest = records(archive, item["member"])
            if len(rows) != item["rows"] or digest != item["sha256"]:
                raise ValueError("Apache population differs from the baseline")
            for index, row in enumerate(rows, 1):
                decision = json.loads(predictions.readline())
                key = hashlib.sha256(f"{digest}:{index}".encode()).hexdigest()
                if key != decision["case_id"]:
                    raise ValueError("Apache baseline case and source row differ")
                yield row, decision["after"]
        if predictions.read(1):
            raise ValueError("baseline contains extra rows")


def apache_inputs(source, reference, expected_seal):
    for index, (row, _) in enumerate(apache_logs(source, reference, expected_seal), 1):
        request = REQUEST.search(row)
        yield {"ordinal": index, "method": request[1], "target": request[2]} if request else {
            "ordinal": index, "method": "", "target": "",
        }


def apache_labels(source, reference, expected_seal):
    with ZipFile(source) as archive:
        rules = yaml.safe_load(archive.read(LABEL_MEMBER))
    filters = [rule["filter"] for rule in rules]
    for row, previous in apache_logs(source, reference, expected_seal):
        yield any(all(term in row for term in terms) for terms in filters), previous, "publisher"


def access_labels(source, reference, expected_seal):
    baseline(reference / "plan.json", reference / "predictions.json", expected_seal)
    for index, (row, earlier) in enumerate(
        zip(publisher_rows(source), read(reference / "predictions.json"), strict=True), 1
    ):
        if earlier["ordinal"] != index:
            raise ValueError("web access baseline order changed")
        yield row["annotation"] != "benign", earlier["after"], row["annotation"]


def capture(args):
    rows = (
        access_inputs(args.reference, args.baseline_seal) if args.kind == "access"
        else apache_inputs(args.source, args.reference, args.baseline_seal)
    )
    args.output.mkdir()
    decisions = args.output / "target-predictions.jsonl"
    binary = args.executable.resolve()
    count = 0
    with (
        decisions.open("xb") as output,
        subprocess.Popen([str(binary), "--target-only"], stdin=subprocess.PIPE, stdout=output) as process,
    ):
        for count, row in enumerate(rows, 1):
            process.stdin.write(canonical(row) + b"\n")
        process.stdin.close()
        if process.wait() or not count:
            raise ValueError("local target inspection failed")
    with decisions.open("rb") as stream:
        returned = sum(1 for _ in stream)
    if returned != count:
        raise ValueError("local inspection response count changed")
    write(args.output / "seal.json", {
        "baseline_seal": args.baseline_seal, "kind": args.kind, "observations": count,
        "binary_sha256": fingerprint(binary), "predictions_sha256": fingerprint(decisions),
        "source_sha256": PUBLISHER_SHA if args.kind == "access" else SOURCE_SHA,
        "crs": "4.25.0", "coraza": "3.8.1",
    })


def score(args):
    seal_path = args.output / "seal.json"
    seal = read(seal_path)
    decisions = args.output / "target-predictions.jsonl"
    if (
        fingerprint(seal_path) != args.candidate_seal or seal["baseline_seal"] != args.baseline_seal
        or seal["kind"] != args.kind or fingerprint(decisions) != seal["predictions_sha256"]
    ):
        raise ValueError("target prediction seal does not match")
    labels = (
        access_labels(args.source, args.reference, args.baseline_seal) if args.kind == "access"
        else apache_labels(args.source, args.reference, args.baseline_seal)
    )
    previous, target, combined = counts(), counts(), counts()
    additional_threats = new_fp = count = 0
    misses = Counter()
    with decisions.open("rb") as stream:
        for count, (line, (truth, old, group)) in enumerate(zip(stream, labels, strict=True), 1):
            row = json.loads(line)
            if row["ordinal"] != count:
                raise ValueError("target prediction order changed")
            candidate = row["alert"]
            after = True if candidate is True else old
            record(previous, truth, old)
            record(target, truth, candidate)
            record(combined, truth, after)
            additional_threats += truth and old is not True and after is True
            new_fp += not truth and old is False and after is True
            if truth and after is not True:
                misses[group] += 1
    if count != seal["observations"] or fingerprint(decisions) != seal["predictions_sha256"]:
        raise ValueError("target prediction population changed")
    write(args.output / "report.json", {
        "capture": seal, "candidate_seal": args.candidate_seal,
        "previous": metrics(previous), "target_only": metrics(target), "combined": metrics(combined),
        "additional_threats": additional_threats, "new_false_positives": new_fp,
        "lost_true_positives": 0, "combined_misses_by_publisher_group": dict(misses),
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("capture", "score"):
        command = actions.add_parser(name)
        command.add_argument("kind", choices=("access", "apache"))
        command.add_argument("source", type=Path)
        command.add_argument("reference", type=Path)
        command.add_argument("output", type=Path)
        command.add_argument("baseline_seal")
        command.add_argument(
            "executable" if name == "capture" else "candidate_seal",
            type=Path if name == "capture" else str,
        )
    args = parser.parse_args()
    if args.action == "capture":
        capture(args)
    else:
        score(args)


if __name__ == "__main__":
    main()
