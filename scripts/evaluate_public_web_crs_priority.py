"""Prioritize corroborated request-target observations while preserving all alerts."""

import argparse
import json
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_web_access import access_record
from scripts.evaluate_public_web_target_crs import (
    access_inputs,
    access_labels,
    apache_labels,
    apache_logs,
)
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.raw_observations import REQUEST, raw_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.web_residual import encoded_argv_request

FILE_INCLUSION_FAMILY = 930
COMMAND_EXECUTION_FAMILY = 932
SQL_INJECTION_FAMILY = 942


def corroborated(line, rule_ids):
    request = REQUEST.search(line) if line is not None else None
    if request is None:
        return False
    families = {rule // 1000 for rule in rule_ids}
    # Match the family's existing signal on the request target alone. Referrer,
    # user-agent and server outcome are not corroboration of the target intent.
    scoped = f'"{request[1]} {request[2]} HTTP/0" {request[3]}'
    raw, semantic = raw_features(scoped), semantic_observations(scoped)
    return (
        FILE_INCLUSION_FAMILY in families and raw["sensitive_file"]
        or SQL_INJECTION_FAMILY in families
        and (raw["sql_injection"] or semantic["http_sql_boolean_comparison"])
        or COMMAND_EXECUTION_FAMILY in families
        and (raw["shell_payload"] or encoded_argv_request(line))
    )


def candidate_seal(args):
    seal_path = args.candidate / "seal.json"
    seal = read(seal_path)
    predictions = args.candidate / "target-predictions.jsonl"
    if (
        fingerprint(seal_path) != args.candidate_seal or seal["kind"] != args.kind
        or seal["baseline_seal"] != args.baseline_seal
        or fingerprint(predictions) != seal["predictions_sha256"]
    ):
        raise ValueError("candidate capture differs from the pinned prediction seal")
    return seal, predictions


def observation_lines(args):
    if args.kind == "apache":
        for line, _ in apache_logs(args.source, args.reference, args.baseline_seal):
            yield line
        return
    # Validate the original observation projection before using it.
    list(access_inputs(args.reference, args.baseline_seal))
    for row in read(args.reference / "observations.json"):
        converted = access_record(row)
        yield converted[1] if converted is not None else None


def capture(args):
    seal, predictions = candidate_seal(args)
    args.output.mkdir()
    path = args.output / "priorities.jsonl"
    count = 0
    with predictions.open("rb") as source, path.open("xb") as out:
        for count, (record_line, line) in enumerate(zip(source, observation_lines(args), strict=True), 1):
            row = json.loads(record_line)
            if row["ordinal"] != count:
                raise ValueError("candidate and observation order differs")
            priority = row["alert"] is True and corroborated(line, row.get("rule_ids", []))
            out.write(canonical({"ordinal": count, "priority": priority}) + b"\n")
    if count != seal["observations"]:
        raise ValueError("observation count changed")
    write(args.output / "seal.json", {
        "kind": args.kind, "observations": count,
        "candidate_seal": args.candidate_seal, "baseline_seal": args.baseline_seal,
        "evaluator_sha256": fingerprint(Path(__file__)), "priorities_sha256": fingerprint(path),
    })


def score(args):
    _, predictions = candidate_seal(args)
    seal_path = args.output / "seal.json"
    seal = read(seal_path)
    path = args.output / "priorities.jsonl"
    if (
        fingerprint(seal_path) != args.priority_seal
        or seal["candidate_seal"] != args.candidate_seal or seal["baseline_seal"] != args.baseline_seal
        or seal["kind"] != args.kind or fingerprint(path) != seal["priorities_sha256"]
        or fingerprint(Path(__file__)) != seal["evaluator_sha256"]
    ):
        raise ValueError("priority capture differs from the pinned seal")
    labels = (
        access_labels(args.source, args.reference, args.baseline_seal) if args.kind == "access"
        else apache_labels(args.source, args.reference, args.baseline_seal)
    )
    previous, all_crs, prioritized = counts(), counts(), counts()
    regular = {"threat": 0, "normal": 0}
    count = existing_losses = 0
    with path.open("rb") as priority_stream, predictions.open("rb") as candidate_stream:
        for count, (line, candidate, (truth, old, _)) in enumerate(
            zip(priority_stream, candidate_stream, labels, strict=True), 1
        ):
            priority, added = json.loads(line), json.loads(candidate)
            if priority["ordinal"] != added["ordinal"] or priority["ordinal"] != count:
                raise ValueError("priority, candidate and label rows differ")
            detected = added["alert"] is True
            elevated = priority["priority"] is True
            if elevated and not detected:
                raise ValueError("priority needs an existing CRS observation")
            record(previous, truth, old)
            record(all_crs, truth, True if detected else old)
            priority_outcome = True if elevated else old
            record(prioritized, truth, priority_outcome)
            existing_losses += truth and old is True and priority_outcome is not True
            if old is False and detected and not elevated:
                regular["threat" if truth else "normal"] += 1
    if count != seal["observations"] or fingerprint(path) != seal["priorities_sha256"]:
        raise ValueError("priority prediction population changed")
    write(args.output / "report.json", {
        "capture": seal, "priority_seal": args.priority_seal,
        "previous": metrics(previous), "all_crs": metrics(all_crs),
        "priority_only_plus_previous": metrics(prioritized), "regular_review_only": regular,
        "existing_true_positive_losses": existing_losses,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    for action in ("capture", "score"):
        command = subcommands.add_parser(action)
        command.add_argument("kind", choices=("access", "apache"))
        for name in ("source", "reference", "candidate", "output"):
            command.add_argument(name, type=Path)
        command.add_argument("baseline_seal")
        command.add_argument("candidate_seal")
        if action == "score":
            command.add_argument("priority_seal")
    args = parser.parse_args()
    (capture if args.action == "capture" else score)(args)


if __name__ == "__main__":
    main()
