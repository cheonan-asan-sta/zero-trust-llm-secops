"""Evaluate causal account login review on the RBA reserved-user projection."""

import argparse
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from scripts.evaluate_local_remote_holdout import read, write
from scripts.f1_lab.account_login_history import (
    FAILURE_WINDOW_MS,
    FAMILIAR_SUCCESS_WINDOW_MS,
    REPEATED_FAILURE_THRESHOLD,
    AccountLoginHistory,
    repeated_failure_warning,
    review_repeated_login,
)
from scripts.f1_lab.native_bayes import counts, metrics, record

ARCHIVE_SHA = "ca1d974e97aebfb30878a613f4ca5c793860a98ba2acb5185c9bc610d7432a33"
MEMBERS = 647_026
ROWS = 2_575_003
ATO_ROWS = 26
# Source timestamps have no time zone. Use only relative elapsed time in this clock.
BASE_TIME = datetime.fromisoformat("2020-01-01")
MILLISECOND = timedelta(milliseconds=1)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bit(value):
    if value not in {b"0", b"1"}:
        raise ValueError("invalid projected Boolean")
    return value == b"1"


def capture(projection, output):
    if (projection / "completed").read_text(encoding="ascii").strip() != ARCHIVE_SHA:
        raise ValueError("incomplete publisher projection")
    observed = projection / "observations.tsv"
    observed_sha = digest(observed)
    output.mkdir()
    plan_path, result = output / "plan.json", output / "predictions.tsv"
    write(
        plan_path,
        {
            "archive_sha256": ARCHIVE_SHA,
            "observation_sha256": observed_sha,
            "cohort": "previously fixed reserved users excluding observed probe users",
            "rows": ROWS,
            "window_ms": FAILURE_WINDOW_MS,
            "familiar_ms": FAMILIAR_SUCCESS_WINDOW_MS,
            "threshold": REPEATED_FAILURE_THRESHOLD,
            "baseline": "existing rule's 3 observed failures, projected to same account in 10 minutes",
            "candidate": "successful current login, same recent captured source, no failures since last success",
            "truth_loaded_by_capture": False,
        },
    )
    history = AccountLoginHistory(max_accounts=MEMBERS)
    previous_time = previous_ordinal = number = 0
    with observed.open("rb") as stream, result.open("xb") as predictions:
        for number, raw in enumerate(stream, 1):
            ordinal, timestamp, account, client, observed_outcome = raw.rstrip(b"\n").split(b"\t")
            value = datetime.fromisoformat(timestamp.decode("ascii"))
            moment = (value - BASE_TIME) // MILLISECOND
            ordinal_number = int(ordinal)
            if moment < previous_time or ordinal_number <= previous_ordinal:
                raise ValueError("unsorted publisher projection")
            previous_time, previous_ordinal = moment, ordinal_number
            success = bit(observed_outcome)
            context = history.observe(
                account=account,
                moment=moment,
                success=success,
                client=None if client == b"-" else client,
            )
            before = repeated_failure_warning(context, success)
            after = review_repeated_login(baseline=before, prior=context, success=success)
            predictions.write(b"%s\t%d\t%d\t%d\n" % (ordinal, success, before, after))
    if number != ROWS or history.account_count != MEMBERS or digest(observed) != observed_sha:
        raise ValueError("projected publisher population or file changed")
    write(
        output / "seal.json",
        {
            "plan_sha256": digest(plan_path),
            "prediction_sha256": digest(result),
            "accounts": MEMBERS,
        },
    )


def score(projection, output, expected_seal):
    plan_path, result, seal_path = (
        output / name for name in ("plan.json", "predictions.tsv", "seal.json")
    )
    seal = read(seal_path)
    if (
        digest(seal_path) != expected_seal
        or digest(plan_path) != seal["plan_sha256"]
        or digest(result) != seal["prediction_sha256"]
    ):
        raise ValueError("login prediction seal mismatch")
    truth_path = projection / "truth.tsv"
    truth_sha = digest(truth_path)
    partitions = defaultdict(
        lambda: {"before": counts(), "candidate": counts(), "lost": 0, "new_fp": 0, "cleared_fp": 0}
    )
    number = 0
    with result.open("rb") as predictions, truth_path.open("rb") as labels:
        for number, (predicted, label) in enumerate(zip(predictions, labels, strict=True), 1):
            ordinal, outcome, before, after = predicted.rstrip(b"\n").split(b"\t")
            expected_ordinal, expected = label.rstrip(b"\n").split(b"\t")
            if expected_ordinal != ordinal:
                raise ValueError("login prediction and label row differ")
            truth, base, candidate = bit(expected), bit(before), bit(after)
            for name in ("all", "successful_login" if bit(outcome) else "failed_login"):
                group = partitions[name]
                record(group["before"], truth, base)
                record(group["candidate"], truth, candidate)
                group["lost"] += truth and base and not candidate
                group["new_fp"] += not truth and candidate and not base
                group["cleared_fp"] += not truth and base and not candidate
    if (
        number != ROWS
        or partitions["all"]["before"]["tp"] + partitions["all"]["before"]["fn"] != ATO_ROWS
    ):
        raise ValueError("reserved ATO population differs")
    if digest(truth_path) != truth_sha or digest(result) != seal["prediction_sha256"]:
        raise ValueError("login scoring inputs changed")
    write(
        output / "report.json",
        {
            "seal_sha256": expected_seal,
            "truth_sha256": truth_sha,
            "truth_scope": "publisher ATO indicator only; unmarked attempted abuse may appear among negatives",
            "groups": {
                group: {
                    **data,
                    "before": metrics(data["before"]),
                    "candidate": metrics(data["candidate"]),
                }
                for group, data in partitions.items()
            },
            "candidate_adopted": False,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projection", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--score-seal")
    args = parser.parse_args()
    if args.score_seal is None:
        capture(args.projection, args.output)
    else:
        score(args.projection, args.output, args.score_seal)
