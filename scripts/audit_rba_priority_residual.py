"""Inspect the seven known RBA priority misses without exposing account values."""

import argparse
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.evaluate_local_remote_holdout import read, write
from scripts.evaluate_public_login_history import bit, digest
from scripts.evaluate_rba_ato_separation import CHANNELS, ROWS, decisions
from scripts.evaluate_rba_login_environment import observed_signals
from scripts.f1_lab.ato_triage import Takeover, assess_login
from scripts.f1_lab.login_environment import WINDOW_MINUTES, Change

REFERENCE = (
    Path(__file__).resolve().parents[1]
    / "docs/infrastructure-results/rba-ato-separation-20261123.json"
)


def residual_rows(predictions, labels):
    selected = set()
    count = 0
    unchanged = 0
    with predictions.open("rb") as rows, labels.open("rb") as truth:
        for count, (row, label) in enumerate(zip(rows, truth, strict=True), 1):
            ordinal, _, *encoded = row.removesuffix(b"\n").split(b"\t")
            truth_ordinal, marked = label.removesuffix(b"\n").split(b"\t")
            if ordinal != truth_ordinal or len(encoded) != len(CHANNELS):
                raise ValueError("residual input rows do not align")
            _, warning, review, priority = map(bit, encoded)
            decision = assess_login(warning=warning, success=True, environment_change=review)
            updated_priority = priority or decision.takeover is Takeover.PRIORITY_REVIEW
            unchanged += updated_priority == priority
            if bit(marked) and review and not priority:
                selected.add(ordinal)
    if count != ROWS or len(selected) != 7:
        raise ValueError("unexpected ATO residual population")
    return selected, unchanged


def isolate_accounts(observations, selected, output):
    accounts = set()
    with observations.open("rb") as rows:
        for row in rows:
            ordinal, _, account, _ = row.split(b"\t", 3)
            if ordinal in selected:
                accounts.add(account)
    count = 0
    with observations.open("rb") as rows, output.open("xb") as scoped:
        for row in rows:
            if row.split(b"\t", 3)[2] in accounts:
                scoped.write(row)
                count += 1
    return count, len(accounts)


def run(projection, confirmation, output):
    reference = read(REFERENCE)["confirmation"]
    observations, labels = (
        projection / "confirmation" / file for file in ("observations.tsv", "truth.tsv")
    )
    predictions = confirmation / "predictions.tsv"
    if (
        digest(confirmation / "seal.json") != reference["report"]["seal_sha256"]
        or digest(predictions) != reference["seal"]["prediction_sha256"]
        or digest(observations) != reference["plan"]["observations_sha256"]
        or digest(labels) != reference["report"]["truth_sha256"]
    ):
        raise ValueError("residual evidence differs from the previous frozen run")
    selected, unchanged = residual_rows(predictions, labels)
    observations_seen = dict.fromkeys((signal.name.lower() for signal in Change), 0)
    delay_counts, signatures = Counter(), Counter()
    with TemporaryDirectory() as scratch:
        scoped = Path(scratch) / "observations.tsv"
        rows, accounts = isolate_accounts(observations, selected, scoped)
        for ordinal, success, repeated, warning, flags, delay in observed_signals(
            scoped, rows, accounts
        ):
            if ordinal not in selected:
                continue
            result = decisions(success, repeated, warning, flags, delay, reference["plan"]["rule"])
            if not result["ato_review"] or result["profile_priority_proxy"]:
                raise ValueError("residual did not reproduce")
            for signal in Change:
                observations_seen[signal.name.lower()] += bool(flags & signal)
            delay_counts[delay] += 1
            signatures[flags, delay] += 1
    if sum(signatures.values()) != 7:
        raise ValueError("residual replay was incomplete")
    write(
        output,
        {
            "source_seal_sha256": reference["report"]["seal_sha256"],
            "reviewed_positive_rows": 7,
            "distinct_accounts": accounts,
            "successful_login_rows": 7,
            "observed_change_counts": observations_seen,
            "success_gap_bucket_minutes": list(WINDOW_MINUTES) + [None],
            "success_gap_counts": dict(sorted(delay_counts.items())),
            "controlled_patterns": [
                {"environment_flags": flags, "delay_bucket": delay, "rows": count}
                for (flags, delay), count in sorted(signatures.items())
            ],
            "verified_mfa_available_rows": 0,
            "verified_device_available_rows": 0,
            "unchanged_priority_without_authoritative_evidence": unchanged,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("projection", "confirmation", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    run(args.projection, args.confirmation, args.output)
