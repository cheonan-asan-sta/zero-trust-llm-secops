"""Diagnose RBA misses on reviewed accounts, then score a frozen candidate on withheld users."""

import argparse
from collections import Counter
from datetime import datetime
from itertools import product
from pathlib import Path

from scripts.evaluate_local_remote_holdout import read, write
from scripts.evaluate_public_login_history import ARCHIVE_SHA, BASE_TIME, MILLISECOND, bit, digest
from scripts.f1_lab.account_login_history import (
    AccountLoginHistory,
    repeated_failure_warning,
    review_repeated_login,
)
from scripts.f1_lab.login_environment import (
    HISTORY_LIMIT,
    WINDOW_MINUTES,
    Change,
    Environment,
    SuccessfulEnvironments,
)
from scripts.f1_lab.native_bayes import counts, metrics, record

COHORTS = {"reviewed": (2_575_003, 647_026, 26), "holdout": (2_572_078, 644_492, 18)}
NETWORK = Change.NEW_ADDRESS | Change.CHANGED_COUNTRY | Change.CHANGED_ASN
PATTERNS = {
    "network_change": NETWORK,
    "previously_unseen_country_and_asn": NETWORK | Change.NEW_COUNTRY | Change.NEW_ASN,
    "network_and_device_change": NETWORK | Change.CHANGED_DEVICE,
    "network_and_os_change": NETWORK | Change.CHANGED_OS,
    "network_and_new_client_profile": NETWORK | Change.NEW_PROFILE,
    "established_account_network_change": NETWORK | Change.MULTIPLE_SUCCESSES,
    "established_account_network_and_client_change": NETWORK
    | Change.MULTIPLE_SUCCESSES
    | Change.NEW_PROFILE,
    "new_asn_and_device_change": Change.NEW_ADDRESS | Change.NEW_ASN | Change.CHANGED_DEVICE,
    "new_asn_and_client_profile": Change.NEW_ADDRESS | Change.NEW_ASN | Change.NEW_PROFILE,
    "new_address_and_changed_client_stack": Change.NEW_ADDRESS
    | Change.CHANGED_OS
    | Change.CHANGED_BROWSER,
}


def matches(rule, flags, delay):
    return (
        rule is not None
        and delay <= rule["window_index"]
        and flags & rule["flags"] == rule["flags"]
    )


def available_for_new_review(success, repeat, baseline):
    return success and not repeat and not baseline


def observed_signals(observed, rows, accounts):
    attempts = AccountLoginHistory(max_accounts=accounts)
    environments = SuccessfulEnvironments()
    last_time = last_ordinal = number = 0
    with observed.open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            ordinal, stamp, account, address, outcome, *client = raw.rstrip(b"\n").split(b"\t")
            moment = (datetime.fromisoformat(stamp.decode("ascii")) - BASE_TIME) // MILLISECOND
            row_number = int(ordinal)
            if row_number <= last_ordinal or moment < last_time or len(client) != 5:
                raise ValueError("environment observation order or width differs")
            last_time, last_ordinal = moment, row_number
            success = bit(outcome)
            environment = Environment(
                *(None if field == b"-" else field for field in (address, *client))
            )
            prior = attempts.observe(
                account=account, moment=moment, success=success, client=environment.address
            )
            repeated = repeated_failure_warning(prior, success)
            baseline = review_repeated_login(baseline=repeated, prior=prior, success=success)
            flags, delay = (
                environments.observe(account, moment, environment)
                if success
                else (0, len(WINDOW_MINUTES))
            )
            yield ordinal, success, repeated, baseline, flags, delay
    if number != rows or attempts.account_count != accounts:
        raise ValueError("unexpected environment evaluation population")


def capture(projection, output, cohort, frozen_path=None, expected_frozen=None):
    if (projection / "completed").read_text(encoding="ascii").strip() != ARCHIVE_SHA:
        raise ValueError("incomplete environment projection")
    frozen = None
    if cohort == "holdout":
        if frozen_path is None or digest(frozen_path) != expected_frozen:
            raise ValueError("holdout requires the frozen reviewed candidate")
        frozen = read(frozen_path)["rule"]
    elif frozen_path is not None or expected_frozen is not None:
        raise ValueError("reviewed predictions do not use the held-out rule")
    observed = projection / cohort / "observations.tsv"
    observed_sha = digest(observed)
    rows, accounts, _ = COHORTS[cohort]
    output.mkdir()
    plan, predictions = output / "plan.json", output / "predictions.tsv"
    write(
        plan,
        {
            "source_sha256": ARCHIVE_SHA,
            "observation_sha256": observed_sha,
            "cohort": cohort,
            "rows": rows,
            "accounts": accounts,
            "history_limit": HISTORY_LIMIT,
            "windows_minutes": WINDOW_MINUTES,
            "frozen_candidate_sha256": expected_frozen,
            "rule": frozen,
            "truth_read_by_capture": False,
        },
    )
    with predictions.open("xb") as saved:
        for ordinal, success, repeated, baseline, flags, delay in observed_signals(
            observed, rows, accounts
        ):
            alert = baseline or (
                available_for_new_review(success, repeated, baseline)
                and matches(frozen, flags, delay)
            )
            saved.write(
                b"%s\t%d\t%d\t%d\t%d\t%d\t%d\n"
                % (ordinal, success, repeated, baseline, flags, delay, alert)
            )
    if digest(observed) != observed_sha:
        raise ValueError("unexpected environment evaluation population")
    write(
        output / "seal.json",
        {"plan_sha256": digest(plan), "prediction_sha256": digest(predictions)},
    )


def occurrences(projection, output, cohort, expected_seal):
    path, plan_path, seal_path = (
        output / file for file in ("predictions.tsv", "plan.json", "seal.json")
    )
    plan, seal = read(plan_path), read(seal_path)
    if (
        digest(seal_path) != expected_seal
        or plan["cohort"] != cohort
        or plan["source_sha256"] != ARCHIVE_SHA
        or digest(path) != seal["prediction_sha256"]
        or digest(plan_path) != seal["plan_sha256"]
    ):
        raise ValueError("environment prediction seal differs")
    rows, _, positive_rows = COHORTS[cohort]
    truth = projection / cohort / "truth.tsv"
    truth_sha = digest(truth)
    before, previous, candidate = counts(), counts(), counts()
    added = Counter()
    missed_features = Counter()
    missed_delays = Counter()
    lost = new_fp = reinstated = positives = number = 0
    with path.open("rb") as predictions, truth.open("rb") as labels:
        for number, (pred, raw) in enumerate(zip(predictions, labels, strict=True), 1):
            ordinal, outcome, original, base, raw_flags, raw_delay, would_alert = pred.rstrip(
                b"\n"
            ).split(b"\t")
            label_ordinal, label = raw.rstrip(b"\n").split(b"\t")
            if ordinal != label_ordinal:
                raise ValueError("environment prediction order differs from truth")
            success, repeated, baseline, alert, expected = map(
                bit, (outcome, original, base, would_alert, label)
            )
            flags, delay = int(raw_flags), int(raw_delay)
            if alert != (
                baseline
                or (
                    available_for_new_review(success, repeated, baseline)
                    and matches(plan["rule"], flags, delay)
                )
            ):
                raise ValueError("sealed candidate differs from plan")
            positives += expected
            record(before, expected, repeated)
            record(previous, expected, baseline)
            record(candidate, expected, alert)
            lost += expected and baseline and not alert
            new_fp += not expected and alert and not baseline
            reinstated += not expected and repeated and not baseline and alert
            if cohort == "reviewed":
                if available_for_new_review(success, repeated, baseline) and flags:
                    added[flags, delay, expected] += 1
                if expected and not baseline:
                    missed_features.update(flag.name for flag in Change if flags & flag)
                    missed_features["CURRENT_SUCCESS"] += success
                    missed_features["ORIGINAL_REPEAT_WARNING"] += repeated
                    if flags & Change.PRIOR_SUCCESS:
                        missed_delays[delay] += 1
    if (
        number != rows
        or positives != positive_rows
        or digest(truth) != truth_sha
        or digest(path) != seal["prediction_sha256"]
    ):
        raise ValueError("unexpected scored environment population")
    report = {
        "cohort": cohort,
        "seal_sha256": expected_seal,
        "truth_sha256": truth_sha,
        "original_repeat_rule": metrics(before),
        "previous_history_candidate": metrics(previous),
        "shadow": metrics(candidate),
        "new_false_positives": new_fp,
        "lost_true_positives": lost,
        "reinstated_previous_false_positives": reinstated,
        "candidate_adopted": False,
    }
    report["additive_alert_precision_upper_bound"] = positives / (positives + previous["fp"])
    report["additive_alert_f1_upper_bound"] = 2 * positives / (2 * positives + previous["fp"])
    report["regression_gate_passed"] = new_fp == lost == reinstated == 0
    if cohort == "reviewed":
        report["missed_events"] = positive_rows - previous["tp"]
        report["missed_feature_observations"] = missed_features
        report["missed_gap_counts_by_window_index"] = missed_delays
        mixed = [
            (count, added[flags, delay, False])
            for (flags, delay, expected), count in added.items()
            if expected and added[flags, delay, False]
        ]
        report["mixed_observation_groups"] = {
            "groups": len(mixed),
            "positives_sharing_a_group_with_negatives": sum(tp for tp, _ in mixed),
            "negatives_in_those_groups": sum(fp for _, fp in mixed),
        }
    return report, added


def choose(previous, occurrences):
    options = []
    for (name, mask), window_index in product(PATTERNS.items(), range(len(WINDOW_MINUTES) + 1)):
        rule = {"name": name, "flags": int(mask), "window_index": window_index}
        fp = tp = 0
        for (flags, delay, truth), count in occurrences.items():
            if matches(rule, flags, delay):
                if truth:
                    tp += count
                else:
                    fp += count
        result = {"new_false_positives": fp, "recovered_true_positives": tp, "rule": rule}
        totals = {key: previous[key] for key in counts()}
        totals.update(
            tp=previous["tp"] + tp,
            fp=previous["fp"] + fp,
            tn=previous["tn"] - fp,
            fn=previous["fn"] - tp,
        )
        result["metrics"] = metrics(totals)
        options.append(result)
    improving = [row for row in options if row["recovered_true_positives"]]
    strict = [row for row in improving if row["new_false_positives"] == 0]
    best = max(
        strict or improving,
        default=None,
        key=lambda row: (
            row["metrics"]["f1"],
            -row["new_false_positives"],
            row["recovered_true_positives"],
            -row["rule"]["window_index"],
        ),
    )
    return {
        "rule": best["rule"] if best else None,
        "qualified_on_reviewed": bool(strict),
        "selection": best,
        "options": options,
    }


def evaluate(projection, output, cohort, seal):
    report, environment_counts = occurrences(projection, output, cohort, seal)
    if cohort == "reviewed":
        chosen = choose(report["previous_history_candidate"], environment_counts)
        write(
            output / "frozen-candidate.json",
            {
                **{key: value for key, value in chosen.items() if key != "options"},
                "reviewed_seal": seal,
            },
        )
        report["selection"] = chosen["selection"]
        report["zero_new_fp_with_recovery_candidates"] = sum(
            row["new_false_positives"] == 0 and row["recovered_true_positives"] > 0
            for row in chosen["options"]
        )
        report["rule_count"] = len(chosen["options"])
    write(output / "report.json", report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projection", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("cohort", choices=COHORTS)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--expected-candidate-sha")
    parser.add_argument("--score-seal")
    args = parser.parse_args()
    if args.score_seal:
        evaluate(args.projection, args.output, args.cohort, args.score_seal)
    else:
        capture(
            args.projection, args.output, args.cohort, args.candidate, args.expected_candidate_sha
        )
