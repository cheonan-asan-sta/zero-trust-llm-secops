"""Compare distinct login warnings and device-profile ATO candidates on unseen RBA users."""

import argparse
from collections import Counter
from itertools import product
from pathlib import Path

from scripts.evaluate_local_remote_holdout import read, write
from scripts.evaluate_public_login_history import ARCHIVE_SHA, bit, digest
from scripts.evaluate_rba_login_environment import (
    NETWORK,
    available_for_new_review,
    observed_signals,
)
from scripts.f1_lab.ato_triage import Takeover, assess_login
from scripts.f1_lab.login_environment import WINDOW_MINUTES, Change
from scripts.f1_lab.native_bayes import counts, metrics, record

ROWS = 3_516_562
ACCOUNTS = 861_603
REFERENCE = (
    Path(__file__).resolve().parents[1]
    / "docs/infrastructure-results/rba-login-environment-20261123.json"
)
PROFILES = {
    "device_type": [Change.CHANGED_DEVICE],
    "operating_system": [Change.CHANGED_OS],
    "browser": [Change.CHANGED_BROWSER],
    "new_profile": [Change.NEW_PROFILE],
    "device_and_os": [Change.CHANGED_DEVICE | Change.CHANGED_OS],
    "browser_and_os": [Change.CHANGED_BROWSER | Change.CHANGED_OS],
    "device_or_os": [Change.CHANGED_DEVICE, Change.CHANGED_OS],
    "device_or_browser": [Change.CHANGED_DEVICE, Change.CHANGED_BROWSER],
    "any_client_change": [
        Change.CHANGED_DEVICE,
        Change.CHANGED_OS,
        Change.CHANGED_BROWSER,
        Change.NEW_PROFILE,
    ],
}


def network_change(flags):
    return flags & NETWORK == NETWORK


def profile_match(rule, flags, delay):
    return delay <= rule["window_index"] and any(flags & mask == mask for mask in rule["any_of"])


def choose_candidate(observations):
    broad_tp = sum(count for (_, _, label), count in observations.items() if label)
    broad_fp = sum(count for (_, _, label), count in observations.items() if not label)
    options = []
    for (name, masks), window in product(PROFILES.items(), range(len(WINDOW_MINUTES) + 1)):
        rule = {"name": name, "any_of": [int(mask) for mask in masks], "window_index": window}
        tp = fp = 0
        for (flags, delay, truth), count in observations.items():
            if profile_match(rule, flags, delay):
                if truth:
                    tp += count
                else:
                    fp += count
        if tp and fp < broad_fp:
            options.append(
                (
                    {
                        "rule": rule,
                        "tp": tp,
                        "fp": fp,
                        "broad_tp": broad_tp,
                        "broad_fp": broad_fp,
                    },
                    (
                        tp == broad_tp,
                        2 * tp >= broad_tp,
                        2 * tp / (broad_tp + tp + fp),
                        tp,
                        -fp,
                        -window,
                    ),
                )
            )
    if not options:
        raise ValueError(
            "no profile rule reduced false positives while detecting a development case"
        )
    return max(options, key=lambda option: option[1])[0]


def freeze(projection, reviewed, previous_holdout, output):
    reference = read(REFERENCE)
    observations = Counter()
    receipts = {}
    sizes = {"reviewed": 2_575_003, "holdout": 2_572_078}
    for cohort, source in (("reviewed", reviewed), ("holdout", previous_holdout)):
        predictions, labels = source / "predictions.tsv", projection / cohort / "truth.tsv"
        pinned = reference[cohort]
        if (
            digest(source / "seal.json") != pinned["report"]["seal_sha256"]
            or digest(predictions) != pinned["seal"]["prediction_sha256"]
            or digest(labels) != pinned["report"]["truth_sha256"]
        ):
            raise ValueError("previously reviewed inputs differ from the recorded evaluation")
        number = 0
        with predictions.open("rb") as rows, labels.open("rb") as truth:
            for number, (prediction, label) in enumerate(zip(rows, truth, strict=True), 1):
                ordinal, success, repeated, warning, flags, delay, _ = prediction.rstrip(
                    b"\n"
                ).split(b"\t")
                truth_ordinal, marked = label.rstrip(b"\n").split(b"\t")
                if ordinal != truth_ordinal:
                    raise ValueError("historical prediction and truth alignment differs")
                features = int(flags)
                if available_for_new_review(
                    bit(success), bit(repeated), bit(warning)
                ) and network_change(features):
                    observations[features, int(delay), bit(marked)] += 1
        if number != sizes[cohort]:
            raise ValueError("historical cohort population differs")
        receipts[cohort] = pinned["report"]["seal_sha256"]
    write(
        output,
        {
            "candidate": choose_candidate(observations),
            "source_seals": receipts,
            "profile_proxy_only": True,
            "confirmation_scope": "account hash buckets 0 through 19 except probe accounts",
            "selection": "prefer preserving all broad positives, then at least half, then best F1 among broad positives and profile false positives",
        },
    )


def decisions(success, repeated, warning, flags, delay, rule):
    broad = available_for_new_review(success, repeated, warning) and network_change(flags)
    review = assess_login(warning=warning, success=success, environment_change=broad)
    return {
        "prior_combined": warning or broad,
        "separate_warning": review.repeated_failure_warning,
        "ato_review": review.takeover is not Takeover.NO_SIGNAL,
        "profile_priority_proxy": broad and profile_match(rule, flags, delay),
    }


CHANNELS = ("prior_combined", "separate_warning", "ato_review", "profile_priority_proxy")
FALLBACK_CHANNELS = (*CHANNELS, "priority_with_missing_mfa_device")


def capture(projection, candidate, expected_candidate_sha, output, *, missing_evidence=False):
    cohort, first, last, rows, accounts = (
        ("missing-evidence", 20, 24, 866_564, 215_362)
        if missing_evidence
        else ("confirmation", 0, 19, ROWS, ACCOUNTS)
    )
    channels = FALLBACK_CHANNELS if missing_evidence else CHANNELS
    population = read(projection / "population.json")
    if (
        (projection / "completed").read_text(encoding="ascii").strip() != ARCHIVE_SHA
        or population["archive_sha256"] != ARCHIVE_SHA
        or (population["bucket_first"], population["bucket_last"], population["rows"])
        != (first, last, rows)
        or digest(candidate) != expected_candidate_sha
    ):
        raise ValueError("RBA confirmation inputs do not match the frozen scope")
    rule = read(candidate)["candidate"]["rule"]
    observations = projection / cohort / "observations.tsv"
    observation_sha = digest(observations)
    output.mkdir()
    plan_path, predictions = output / "plan.json", output / "predictions.tsv"
    write(
        plan_path,
        {
            "projection": population,
            "observations_sha256": observation_sha,
            "accounts": accounts,
            "candidate_sha256": expected_candidate_sha,
            "rule": rule,
            "channels": channels,
            "verified_mfa_available": False,
            "verified_device_available": False,
            "truth_read_by_capture": False,
        },
    )
    with predictions.open("xb") as stream:
        for ordinal, success, repeated, warning, flags, delay in observed_signals(
            observations, rows, accounts
        ):
            decision = decisions(success, repeated, warning, flags, delay, rule)
            if missing_evidence:
                review = assess_login(
                    warning=warning, success=success, environment_change=decision["ato_review"]
                )
                decision[FALLBACK_CHANNELS[-1]] = (
                    decision["profile_priority_proxy"]
                    or review.takeover is Takeover.PRIORITY_REVIEW
                )
            stream.write(
                b"\t".join(
                    (
                        ordinal,
                        b"%d" % repeated,
                        *(b"%d" % decision[channel] for channel in channels),
                    )
                )
                + b"\n"
            )
    if digest(observations) != observation_sha:
        raise ValueError("confirmation observations changed")
    write(
        output / "seal.json",
        {"plan_sha256": digest(plan_path), "prediction_sha256": digest(predictions)},
    )


def score(projection, output, expected_seal, *, missing_evidence=False):
    plan, predictions, seal_path = (
        output / name for name in ("plan.json", "predictions.tsv", "seal.json")
    )
    seal = read(seal_path)
    if (
        digest(seal_path) != expected_seal
        or digest(plan) != seal["plan_sha256"]
        or digest(predictions) != seal["prediction_sha256"]
    ):
        raise ValueError("RBA confirmation seal differs")
    cohort, expected_rows = (
        ("missing-evidence", 866_564) if missing_evidence else ("confirmation", ROWS)
    )
    channels = FALLBACK_CHANNELS if missing_evidence else CHANNELS
    plan_data = read(plan)
    if tuple(plan_data["channels"]) != channels or plan_data["projection"]["rows"] != expected_rows:
        raise ValueError("RBA seal has a different evaluation scope")
    result = {channel: counts() for channel in channels}
    warning_changes = lost_review = priority_demoted = 0
    restored = cleared_warnings = new_priority_fp = number = 0
    changes = added_fp = lost_tp = 0
    labels = projection / cohort / "truth.tsv"
    label_sha = digest(labels)
    with predictions.open("rb") as rows, labels.open("rb") as truth:
        for number, (row, label) in enumerate(zip(rows, truth, strict=True), 1):
            ordinal, original, *encoded = row.rstrip(b"\n").split(b"\t")
            label_ordinal, marked = label.rstrip(b"\n").split(b"\t")
            if ordinal != label_ordinal:
                raise ValueError("RBA confirmation truth alignment differs")
            expected = bit(marked)
            values = dict(zip(channels, map(bit, encoded), strict=True))
            for channel, prediction in values.items():
                record(result[channel], expected, prediction)
            warning = values["separate_warning"]
            review = values["ato_review"]
            priority = values["profile_priority_proxy"]
            warning_changes += (warning or review) != values["prior_combined"]
            lost_review += expected and values["prior_combined"] and not (warning or review)
            priority_demoted += expected and review and not priority
            restored += not expected and bit(original) and not warning and (review or priority)
            cleared_warnings += not expected and bit(original) and not warning
            new_priority_fp += not expected and priority and not review
            if missing_evidence:
                current = values[FALLBACK_CHANNELS[-1]]
                changes += current != priority
                added_fp += not expected and current and not priority
                lost_tp += expected and priority and not current
    if (
        number != expected_rows
        or digest(labels) != label_sha
        or digest(predictions) != seal["prediction_sha256"]
    ):
        raise ValueError("RBA confirmation data changed or is incomplete")
    write(
        output / "report.json",
        {
            "seal_sha256": expected_seal,
            "truth_sha256": label_sha,
            "groups": {name: metrics(value) for name, value in result.items()},
            "warning_or_review_changes_against_prior_combined": warning_changes,
            "lost_existing_detections_across_both_channels": lost_review,
            "ato_positives_kept_in_review_instead_of_priority": priority_demoted,
            "restored_previously_cleared_false_positives": restored,
            "previously_cleared_repeated_warnings_on_unmarked_rows": cleared_warnings,
            "new_priority_false_positives_outside_broad_ato_review": new_priority_fp,
            "mfa_or_device_authoritative_metrics_measured": False,
            "candidate_adopted": False,
            **(
                {
                    "missing_evidence_regression": {
                        "rows_changed": changes,
                        "new_false_positives": added_fp,
                        "lost_true_positives": lost_tp,
                        "authoritative_evidence_coverage": 0,
                    }
                }
                if missing_evidence
                else {}
            ),
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode, extras in (
        ("freeze", (("reviewed", Path), ("previous_holdout", Path))),
        ("capture", (("candidate", Path), ("expected_candidate_sha", str))),
        ("score", (("expected_seal", str),)),
    ):
        command = sub.add_parser(mode)
        command.add_argument("projection", type=Path)
        command.add_argument("output", type=Path)
        for name, kind in extras:
            command.add_argument(name, type=kind)
        if mode != "freeze":
            command.add_argument("--missing-evidence", action="store_true")
    args = parser.parse_args()
    if args.mode == "freeze":
        freeze(args.projection, args.reviewed, args.previous_holdout, args.output)
    elif args.mode == "capture":
        capture(
            args.projection,
            args.candidate,
            args.expected_candidate_sha,
            args.output,
            missing_evidence=args.missing_evidence,
        )
    else:
        score(
            args.projection, args.output, args.expected_seal, missing_evidence=args.missing_evidence
        )


if __name__ == "__main__":
    main()
