"""Fit a local POST review candidate on request shape and CRS rule IDs."""

import argparse
import csv
import json
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_post_body_shape import (
    choose,
    load_features,
    measurements,
    ordinary_labels,
    split_by_date,
)
from scripts.evaluate_public_post_crs import baseline
from scripts.evaluate_public_successful_post import file_digests


def load_crs(directory, source_sha, native_sha, *, with_rules):
    seal_file = directory / "seal.json"
    seal = read(seal_file)
    predictions = directory / "crs-predictions.jsonl"
    if (
        seal["source_sha256"] != source_sha
        or seal["reference_sha256"] != native_sha
        or seal.get("attack_rule_ids", False) is not with_rules
        or fingerprint(predictions) != seal["predictions_sha256"]
    ):
        raise ValueError("CRS evidence failed seal verification")
    values = {}
    with predictions.open("rb") as stream:
        for line in stream:
            row = json.loads(line)
            ordinal, alert, rule_ids = row["ordinal"], row["alert"], row.get("rule_ids", [])
            if (
                type(ordinal) is not int
                or ordinal < 1
                or ordinal in values
                or type(alert) is not bool
                or not isinstance(rule_ids, list)
                or any(
                    type(rule) is not int or not 900_000 <= rule < 1_000_000 for rule in rule_ids
                )
                or rule_ids != sorted(set(rule_ids))
                or (rule_ids and not with_rules)
            ):
                raise ValueError("invalid or unavailable CRS decision")
            values[ordinal] = (alert, frozenset(rule_ids))
    return values, fingerprint(seal_file)


def compare_reference(native, reference, observed):
    if not (native.keys() == reference.keys() == observed.keys()):
        raise ValueError("CRS and native populations differ")
    if any(reference[ordinal][0] != observed[ordinal][0] for ordinal in reference):
        raise ValueError("collecting rule IDs changed an existing CRS decision")


def design(cases, rule_ids, vocabulary):
    return [
        [*shape, *[rule in rule_ids[ordinal] for rule in vocabulary]] for ordinal, _, shape in cases
    ]


def candidate_scores(model, cases, rule_ids, vocabulary, crs):
    probabilities = model.predict_proba(design(cases, rule_ids, vocabulary))[:, 1]
    return [
        1.0 if crs[case[0]] else float(score)
        for case, score in zip(cases, probabilities, strict=True)
    ]


def fit_and_check(source, original, original_crs, captured, output):
    from sklearn import __version__ as sklearn_version
    from sklearn.ensemble import ExtraTreesClassifier
    from threadpoolctl import threadpool_limits

    source_sha = file_digests(source)
    native, native_sha = baseline(original)
    if read(original / "plan.json")["source_sha256"] != source_sha:
        raise ValueError("native evidence source differs")
    reference, reference_sha = load_crs(original_crs, source_sha, native_sha, with_rules=False)
    observed, observed_sha = load_crs(captured, source_sha, native_sha, with_rules=True)
    compare_reference(native, reference, observed)
    before = {ordinal: row["before"] for ordinal, row in native.items()}
    crs = {ordinal: alert for ordinal, (alert, _) in observed.items()}
    union = {ordinal: before[ordinal] or alert for ordinal, alert in crs.items()}
    rule_ids = {ordinal: rules for ordinal, (_, rules) in observed.items()}

    groups = load_features(source)
    if {ordinal for cases in groups.values() for ordinal, _, _ in cases} != native.keys():
        raise ValueError("CRS evidence and feature populations differ")
    development, calibration, temporal = split_by_date(groups)
    truth = ordinary_labels(source, {row[0] for row in development + calibration})
    fit_labels = [truth[row[0]] for row in development]
    if len(set(fit_labels)) != 2 or len({truth[row[0]] for row in calibration}) != 2:
        raise ValueError("both labels are required for fitting and calibration")
    vocabulary = sorted(set().union(*(rule_ids[row[0]] for row in development)))
    if not vocabulary:
        raise ValueError("no development CRS rules observed")
    model = ExtraTreesClassifier(
        n_estimators=128, min_samples_leaf=3, max_features=0.75, random_state=42, n_jobs=3
    )

    with threadpool_limits(limits=3):
        model.fit(design(development, rule_ids, vocabulary), fit_labels)
        raw = candidate_scores(model, calibration, rule_ids, vocabulary, crs)
        ranking, calibrated = choose(calibration, raw, truth, union)
        predictions = candidate_scores(model, temporal, rule_ids, vocabulary, crs)
    threshold = ranking[-1]

    output.mkdir()
    plan_file = output / "plan.json"
    prediction_file = output / "predictions.json"
    write(
        plan_file,
        {
            "source_sha256": source_sha,
            "native_seal_sha256": native_sha,
            "original_crs_seal_sha256": reference_sha,
            "rule_crs_seal_sha256": observed_sha,
            "original_crs_alerts_identical": len(observed),
            "days": {
                "development": "2020-07-17",
                "calibration": "2020-07-18",
                "diagnostic": "2020-07-19",
            },
            "sizes": {
                "development": len(development),
                "calibration": len(calibration),
                "diagnostic": len(temporal),
            },
            "training_rule_ids": vocabulary,
            "model": model.get_params(),
            "scikit_learn": sklearn_version,
            "threshold": threshold,
            "qualified_in_calibration": ranking[0],
            "calibration_candidate_against_native_or_crs": calibrated,
        },
    )
    write(
        prediction_file,
        [
            {"ordinal": row[0], "score": probability}
            for row, probability in zip(temporal, predictions, strict=True)
        ],
    )
    seal = {
        "plan_sha256": fingerprint(plan_file),
        "predictions_sha256": fingerprint(prediction_file),
    }
    write(output / "seal.json", seal)
    expected = ordinary_labels(source, {row[0] for row in temporal})
    if fingerprint(prediction_file) != seal["predictions_sha256"]:
        raise ValueError("sealed diagnostic predictions changed")
    predictions = read(prediction_file)
    if [row["ordinal"] for row in predictions] != [row[0] for row in temporal]:
        raise ValueError("diagnostic prediction rows differ")

    write(
        output / "report.json",
        {
            **seal,
            "source_role": "previously examined source; time- and duplicate-separated development diagnostic",
            "candidate_adopted": False,
            "modes": {
                **{
                    name: measurements(
                        [mapping[row[0]] for row in temporal], temporal, expected, union, 0.5
                    )
                    for name, mapping in (
                        ("native", before),
                        ("crs", crs),
                        ("native_or_crs", union),
                    )
                },
                "crs_or_rule_shape": measurements(
                    [row["score"] for row in predictions], temporal, expected, union, threshold
                ),
            },
        },
    )
    return model, vocabulary, threshold


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument("original_crs", type=Path)
    parser.add_argument("capture_with_rules", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    csv.field_size_limit(1_048_576)
    fit_and_check(
        args.source, args.original, args.original_crs, args.capture_with_rules, args.output
    )
