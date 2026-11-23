"""Time- and duplicate-separated SR-BH POST body comparison (observed source)."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier
from threadpoolctl import threadpool_limits

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_successful_post import (
    file_digests,
    published_truth,
    selected,
    source_rows,
)
from scripts.f1_lab.native_bayes import counts, metrics, record

DAYS = {"17/Jul/2020": "development", "18/Jul/2020": "calibration", "19/Jul/2020": "temporal"}
MARKS = tuple("?&=%/[]{}'\"\\,:;+-_*#@$!()")


def group_key(target, body):
    return hashlib.sha256(json.dumps([target, body], ensure_ascii=False).encode()).hexdigest()


def text_shape(value):
    symbols = Counter(value)
    return [
        len(value),
        len(symbols),
        sum(n for char, n in symbols.items() if char.isdigit()),
        sum(n for char, n in symbols.items() if char.isalpha()),
        sum(n for char, n in symbols.items() if char.isspace()),
        sum(n for char, n in symbols.items() if ord(char) > 127),
        max(symbols.values(), default=0),
        *[symbols[char] for char in MARKS],
    ]


def load_features(source):
    cohorts = defaultdict(list)
    for ordinal, row, _ in source_rows(source):
        if row is None or not selected(row):
            continue
        day = row["timestamp"][:11]
        cohort = DAYS.get(day)
        if cohort is None:
            raise ValueError("unexpected target day")
        target, body = row["request_http_request"], row["request_body"]
        try:
            parsed = urlsplit(target)
            depth = parsed.path.count("/")
        except ValueError:
            depth = -1
        features = [
            int(row["response_http_status_code"]),
            depth,
            *text_shape(target),
            *text_shape(body),
        ]
        cohorts[cohort].append((ordinal, group_key(target, body), features))
    return cohorts


def ordinary_labels(source, ordinals):
    truth = {}
    for ordinal, _, flags in source_rows(source, include_truth=True):
        if ordinal in ordinals:
            label = published_truth(flags)
            if label is None:
                raise ValueError("selected POST label is ambiguous")
            truth[ordinal] = label
    if set(truth) != ordinals:
        raise ValueError("missing labels")
    return truth


def measurements(scores, cases, truth, baseline, threshold):
    values = counts()
    new_fp = lost_tp = 0
    for (ordinal, _, _), probability in zip(cases, scores, strict=True):
        expected = truth[ordinal]
        prediction = bool(probability >= threshold)
        old = baseline[ordinal]
        record(values, expected, prediction)
        new_fp += not expected and old is False and prediction
        lost_tp += expected and old is True and not prediction
    return {**metrics(values), "new_false_positives": new_fp, "lost_true_positives": lost_tp}


def choose(calibration, probabilities, truth, baseline):
    ranked = []
    for cut in np.linspace(0, 1, 101):
        scored = measurements(probabilities, calibration, truth, baseline, cut)
        qualified = (
            scored["precision"] is not None
            and scored["precision"] >= 0.95
            and scored["recall"] >= 0.95
            and scored["f1"] >= 0.95
            and scored["false_positive_rate"] <= 0.05
            and scored["new_false_positives"] == scored["lost_true_positives"] == 0
        )
        value = (
            qualified,
            scored["f1"],
            -scored["false_positive_rate"],
            -scored["lost_true_positives"],
            float(cut),
        )
        ranked.append((value, scored))
    return max(ranked, key=lambda row: row[0])


def run(source, native, output, source_sha):
    output.mkdir()
    groups = load_features(source)
    temporal = groups["temporal"]
    temporal_keys = {key for _, key, _ in temporal}
    calibration = [row for row in groups["calibration"] if row[1] not in temporal_keys]
    other_keys = temporal_keys | {key for _, key, _ in calibration}
    development = [row for row in groups["development"] if row[1] not in other_keys]
    expected = {row[0] for row in development + calibration}
    truth = ordinary_labels(source, expected)
    native_path = native / "predictions.jsonl"
    native_seal = read(native / "seal.json")
    if fingerprint(native_path) != native_seal["predictions_sha256"]:
        raise ValueError("invalid native reference")
    with native_path.open("rb") as stream:
        baseline = {row["ordinal"]: row["before"] for row in map(json.loads, stream)}
    train_labels = [truth[row[0]] for row in development]
    if len(set(train_labels)) != 2 or len({truth[row[0]] for row in calibration}) != 2:
        raise ValueError("both labels required in development and calibration")
    model = ExtraTreesClassifier(
        n_estimators=128, min_samples_leaf=3, max_features=0.75, random_state=42, n_jobs=3
    )
    with threadpool_limits(limits=3):
        model.fit([row[2] for row in development], train_labels)
        cal_prob = model.predict_proba([row[2] for row in calibration])[:, 1]
        ranking, cal_values = choose(calibration, cal_prob, truth, baseline)
        threshold = ranking[-1]
        predict = model.predict_proba([row[2] for row in temporal])[:, 1]
    write(
        output / "plan.json",
        {
            "source_sha256": source_sha,
            "development_dates": ["17/Jul/2020"],
            "calibration_dates": ["18/Jul/2020"],
            "temporal_dates": ["19/Jul/2020"],
            "observation": "generic bounded shape of request target and body; only response status retained",
            "model": "ExtraTreesClassifier 128, min_samples_leaf=3, max_features=.75, seed=42",
            "threshold": threshold,
            "qualified_in_calibration": ranking[0],
            "calibration_metrics": cal_values,
            "input": {key: len(value) for key, value in groups.items()},
            "used": {
                "development": len(development),
                "calibration": len(calibration),
                "temporal": len(temporal),
            },
            "fit_label_counts": dict(
                Counter("threat" if flag else "normal" for flag in train_labels)
            ),
            "frozen_at": datetime.now(UTC).isoformat(timespec="seconds"),
        },
    )
    path = output / "predictions.json"
    write(
        path,
        [
            {"ordinal": row[0], "score": float(prob)}
            for row, prob in zip(temporal, predict, strict=True)
        ],
    )
    seal = fingerprint(path)
    write(
        output / "seal.json",
        {"predictions_sha256": seal, "plan_sha256": fingerprint(output / "plan.json")},
    )
    final_labels = ordinary_labels(source, {case[0] for case in temporal})
    assert fingerprint(path) == seal
    stored = read(path)
    if [row["ordinal"] for row in stored] != [row[0] for row in temporal]:
        raise ValueError("temporal predictions reordered")
    current = counts()
    for row in temporal:
        record(current, final_labels[row[0]], baseline[row[0]])
    report = measurements(
        [row["score"] for row in stored], temporal, final_labels, baseline, threshold
    )
    write(
        output / "report.json",
        {
            "prediction_sha256": seal,
            "native": metrics(current),
            "candidate": report,
            "claims_independent_source": False,
            "candidate_adopted": False,
        },
    )


if __name__ == "__main__":
    import csv

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("native", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    csv.field_size_limit(1_048_576)
    run(args.source, args.native, args.output, file_digests(args.source))
