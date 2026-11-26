"""Calibrate on development sources and evaluate the frozen model on PKDD."""

import argparse
import json
import subprocess
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_legitimate_web_crs import BINARY_SHA, RECEIPT_SHA, ROWS, request_rows
from scripts.evaluate_public_post_body_shape import group_key
from scripts.evaluate_public_web_shape_transfer import (
    PARAMETERS,
    TRAIN_SHA,
    features,
    fit,
    publisher_truth,
    training_groups,
)
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical

PKDD_SHA = "b2a9a4cda4dff600bd9012b21fceedadd1821937329a98321142698b65a6bf2c"
PKDD_ROWS = 10_024
LEGITIMATE_FIT_ROWS = 8_823  # The first nine of the twelve pinned development files.
MODES = ("fixed", "calibrated", "crs", "crs_or_calibrated")


def development_groups(train, legitimate):
    if fingerprint(train) != TRAIN_SHA:
        raise ValueError("FPAD training source changed")
    train_fpad, calibrate_fpad = [], []
    with train.open("rb") as stream:
        for row in map(json.loads, stream):
            example = (row["url"], row["body"], publisher_truth(row))
            key = group_key(example[0], example[1])
            split = calibrate_fpad if int(key[:8], 16) % 5 == 0 else train_fpad
            split.append(example)
    normals = [(row["url"], row["data"], False)
               for row in request_rows(legitimate, receipt_sha=RECEIPT_SHA, expected_rows=ROWS)]
    groups, skipped = training_groups(train_fpad + normals[:LEGITIMATE_FIT_ROWS])
    calibration = {"fpad": calibrate_fpad, "legitimate": normals[LEGITIMATE_FIT_ROWS:]}
    used = {group_key(target, body) for target, body, _ in train_fpad + calibrate_fpad + normals}
    return groups, skipped, calibration, used


def calibration_result(model, groups, calibration):
    scores = {}
    for split, examples in calibration.items():
        projected = [(features(target, body), truth) for target, body, truth in examples
                     if group_key(target, body) not in groups]
        inputs = [(vector, truth) for vector, truth in projected if vector is not None]
        scores[split] = zip(model.predict_proba([vector for vector, _ in inputs])[:, 1],
                            [truth for _, truth in inputs], strict=True)
    scores = {split: list(rows) for split, rows in scores.items()}
    eligible = []
    for step in range(100, 201):
        threshold = step / 200
        totals = {name: counts() for name in scores}
        for name, rows in scores.items():
            for probability, truth in rows:
                record(totals[name], truth, bool(probability >= threshold))
        summary = {name: metrics(values) for name, values in totals.items()}
        fpad, normal = summary["fpad"], summary["legitimate"]
        if (normal["false_positive_rate"] <= .01 and fpad["false_positive_rate"] <= .05
                and fpad["precision"] is not None and fpad["precision"] >= .95):
            rank = (fpad["recall"], fpad["f1"], -normal["false_positive_rate"], threshold)
            eligible.append((rank, summary))
    if not eligible:
        raise ValueError("no threshold meets the development constraints")
    rank, summary = max(eligible, key=lambda candidate: candidate[0])
    summary["legitimate"].update(precision=None, f1=None, recall=None)
    return rank[-1], summary


def capture(pkdd, output, binary, model, threshold, used):
    if fingerprint(pkdd) != PKDD_SHA or fingerprint(binary) != BINARY_SHA:
        raise ValueError("unexpected PKDD source or CRS executable")
    with pkdd.open("rb") as stream:
        rows = [(row["method"], row["url"], row["body"]) for row in map(json.loads, stream)]
    if len(rows) != PKDD_ROWS:
        raise ValueError("unexpected PKDD population")
    requests = (canonical({"ordinal": index, "method": method, "target": target}) + b"\n"
                for index, (method, target, _) in enumerate(rows, 1))
    raw = subprocess.run([str(binary.resolve()), "--target-only"], input=b"".join(requests),
                         check=True, stdout=subprocess.PIPE).stdout
    matches = map(json.loads, raw.splitlines())
    shapes = [features(target, body) for _, target, body in rows]
    probabilities = iter(model.predict_proba([shape for shape in shapes if shape is not None])[:, 1])
    with output.open("xb") as stream:
        for index, ((_, target, body), shape, observed) in enumerate(zip(rows, shapes, matches, strict=True), 1):
            if observed["ordinal"] != index:
                raise ValueError("CRS changed PKDD row order")
            probability = float(next(probabilities)) if shape is not None else None
            fixed = probability >= .95 if probability is not None else None
            adjusted = probability >= threshold if probability is not None else None
            crs = observed["alert"]
            merged = True if adjusted is True or crs is True else None
            if adjusted is False and crs is False:
                merged = False
            stream.write(canonical({"ordinal": index, "overlap": group_key(target, body) in used,
                                    "fixed": fixed, "calibrated": adjusted, "crs": crs,
                                    "crs_or_calibrated": merged}) + b"\n")


def score(pkdd, predictions, expected_sha):
    if fingerprint(pkdd) != PKDD_SHA or fingerprint(predictions) != expected_sha:
        raise ValueError("PKDD scoring seal changed")
    totals, excluded = {mode: counts() for mode in MODES}, 0
    with pkdd.open("rb") as truth, predictions.open("rb") as observed:
        for index, (row, predicted) in enumerate(zip(map(json.loads, truth), map(json.loads, observed), strict=True), 1):
            if predicted["ordinal"] != index or type(row["label"]) is not int or row["label"] not in range(8):
                raise ValueError("PKDD labels and prediction rows differ")
            excluded += predicted["overlap"]
            if not predicted["overlap"]:
                for mode in MODES:
                    record(totals[mode], row["label"] != 0, predicted[mode])
    return {"excluded_training_overlap": excluded, "scores": {name: metrics(v) for name, v in totals.items()}}


def run(train, legitimate, pkdd, output, binary):
    from sklearn import __version__ as sklearn_version
    from threadpoolctl import threadpool_limits

    groups, skipped, calibration, used = development_groups(train, legitimate)
    output.mkdir()
    predictions = output / "predictions.jsonl"
    with threadpool_limits(limits=3):
        model, fit_rows = fit(groups)
        threshold, development = calibration_result(model, groups, calibration)
        plan = output / "plan.json"
        write(plan, {"fit_rows": fit_rows, "skipped_fit_rows": skipped, "threshold": threshold,
                     "calibration": development, "scikit_learn": sklearn_version, "parameters": PARAMETERS,
                     "training_sha256": TRAIN_SHA, "normal_receipt_sha256": RECEIPT_SHA,
                     "pkdd_source_sha256": PKDD_SHA, "binary_sha256": BINARY_SHA})
        capture(pkdd, predictions, binary, model, threshold, used)
    seal, prediction_sha = output / "seal.json", fingerprint(predictions)
    write(seal, {"plan_sha256": fingerprint(plan), "predictions_sha256": prediction_sha,
                 "evaluator_sha256": fingerprint(Path(__file__))})
    results = score(pkdd, predictions, prediction_sha)
    write(output / "report.json", {"seal_sha256": fingerprint(seal), "plan": read(plan), "pkdd": results})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("train", "legitimate", "pkdd", "output", "binary"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    run(args.train, args.legitimate, args.pkdd, args.output, args.binary)


if __name__ == "__main__":
    main()
