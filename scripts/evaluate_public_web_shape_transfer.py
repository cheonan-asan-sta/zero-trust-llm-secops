"""Test whether legitimate traffic improves a request-shape model's transfer."""

import argparse
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_fpad_crs import DATASETS, source_rows
from scripts.evaluate_public_legitimate_web_crs import (
    HOLDOUT_ROWS,
    HOLDOUT_SHA,
    RECEIPT_SHA,
    ROWS,
    request_rows,
)
from scripts.evaluate_public_post_body_shape import group_key, text_shape
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical

TRAIN_SHA = "e450fd0a0de45e5ce29053b82573e703be5e30cf8e29f02a770fa27f60fef908"
THRESHOLD = 0.95
PARAMETERS = {"n_estimators": 128, "min_samples_leaf": 3, "max_features": .75, "random_state": 42, "n_jobs": 3}
MODES = ("publisher_training_only", "with_legitimate_development")
SPLITS = ("fpad", "fpad-ood", "legitimate")


def features(target, body):
    if len(target.encode()) > 16384 or len(body.encode()) > 1048576:
        return None
    return [*text_shape(target), *text_shape(body)]


def observed_host(row):
    values = [value for key, value in row["headers"].items() if key.casefold() == "host"]
    if len(values) != 1 or not isinstance(values[0], str):
        return None
    try:
        host = urlsplit("//" + values[0]).hostname
    except ValueError:
        return None
    return host.rstrip(".").casefold() if host else None


def publisher_truth(row):
    if type(row["label"]) is not int or row["label"] not in range(5):
        raise ValueError("unrecognized FPAD class label")
    return row["label"] != 0


def training_groups(examples):
    groups, skipped = {}, 0
    for target, body, truth in examples:
        value = features(target, body)
        if value is None:
            skipped += 1
            continue
        key = group_key(target, body)
        groups.setdefault(key, (value, set()))[1].add(truth)
    return groups, skipped


def fit(groups):
    from sklearn.ensemble import ExtraTreesClassifier

    examples = [(vector, next(iter(labels))) for vector, labels in groups.values() if len(labels) == 1]
    x, y = zip(*examples, strict=True)
    return ExtraTreesClassifier(**PARAMETERS).fit(x, y), len(y)


def capture(path, observed, groups, known_hosts, models):
    projections = [(group_key(target, body) in groups, host is not None and host not in known_hosts,
                    features(target, body)) for target, body, host in observed]
    # All rows retain their original index, including rows too large for the candidate.
    x = [vector for _, _, vector in projections if vector is not None]
    passed = [iter(model.predict_proba(x)[:, 1] >= THRESHOLD) for model in models]
    with path.open("xb") as stream:
        for ordinal, (overlap, unseen_host, vector) in enumerate(projections, 1):
            record_out = {"ordinal": ordinal, "training_overlap": overlap, "unseen_host": unseen_host}
            record_out.update({mode: bool(next(values)) if vector is not None else None
                               for mode, values in zip(MODES, passed, strict=True)})
            stream.write(canonical(record_out) + b"\n")


def load_crs(directory, split):
    seal_path = directory / "seal.json"
    seal = read(seal_path)
    if split == "legitimate":
        if seal["source_receipt_sha256"] != HOLDOUT_SHA:
            raise ValueError("CRS results use a different legitimate sample")
        path, expected = directory / "target.jsonl", seal["predictions_sha256"]["target"]
        expected_rows = HOLDOUT_ROWS
    else:
        plan_path = directory / "plan.json"
        plan = read(plan_path)
        source_sha, expected_rows = DATASETS[split]
        if (fingerprint(plan_path) != seal["plan_sha256"] or plan["split"] != split
                or plan["source_sha256"] != source_sha):
            raise ValueError("CRS results use a different FPAD split")
        path, expected = directory / "predictions.jsonl", seal["predictions_sha256"]
    if fingerprint(path) != expected:
        raise ValueError("CRS prediction seal mismatch")
    with path.open("rb") as stream:
        values = []
        for ordinal, row in enumerate(map(json.loads, stream), 1):
            if row["ordinal"] != ordinal or (row["alert"] is not None and type(row["alert"]) is not bool):
                raise ValueError("CRS prediction order changed")
            values.append(row["alert"])
    if len(values) != expected_rows:
        raise ValueError("unexpected CRS population")
    return values, fingerprint(seal_path)


def score(path, labels, split, crs=None):
    modes = (*MODES, "crs_target", "crs_or_legitimate_model") if crs is not None else MODES
    cohorts = {"all": {mode: counts() for mode in modes}}
    if split == "legitimate":
        cohorts["unseen_host"] = {mode: counts() for mode in modes}
    scope = Counter()
    changes = Counter()
    fusion = Counter()
    with path.open("rb") as stream:
        for ordinal, (line, truth) in enumerate(zip(stream, labels, strict=True), 1):
            row = json.loads(line)
            if row["ordinal"] != ordinal:
                raise ValueError("shape prediction order changed")
            scope["total_rows"] += 1
            if row["training_overlap"]:
                scope["exact_training_overlap"] += 1
                continue
            before, after = (row[mode] for mode in MODES)
            if before is False and after is True:
                changes["new_true_positives" if truth else "new_false_positives"] += 1
            if before is True and after is False:
                changes["lost_true_positives" if truth else "resolved_false_positives"] += 1
            if crs is not None:
                fixed = crs[ordinal - 1]
                merged = None
                if after is True or fixed is True:
                    merged = True
                elif after is False and fixed is False:
                    merged = False
                row.update(crs_target=fixed, crs_or_legitimate_model=merged)
                if fixed is False and merged is True:
                    fusion["additional_true_positives" if truth else "new_false_positives"] += 1
                if truth and before is True and merged is not True:
                    fusion["lost_vs_publisher_shape"] += 1
            for mode in modes:
                record(cohorts["all"][mode], truth, row[mode])
                if split == "legitimate" and row["unseen_host"]:
                    record(cohorts["unseen_host"][mode], truth, row[mode])
    if crs is not None and len(crs) != scope["total_rows"]:
        raise ValueError("CRS observation count changed")
    results = {name: {mode: metrics(value) for mode, value in groups.items()} for name, groups in cohorts.items()}
    if split != "fpad":
        limited = ("precision", "recall", "f1") if split == "legitimate" else ("precision", "f1", "false_positive_rate")
        for modes in results.values():
            for values in modes.values():
                values.update(dict.fromkeys(limited))
    return {"scope": dict(scope), "results": results, "changes": dict(changes), "crs_fusion": dict(fusion)}


def run(fpad, legitimate_dev, legitimate_holdout, output, crs_directories=None):
    from sklearn import __version__ as sklearn_version
    from threadpoolctl import threadpool_limits

    train = fpad / "fpad-train.jsonl"
    if fingerprint(train) != TRAIN_SHA:
        raise ValueError("FPAD training fingerprint changed")
    with train.open("rb") as stream:
        publisher = [(row["url"], row["body"], publisher_truth(row)) for row in map(json.loads, stream)]
    development = list(request_rows(legitimate_dev, receipt_sha=RECEIPT_SHA, expected_rows=ROWS))
    holdout = list(request_rows(legitimate_holdout, receipt_sha=HOLDOUT_SHA, expected_rows=HOLDOUT_ROWS))
    if read(legitimate_holdout / "plan.json")["development_plan_sha256"] != fingerprint(legitimate_dev / "plan.json"):
        raise ValueError("legitimate holdout was selected against a different development population")

    normals = [(row["url"], row["data"], False) for row in development]
    hosts = {observed_host(row) for row in development}
    old_groups, old_skipped = training_groups(publisher)
    new_groups, new_skipped = training_groups(publisher + normals)
    output.mkdir()
    paths = {split: output / f"{split}.jsonl" for split in SPLITS}
    with threadpool_limits(limits=3):
        old, old_count = fit(old_groups)
        new, new_count = fit(new_groups)
        for split, path in paths.items():
            if split == "legitimate":
                rows = ((row["url"], row["data"], observed_host(row)) for row in holdout)
            else:
                rows = ((row["url"], row["body"], None) for row in source_rows(fpad / f"{split}-test.jsonl", split))
            capture(path, rows, new_groups, hosts, (old, new))

    references = {split: load_crs(directory, split) for split, directory in zip(
        SPLITS, crs_directories, strict=True
    )} if crs_directories else {}
    plan = output / "plan.json"
    write(plan, {"training_sha256": TRAIN_SHA, "legitimate_development_receipt": RECEIPT_SHA,
                 "legitimate_holdout_receipt": HOLDOUT_SHA, "threshold": THRESHOLD, "scikit_learn": sklearn_version,
                 "parameters": PARAMETERS, "old_groups_used": old_count, "new_groups_used": new_count,
                 "old_skipped": old_skipped, "new_skipped": new_skipped,
                 "crs_reference_seals": {split: proof for split, (_, proof) in references.items()},
                 "features": "bounded body and target character shape; host used only for reporting"})
    digests = {split: fingerprint(path) for split, path in paths.items()}
    seal = output / "seal.json"
    write(seal, {"plan_sha256": fingerprint(plan), "predictions_sha256": digests,
                 "evaluator_sha256": fingerprint(Path(__file__))})
    reports = {}
    for split, path in paths.items():
        truth = ((False for _ in holdout) if split == "legitimate" else (
            publisher_truth(row) for row in source_rows(fpad / f"{split}-test.jsonl", split)
        ))
        observations, _ = references.get(split, (None, None))
        reports[split] = score(path, truth, split, observations)
        if fingerprint(path) != digests[split]:
            raise ValueError("sealed shape prediction changed")
    write(output / "report.json", {"plan": read(plan), "seal_sha256": fingerprint(seal), "tests": reports})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fpad", "legitimate_dev", "legitimate_holdout", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--crs", nargs=3, type=Path, metavar=("FPAD", "OOD", "LEGITIMATE"))
    args = parser.parse_args()
    run(args.fpad, args.legitimate_dev, args.legitimate_holdout, args.output, args.crs)


if __name__ == "__main__":
    main()
