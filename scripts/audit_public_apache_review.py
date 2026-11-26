"""Diagnose alert review cohorts against an existing sealed Apache evaluation."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile

import yaml

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_apache_transfer import (
    LABEL_MEMBER,
    SOURCE_SHA,
    THRESHOLD,
    frozen_model,
    records,
)
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_context import extra_observations, ordered_http_context
from scripts.f1_lab.raw_observations import REQUEST, raw_features, raw_time
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.web_post_refinement import SuccessfulPostRefinement
from scripts.f1_lab.web_residual import ACCESS, WebResidualRefinement, build_evidence
from scripts.f1_lab.web_sensitive_read import evidence, refine

COHORTS = {"GET_3xx": ("GET", 3), "HEAD_3xx": ("HEAD", 3), "POST_2xx": ("POST", 2)}
BY_METHOD_STATUS = {value: key for key, value in COHORTS.items()}


def auditor_sha256():
    return hashlib.sha256(Path(__file__).read_text(encoding="utf-8").encode()).hexdigest()


def sealed_evaluation(original):
    seal = read(original / "seal.json")
    plan_path = original / "plan.json"
    plan = read(plan_path)
    if (
        plan["archive_sha256"] != SOURCE_SHA
        or fingerprint(plan_path) != seal["plan_sha256"]
        or fingerprint(original / "predictions.jsonl") != seal["prediction_sha256"]
        or plan["members"] != [item["member"] for item in seal["media"]]
    ):
        raise ValueError("Apache reference is not sealed")
    return seal, plan


def paired_rows(source, original, seal):
    """Consume the reference in exact archive member and ordinal order."""
    with ZipFile(source) as archive, (original / "predictions.jsonl").open("rb") as prediction:
        for member in seal["media"]:
            rows, digest = records(archive, member["member"])
            if len(rows) != member["rows"] or digest != member["sha256"]:
                raise ValueError("Apache input changed")
            joined = []
            for ordinal, line in enumerate(rows, 1):
                entry = json.loads(prediction.readline())
                case = hashlib.sha256(f"{digest}:{ordinal}".encode()).hexdigest()
                if entry["case_id"] != case:
                    raise ValueError("Apache predictions are not aligned")
                joined.append((ordinal, line, entry))
            yield digest, joined
        if prediction.read(1):
            raise ValueError("extra Apache reference predictions")


def predict_member(digest, joined, model, residual, post):
    timed = [
        (ordinal, raw_time(line, 1735689600, 1767225600, source_timezone="UTC"), line)
        for ordinal, line, _ in joined
    ]
    windows = ordered_http_context(timed)
    review = build_evidence(timed, "access", digest)
    scores = {}
    for ordinal, line, old in joined:
        request = REQUEST.search(line)
        if request is None:
            raise ValueError("reference included an unparsable request")
        cohort = BY_METHOD_STATUS.get((request[1], int(request[3]) // 100), "other")
        candidate = old["after"]
        group = None
        if candidate is True and cohort != "other":
            features = {**raw_features(line), **extra_observations(line), **semantic_observations(line),
                        **windows[ordinal]}
            key = canonical(features)
            if key not in scores:
                scores[key] = model.web_model.probability(features)
            base = scores[key]
            hit = base >= THRESHOLD
            decision = OperationDecision(base, base, hit, hit, "unchanged")
            decision = residual.refine(decision, features, old["case_id"], review.get(old["case_id"]))
            decision = refine(decision, features, old["case_id"], evidence(line, digest, ordinal))
            if hit != old["before"] or decision.alert != old["after"]:
                raise ValueError("Apache reference decision did not reproduce")
            candidate = post.refine(decision, features).alert if cohort == "POST_2xx" else decision.alert
            group = hashlib.sha256(key).hexdigest()
        yield {"case_id": old["case_id"], "cohort": cohort, "base": old["after"],
               "post_candidate": candidate, "group": group,
               "combined_format": ACCESS.fullmatch(line) is not None}


def capture(source, original, output):
    reference, plan = sealed_evaluation(original)
    model, pins = frozen_model()
    if pins != plan["model_pins"]:
        raise ValueError("current web model pins differ from the Apache reference")
    post = SuccessfulPostRefinement(model.web_model)
    residual = WebResidualRefinement(model)
    output.mkdir()
    path = output / "diagnostic.jsonl"
    with path.open("xb") as stream:
        for digest, joined in paired_rows(source, original, reference):
            for row in predict_member(digest, joined, model, residual, post):
                stream.write(canonical(row) + b"\n")
    write(output / "seal.json", {
        "capture_sha256": fingerprint(path),
        "reference_sha256": fingerprint(original / "seal.json"),
        "source_sha256": SOURCE_SHA,
        "frozen_model_commit": plan["candidate_commit"],
        "auditor_sha256": auditor_sha256(),
    })


def score(source, original, output, expected_sha256):
    reference, _ = sealed_evaluation(original)
    path = output / "diagnostic.jsonl"
    seal_file = output / "seal.json"
    seal = read(seal_file)
    if (
        fingerprint(seal_file) != expected_sha256
        or seal["source_sha256"] != SOURCE_SHA or seal["auditor_sha256"] != auditor_sha256()
        or fingerprint(original / "seal.json") != seal["reference_sha256"]
        or fingerprint(path) != seal["capture_sha256"]
    ):
        raise ValueError("Apache diagnostic seal mismatch")

    groups = defaultdict(Counter)
    cohorts = defaultdict(counts)
    coverage = Counter()
    baseline, candidate = counts(), counts()
    new_fp = lost_tp = 0
    with ZipFile(source) as archive:
        rules = [entry["filter"] for entry in yaml.safe_load(archive.read(LABEL_MEMBER))]
    with path.open("rb") as diagnostic:
        for _, joined in paired_rows(source, original, reference):
            for _, line, old in joined:
                row = json.loads(diagnostic.readline())
                if row["case_id"] != old["case_id"] or row["base"] is not old["after"]:
                    raise ValueError("Apache diagnostic rows do not match reference")
                truth = any(all(term in line for term in terms) for terms in rules)
                current, forecast = row["base"], row["post_candidate"]
                record(baseline, truth, current)
                record(candidate, truth, forecast)
                record(cohorts[row["cohort"]], truth, current)
                new_fp += not truth and current is False and forecast is True
                lost_tp += truth and current is True and forecast is not True
                coverage[row["cohort"]] += row["combined_format"]
                if row["group"] is not None:
                    groups[row["cohort"], row["group"]][truth] += 1
        if diagnostic.read(1) or fingerprint(path) != seal["capture_sha256"]:
            raise ValueError("Apache diagnostic population changed")
    expected = read(original / "report-publisher.json")
    if expected["seal_sha256"] != seal["reference_sha256"] or metrics(baseline) != expected["after"]:
        raise ValueError("Apache diagnostic did not reproduce published baseline")
    mixed = defaultdict(Counter)
    for (cohort, _), support in groups.items():
        if support[True] and support[False]:
            mixed[cohort].update(groups=1, tp=support[True], fp=support[False])
    report = {
        "before": metrics(baseline), "post_candidate": metrics(candidate),
        "new_false_positives": new_fp, "lost_true_positives": lost_tp,
        "candidate_adopted": False,
        "cohorts": {name: {**cohorts[name], "combined_format": coverage[name],
                           "label_mixed_identical_features": dict(mixed[name])}
                    for name in COHORTS},
        "capture_sha256": seal["capture_sha256"],
        "diagnostic_seal_sha256": expected_sha256,
        "reference_seal_sha256": seal["reference_sha256"],
        "auditor_sha256": seal["auditor_sha256"],
        "frozen_model_commit": seal["frozen_model_commit"],
        "purpose": "observed-source error diagnosis only",
    }
    write(output / "report.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--score-seal")
    args = parser.parse_args()
    if fingerprint(args.source) != SOURCE_SHA:
        raise ValueError("unexpected public archive")
    if args.score_seal:
        score(args.source, args.original, args.output, args.score_seal)
    else:
        capture(args.source, args.original, args.output)


if __name__ == "__main__":
    main()
