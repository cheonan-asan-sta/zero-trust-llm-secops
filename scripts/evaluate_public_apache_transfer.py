"""Replay a pinned external Apache corpus offline, then score publisher labels."""

import argparse
import gzip
import hashlib
import json
import re
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from time import perf_counter
from zipfile import ZipFile

import yaml

from scripts.evaluate_local_remote_holdout import fingerprint, git, read, write
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_context import extra_observations, ordered_http_context
from scripts.f1_lab.raw_observations import REQUEST, raw_features, raw_time
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.transfer_evaluation import load_detector
from scripts.f1_lab.web_residual import WebResidualRefinement, build_evidence
from scripts.f1_lab.web_sensitive_read import evidence, refine

SOURCE_SHA = "1429caba2803c3e8c90e9fb287bc04f6f8249f8bb34712b39127044e134d631f"
SOURCE = "https://zenodo.org/records/20001206"
LABEL_MEMBER = "organization-x/ground-truth/organization-x.yaml"
ACCESS = re.compile(r"organization-x/log/apache2/web-access\.log(?:\.\d+(?:\.gz)?)?")
FROZEN = Path("infra/f1-lab/frozen-vpn-control-v114")
MAX_SOURCE_ROWS = 200_000
THRESHOLD = 0.95


def evaluator_sha256():
    source = Path(__file__).read_text(encoding="utf-8")
    return hashlib.sha256(source.encode("utf-8")).hexdigest()

def frozen_model():
    manifest = read(FROZEN / "legacy.json")["models"]
    specs = {name: {**entry, "path": str(FROZEN / entry["path"])} for name, entry in manifest.items()}
    return load_detector(Path("."), specs, specs["policy"]).operation_model, specs


@contextmanager
def observation_stream(archive, member):
    with archive.open(member) as raw:
        if member.endswith(".gz"):
            with gzip.GzipFile(fileobj=raw) as expanded:
                yield expanded
        else:
            yield raw


def records(archive, member):
    with observation_stream(archive, member) as stream:
        rows = []
        digest = hashlib.sha256()
        while raw := stream.readline(MAX_ROW + 1):
            if len(raw) > MAX_ROW or len(rows) >= MAX_SOURCE_ROWS:
                raise ValueError("web access observation bound")
            digest.update(raw)
            rows.append(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
    return rows, digest.hexdigest()


def forecast(model, residual, rows, source_hash):
    timed = []
    for ordinal, line in enumerate(rows, 1):
        try:
            moment = raw_time(line, 1735689600, 1767225600, source_timezone="UTC")
        except ValueError:
            moment = None
        timed.append((ordinal, moment, line))
    windows = ordered_http_context(timed)
    review = build_evidence(timed, "access", source_hash)
    cache = {}
    for ordinal, moment, line in timed:
        case = hashlib.sha256(f"{source_hash}:{ordinal}".encode()).hexdigest()
        if moment is None or REQUEST.search(line) is None or "\ufffd" in line:
            yield {"case_id": case, "before": None, "after": None}
            continue
        features = {**raw_features(line), **extra_observations(line), **semantic_observations(line),
                    **windows[ordinal]}
        key = canonical(features)
        if key not in cache:
            cache[key] = model.web_model.probability(features)
        score = cache[key]
        hit = score >= THRESHOLD
        decision = OperationDecision(score, score, hit, hit, "frozen_web_baseline")
        decision = residual.refine(decision, features, case, review.get(case))
        decision = refine(decision, features, case, evidence(line, source_hash, ordinal))
        yield {"case_id": case, "before": hit, "after": decision.alert}


def capture(source, output, revision):
    if git("rev-parse", "HEAD").decode().strip() != revision or git(
        "status", "--porcelain", "--untracked-files=no"
    ).strip():
        raise ValueError("clean frozen product revision required")
    model, specs = frozen_model()
    residual = WebResidualRefinement(model)
    start = perf_counter()
    output.mkdir()
    predictions = output / "predictions.jsonl"
    with ZipFile(source) as archive:
        names = sorted(name for name in archive.namelist() if ACCESS.fullmatch(name))
        if not names or len(names) != len(set(names)):
            raise ValueError("invalid web access population")
        write(output / "plan.json", {"candidate_commit": revision, "archive_sha256": SOURCE_SHA,
              "evaluator_sha256": evaluator_sha256(), "source": SOURCE, "model_pins": specs,
              "threshold": THRESHOLD, "members": names, "unit": "physical Apache web access row",
              "label_modes": ["publisher", "strict"], "history": "event time within each physical member"})
        receipts = []
        with predictions.open("xb") as stream:
            for name in names:
                rows, digest = records(archive, name)
                receipts.append({"member": name, "sha256": digest, "rows": len(rows)})
                for prediction in forecast(model, residual, rows, digest):
                    stream.write(canonical(prediction) + b"\n")
        write(output / "seal.json", {"plan_sha256": fingerprint(output / "plan.json"),
              "media": receipts, "prediction_sha256": fingerprint(predictions),
              "capture_seconds": round(perf_counter() - start, 3)})


def score(source, output, sealed_sha, mode):
    seal_path = output / "seal.json"
    plan_path = output / "plan.json"
    predictions = output / "predictions.jsonl"
    seal = read(seal_path)
    plan = read(plan_path)
    if fingerprint(seal_path) != sealed_sha or fingerprint(plan_path) != seal["plan_sha256"] or (
        fingerprint(predictions) != seal["prediction_sha256"] or plan["archive_sha256"] != SOURCE_SHA
        or plan["evaluator_sha256"] != evaluator_sha256()
        or plan["members"] != [item["member"] for item in seal["media"]]
    ):
        raise ValueError("sealed evaluation changed")

    before, after = counts(), counts()
    matched = Counter()
    introduced_fp = lost_tp = 0
    with ZipFile(source) as archive, predictions.open("rb") as stream:
        label_bytes = archive.read(LABEL_MEMBER)
        rules = yaml.safe_load(label_bytes)
        filters = [(rule["id"], rule["filter"]) for rule in rules
                   if mode == "publisher" or rule["sensitivity"] == mode]
        if not filters or not all(terms and all(isinstance(term, str) and term for term in terms)
                                  for _, terms in filters):
            raise ValueError("publisher truth filters missing")
        for item in seal["media"]:
            rows, digest = records(archive, item["member"])
            if len(rows) != item["rows"] or digest != item["sha256"]:
                raise ValueError("prediction population changed")
            for ordinal, line in enumerate(rows, 1):
                entry = json.loads(stream.readline())
                case = hashlib.sha256(f"{digest}:{ordinal}".encode()).hexdigest()
                if entry["case_id"] != case:
                    raise ValueError("published label and prediction rows are not aligned")
                matches = {rule for rule, patterns in filters if all(pattern in line for pattern in patterns)}
                matched.update(matches)
                target = bool(matches)
                old, new = entry["before"], entry["after"]
                record(before, target, old)
                record(after, target, new)
                introduced_fp += not target and old is False and new is True
                lost_tp += target and old is True and new is not True
        if stream.read(1):
            raise ValueError("extra prediction rows")
    if fingerprint(predictions) != seal["prediction_sha256"]:
        raise ValueError("predictions changed during scoring")
    write(output / f"report-{mode}.json", {"candidate_commit": plan["candidate_commit"], "source": SOURCE,
          "publisher_rules_used": len(filters), "publisher_distinct_rule_ids": len({rule for rule, _ in filters}),
          "seal_sha256": sealed_sha, "publisher_filter_sha256": hashlib.sha256(label_bytes).hexdigest(),
          "mode": mode, "matching": "case-sensitive literal AND per rule; OR across rules", "before": metrics(before), "after": metrics(after), "rule_match_counts": dict(matched),
          "new_false_positives": introduced_fp, "lost_true_positives": lost_tp})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for action, argument in (("capture", "revision"), ("score", "sealed_sha")):
        command = actions.add_parser(action)
        command.add_argument("source", type=Path)
        command.add_argument("output", type=Path)
        command.add_argument(argument)
        if action == "score":
            command.add_argument("--mode", choices=("publisher", "strict"), required=True)
    args = parser.parse_args()
    if fingerprint(args.source) != SOURCE_SHA:
        raise ValueError("public source does not match pinned archive")
    if args.action == "capture":
        capture(args.source, args.output, args.revision)
    else:
        score(args.source, args.output, args.sealed_sha, args.mode)


if __name__ == "__main__":
    main()
