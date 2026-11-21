"""Train and score a local KREONET residual model on pre-existing time cohorts."""

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

from scripts.evaluate_kreonet_auth import SOURCE_HASH, SOURCE_SIZE, WINDOWS, score
from scripts.evaluate_local_remote_holdout import fingerprint, read, write

COHORTS = ("development", "calibration", "holdout")
CALIBRATION_FPR_LIMIT = 0.04
GUARD_MARGIN = 0.05
MIN_GROUP_NORMALS = 30

ALLOWED_MODULES = {"request", "op", "idp", "sp", "rp", "ldap", "admin", "auth"}
ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
ALLOWED_STATUS = {
    200,
    201,
    204,
    301,
    302,
    303,
    304,
    307,
    308,
    400,
    401,
    403,
    404,
    409,
    429,
    500,
    502,
    503,
}
CONTEXT = ("user_id", "client_ip", "user_agent", "ref", "ref_id")


def stage(row):
    module = row.get("module")
    method = row.get("http_method")
    status = row.get("http_status")
    return (
        module if module in ALLOWED_MODULES else "other",
        method if method in ALLOWED_METHODS else "other",
        status if status in ALLOWED_STATUS else 0,
    )


def clean(val):
    return val.strip() if isinstance(val, str) else ""


def context_relation(a, b):
    if a and b:
        return "same" if a == b else "different"
    if a:
        return "lost"
    if b:
        return "gained"
    return "absent"


def log_time(ms):
    return min(24, int(math.log2(1 + max(0, ms))))


def project(rows, family):
    rows = sorted(rows, key=lambda row: row[0])
    by_stage = defaultdict(list)
    features = Counter()
    steps = [":".join(map(str, item[1])) for item in rows]
    for t, st, vals, dur in rows:
        by_stage[":".join(map(str, st))].append((t, vals, dur))
        features[f"status|{st[2]}"] += 1
    features["events"] = len(rows)
    for stepset, mark in ((steps, "st"), ([str(row[1][0]) for row in rows], "mod")):
        for n in (2, 3, 4):
            for i in range(len(stepset) - n + 1):
                gram = "|".join(stepset[i : i + n])
                features[f"{mark}|{n}|{gram}"] += 1
                if i == 0:
                    features[f"{mark}|prefix|{gram}"] = 1
                if i + n == len(stepset):
                    features[f"{mark}|suffix|{gram}"] = 1
    for st, items in by_stage.items():
        features[f"count|{st}"] = len(items)
        for idx, field in enumerate(CONTEXT):
            values = [item[1][idx] for item in items]
            features[f"present|{st}|{field}"] = sum(bool(v) for v in values)
            features[f"distinct|{st}|{field}"] = len({v for v in values if v})
        if family == "timing":
            valid = [item[2] for item in items if item[2] is not None]
            if valid:
                features[f"duration_min|{st}"] = 1 + log_time(min(valid))
                features[f"duration_max|{st}"] = 1 + log_time(max(valid))
    for idx, field in enumerate(CONTEXT):
        features[f"distinct|all|{field}"] = len({item[2][idx] for item in rows if item[2][idx]})
    for i, (left, right) in enumerate(pairwise(rows)):
        prefix = f"{steps[i]}|{steps[i + 1]}"
        for idx, field in enumerate(CONTEXT):
            relation = context_relation(left[2][idx], right[2][idx])
            features[f"edge_context|{prefix}|{field}|{relation}"] += 1
        if family == "timing":
            gap_ms = (right[0] - left[0]).total_seconds() * 1000
            features[f"edge_gap|{prefix}|{log_time(gap_ms)}"] += 1
    if family == "timing":
        features["trace_elapsed"] = log_time((rows[-1][0] - rows[0][0]).total_seconds() * 1000)
    return dict(features)


def read_reference(references):
    members = {}
    seals = {}
    for cohort, directory in zip(COHORTS, references, strict=True):
        plan_path = directory / "plan.json"
        packet_path = directory / "predictions.json"
        plan, packet, report = (
            read(plan_path),
            read(packet_path),
            read(directory / "report.json"),
        )
        start, stop = WINDOWS[cohort]
        seal = fingerprint(packet_path)
        if (
            plan.get("source_sha256") != SOURCE_HASH
            or plan.get("holdout_start") != start.isoformat()
            or plan.get("holdout_stop_exclusive") != stop.isoformat()
            or packet.get("plan_sha256") != fingerprint(plan_path)
            or report.get("prediction_sha256") != seal
        ):
            raise ValueError(f"invalid reference artifact: {cohort}")
        seals[cohort] = seal
        for key, row in packet["prediction_rows"].items():
            if key in members or "auth_outcome_signals" not in row:
                raise ValueError("reference must contain disjoint auth outcome evaluations")
            if type(row["prediction"]) is not bool:
                raise ValueError("invalid reference prediction")
            members[key] = (cohort, row["prediction"])
    return members, seals


def read_observations(source, members, *, local_source_sha256=None):
    expected_hash = SOURCE_HASH if local_source_sha256 is None else local_source_sha256
    if local_source_sha256 is None and source.stat().st_size != SOURCE_SIZE:
        raise ValueError("public dataset does not match pinned bytes")
    if fingerprint(source) != expected_hash:
        raise ValueError("public dataset does not match pinned bytes")
    events = defaultdict(list)
    labels = {}
    with source.open("rb") as stream:
        for raw in stream:
            row = json.loads(raw)
            key = hashlib.sha256(row["trace_id"].encode()).hexdigest()
            if key not in members:
                continue
            timestamp = datetime.fromisoformat(row["timestamp"])
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
            cohort, _ = members[key]
            start, stop = WINDOWS[cohort]
            if not start <= timestamp < stop:
                raise ValueError("reference member crosses cohort boundary")
            duration = row.get("duration_ms")
            if type(duration) is not int or duration < 0:
                duration = None
            events[key].append(
                (
                    timestamp,
                    stage(row),
                    tuple(clean(row.get(field)) for field in CONTEXT),
                    duration,
                )
            )
            if cohort != "holdout" and labels.setdefault(key, row["label"]) != row["label"]:
                raise ValueError("inconsistent training labels")
    if events.keys() != members.keys():
        raise ValueError("reference membership does not match source")
    return events, labels


def cohort_group(rows):
    initial = min(rows, key=lambda row: row[0])[1][0]
    return tuple(sorted({row[1][2] for row in rows})), initial


def fit_models(events, train_keys, truth):
    import numpy as np
    from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
    from sklearn.feature_extraction import DictVectorizer

    models = (
        (
            "context",
            HistGradientBoostingClassifier(
                max_iter=240, max_leaf_nodes=31, l2_regularization=1, random_state=42
            ),
        ),
        (
            "timing",
            ExtraTreesClassifier(n_estimators=160, min_samples_leaf=2, random_state=42, n_jobs=3),
        ),
    )
    fitted = []
    for family, model in models:
        raw = [project(events[key], family) for key in train_keys]
        support = Counter(name for features in raw for name, value in features.items() if value)
        vectorizer = DictVectorizer(dtype=np.float32)
        matrix = vectorizer.fit_transform(
            {name: value for name, value in features.items() if support[name] >= 5}
            for features in raw
        )
        model.fit(matrix.toarray() if family == "context" else matrix, truth)
        fitted.append((family, vectorizer, model))
    return fitted


def model_scores(events, keys, fitted):
    import numpy as np

    if not keys:
        return np.array([], dtype=float)
    scores = []
    for family, vectorizer, model in fitted:
        matrix = vectorizer.transform(project(events[key], family) for key in keys)
        matrix = matrix.toarray() if family == "context" else matrix
        scores.append(model.predict_proba(matrix)[:, 1])
    return np.max(scores, axis=0)


def calibrate(events, keys, scores, labels, baseline_labels):
    import numpy as np

    truth = np.array([labels[key] == "attack" for key in keys])
    groups = defaultdict(list)
    for key, value, attack in zip(keys, scores, truth, strict=True):
        if not attack:
            groups[cohort_group(events[key])].append(float(value))
    if not groups or not truth.any():
        raise ValueError("calibration needs both normal and attack residuals")
    global_cut = float(max(scores[~truth]))
    guarded = {
        key: max(values) for key, values in groups.items() if len(values) >= MIN_GROUP_NORMALS
    }
    best = None
    normal_total = len(truth) - int(truth.sum()) + baseline_labels["benign"]
    for cut in np.unique(scores):
        selected = scores > cut
        tp = baseline_labels["attack"] + int((selected & truth).sum())
        fp = baseline_labels["benign"] + int((selected & ~truth).sum())
        if tp and fp / normal_total <= CALIBRATION_FPR_LIMIT and tp / (tp + fp) >= 0.95:
            candidate = (tp, -fp, float(cut))
            best = max(best, candidate) if best is not None else candidate
    if best is None:
        raise ValueError("no calibration operating point satisfies the precision and FPR bounds")
    return global_cut, guarded, best[2]


def capture(output, source, references):
    import sklearn
    from threadpoolctl import threadpool_limits

    members, seals = read_reference(references)
    events, labels = read_observations(source, members)
    development, calibration = (
        [
            key
            for key, (split, hit) in members.items()
            if split == cohort and not hit and labels[key] in {"attack", "benign"}
        ]
        for cohort in COHORTS[:2]
    )
    baseline_labels = Counter(
        labels[key] for key, (split, hit) in members.items() if split == "calibration" and hit
    )
    with threadpool_limits(limits=3):
        fitted = fit_models(events, development, [labels[key] == "attack" for key in development])
        probabilities = model_scores(events, calibration, fitted)
        global_cut, guarded, budget_cut = calibrate(
            events, calibration, probabilities, labels, baseline_labels
        )
        common_plan = {
            "source_sha256": SOURCE_HASH,
            "reference_prediction_sha256": seals,
            "library": sklearn.__version__,
            "classifier": "max(context HistGradientBoosting, timing ExtraTrees)",
            "feature_inputs": [
                "relative timestamp and duration_ms buckets",
                "module, http_method and http_status",
                "same-trace presence, distinct count and equality of user_id, client_ip, user_agent, ref, ref_id",
            ],
            "fit_population": "development baseline misses",
            "calibration_population": "calibration baseline misses; include prior hits in metrics",
            "score_population": "holdout",
            "threshold_margin": GUARD_MARGIN,
            "guarded_global_threshold": global_cut,
            "guarded_group_thresholds": [
                {"status_and_initial_module": [list(key[0]), key[1]], "threshold": value}
                for key, value in sorted(guarded.items())
            ],
            "target_threshold": budget_cut,
            "calibration_fpr_limit": CALIBRATION_FPR_LIMIT,
        }
        for policy in ("guarded", "target"):
            directory = output / policy
            directory.mkdir(parents=True, exist_ok=True)
            plan = {**common_plan, "policy": policy}
            plan_path = directory / "plan.json"
            if plan_path.exists() and read(plan_path) != plan:
                raise ValueError(f"existing {policy} plan differs from this run")
            if not plan_path.exists():
                write(plan_path, plan)

        residual = [key for key, (split, hit) in members.items() if split == "holdout" and not hit]
        scores = dict(zip(residual, model_scores(events, residual, fitted), strict=True))
    for policy in ("guarded", "target"):
        directory = output / policy
        rows = {}
        for key, (split, prior) in members.items():
            if split != "holdout":
                continue
            model_score = None if prior else float(scores[key])
            threshold = budget_cut
            if policy == "guarded" and not prior:
                threshold = guarded.get(cohort_group(events[key]), global_cut) + GUARD_MARGIN
            additional = model_score is not None and model_score > threshold
            rows[key] = {
                "prediction": prior or additional,
                "baseline_prediction": prior,
                "previous_auth_outcome_prediction": prior,
                "model_signals": ["calibrated_residual_model"] if additional else [],
                "model_score": model_score,
            }
        packet = directory / "predictions.json"
        write(
            packet, {"plan_sha256": fingerprint(directory / "plan.json"), "prediction_rows": rows}
        )
        print(f"{policy} {fingerprint(packet)}")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="phase", required=True)
    capture_cli = commands.add_parser("capture")
    capture_cli.add_argument("output", type=Path)
    capture_cli.add_argument("--source", type=Path, required=True)
    capture_cli.add_argument("--references", nargs=3, type=Path, required=True)
    score_cli = commands.add_parser("score")
    score_cli.add_argument("output", type=Path)
    score_cli.add_argument("--source", type=Path, required=True)
    score_cli.add_argument("--prediction-sha256", required=True)
    args = cli.parse_args()
    if args.phase == "capture":
        capture(args.output, args.source, args.references)
    else:
        score(args.output, args.prediction_sha256, args.source)


if __name__ == "__main__":
    main()
