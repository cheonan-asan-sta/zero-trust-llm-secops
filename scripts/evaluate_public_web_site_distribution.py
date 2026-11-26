"""Score the third site-separated legitimate sample on local frozen predictions."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.evaluate_local_remote_holdout import fingerprint, write
from scripts.evaluate_public_legitimate_web_crs import EXPANDED_ROWS, EXPANDED_SHA, request_members
from scripts.evaluate_public_post_body_shape import group_key
from scripts.evaluate_public_web_calibrated_transfer import calibration_result, development_groups
from scripts.evaluate_public_web_shape_transfer import features, fit
from scripts.f1_lab.operation_context import canonical

PREDICTION_PINS = {
    "target": "eca3a19d110155ae583107d8c8ef1b556ad20010109023b9c0328bc311201fe9",
    "target_body": "78f557dedd02c84fec05d5bb62645f38db45cbe6d6851eb8478b36d8c08755ad",
}
ARMS = ("target", "target_or_body", "target_or_shape")
THRESHOLD = 0.84


def scope(rows):
    if not rows:
        raise ValueError("no legitimate cases in this site group after exclusion")
    return {
        "population": len(rows),
        "recorded_bodies": sum(row["body_included"] for row in rows),
        "scopes": {
            arm: {
                "alerts": sum(row[arm] is True for row in rows),
                "unknown": sum(row[arm] is None for row in rows),
                "false_positive_rate": sum(row[arm] is not False for row in rows) / len(rows),
            }
            for arm in ARMS
        },
    }


def preserve_target(target, additional):
    if target is True or additional is True:
        return True
    if target is False and additional is False:
        return False
    return None


def capture_group(examples, model, prior, typed, first_ordinal, used):
    vectors = [features(row["url"], row["data"]) for row in examples]
    usable = [vector for vector in vectors if vector is not None]
    probabilities = iter(model.predict_proba(usable)[:, 1] if usable else ())
    for offset, (row, vector) in enumerate(zip(examples, vectors, strict=True)):
        ordinal = first_ordinal + offset
        target, body = next(prior), next(typed)
        if target["ordinal"] != ordinal or body["ordinal"] != ordinal:
            raise ValueError("unexpected prediction order")
        has_body = body.get("body_included", False)
        old, new = target["alert"], body["alert"]
        if old is not new and not has_body:
            raise ValueError("no body explains a decision change")
        shape = bool(next(probabilities) >= THRESHOLD) if vector is not None else None
        yield {
            "ordinal": ordinal, "overlap": group_key(row["url"], row["data"]) in used,
            "target": old, "target_or_body": preserve_target(old, new),
            "target_or_shape": preserve_target(old, shape), "body_included": has_body,
            "lost_direct_alert": old is True and new is not True,
        }


def evaluate(source, train, legitimate_development, replay, output):
    from sklearn import __version__ as sklearn_version
    from threadpoolctl import threadpool_limits

    paths = {arm: replay / f"{arm}.jsonl" for arm in PREDICTION_PINS}
    if {arm: fingerprint(path) for arm, path in paths.items()} != PREDICTION_PINS:
        raise ValueError("unexpected frozen CRS predictions")
    groups, _, calibration, used = development_groups(train, legitimate_development)
    predictions = []
    members = []
    with (threadpool_limits(limits=3), paths["target"].open("rb") as earlier,
          paths["target_body"].open("rb") as later):
        model, _ = fit(groups)
        threshold, _ = calibration_result(model, groups, calibration)
        if threshold != THRESHOLD or sklearn_version != "1.7.2":
            raise ValueError("frozen shape calibration changed")
        prior, typed = map(json.loads, earlier), map(json.loads, later)
        for index, examples in request_members(source, receipt_sha=EXPANDED_SHA):
            rows = list(capture_group(examples, model, prior, typed, len(predictions) + 1, used))
            kept = [row for row in rows if not row["overlap"]]
            predictions.extend(rows)
            members.append({"member": index, "before_exclusion": len(rows), **scope(kept)})
        if next(prior, None) is not None or next(typed, None) is not None:
            raise ValueError("leftover CRS predictions")
    if len(members) != 32 or len(predictions) != EXPANDED_ROWS:
        raise ValueError("unexpected legitimate population")
    if {arm: fingerprint(path) for arm, path in paths.items()} != PREDICTION_PINS:
        raise ValueError("frozen CRS predictions changed")
    unseen = [row for row in predictions if not row["overlap"]]
    output.mkdir()
    prediction_path = output / "predictions.jsonl"
    digest = hashlib.sha256()
    with prediction_path.open("xb") as stream:
        for row in predictions:
            line = canonical(row) + b"\n"
            stream.write(line)
            digest.update(line)
    write(output / "report.json", {
        "schema": "public-normal-web-site-distribution-1", "scope": "publisher-labeled legitimate requests only",
        "candidate_adopted": False, "source_receipt_sha256": EXPANDED_SHA,
        "source_plan_sha256": fingerprint(source / "plan.json"),
        "crs_predictions_sha256": PREDICTION_PINS, "shape_threshold": threshold,
        "predictions_sha256": digest.hexdigest(), "sklearn": sklearn_version,
        "all": scope(predictions), "unseen_shape_keys": scope(unseen),
        "lost_direct_alerts": sum(row["lost_direct_alert"] for row in predictions),
        "members_above_five_percent": {
            arm: sum(item["scopes"][arm]["false_positive_rate"] > .05 for item in members) for arm in ARMS
        },
        "max_member_fpr": {arm: max(item["scopes"][arm]["false_positive_rate"] for item in members) for arm in ARMS},
        "members": members,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "train", "legitimate_development", "replay", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    evaluate(args.source, args.train, args.legitimate_development, args.replay, args.output)


if __name__ == "__main__":
    main()
