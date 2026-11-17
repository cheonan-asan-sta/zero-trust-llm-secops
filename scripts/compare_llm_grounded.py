"""Compare the same development cohort without hiding lost detections in net counts."""

import argparse
import json
from pathlib import Path

from scripts.evaluate_llm_grounded import metrics


def compare_rows(reference, candidate):
    def indexed(rows):
        result = {}
        for row in rows:
            if row["id"] in result or type(row["truth"]) is not bool:
                raise ValueError("duplicate_case_or_invalid_truth")
            if row["prediction"] is not None and type(row["prediction"]) is not bool:
                raise ValueError("invalid_prediction")
            result[row["id"]] = row
        return result

    before, after = indexed(reference), indexed(candidate)
    if not before or before.keys() != after.keys():
        raise ValueError("cohort_mismatch")
    if any(before[k]["truth"] != after[k]["truth"] for k in before):
        raise ValueError("truth_mismatch")
    lost_tp, new_fp, recovered_tp, corrected_fp = [], [], [], []
    for key, row in before.items():
        old, new = row["prediction"], after[key]["prediction"]
        if row["truth"]:
            if old is True and new is not True:
                lost_tp.append(key)
            if old is not True and new is True:
                recovered_tp.append(key)
        else:
            if old is False and new is not False:
                new_fp.append(key)
            if old is not False and new is False:
                corrected_fp.append(key)
    baseline, revised = metrics(reference), metrics(candidate)
    return {
        "cases": len(before),
        "reference": baseline,
        "candidate": revised,
        "lost_TP_ids": sorted(lost_tp),
        "new_FP_ids": sorted(new_fp),
        "recovered_TP_ids": sorted(recovered_tp),
        "corrected_FP_ids": sorted(corrected_fp),
        "no_lost_detections": not lost_tp and revised["FN"] <= baseline["FN"],
        "FP_reduced": revised["FP"] < baseline["FP"],
        "FP_not_increased": revised["FP"] <= baseline["FP"],
        "no_new_false_positives": not new_fp,
        "scope": "same_cohort_development_only_not_independent_acceptance",
    }


def read_arm(path, arm):
    return [
        r for raw in Path(path).read_bytes().splitlines() if (r := json.loads(raw))["arm"] == arm
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--reference-arm", default="grounded")
    parser.add_argument("--candidate-arm", default="grounded")
    args = parser.parse_args()
    print(
        json.dumps(
            compare_rows(
                read_arm(args.reference, args.reference_arm),
                read_arm(args.candidate, args.candidate_arm),
            ),
            indent=2,
        )
    )
