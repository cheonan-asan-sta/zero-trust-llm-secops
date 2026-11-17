"""Descriptive uncertainty diagnostics; does not alter predictions or acceptance gates.

Wilson intervals assume IID Bernoulli trials. Authored/family-clustered test cases
are not a random deployment sample; these numbers must not certify deployment.
Formula: https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm
"""

import math
from statistics import NormalDist

from scripts.evaluate_llm_grounded import metrics


def wilson(successes: int, trials: int, confidence=0.95):
    if type(successes) is not int or type(trials) is not int or not 0 <= successes <= trials:
        raise ValueError("invalid_binomial_counts")
    if not math.isfinite(confidence) or not 0 < confidence < 1:
        raise ValueError("invalid_confidence")
    if not trials:
        return None
    z = NormalDist().inv_cdf((1 + confidence) / 2)
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    radius = (
        z
        / denominator
        * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
    )
    return {"lower": max(0.0, center - radius), "upper": min(1.0, center + radius)}


def describe(rows):
    # This function is for one cohort/repetition. Never pool repeated calls as new cases.
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_case_requires_separate_repetitions")
    result = metrics(rows)
    tp, fp, fn, tn = (result[k] for k in ("TP", "FP", "FN", "TN"))
    family_ids = {row.get("family_id", row["id"]) for row in rows}
    return {
        "cases": len(rows),
        "families": len(family_ids),
        "metrics": result,
        "illustrative_iid_wilson_95": {
            "precision": wilson(tp, tp + fp),
            "recall": wilson(tp, tp + fn),
            "FPR": wilson(fp, fp + tn),
            "FNR": wilson(fn, tp + fn),
        },
        "assumption": "IID binomial; not established for authored/family-clustered cases",
        "family_clustering_present": len(family_ids) < len(rows),
        "independent_acceptance": False,
        "original_acceptance_thresholds_changed": False,
        "F1_interval": None,
        "F1_interval_reason": "F1 is not a single binomial proportion; no naive Wilson interval",
    }
