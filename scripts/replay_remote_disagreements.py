"""Measure remote-access review workload and binary promotion risk offline."""

import argparse
import asyncio
import hashlib
from collections import Counter
from pathlib import Path

from app.grounded_prompting import exception_context
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_development import write_json
from scripts.replay_hybrid_development import load_published, replay_arm


def review_reason(event, llm_prediction, rule_prediction):
    if (
        event.action != "REMOTE_ACCESS"
        or event.network.access_method not in {"remote", "vpn"}
        or llm_prediction is True
        or rule_prediction is not True
    ):
        return None
    if exception_context(event)["matches_event_context"]:
        return "scoped_claim_requires_issuer_verification"
    if event.auth_context.mfa != "success":
        return "mfa_and_approval_require_verification"
    return "approval_requires_verification"


def compare_routes(source, cases, rule_rows):
    rules = {row["id"]: row["prediction"] for row in rule_rows}
    queue = []
    reasons = {}
    for row in source:
        key = row["id"]
        event = cases[key].event
        reason = review_reason(event, row["prediction"], rules[key])
        if reason is None:
            continue
        reasons[key] = reason
        queue.append(
            {
                "id": key,
                "domain": row["domain"],
                "family_id": row["family_id"],
                "reason": reason,
                "source_prediction": row["prediction"],
                "source_error": row.get("error"),
                "truth": row["truth"],
            }
        )
    scoped_claims = {
        key
        for key, reason in reasons.items()
        if reason == "scoped_claim_requires_issuer_verification"
    }

    def simulated_promotion(ids):
        candidate = [
            {**row, "prediction": True, "error": None} if row["id"] in ids else row
            for row in source
        ]
        return compare_rows(source, candidate)

    return {
        "cases": len(source),
        "review_queue": queue,
        "reasons": dict(sorted(Counter(reasons.values()).items())),
        "queued_normal_cases": sum(not row["truth"] for row in queue),
        "queued_source_false_negatives": sum(row["truth"] for row in queue),
        "binary_promotion_simulations": {
            "all_disagreements": simulated_promotion(reasons),
            "excluding_event_supplied_scoped_claims": simulated_promotion(
                reasons.keys() - scoped_claims
            ),
        },
        "fresh_provider_requests": 0,
        "runtime_adoption": False,
        "independent_acceptance": False,
    }


def run(directory):
    directory = Path(directory)
    root = Path(__file__).resolve().parents[1]
    inputs = (
        "app/data/benchmark/cases.jsonl",
        "docs/infrastructure-results/llm-development360-20261117.json",
        "app/analyzers/rule_based.py",
        "app/grounded_prompting.py",
        "scripts/compare_llm_grounded.py",
        "scripts/evaluate_llm_grounded.py",
        "scripts/replay_hybrid_development.py",
        "scripts/replay_remote_disagreements.py",
    )
    pins = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in inputs}
    _, _, source, cases = load_published()
    rules = asyncio.run(replay_arm(source, cases, mode="rule"))
    result = compare_routes(source, cases, rules)
    if any(
        hashlib.sha256((root / name).read_bytes()).hexdigest() != pin for name, pin in pins.items()
    ):
        raise ValueError("remote_replay_input_changed")
    directory.mkdir(parents=True, exist_ok=False)
    result["input_sha256"] = pins
    write_json(directory / "report.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    run(args.directory)
