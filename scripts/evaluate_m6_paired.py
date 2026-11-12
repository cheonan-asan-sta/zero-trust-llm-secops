"""Evaluate paired OIDC sessions with shared model inputs and local scoring."""

import asyncio
import json
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation

from scripts import evaluate_m6 as m6
from scripts.evaluate_m6_live import summarize_live
from scripts.evaluate_m6_public import (
    bind_cases,
    configured_credentials,
    execution_plan,
    run_comparison,
)
from scripts.m6_paired_mock import PairedMock
from scripts.prepare_m7_paired import verified_bundle


def pair_members(cases):
    pairs = defaultdict(list)
    for case in cases:
        pairs[case["pair_id"]].append(case)
    if len(pairs) != 100 or any(
        Counter(case["expected_label"] for case in members) != {"normal": 1, "threat": 1}
        for members in pairs.values()
    ):
        raise ValueError("m6_invalid_scoring_pairs")
    return pairs


def count_pairs(pairs, results):
    by_id = {row["case_id"]: row for row in results}
    expected_ids = {case["case_id"] for members in pairs.values() for case in members}
    if len(by_id) != len(results) or set(by_id) != expected_ids:
        raise ValueError("m6_incomplete_pair_results")
    counts = Counter()
    for members in pairs.values():
        correct = sum(
            by_id[case["case_id"]]["status"] == "ok"
            and by_id[case["case_id"]]["predicted_label"] == case["expected_label"]
            for case in members
        )
        counts[correct] += 1
    return {"total": len(pairs), "both_correct": counts[2], "one_correct": counts[1],
            "neither_correct": counts[0]}


def summarize_pairs(model, cases, pairs, *, field=None):
    summary = model["summary"]
    summary["response_error_count"] = summary["status_counts"].get("response_error", 0)
    summary["pairs"] = count_pairs(pairs, model["results"])
    if field is None:
        return
    slices = defaultdict(list)
    pairs_by_slice = defaultdict(dict)
    for case in cases:
        slices[case[field]].append(case)
    for pair_id, members in pairs.items():
        value = members[0][field]
        if members[1][field] != value:
            raise ValueError("m6_paired_slice_mismatch")
        pairs_by_slice[value][pair_id] = members
    by_id = {row["case_id"]: row for row in model["results"]}
    summaries = {}
    for value, members in slices.items():
        selected = [by_id[case["case_id"]] for case in members]
        details = summarize_live(selected, members)
        details["response_error_count"] = details["status_counts"].get("response_error", 0)
        details["pairs"] = count_pairs(pairs_by_slice[value], selected)
        summaries[value] = details
    model["by_" + field] = summaries


def run_strengthened_live(args):
    from scripts.m6_paired_live import run_paired_live
    from scripts.prepare_m7_paired_strengthened import verified_bundle as verify_strengthened

    files, manifest = verify_strengthened(args.m7_paired)
    requests = files["model-requests.jsonl"]
    scoring = files["private/scoring-labels.jsonl"]
    inputs, cases = bind_cases(
        requests, scoring, {"normal": 100, "threat": 100}, ("pair_id", "scenario", "cohort"),
    )
    pairs = pair_members(cases)
    provenance = {
        "scope": manifest["scope"],
        "manifest_sha256": m6.digest(files["manifest.json"]),
        "requests_sha256": m6.digest(requests),
        "scoring_sha256": m6.digest(scoring),
        "prior_overlap": manifest["prior_overlap"],
        "relationship_baseline": manifest["relationship_baseline"],
    }
    plan = execution_plan(inputs, cases, provenance) | {
        "schema": "m6-paired-oidc-strengthened-live-plan-1", "pairs": len(pairs),
    }
    try:
        max_usd = Decimal(args.live_max_usd)
    except InvalidOperation as exc:
        raise ValueError("m6_paired_live_cost_limit") from exc
    report = asyncio.run(run_paired_live(
        args.output_dir, inputs, cases, provenance, plan, configured_credentials(),
        max_requests=args.max_requests, max_usd=max_usd,
        **({"wall_seconds": args.wall_seconds} if args.wall_seconds is not None else {}),
    ))
    for model in report["models"].values():
        summarize_pairs(model, cases, pairs, field="cohort")
        summarize_pairs(model, cases, pairs, field="scenario")
    report["schema"] = "m6-paired-oidc-strengthened-live-report-1"
    m6.write_report(args.output_dir / "report.json", report)
    print(json.dumps({"sessions": len(cases), "pairs": len(pairs), "stop_reason": report["stop_reason"],
                      **report["budget"], "report": str(args.output_dir / "report.json")}))
    return int(bool(report["stop_reason"]) or report["budget"]["actual_provider_requests"] != args.max_requests)


def run_cli(args):
    if args.live:
        return run_strengthened_live(args)
    files, manifest = verified_bundle(args.m7_paired)
    requests = files["model-requests.jsonl"]
    scoring = files["private/scoring-labels.jsonl"]
    inputs, cases = bind_cases(requests, scoring, {"normal": 100, "threat": 100}, ("pair_id", "scenario"))
    pairs = pair_members(cases)
    provenance = {
        "scope": manifest["scope"],
        "manifest_sha256": m6.digest(files["manifest.json"]),
        "requests_sha256": m6.digest(requests),
        "scoring_sha256": m6.digest(scoring),
        "prior_overlap": manifest["prior_overlap"],
        "relationship_baseline": manifest["relationship_baseline"],
    }
    plan = execution_plan(inputs, cases, provenance) | {
        "schema": "m6-paired-oidc-mock-plan-1", "pairs": len(pairs),
    }
    required = plan["generation_requests"]
    if args.max_requests is not None and args.max_requests != required:
        raise ValueError("m6_paired_request_limit")
    mock = PairedMock(inputs)
    report = asyncio.run(run_comparison(
        args.output_dir, inputs, cases, provenance, plan, mock.credentials,
        max_requests=required, max_usd=Decimal(plan["max_reserved_usd"]), transport=mock.transport,
    ))
    verification = mock.verify()
    budget = report["budget"]
    if (report["stop_reason"] is not None or report["mode"] != "mock"
            or budget["actual_provider_requests"] != 0
            or budget["simulated_inference_requests"] != required
            or verification["verified_generation_requests"] != required
            or verification["verified_openai_token_count_requests"] != plan["planned_openai_token_count_requests"]):
        raise ValueError("m6_paired_mock_request_count")
    for model in report["models"].values():
        summarize_pairs(model, cases, pairs)
    report |= {
        "schema": "m6-paired-oidc-mock-report-1",
        "wire_verification": verification,
        "prediction_source": "Deterministic fixture with the same injected outcomes for each model adapter.",
    }
    m6.write_report(args.output_dir / "report.json", report)
    print(json.dumps({"sessions": len(cases), "pairs": len(pairs), **budget,
                      "report": str(args.output_dir / "report.json")}))
    return 0
