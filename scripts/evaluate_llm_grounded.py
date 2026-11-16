"""Bounded paid comparison on authored DEVELOPMENT cases; not independent acceptance."""

import argparse
import asyncio
import hashlib
import json
import os
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from dotenv import dotenv_values
from openai import AsyncOpenAI

from app.analyzers.openai_analyzer import SYSTEM_INSTRUCTIONS
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.grounded_prompting import (
    GROUNDED_INSTRUCTIONS,
    grounded_input,
    grounded_output_type,
    validate_grounded,
)
from app.models import SecurityAssessment
from app.prompting import build_analysis_input
from app.services.detection_benchmark import BenchmarkCase

ROOT = Path(__file__).resolve().parents[1]
MODEL = "gpt-5.4-mini-2026-03-17"
INPUT_RATE, OUTPUT_RATE = 0.75 / 1_000_000, 4.5 / 1_000_000
OUTPUT_LIMIT = 1200


def select_cases(path, family_offset=0, families_per_group=2):
    if not 0 <= family_offset <= 16 or families_per_group not in (1, 2):
        raise ValueError("family_selection_bound")
    groups = defaultdict(list)
    for raw in Path(path).read_bytes().splitlines():
        case = BenchmarkCase.model_validate_json(raw)
        if case.split == "development":
            groups[case.domain, case.threat].append(case)
    selected = []
    for key in sorted(groups):
        seen = set()
        for case in sorted(groups[key], key=lambda c: c.case_id):
            if case.family_id in seen:
                continue
            seen.add(case.family_id)
            if len(seen) > family_offset:
                selected.append(case)
            if len(seen) == family_offset + families_per_group:
                break
        if len(seen) != family_offset + families_per_group:
            raise ValueError("insufficient_development_family_support")
    if (
        len(selected) != 12 * families_per_group
        or sum(c.threat for c in selected) != 6 * families_per_group
    ):
        raise ValueError("paired_development_cohort")
    return selected


def metrics(rows):
    tp = fp = fn = tn = unknown = 0
    for r in rows:
        truth, prediction = r["truth"], r["prediction"]
        unknown += prediction is None
        if truth:
            tp += prediction is True
            fn += prediction is not True
        else:
            fp += prediction is not False
            tn += prediction is False
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "unknown_or_error": unknown,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "F1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "FPR": fp / (fp + tn) if fp + tn else None,
        "FNR": fn / (tp + fn) if tp + fn else None,
    }


def prediction(a):
    return None if a.violation_type.value == "UNKNOWN" else a.violation_type.value != "NORMAL"


def reservation(
    messages, input_rate=INPUT_RATE, output_rate=OUTPUT_RATE, output_limit=OUTPUT_LIMIT
):
    # UTF-8 bytes plus large schema/protocol allowance conservatively bound input tokens.
    upper = len(json.dumps(messages, ensure_ascii=False).encode()) + 8192
    if upper > 32768:
        raise ValueError("input_bound")
    return upper * input_rate + output_limit * output_rate


def include_unattempted(rows, requests, truth):
    """A stopped paid run must retain its entire frozen cohort in the denominator."""
    seen = {(r["id"], r["arm"]) for r in rows}
    return rows + [
        {
            "id": r["id"],
            "arm": r["arm"],
            "truth": truth[r["id"]],
            "prediction": None,
            "error": "not_attempted",
        }
        for r in requests
        if (r["id"], r["arm"]) not in seen
    ]


async def run(
    directory,
    key_file=None,
    family_offset=0,
    families_per_group=2,
    model=MODEL,
    llm_arms=("legacy", "grounded"),
    max_budget=5,
):
    if (
        model not in {MODEL, "gpt-6.1-sol"}
        or not llm_arms
        or not set(llm_arms) <= {"legacy", "grounded"}
        or not 0 < max_budget <= 5
    ):
        raise ValueError("evaluation_options")
    input_rate, output_rate = (
        (INPUT_RATE, OUTPUT_RATE) if model == MODEL else (2 / 1_000_000, 10 / 1_000_000)
    )
    output_limit = OUTPUT_LIMIT if model == MODEL else 2400
    effort = "none" if model == MODEL else "low"
    directory = Path(directory)
    if directory.exists():
        raise ValueError("output_exists")
    key = os.environ.get("OPENAI_API_KEY")
    if not key and key_file:
        key = dotenv_values(key_file).get("OPENAI_API_KEY")
    if not key:
        raise ValueError("missing_credential")
    cases_path = ROOT / "app/data/benchmark/cases.jsonl"
    cases = select_cases(cases_path, family_offset, families_per_group)
    directory.mkdir(parents=True)
    (directory / "private").mkdir()
    requests, truth = [], {}
    for case in cases:
        identity = hashlib.sha256(case.case_id.encode()).hexdigest()
        event = case.event.model_copy(update={"event_id": identity, "ground_truth": None})
        truth[identity] = case.threat
        for arm in llm_arms:
            messages = (
                [
                    {"role": "system", "content": SYSTEM_INSTRUCTIONS},
                    *build_analysis_input(event, 1),
                ]
                if arm == "legacy"
                else [{"role": "system", "content": GROUNDED_INSTRUCTIONS}, *grounded_input(event)]
            )
            requests.append({"id": identity, "arm": arm, "messages": messages, "event": event})
    # Alternate arm ordering to avoid consistently privileging one arm by ordering/cache effects.
    requests.sort(key=lambda r: (r["id"], r["arm"] if int(r["id"][0], 16) % 2 else r["arm"][::-1]))
    payload = b"".join(
        (
            json.dumps({k: v for k, v in r.items() if k != "event"}, ensure_ascii=False) + "\n"
        ).encode()
        for r in requests
    )
    (directory / "inputs.jsonl").write_bytes(payload)
    (directory / "private/truth.json").write_bytes(json.dumps(truth, sort_keys=True).encode())
    plan = {
        "schema": "llm-paired-development-1",
        "model": model,
        "arms": ["rule", *llm_arms],
        "cases": len(cases),
        "families": len(cases),
        "normal": len(cases) // 2,
        "threat": len(cases) // 2,
        "family_offset": family_offset,
        "families_per_group": families_per_group,
        "max_requests": len(llm_arms) * len(cases),
        "max_budget_usd": max_budget,
        "max_output_tokens": output_limit,
        "reasoning_effort": effort,
        "max_retries": 0,
        "concurrency": 1,
        "input_sha256": hashlib.sha256(payload).hexdigest(),
        "cases_sha256": hashlib.sha256(cases_path.read_bytes()).hexdigest(),
        "source_kind": "authored_synthetic_development_expected_labels",
        "independent_evaluation": False,
        "original_native_population_changed": False,
        "key_persisted_or_in_prompt": False,
        "rates_source": (
            "https://developers.openai.com/api/docs/models/gpt-5.4-mini"
            if model == MODEL
            else "https://developers.openai.com/api/docs/models/gpt-6.1-sol"
        ),
        "input_rate_per_million": input_rate * 1_000_000,
        "output_rate_per_million": output_rate * 1_000_000,
    }
    plan["source_pins"] = {
        p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
        for p in (
            "app/grounded_prompting.py",
            "app/analyzers/openai_analyzer.py",
            "scripts/evaluate_llm_grounded.py",
        )
    }
    (directory / "plan.json").write_bytes((json.dumps(plan, indent=2) + "\n").encode())
    rows, reserved, attempts = [], 0.0, 0
    for case in cases:
        a = RuleBasedAnalyzer().assess(case.event)
        rows.append(
            {
                "arm": "rule",
                "id": hashlib.sha256(case.case_id.encode()).hexdigest(),
                "prediction": prediction(a),
                "truth": case.threat,
                "latency_seconds": 0,
            }
        )
    fatal = None
    async with AsyncOpenAI(
        api_key=key, base_url="https://api.openai.com/v1", timeout=45, max_retries=0
    ) as client:
        for request in requests:
            amount = reservation(request["messages"], input_rate, output_rate, output_limit)
            if attempts >= len(llm_arms) * len(cases) or reserved + amount > max_budget:
                fatal = "budget_or_request_limit"
                break
            reserved += amount
            attempts += 1
            row = {
                "id": request["id"],
                "arm": request["arm"],
                "truth": truth[request["id"]],
                "prediction": None,
                "error": None,
                "input_tokens": None,
                "output_tokens": None,
            }
            start = time.monotonic()
            try:
                response = await client.responses.parse(
                    model=model,
                    store=False,
                    service_tier="default",
                    reasoning={"effort": effort},
                    text={"verbosity": "low"},
                    max_output_tokens=output_limit,
                    input=request["messages"],
                    text_format=(
                        grounded_output_type(request["event"])
                        if request["arm"] == "grounded"
                        else SecurityAssessment
                    ),
                )
                row.update(
                    resolved_model=response.model,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                )
                a = response.output_parsed
                if a is None:
                    raise ValueError("missing_structured_output")
                row["raw_assessment"] = a.model_dump(mode="json")
                if request["arm"] == "grounded":
                    a = validate_grounded(a, request["event"])
                row.update(prediction=prediction(a), assessment=a.model_dump(mode="json"))
            except Exception as error:  # noqa: BLE001 -- retain safe failure codes, never provider text/secrets
                row["error"] = type(error).__name__
                if type(error).__name__ in {
                    "AuthenticationError",
                    "PermissionDeniedError",
                    "RateLimitError",
                    "NotFoundError",
                }:
                    fatal = row["error"]
            row["latency_seconds"] = time.monotonic() - start
            rows.append(row)
            with (directory / "private/predictions.jsonl").open("ab") as f:
                f.write((json.dumps(row, ensure_ascii=False) + "\n").encode())
            print(
                json.dumps(
                    {"attempt": attempts, "arm": row["arm"], "status": row["error"] or "ok"}
                ),
                flush=True,
            )
            if fatal:
                break
    actual = sum(
        (r.get("input_tokens") or 0) * input_rate + (r.get("output_tokens") or 0) * output_rate
        for r in rows
    )
    scoring_rows = include_unattempted(rows, requests, truth)
    results = {
        arm: metrics([r for r in scoring_rows if r["arm"] == arm]) for arm in ("rule", *llm_arms)
    }
    report = {
        "at": datetime.now(UTC).isoformat(),
        "completed": attempts == len(llm_arms) * len(cases) and fatal is None,
        "fatal_error_code": fatal,
        "attempts": attempts,
        "reserved_upper_usd": reserved,
        "known_usage_estimated_usd": actual,
        "unknown_usage_attempts": sum(
            r.get("error") is not None and r.get("input_tokens") is None for r in rows
        ),
        "billing_is_provider_invoice_authoritative": True,
        "model": model,
        "metrics": results,
        "unattempted_requests": len(scoring_rows) - len(rows),
        "scope": plan["source_kind"],
        "independent_evaluation": False,
        "original_F1_updated": False,
        "policy_enforcement_changed": False,
        "plan_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    }
    (directory / "report.json").write_bytes(
        (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
    )
    print(json.dumps(report), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--key-env-file", type=Path)
    parser.add_argument("--family-offset", type=int, default=0)
    parser.add_argument("--families-per-group", type=int, default=2)
    parser.add_argument("--model", default=MODEL, choices=[MODEL, "gpt-6.1-sol"])
    parser.add_argument("--grounded-only", action="store_true")
    parser.add_argument("--max-budget", type=float, default=5)
    args = parser.parse_args()
    try:
        report = asyncio.run(
            run(
                args.directory,
                args.key_env_file,
                args.family_offset,
                args.families_per_group,
                args.model,
                ("grounded",) if args.grounded_only else ("legacy", "grounded"),
                args.max_budget,
            )
        )
        if not report["completed"]:
            raise SystemExit(1)
    except Exception as error:  # noqa: BLE001 -- CLI must not print credential-bearing exception details
        print(json.dumps({"completed": False, "error_code": type(error).__name__}))
        raise SystemExit(1) from None
