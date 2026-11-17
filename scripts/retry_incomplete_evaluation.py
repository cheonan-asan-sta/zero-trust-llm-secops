"""One actual higher-limit retry for every naturally token-truncated source case.

This replays successful first-attempt predictions unchanged. It is not a new
360-request test, not an independent evaluation, and never overwrites its source.
"""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from dotenv import dotenv_values
from openai import AsyncOpenAI

from app.analyzers.structured_response import StructuredResponseFailure, parse_structured_response
from app.grounded_prompting import (
    GROUNDED_INSTRUCTIONS,
    grounded_input,
    grounded_output_type,
    validate_grounded,
)
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_development import development_cases, write_json
from scripts.evaluate_llm_grounded import (
    INPUT_RATE,
    MODEL,
    OUTPUT_RATE,
    metrics,
    prediction,
    reservation,
)


def load_source(source):
    source = Path(source)
    plan = json.loads((source / "plan.json").read_bytes())
    report = json.loads((source / "report.json").read_bytes())
    payload = (source / "private/inputs.jsonl").read_bytes()
    if (
        not report["completed"]
        or plan["model"] != MODEL
        or hashlib.sha256(payload).hexdigest() != plan["inputs_sha256"]
    ):
        raise ValueError("source_provenance")
    rows = [json.loads(x) for x in (source / "private/predictions.jsonl").read_bytes().splitlines()]
    messages = {r["id"]: r["messages"] for r in map(json.loads, payload.splitlines())}
    cases_path = Path(__file__).resolve().parents[1] / "app/data/benchmark/cases.jsonl"
    if hashlib.sha256(cases_path.read_bytes()).hexdigest() != plan["cases_sha256"]:
        raise ValueError("source_population_changed")
    cases = {
        hashlib.sha256(c.case_id.encode()).hexdigest(): c for c in development_cases(cases_path)
    }
    if (
        len(rows) != 360
        or len({r["id"] for r in rows}) != 360
        or set(cases) != set(messages)
        or {r["id"] for r in rows} != set(cases)
    ):
        raise ValueError("source_cohort_changed")
    for row in rows:
        if row["truth"] is not cases[row["id"]].threat:
            raise ValueError("source_label_changed")
    eligible = [
        r
        for r in rows
        if r.get("error_code") == "response_not_completed"
        and r.get("response_diagnostics", {}).get("status") == "incomplete"
        and r.get("response_diagnostics", {}).get("incomplete_reason") == "max_output_tokens"
    ]
    return plan, report, rows, cases, messages, eligible


async def run(source, directory, key_file, *, max_budget=0.08):
    if not 0 < max_budget <= 0.08:
        raise ValueError("evaluation_options")
    directory = Path(directory)
    if directory.exists():
        raise ValueError("output_exists")
    old_plan, old_report, rows, cases, messages, eligible = load_source(source)
    if old_plan["max_output_tokens"] >= 4000:
        raise ValueError("retry_limit_not_larger")
    for row in eligible:
        case = cases[row["id"]]
        event = case.event.model_copy(update={"event_id": row["id"], "ground_truth": None})
        if messages[row["id"]] != [
            {"role": "system", "content": GROUNDED_INSTRUCTIONS},
            *grounded_input(event),
        ]:
            raise ValueError("frozen_input_no_longer_matches")
    key = dotenv_values(key_file).get("OPENAI_API_KEY")
    if not key:
        raise ValueError("missing_credential")
    directory.mkdir(parents=True)
    plan = {
        "schema": "natural-incomplete-bounded-retry-replay-1",
        "model": MODEL,
        "source_plan_sha256": hashlib.sha256((Path(source) / "plan.json").read_bytes()).hexdigest(),
        "source_predictions_sha256": hashlib.sha256(
            (Path(source) / "private/predictions.jsonl").read_bytes()
        ).hexdigest(),
        "source_inputs_sha256": old_plan["inputs_sha256"],
        "eligible_ids": [r["id"] for r in eligible],
        "eligibility": "all and only naturally incomplete max_output_tokens responses, regardless of truth",
        "max_requests": len(eligible),
        "max_retries_per_case": 1,
        "SDK_HTTP_retries": 0,
        "max_output_tokens": 4000,
        "max_budget_usd": max_budget,
        "fresh_360_pipeline_test": False,
        "source_overwritten": False,
        "independent_acceptance": False,
    }
    write_json(directory / "plan.json", plan)
    replacements, receipts, reserved, fatal = {}, [], 0.0, None
    async with AsyncOpenAI(
        api_key=key, base_url="https://api.openai.com/v1", timeout=45, max_retries=0
    ) as client:
        for original in eligible:
            identity = original["id"]
            amount = reservation(messages[identity], INPUT_RATE, OUTPUT_RATE, 4000)
            if reserved + amount > max_budget:
                fatal = "budget_limit"
                break
            reserved += amount
            receipt = {
                "id": identity,
                "reserved_usd": amount,
                "input_tokens": None,
                "output_tokens": None,
                "prediction": None,
                "error": None,
            }
            receipts.append(receipt)
            write_json(directory / "receipts.json", receipts)
            event = cases[identity].event.model_copy(
                update={"event_id": identity, "ground_truth": None}
            )
            try:
                response, diagnostic = await parse_structured_response(
                    client,
                    model=MODEL,
                    store=False,
                    service_tier="default",
                    reasoning={"effort": old_plan["reasoning_effort"]},
                    text={"verbosity": "low"},
                    max_output_tokens=4000,
                    input=messages[identity],
                    text_format=grounded_output_type(event),
                )
                receipt.update(
                    input_tokens=diagnostic.input_tokens,
                    output_tokens=diagnostic.output_tokens,
                    response_diagnostics=diagnostic.as_dict(),
                )
                assessment = validate_grounded(response.output_parsed, event)
                receipt.update(
                    prediction=prediction(assessment), assessment=assessment.model_dump(mode="json")
                )
                replacements[identity] = original | {
                    "prediction": receipt["prediction"],
                    "error": None,
                    "assessment": receipt["assessment"],
                    "first_attempt_error": original.get("error"),
                    "first_attempt_diagnostics": original.get("response_diagnostics"),
                    "first_attempt": original,
                    "error_code": None,
                    "response_diagnostics": diagnostic.as_dict(),
                    "actual_retry": receipt,
                }
            except Exception as error:  # noqa: BLE001 -- retain safe codes only
                receipt["error"] = type(error).__name__
                if isinstance(error, StructuredResponseFailure):
                    receipt.update(
                        error_code=error.code,
                        response_diagnostics=error.diagnostics.as_dict(),
                        input_tokens=error.diagnostics.input_tokens,
                        output_tokens=error.diagnostics.output_tokens,
                    )
                if type(error).__name__ in {
                    "AuthenticationError",
                    "PermissionDeniedError",
                    "RateLimitError",
                    "NotFoundError",
                }:
                    fatal = type(error).__name__
            write_json(directory / "receipts.json", receipts)
            if identity not in replacements:
                replacements[identity] = original | {"first_attempt": original, "actual_retry": receipt}
            if fatal:
                break
    candidate = [replacements.get(r["id"], r) for r in rows]
    result = {
        "schema": plan["schema"],
        "completed": fatal is None and len(receipts) == len(eligible),
        "fatal": fatal,
        "eligible": len(eligible),
        "attempts": len(receipts),
        "source_first_attempt_metrics": old_report["metrics"],
        "replayed_pipeline_metrics": metrics(candidate),
        "comparison": compare_rows(rows, candidate),
        "reserved_upper_usd": reserved,
        "known_usage_estimated_usd": sum(
            (r["input_tokens"] or 0) * INPUT_RATE + (r["output_tokens"] or 0) * OUTPUT_RATE
            for r in receipts
        ),
        "unknown_usage_attempts": sum(
            r["input_tokens"] is None or r["output_tokens"] is None for r in receipts
        ),
        "unknown_usage_reserved_usd": sum(
            r["reserved_usd"]
            for r in receipts
            if r["input_tokens"] is None or r["output_tokens"] is None
        ),
        "fresh_360_pipeline_test": False,
        "source_overwritten": False,
        "independent_acceptance": False,
    }
    write_json(directory / "replayed-predictions.json", candidate)
    write_json(directory / "report.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--key-env-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(run(args.source, args.directory, args.key_env_file))))
    except Exception as error:  # noqa: BLE001 -- secret-safe CLI
        print(json.dumps({"completed": False, "error_code": type(error).__name__}))
        raise SystemExit(1) from None
