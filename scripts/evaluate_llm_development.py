"""Freeze and score all authored development variants; never read holdout inputs.

Known usage releases unused per-request reservation. A request without trustworthy
usage retains its full reservation. A crash leaves the pending request reserved.
This is characterization of already authored data, not independent acceptance.
"""

import argparse
import asyncio
import hashlib
import json
import math
import os
import time
from collections import defaultdict
from datetime import UTC, datetime
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
from app.services.detection_benchmark import BenchmarkCase
from scripts.evaluate_llm_grounded import (
    INPUT_RATE,
    MODEL,
    OUTPUT_RATE,
    metrics,
    prediction,
    reservation,
)


def write_json(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def development_cases(path):
    # Inspect split first. Holdout event objects are never parsed or sent to a model.
    cases = []
    for line in Path(path).read_bytes().splitlines():
        raw = json.loads(line)
        if raw.get("split") == "development":
            cases.append(BenchmarkCase.model_validate(raw))
    if len(cases) != 360 or len({c.case_id for c in cases}) != 360:
        raise ValueError("development_population_changed")
    return sorted(cases, key=lambda c: c.case_id)


async def run(directory, key_file=None, *, max_budget=2.0, stop_at=None):
    if not math.isfinite(max_budget) or not 0 < max_budget <= 2:
        raise ValueError("evaluation_options")
    directory = Path(directory)
    if directory.exists():
        raise ValueError("output_exists")
    deadline = datetime.fromisoformat(stop_at) if stop_at else None
    if deadline is not None and (deadline.tzinfo is None or deadline <= datetime.now(UTC)):
        raise ValueError("invalid_deadline")
    key = os.environ.get("OPENAI_API_KEY") or (
        dotenv_values(key_file).get("OPENAI_API_KEY") if key_file else None
    )
    if not key:
        raise ValueError("missing_credential")
    root = Path(__file__).resolve().parents[1]
    cases_path = root / "app/data/benchmark/cases.jsonl"
    cases = development_cases(cases_path)
    directory.mkdir(parents=True)
    private = directory / "private"
    private.mkdir()
    requests = []
    for case in cases:
        identity = hashlib.sha256(case.case_id.encode()).hexdigest()
        event = case.event.model_copy(update={"event_id": identity, "ground_truth": None})
        messages = [{"role": "system", "content": GROUNDED_INSTRUCTIONS}, *grounded_input(event)]
        requests.append((case, identity, event, messages))
    inputs = b"".join(
        (json.dumps({"id": i, "messages": m}, ensure_ascii=False) + "\n").encode()
        for _, i, _, m in requests
    )
    (private / "inputs.jsonl").write_bytes(inputs)
    plan = {
        "schema": "all-authored-development-characterization-1",
        "model": MODEL,
        "max_output_tokens": 2400,
        "reasoning_effort": "low",
        "store": False,
        "max_retries": 0,
        "concurrency": 1,
        "cases": 360,
        "families": len({c.family_id for c in cases}),
        "max_requests": 360,
        "max_budget_usd": max_budget,
        "stop_at": stop_at,
        "cases_sha256": hashlib.sha256(cases_path.read_bytes()).hexdigest(),
        "inputs_sha256": hashlib.sha256(inputs).hexdigest(),
        "split": "development",
        "independent_evaluation": False,
        "holdout_evaluated": False,
        "historical_proof_backfilled": False,
        "rate_input_per_million": INPUT_RATE * 1e6,
        "rate_output_per_million": OUTPUT_RATE * 1e6,
        "source_pins": {},
    }
    for file in (
        "scripts/evaluate_llm_development.py",
        "scripts/evaluate_llm_grounded.py",
        "app/analyzers/structured_response.py",
        "app/grounded_prompting.py",
        "app/models.py",
    ):
        content = (root / file).read_bytes()
        plan["source_pins"][file] = hashlib.sha256(content).hexdigest()
        target = directory / "source-snapshot" / file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    write_json(directory / "plan.json", plan)
    rows, settled, unknown_reserved = [], 0.0, 0.0
    pending, fatal = None, None

    def checkpoint():
        write_json(
            directory / "cost-checkpoint.json",
            {
                "known_usage_estimated_usd": settled,
                "unknown_usage_reserved_usd": unknown_reserved,
                "pending_request": pending,
                "charged_or_reserved_usd": settled
                + unknown_reserved
                + (pending["reserved_usd"] if pending else 0),
                "max_budget_usd": max_budget,
                "completed_rows": len(rows),
            },
        )

    checkpoint()
    async with AsyncOpenAI(api_key=key, timeout=45, max_retries=0) as client:
        for case, identity, event, messages in requests:
            amount = reservation(messages, INPUT_RATE, OUTPUT_RATE, 2400)
            if settled + unknown_reserved + amount > max_budget:
                fatal = "budget_limit"
                break
            if deadline and (deadline - datetime.now(UTC)).total_seconds() <= 50:
                fatal = "deadline"
                break
            pending = {"id": identity, "reserved_usd": amount}
            checkpoint()
            row = {
                "id": identity,
                "domain": case.domain,
                "family_id": case.family_id,
                "truth": case.threat,
                "prediction": None,
                "error": None,
                "input_tokens": None,
                "output_tokens": None,
                "request_attempted": True,
            }
            started = time.monotonic()
            try:
                response, diagnostics = await parse_structured_response(
                    client,
                    model=MODEL,
                    store=False,
                    service_tier="default",
                    reasoning={"effort": "low"},
                    text={"verbosity": "low"},
                    max_output_tokens=2400,
                    input=messages,
                    text_format=grounded_output_type(event),
                )
                row.update(
                    response_diagnostics=diagnostics.as_dict(),
                    input_tokens=diagnostics.input_tokens,
                    output_tokens=diagnostics.output_tokens,
                    resolved_model=response.model,
                )
                assessment = validate_grounded(response.output_parsed, event)
                row.update(
                    prediction=prediction(assessment), assessment=assessment.model_dump(mode="json")
                )
            except Exception as error:  # noqa: BLE001 -- never persist provider error text
                row["error"] = type(error).__name__
                if isinstance(error, StructuredResponseFailure):
                    row.update(
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
            row["latency_seconds"] = time.monotonic() - started
            if row["input_tokens"] is None or row["output_tokens"] is None:
                unknown_reserved += amount
            else:
                settled += row["input_tokens"] * INPUT_RATE + row["output_tokens"] * OUTPUT_RATE
            with (private / "predictions.jsonl").open("ab") as stream:
                stream.write((json.dumps(row, ensure_ascii=False) + "\n").encode())
            rows.append(row)
            pending = None
            checkpoint()
            print(
                json.dumps(
                    {
                        "attempt": len(rows),
                        "status": row["error"] or "ok",
                        "cost_or_reserved_usd": settled + unknown_reserved,
                    }
                ),
                flush=True,
            )
            if fatal:
                break
    attempted = {r["id"] for r in rows}
    scored = rows + [
        {
            "id": i,
            "domain": c.domain,
            "family_id": c.family_id,
            "truth": c.threat,
            "prediction": None,
            "error": "not_attempted",
            "request_attempted": False,
        }
        for c, i, _, _ in requests
        if i not in attempted
    ]
    domains = defaultdict(list)
    for row in scored:
        domains[row["domain"]].append(row)
    report = {
        "schema": plan["schema"],
        "completed": len(rows) == 360 and fatal is None,
        "fatal": fatal,
        "attempts": len(rows),
        "unattempted": 360 - len(rows),
        "metrics": metrics(scored),
        "by_domain": {d: metrics(r) for d, r in domains.items()},
        "known_usage_estimated_usd": settled,
        "unknown_usage_reserved_usd": unknown_reserved,
        "unknown_usage_attempts": sum(
            r["input_tokens"] is None or r["output_tokens"] is None for r in rows
        ),
        "max_budget_usd": max_budget,
        "families": plan["families"],
        "independent_evaluation": False,
        "holdout_evaluated": False,
        "native_metrics_updated": False,
        "plan_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    }
    write_json(directory / "report.json", report)
    print(json.dumps(report), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--key-env-file", type=Path)
    parser.add_argument("--max-budget", type=float, default=2)
    parser.add_argument("--stop-at")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run(args.directory, args.key_env_file, max_budget=args.max_budget, stop_at=args.stop_at)
        )
        if not result["completed"]:
            raise SystemExit(1)
    except Exception as error:  # noqa: BLE001 -- secret-safe command output
        print(json.dumps({"completed": False, "error_code": type(error).__name__}))
        raise SystemExit(1) from None
