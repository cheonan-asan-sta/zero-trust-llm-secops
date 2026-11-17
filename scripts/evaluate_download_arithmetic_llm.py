"""Evaluate every changed DOWNLOAD input; replay unchanged predictions explicitly.

This is a development ablation, never a fresh 360-call or independent evaluation.
The arithmetic candidate is not connected to the runtime analyzer.
"""

import argparse
import asyncio
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path

from dotenv import dotenv_values
from openai import AsyncOpenAI

from app.analyzers.structured_response import StructuredResponseFailure
from app.grounded_prompting import (
    GROUNDED_INSTRUCTIONS,
    grounded_input,
    grounded_output_type,
    validate_grounded,
)
from scripts.bounded_llm_requests import BoundedRequests
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_development import write_json
from scripts.evaluate_llm_grounded import MODEL, metrics, prediction
from scripts.retry_incomplete_evaluation import load_source


def prepare(source):
    old_plan, old_report, rows, cases, messages, _ = load_source(source)
    inputs, changed = [], []
    for row in rows:
        identity, case = row["id"], cases[row["id"]]
        event = case.event.model_copy(update={"event_id": identity, "ground_truth": None})
        reference = [{"role": "system", "content": GROUNDED_INSTRUCTIONS}, *grounded_input(event)]
        if messages[identity] != reference:
            raise ValueError("source_message_drift")
        candidate = [
            {"role": "system", "content": GROUNDED_INSTRUCTIONS},
            *grounded_input(event, download_volume_arithmetic=True),
        ]
        differs = candidate != reference
        if differs and event.action != "DOWNLOAD":
            raise ValueError("unexpected_changed_action")
        inputs.append({"id": identity, "messages": candidate, "input_changed": differs})
        if differs:
            changed.append((row, event, candidate))
    if not changed or len(changed) > 72:
        raise ValueError("changed_population_capacity")
    return old_plan, old_report, rows, inputs, changed


async def run(source, directory, key_file, *, max_budget=0.4, stop_at):
    source, directory = Path(source), Path(directory)
    deadline = datetime.fromisoformat(stop_at)
    if (
        not math.isfinite(max_budget)
        or not 0 < max_budget <= 0.4
        or deadline.tzinfo is None
        or directory.exists()
        or directory.resolve().is_relative_to(source.resolve())
    ):
        raise ValueError("evaluation_options")
    old_plan, old_report, rows, inputs, changed = prepare(source)
    source_paths = [
        source / name
        for name in (
            "plan.json",
            "report.json",
            "private/inputs.jsonl",
            "private/predictions.jsonl",
        )
    ]
    source_hashes = {
        str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths
    }
    key = dotenv_values(key_file).get("OPENAI_API_KEY")
    if not key:
        raise ValueError("missing_credential")
    directory.mkdir(parents=True)
    (directory / "private").mkdir()
    payload = b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode() for row in inputs)
    (directory / "private/inputs.jsonl").write_bytes(payload)
    plan = {
        "schema": "download-arithmetic-changed-input-replay-1",
        "model": MODEL,
        "original_cases": 360,
        "changed_inputs": len(changed),
        "unchanged_inputs": 360 - len(changed),
        "selection": "all and only inputs changed by the predeclared DOWNLOAD-only arithmetic builder; no label selection",
        "cases_sha256": old_plan["cases_sha256"],
        "source_file_sha256": source_hashes,
        "inputs_sha256": hashlib.sha256(payload).hexdigest(),
        "max_budget_usd": max_budget,
        "max_provider_calls": len(changed),
        "reasoning_effort": "low",
        "max_output_tokens": 2400,
        "SDK_retries": 0,
        "stop_at": stop_at,
        "fresh_360_pipeline_test": False,
        "prediction_reuse_on_unchanged_inputs": True,
        "runtime_adoption": False,
        "independent_acceptance": False,
        "holdout_evaluated": False,
        "native_metrics_updated": False,
        "development_gate": [
            "complete every changed input",
            "no lost original TP IDs",
            "no new FP IDs",
            "F1 not lower",
            "at least one corrected FP or recovered TP",
            "no new provider errors",
        ],
        "source_pins": {},
    }
    root = Path(__file__).resolve().parents[1]
    for name in (
        "scripts/evaluate_download_arithmetic_llm.py",
        "scripts/retry_incomplete_evaluation.py",
        "scripts/bounded_llm_requests.py",
        "scripts/evaluate_llm_grounded.py",
        "scripts/evaluate_llm_development.py",
        "app/analyzers/structured_response.py",
        "app/grounded_prompting.py",
        "app/models.py",
        "app/services/sigma.py",
        "app/services/ocsf.py",
    ):
        content = (root / name).read_bytes()
        plan["source_pins"][name] = hashlib.sha256(content).hexdigest()
        target = directory / "source-snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    write_json(directory / "plan.json", plan)
    ledger = BoundedRequests(
        directory, max_budget=max_budget, max_requests=len(changed), deadline=deadline
    )
    updates = {}
    async with AsyncOpenAI(api_key=key, timeout=30, max_retries=0) as client:
        for previous, event, messages in changed:
            row = {
                "id": previous["id"],
                "truth": previous["truth"],
                "domain": previous["domain"],
                "family_id": previous["family_id"],
                "prediction": None,
                "error": None,
                "input_changed": True,
                "prediction_reused": False,
                "reference": previous,
            }
            first = len(ledger.receipts)
            try:
                response, diagnostic = await ledger.capture(
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
                result = validate_grounded(response.output_parsed, event)
                row.update(
                    prediction=prediction(result),
                    assessment=result.model_dump(mode="json"),
                    response_diagnostics=diagnostic.as_dict(),
                )
            except Exception as error:  # noqa: BLE001 -- no provider message persisted
                row["error"] = type(error).__name__
                if isinstance(error, StructuredResponseFailure):
                    row.update(
                        error_code=error.code, response_diagnostics=error.diagnostics.as_dict()
                    )
            row["provider_request_attempted"] = len(ledger.receipts) > first
            updates[row["id"]] = row
            write_json(directory / "private/changed-predictions.json", list(updates.values()))
            print(
                json.dumps(
                    {
                        "completed_changed_rows": len(updates),
                        "requests": len(ledger.receipts),
                        "known_usd": ledger.totals()[0],
                    }
                ),
                flush=True,
            )
            if ledger.fatal:
                break
    changed_ids = {row["id"] for row, _, _ in changed}
    candidate = []
    for previous in rows:
        identity = previous["id"]
        if identity in updates:
            candidate.append(updates[identity])
        elif identity in changed_ids:
            candidate.append(
                {
                    "id": identity,
                    "truth": previous["truth"],
                    "domain": previous["domain"],
                    "family_id": previous["family_id"],
                    "prediction": None,
                    "error": "not_attempted",
                    "input_changed": True,
                    "prediction_reused": False,
                    "reference": previous,
                }
            )
        else:
            candidate.append(previous | {"input_changed": False, "prediction_reused": True})
    comparison = compare_rows(rows, candidate)
    known, unknown = ledger.totals()
    complete = ledger.fatal is None and len(ledger.receipts) == len(changed)
    errors = sum(r.get("error") is not None for r in candidate if r["input_changed"])
    gate = (
        complete
        and comparison["no_lost_detections"]
        and comparison["no_new_false_positives"]
        and comparison["candidate"]["F1"] >= comparison["reference"]["F1"]
        and bool(comparison["corrected_FP_ids"] or comparison["recovered_TP_ids"])
        and not errors
    )
    unchanged_source = all(
        hashlib.sha256(p.read_bytes()).hexdigest() == source_hashes[str(p.relative_to(source))]
        for p in source_paths
    )
    gate = gate and unchanged_source
    report = {
        "schema": plan["schema"],
        "completed": complete,
        "fatal": ledger.fatal,
        "attempts": len(ledger.receipts),
        "known_usage_estimated_usd": known,
        "unknown_usage_reserved_usd": unknown,
        "changed_input_metrics": metrics([r for r in candidate if r["input_changed"]]),
        "source_full_360_metrics": old_report["metrics"],
        "reference_changed_input_metrics": metrics([r for r in rows if r["id"] in changed_ids]),
        "replayed_360_comparison": comparison,
        "development_candidate_gate_passed": bool(gate),
        "fresh_360_pipeline_test": False,
        "reused_predictions": 360 - len(changed),
        "source_overwritten": not unchanged_source,
        "runtime_adoption": False,
        "independent_acceptance": False,
        "holdout_evaluated": False,
        "native_metrics_updated": False,
        "plan_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    }
    write_json(directory / "replayed-predictions.json", candidate)
    write_json(directory / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--key-env-file", type=Path, required=True)
    parser.add_argument("--max-budget", type=float, default=0.4)
    parser.add_argument("--stop-at", required=True)
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run(
                args.source,
                args.directory,
                args.key_env_file,
                max_budget=args.max_budget,
                stop_at=args.stop_at,
            )
        )
        print(json.dumps(result))
        if not result["completed"]:
            raise SystemExit(1)
    except Exception as error:  # noqa: BLE001 -- never print credentials/provider text
        print(json.dumps({"completed": False, "error_code": type(error).__name__}))
        raise SystemExit(1) from None
