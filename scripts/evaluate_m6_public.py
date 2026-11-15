"""Run the three-model M6 comparison on the verified public policy-denial cohort."""

import asyncio
import json
import time
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

import httpx
from pydantic import SecretStr

from scripts import evaluate_m6 as m6
from scripts import m6_public_providers as providers
from scripts import prepare_m7 as m7
from scripts import prepare_m7_evidence_holdout as holdout
from scripts.evaluate_m6_live import LiveKeys, result_for, summarize_live, write_ledger
from scripts.m6_live_providers import INPUT_LIMIT, OUTPUT_LIMIT

PRICING = {
    "gpt-5.4-mini": (Decimal("0.75"), Decimal("4.5")),
    "gpt-6.1-sol": (Decimal(2), Decimal(10)),
    "jev-1.14.0": (Decimal("0.042"), Decimal(0)),
}
PRICING_SOURCES = [
    "https://developers.openai.com/api/docs/models/gpt-5.4-mini",
    "https://developers.openai.com/api/docs/models/gpt-6.1-sol",
    "https://help.typesafe.ai/articles/5187202169-how-much-does-jev-cost",
]
SCOPE = "Policy-denial recognition on 12 public synthetic sessions; the 403-only rule separates the labels."
REQUEST_SECONDS = 30
WALL_SECONDS = 600
JEV_CONTEXT_LIMIT = 65_536
JEV_MAX_WIRE_BYTES = 5120


class PublicKeys(LiveKeys):
    typesafe_api_key: SecretStr | None = None


def configured_credentials():
    settings = PublicKeys()
    return {
        model: value.get_secret_value().strip() if value else ""
        for model, field in providers.CREDENTIAL_ENV.items()
        for value in (getattr(settings, field.lower()),)
    }


def bind_cases(requests, scoring, expected_counts, metadata_fields):
    scoring_rows = [json.loads(line, object_pairs_hook=m6.unique_fields) for line in scoring.splitlines()]
    labels = {row["session_id"]: row for row in scoring_rows}
    if len(labels) != len(scoring_rows):
        raise ValueError("m6_duplicate_scoring_id")
    inputs, cases = [], []
    for payload in requests.splitlines():
        request = json.loads(payload, object_pairs_hook=m6.unique_fields)
        case_id = request["case_id"]
        label = labels.pop(case_id)
        digest = m6.digest(payload)
        if digest != label["input_sha256"] or m6.canonical(request) != payload:
            raise ValueError("m6_public_request_digest")
        cases.append({
            "case_id": case_id, "input_sha256": digest, "expected_label": label["expected_label"],
            **{field: label[field] for field in metadata_fields},
        })
        inputs.append((request, payload))
    if labels or Counter(case["expected_label"] for case in cases) != expected_counts:
        raise ValueError("m6_public_cohort_size")
    return inputs, cases


def prepare_cases(directory, source):
    files, manifest = holdout.build(source, json.loads(m7.SOURCE.read_bytes()))
    if any((directory / name).read_bytes() != data for name, data in files.items()):
        raise ValueError("m6_public_bundle_changed")
    requests = files["model-requests.jsonl"]
    scoring = files["private/scoring-labels.jsonl"]
    inputs, cases = bind_cases(requests, scoring, {"normal": 6, "threat": 6}, ("evidence_basis",))
    provenance = {
        "scope": SCOPE,
        "manifest_sha256": m6.digest(files["manifest.json"]),
        "requests_sha256": m6.digest(requests),
        "scoring_sha256": m6.digest(scoring),
        "source_sha256": manifest["source_sha256"],
        "source_revision": manifest["source_revision"],
        "excluded_indeterminate_development_sessions": manifest["excluded_indeterminate_development_sessions"],
        "overlap_with_prior": manifest["overlap_with_prior"],
    }
    return inputs, cases, provenance


def cost(model, input_tokens, output_tokens):
    input_rate, output_rate = PRICING[model]
    return (input_rate * input_tokens + output_rate * output_tokens) / 1_000_000


def execution_plan(inputs, cases, provenance):
    reserves = {model: cost(model, INPUT_LIMIT, OUTPUT_LIMIT) for model in providers.OPENAI_MODELS}
    # Jev has no count endpoint. Reserve against its documented context and cap the local request.
    reserves[providers.JEV_MODEL] = cost(providers.JEV_MODEL, JEV_CONTEXT_LIMIT, 0)
    for request, payload in inputs:
        choice_bytes = len(request["question"].encode()) + sum(len(label) for label in request["labels"])
        if len(payload) + choice_bytes > INPUT_LIMIT or providers.jev_wire_size(payload) > JEV_MAX_WIRE_BYTES:
            raise ValueError("m6_public_input_too_large")
    return {
        "schema": "m6-public-evidence-plan-1", **provenance,
        "mode": "preflight", "models": list(providers.MODELS), "cases": len(cases),
        "input_hashes": {case["case_id"]: case["input_sha256"] for case in cases},
        "generation_requests": len(cases) * len(providers.MODELS),
        "planned_openai_token_count_requests": len(cases) * len(providers.OPENAI_MODELS),
        "max_reserved_usd": str(len(cases) * sum(reserves.values())),
        "reserve_per_request_usd": {model: str(value) for model, value in reserves.items()},
        "pricing_sources": PRICING_SOURCES, "max_input_tokens": INPUT_LIMIT,
        "openai_max_output_tokens": OUTPUT_LIMIT, "retries": 0,
        "jev_context_reserved_tokens": JEV_CONTEXT_LIMIT, "jev_max_wire_bytes": JEV_MAX_WIRE_BYTES,
    }


def baseline(inputs, cases):
    results = []
    for (request, _), case in zip(inputs, cases, strict=True):
        label = "threat" if any(event["http_status"] == 403 for event in request["events"]) else "normal"
        results.append(m6.result(case["case_id"], case["input_sha256"], status="ok", label=label))
    return {"rule": "threat if any input event has HTTP 403", "summary": summarize_live(results, cases)}


async def run_comparison(output, inputs, cases, provenance, plan, credentials, *, max_requests, max_usd,
                         wall_seconds=WALL_SECONDS, transport=None):
    if (any(not credentials.get(model) for model in providers.MODELS)
            or max_requests != plan["generation_requests"] or wall_seconds <= 0
            or not max_usd.is_finite() or max_usd < Decimal(plan["max_reserved_usd"])):
        raise ValueError("m6_public_live_limits_or_credentials")

    mock = isinstance(transport, httpx.MockTransport)
    mode = "mock" if mock else "live"
    budget_limit_key = "simulated_usd_limit" if mock else "authorized_usd"
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    m6.write_report(output / "plan.json", plan | {
        "mode": mode, budget_limit_key: str(max_usd), "wall_seconds": wall_seconds,
    })
    deadline = time.monotonic() + wall_seconds
    results = {model: {} for model in providers.MODELS}
    count_calls, generated = 0, 0
    known_cost = unreconciled = Decimal(0)
    stop = None
    async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False) as client:
        with (output / "requests.jsonl").open("x", encoding="utf-8") as ledger:
            for (request, payload), case in zip(inputs, cases, strict=True):
                for model in providers.MODELS:
                    timeout = min(REQUEST_SECONDS, deadline - time.monotonic())
                    if timeout <= 0:
                        stop = "wall_limit"
                        break
                    if model in providers.OPENAI_MODELS:
                        count_calls += 1
                        try:
                            count = await asyncio.wait_for(
                                providers.count_input(client, model, credentials[model], payload, timeout), timeout,
                            )
                        except (providers.ProviderError, TimeoutError):
                            stop = "token_count_unavailable"
                            break
                        if type(count) is not int or not 0 < count <= INPUT_LIMIT:
                            stop = "input_limit"
                            break
                    timeout = min(REQUEST_SECONDS, deadline - time.monotonic())
                    if timeout <= 0:
                        stop = "wall_limit"
                        break
                    identity = {"model": model, "case_id": case["case_id"], "input_sha256": case["input_sha256"]}
                    reserved_usd = plan["reserve_per_request_usd"][model]
                    attempt = {"reserved_usd": reserved_usd, "started_at": datetime.now(UTC).isoformat()}
                    if model in providers.OPENAI_MODELS:
                        attempt["input_tokens_preflight"] = count
                    write_ledger(ledger, {"kind": "reserved", **identity, **attempt})
                    generated += 1
                    started = time.monotonic()
                    try:
                        receipt = await asyncio.wait_for(
                            providers.infer(client, model, credentials[model], payload, timeout), timeout,
                        )
                    except TimeoutError:
                        receipt = {"status": "timeout"}
                    attempt["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
                    for field in ("resolved_model", "http_status", "input_tokens", "output_tokens", "request_id"):
                        attempt[field] = receipt.get(field)
                    input_used, output_used = attempt["input_tokens"], attempt["output_tokens"]
                    if type(input_used) is int and type(output_used) is int and min(input_used, output_used) >= 0:
                        charged = cost(model, input_used, output_used)
                        known_cost += charged
                        cost_field = "simulated_cost_estimate_usd" if mock else "usage_cost_estimate_usd"
                        attempt[cost_field] = str(charged)
                        if input_used > INPUT_LIMIT or charged > Decimal(reserved_usd):
                            stop = "usage_limit"
                    else:
                        unreconciled += Decimal(reserved_usd)
                    row = result_for(request, case, receipt, attempt)
                    if receipt.get("validation_error"):
                        attempt["validation_error"] = receipt["validation_error"]
                    for field in ("confidence", "probabilities"):
                        if field in receipt:
                            row[field] = receipt[field]
                    results[model][case["case_id"]] = row
                    write_ledger(ledger, {"kind": "result", **identity, "result": row})
                    if attempt["http_status"] in {400, 401, 402, 403, 404, 422, 429}:
                        stop = "provider_rejected"
                    if stop:
                        break
                if stop:
                    break

    models = {}
    for model, rows in results.items():
        ordered = [rows.get(case["case_id"]) or m6.result(
            case["case_id"], case["input_sha256"], status="not_run",
        ) for case in cases]
        models[model] = {"results": ordered, "summary": summarize_live(ordered, cases)}
    budget = {
        "actual_provider_requests": 0 if mock else generated,
        "openai_token_count_requests": 0 if mock else count_calls,
        "usage_cost_estimate_usd": "0" if mock else str(known_cost),
        "unreconciled_max_usd": "0" if mock else str(unreconciled),
    }
    if mock:
        budget.update(
            simulated_inference_requests=generated, simulated_openai_token_count_requests=count_calls,
            simulated_usage_cost_estimate_usd=str(known_cost),
            simulated_unreconciled_max_usd=str(unreconciled),
        )
    return {
        **provenance, "mode": mode, "stop_reason": stop,
        "cases": cases, "models": models, "status_baseline": baseline(inputs, cases),
        "budget": budget,
    }


async def run_live(output, inputs, cases, provenance, plan, credentials, *, max_requests, max_usd,
                   wall_seconds=WALL_SECONDS, transport=None):
    comparison = await run_comparison(
        output, inputs, cases, provenance, plan, credentials, max_requests=max_requests, max_usd=max_usd,
        wall_seconds=wall_seconds, transport=transport,
    )
    report = {"schema": "m6-public-evidence-report-1", **comparison}
    m6.write_report(output / "report.json", report)
    return report


def run_cli(args):
    inputs, cases, provenance = prepare_cases(args.m7_public, args.m7_source)
    plan = execution_plan(inputs, cases, provenance)
    if not args.live:
        args.output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        m6.write_report(args.output_dir / "plan.json", plan)
        print(json.dumps({key: plan[key] for key in ("cases", "generation_requests", "max_reserved_usd")}))
        return 0
    try:
        max_usd = Decimal(args.live_max_usd)
    except InvalidOperation as exc:
        raise ValueError("m6_public_cost_limit") from exc
    report = asyncio.run(run_live(
        args.output_dir, inputs, cases, provenance, plan, configured_credentials(),
        max_requests=args.max_requests, max_usd=max_usd,
        wall_seconds=WALL_SECONDS if args.wall_seconds is None else args.wall_seconds,
    ))
    print(json.dumps({"stop_reason": report["stop_reason"], "budget": report["budget"]}))
    return int(bool(report["stop_reason"]) or any(
        value["summary"]["failed_count"] or value["summary"]["not_run_count"]
        for value in report["models"].values()
    ))
