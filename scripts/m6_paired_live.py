"""Bounded, audited provider execution for the 200-session paired evaluation."""

import asyncio
import json
import time
from datetime import UTC, datetime
from decimal import Decimal

import httpx

from scripts import evaluate_m6 as m6
from scripts import m6_live_providers as live
from scripts import m6_public_providers as providers
from scripts.evaluate_m6_live import result_for, summarize_live, write_ledger
from scripts.evaluate_m6_public import JEV_CONTEXT_LIMIT, REQUEST_SECONDS, baseline, cost

SESSION_COUNT = 200
GENERATION_LIMIT = SESSION_COUNT * len(providers.MODELS)
COUNT_URL = live.OPENAI_URL + "/input_tokens"
REQUEST_FIELDS = {"case_id", "events", "evidence_ids", "labels", "question"}
PRIVATE_FIELDS = {"expected_label", "pair_id", "scenario", "scoring_label"}
OPENAI_COUNT_FIELDS = {"model", "input", "reasoning", "text", "truncation"}
OPENAI_GENERATION_FIELDS = OPENAI_COUNT_FIELDS | {"store", "service_tier", "max_output_tokens"}
FATAL_PROVIDER_STATUS = {400, 401, 402, 403, 404, 422, 429}
PREFLIGHT_INTERVAL_SECONDS = 0.2


def _has_private_fields(value):
    if isinstance(value, dict):
        return bool(PRIVATE_FIELDS & value.keys()) or any(map(_has_private_fields, value.values()))
    if isinstance(value, (list, tuple)):
        return any(map(_has_private_fields, value))
    return False


class WireAudit:
    """Validate the actual HTTP envelopes against the frozen, unscored payload bytes."""

    def __init__(self, inputs):
        self.inputs = {}
        for request, payload in inputs:
            case_id = request["case_id"]
            if (case_id in self.inputs or set(request) != REQUEST_FIELDS
                    or tuple(request["labels"]) != m6.LABELS or m6.canonical(request) != payload
                    or _has_private_fields(request)):
                raise ValueError("m6_paired_live_input_shape")
            self.inputs[case_id] = payload
        self.generated = {model: set() for model in providers.MODELS}
        self.counted = {model: set() for model in providers.OPENAI_MODELS}

    async def check(self, outgoing):
        body = json.loads(outgoing.content, object_pairs_hook=m6.unique_fields)
        url, model = str(outgoing.url), body["model"]
        is_count = url == COUNT_URL
        if outgoing.method != "POST":
            raise ValueError("m6_paired_live_wire_method")
        if model in providers.OPENAI_MODELS and url in {live.OPENAI_URL, COUNT_URL}:
            content = body["input"][0]["content"]
            fixed_fields = OPENAI_COUNT_FIELDS if is_count else OPENAI_GENERATION_FIELDS
            if (set(body) != fixed_fields or body["input"] != [{"role": "user", "content": content}]
                    or body["reasoning"] != {"effort": "low"} or body["truncation"] != "disabled"
                    or body["text"] != {"format": {
                        "type": "json_schema", "name": "m6_classification", "schema": live.SCHEMA, "strict": True,
                    }}
                    or (not is_count and (body["store"] is not False or body["service_tier"] != "default"
                                          or body["max_output_tokens"] != live.OUTPUT_LIMIT))):
                raise ValueError("m6_paired_live_openai_envelope")
        elif model == providers.JEV_MODEL and url == providers.JEV_URL:
            content = body["state"]
            request = json.loads(content, object_pairs_hook=m6.unique_fields)
            expected_questions = {"classification": {
                "type": "choice", "instructions": request["question"],
                "criteria": dict.fromkeys(request["labels"]),
            }}
            if set(body) != {"model", "state", "questions"} or body["questions"] != expected_questions:
                raise ValueError("m6_paired_live_jev_envelope")
        else:
            raise ValueError("m6_paired_live_wire_endpoint")
        case_id = json.loads(content, object_pairs_hook=m6.unique_fields)["case_id"]
        if content.encode() != self.inputs.get(case_id):
            raise ValueError("m6_paired_live_wire_payload_changed")
        seen = self.counted[model] if is_count else self.generated[model]
        if case_id in seen:
            raise ValueError("m6_paired_live_duplicate_request")
        seen.add(case_id)

    def summary(self):
        per_model = {model: len(ids) for model, ids in self.generated.items()}
        common = set.intersection(*self.generated.values())
        return {
            "matched_input_sessions": len(common),
            "verified_generation_requests": sum(per_model.values()),
            "verified_openai_token_count_requests": sum(len(ids) for ids in self.counted.values()),
            "generation_requests_by_model": per_model,
            "same_input_bytes_per_model": True,
            "scoring_fields_present": False,
        }


async def run_paired_live(output, inputs, cases, provenance, plan, credentials, *, max_requests, max_usd,
                          wall_seconds=1800, parallel_per_openai=4, transport=None):
    if (len(inputs) != SESSION_COUNT or len(cases) != SESSION_COUNT or max_requests != GENERATION_LIMIT
            or max_requests != plan["generation_requests"] or not max_usd.is_finite() or max_usd <= 0
            or wall_seconds <= 0 or not 1 <= parallel_per_openai <= 4
            or any(not credentials.get(model) for model in providers.MODELS)):
        raise ValueError("m6_paired_live_limits_or_credentials")
    work = list(zip(inputs, cases, strict=True))
    if any(request["case_id"] != case["case_id"] or m6.digest(payload) != case["input_sha256"]
           for (request, payload), case in work):
        raise ValueError("m6_paired_live_case_mismatch")
    audit = WireAudit(inputs)
    concurrency = dict.fromkeys(providers.OPENAI_MODELS, parallel_per_openai) | {providers.JEV_MODEL: 1}
    mock = isinstance(transport, httpx.MockTransport)
    mode = "mock" if mock else "live"
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    m6.write_report(output / "plan.json", plan | {
        "mode": mode, "wall_seconds": wall_seconds, "max_requests": max_requests,
        "simulated_usd_limit" if mock else "authorized_usd": str(max_usd),
        "concurrency_by_model": concurrency, "retries": 0,
    })
    deadline = time.monotonic() + wall_seconds
    next_preflight = time.monotonic()
    counts, reserves = {}, {}
    results = {model: {} for model in providers.MODELS}
    known_cost = unreconciled = reserved = planned = Decimal(0)
    stop = None

    def timeout():
        return min(REQUEST_SECONDS, deadline - time.monotonic())

    async def run_lanes(models, call):
        async def lane(model, rows):
            for (request, payload), case in rows:
                if stop:
                    break
                await call(model, request, payload, case)

        async with asyncio.TaskGroup() as group:
            for model in models:
                rows = iter(work)
                for _ in range(concurrency[model]):
                    group.create_task(lane(model, rows))

    async with (
        httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False,
                          event_hooks={"request": [audit.check]}) as client,
    ):
        with (output / "requests.jsonl").open("x", encoding="utf-8") as ledger:
            async def preflight(model, _request, payload, case):
                nonlocal stop, next_preflight
                if not mock:
                    now = time.monotonic()
                    delay = max(0, next_preflight - now)
                    next_preflight = now + delay + PREFLIGHT_INTERVAL_SECONDS
                    await asyncio.sleep(delay)
                seconds = timeout()
                if stop or seconds <= 0:
                    stop = stop or "wall_limit"
                    return
                try:
                    count = await asyncio.wait_for(
                        providers.count_input(client, model, credentials[model], payload, seconds), seconds,
                    )
                except (providers.ProviderError, TimeoutError) as exc:
                    stop = stop or "token_count_unavailable"
                    write_ledger(ledger, {"kind": "token_count_error", "model": model,
                                          "case_id": case["case_id"], "input_sha256": case["input_sha256"],
                                          "status": str(exc) or "timeout"})
                    return
                if type(count) is not int or not 0 < count <= live.INPUT_LIMIT:
                    stop = stop or "input_limit"
                    return
                counts[model, case["case_id"]] = count
                write_ledger(ledger, {"kind": "token_count", "model": model,
                                      "case_id": case["case_id"], "input_sha256": case["input_sha256"],
                                      "input_tokens": count})

            async def infer(model, request, payload, case):
                nonlocal stop, known_cost, unreconciled, reserved
                seconds = timeout()
                if seconds <= 0:
                    stop = stop or "wall_limit"
                    return
                case_id = case["case_id"]
                reservation = reserves[model, case_id]
                attempt = {"reserved_usd": str(reservation), "started_at": datetime.now(UTC).isoformat()}
                if model in providers.OPENAI_MODELS:
                    attempt["input_tokens_preflight"] = counts[model, case_id]
                identity = {"model": model, "case_id": case_id, "input_sha256": case["input_sha256"]}
                write_ledger(ledger, {"kind": "reserved", **identity, **attempt})
                reserved += reservation
                started = time.monotonic()
                try:
                    receipt = await asyncio.wait_for(
                        providers.infer(client, model, credentials[model], payload, seconds), seconds,
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
                    if input_used > live.INPUT_LIMIT or charged > reservation:
                        stop = stop or "usage_limit"
                else:
                    unreconciled += reservation
                row = result_for(request, case, receipt, attempt)
                if receipt.get("validation_error"):
                    attempt["validation_error"] = receipt["validation_error"]
                for field in ("confidence", "probabilities"):
                    if field in receipt:
                        row[field] = receipt[field]
                results[model][case_id] = row
                write_ledger(ledger, {"kind": "result", **identity, "result": row})
                if attempt["http_status"] in FATAL_PROVIDER_STATUS:
                    stop = stop or "provider_rejected"

            await run_lanes(providers.OPENAI_MODELS, preflight)
            if not stop:
                reserves = {(model, case_id): cost(model, count, live.OUTPUT_LIMIT)
                            for (model, case_id), count in counts.items()}
                reserves.update({(providers.JEV_MODEL, case["case_id"]): cost(providers.JEV_MODEL, JEV_CONTEXT_LIMIT, 0)
                                 for case in cases})
                planned = sum(reserves.values())
                write_ledger(ledger, {"kind": "budget", "planned_reservation_usd": str(planned)})
                if planned > max_usd:
                    stop = "budget_limit"
                else:
                    await run_lanes(providers.MODELS, infer)

    models = {}
    for model, rows in results.items():
        ordered = [rows.get(case["case_id"]) or m6.result(
            case["case_id"], case["input_sha256"], status="not_run",
        ) for case in cases]
        models[model] = {"results": ordered, "summary": summarize_live(ordered, cases)}
    verification = audit.summary()
    generated = verification["verified_generation_requests"]
    preflights = verification["verified_openai_token_count_requests"]
    budget = {
        "actual_provider_requests": 0 if mock else generated,
        "openai_token_count_requests": 0 if mock else preflights,
        "usage_cost_estimate_usd": "0" if mock else str(known_cost),
        "unreconciled_max_usd": "0" if mock else str(unreconciled),
        "planned_reservation_usd": str(planned), "reserved_usd": str(reserved),
    }
    if mock:
        budget.update(simulated_inference_requests=generated, simulated_openai_token_count_requests=preflights)
    return {
        **provenance, "mode": mode, "stop_reason": stop, "cases": cases, "models": models,
        "status_baseline": baseline(inputs, cases), "budget": budget, "wire_verification": verification,
        "concurrency_by_model": concurrency,
    }
