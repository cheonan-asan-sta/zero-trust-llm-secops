"""Prepare and run a paired provider evaluation of the local M7 cohort."""

import asyncio
import json
import os
import time
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

import httpx
from pydantic import SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from scripts import evaluate_m6 as m6
from scripts import m6_live_providers as providers
from scripts import prepare_m7 as m7
from scripts import prepare_m7_local as local

REQUEST_SECONDS = 30
INPUT_RATE = Decimal(2)
OUTPUT_RATE = Decimal(10)
TOKEN_RATE_UNIT = Decimal(1_000_000)
RATE_SOURCES = [
    "https://developers.openai.com/api/docs/models/gpt-6.1-sol",
    "https://platform.claude.com/docs/en/models/sonnet-5-5/overview",
]


class LiveKeys(BaseSettings):
    model_config = SettingsConfigDict(env_file=local.ROOT / ".env.local", extra="ignore")
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None


def configured_credentials():
    settings = LiveKeys()
    return {
        model: value.get_secret_value().strip() if value else ""
        for model, field in providers.CREDENTIAL_ENV.items()
        for value in (getattr(settings, field.lower()),)
    }


def prepare_cases(directory, prior_paths=None):
    manifest = local.verify_bundle(directory) if prior_paths is None else local.verify_bundle(
        directory, prior_paths=prior_paths,
    )
    if manifest["schema"] != "m7-local-oidc-capture-1":
        raise ValueError("m6_live_dataset_schema")
    observations = (directory / "observations.jsonl").read_bytes()
    label_data = (directory / "private/scoring-labels.jsonl").read_bytes()
    if (m7.sha(observations) != manifest["files"]["observations.jsonl"]
            or m7.sha(label_data) != manifest["files"]["private/scoring-labels.jsonl"]):
        raise ValueError("m6_live_dataset_changed")
    sessions = m7.read_rows(observations, m7.EnrichedSession)
    labels = {}
    for line in label_data.splitlines():
        row = json.loads(line)
        if (set(row) != {"session_id", "expected_label"} or row["session_id"] in labels
                or row["expected_label"] not in {"normal", "threat"}):
            raise ValueError("m6_live_scoring_labels")
        labels[row["session_id"]] = row["expected_label"]
    if (len(sessions) != 200 or {session.session_id for session in sessions} != labels.keys()
            or Counter(labels.values()) != {"normal": 100, "threat": 100}):
        raise ValueError("m6_live_cohort")

    inputs, cases = [], []
    for session in sessions:
        request = m6.m7_request(session, m6.M7_ENRICHED_QUESTION)
        payload = m6.canonical(request)
        case = {
            "case_id": session.session_id, "input_sha256": m6.digest(payload),
            "event_count": len(session.events), "expected_label": labels[session.session_id],
        }
        cases.append(case)
        inputs.append((request, payload, case))
    provenance = {
        "dataset_sha256": m7.sha(observations), "labels_sha256": m7.sha(label_data),
        "split_manifest_sha256": m7.sha(json.dumps(manifest, ensure_ascii=False, indent=2).encode() + b"\n"),
        "prompt_contract_sha256": m6.digest(m6.canonical({
            "question": m6.M7_ENRICHED_QUESTION, "response_schema": providers.SCHEMA,
        })),
        "scope": manifest["scope"],
    }
    return inputs, cases, provenance


def cost(input_tokens, output_tokens):
    return (INPUT_RATE * input_tokens + OUTPUT_RATE * output_tokens) / TOKEN_RATE_UNIT


def execution_plan(inputs, cases, provenance, credentials):
    required = len(inputs) * len(providers.MODELS)
    return {
        "schema": "m6-m7-live-plan-1", **provenance,
        "mode": "preflight", "models": list(providers.MODELS), "cases": len(cases),
        "input_hashes": {case["case_id"]: case["input_sha256"] for case in cases},
        "required_generation_requests": required,
        "token_count_requests": required,
        "per_request_input_limit": providers.INPUT_LIMIT,
        "per_request_output_limit": providers.OUTPUT_LIMIT,
        "max_reserved_usd": str(required * cost(providers.INPUT_LIMIT, providers.OUTPUT_LIMIT)),
        "pricing_sources": RATE_SOURCES, "retries": 0, "concurrency": 1, "effort": "low",
        "missing_credentials": [env for model, env in providers.CREDENTIAL_ENV.items()
                                if not credentials.get(model)],
        "actual_provider_requests": 0,
    }


def summarize_live(rows, cases):
    summary = m6.summarize(rows, cases)
    summary["reserved_usd"] = summary.pop("simulated_reserved_usd")
    truth = {case["case_id"]: case["expected_label"] for case in cases}
    statuses = summary["status_counts"]
    unresolved = Counter(truth[row["case_id"]] for row in rows if row["status"] != "ok")
    abstained = statuses.get("abstained", 0)
    not_run = statuses.get("not_run", 0)
    normals = summary["normal_count"]
    fp = summary["confusion"]["fp"]
    validation_failures = Counter(
        attempt["validation_error"]
        for row in rows for attempt in row["attempts"]
        if "validation_error" in attempt
    )
    return summary | {
        "abstained_count": abstained,
        "failed_count": len(rows) - summary["classified_count"] - abstained - not_run,
        "not_run_count": not_run,
        "validation_failure_counts": dict(validation_failures),
        "unresolved_by_label": {label: unresolved[label] for label in ("normal", "threat")},
        "operational_false_positive_rate_bounds": [fp / normals, (fp + unresolved["normal"]) / normals],
    }


def write_ledger(stream, value):
    stream.write(json.dumps(value, ensure_ascii=False) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def validate_classification(raw, request, attempt):
    if not isinstance(raw, str):
        return None, "invalid_response_text"
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError:
        return None, "invalid_response_text"
    if len(encoded) > m6.MAX_RESPONSE_BYTES:
        return None, "response_too_large"
    attempt["response_sha256"] = m6.digest(encoded)
    try:
        value = json.loads(raw, object_pairs_hook=m6.unique_fields)
    except (ValueError, RecursionError):
        return None, "invalid_json"
    if not isinstance(value, dict) or set(value) != set(providers.SCHEMA["required"]):
        return None, "invalid_response_fields"
    try:
        classification = m6.Classification.model_validate(value, strict=True)
    except ValidationError:
        return None, "invalid_field_value"
    if classification.case_id != request["case_id"]:
        return None, "case_id_mismatch"
    if not set(classification.evidence_ids) <= set(request["evidence_ids"]):
        return None, "evidence_id_mismatch"
    return classification, None


def result_for(request, case, receipt, attempt):
    status = receipt["status"]
    fields = {}
    validation_error = "provider_response_invalid" if status == "response_error" else None
    if status == "completed":
        classification, validation_error = validate_classification(receipt.get("raw"), request, attempt)
        if validation_error:
            status = "response_error"
        else:
            status = "abstained" if classification.predicted_label == "unknown" else "ok"
            fields = {
                "label": classification.predicted_label, "evidence_ids": classification.evidence_ids,
                "output_schema_valid": True,
            }
    if validation_error:
        attempt["validation_error"] = validation_error
    attempt["status"] = status
    return m6.result(case["case_id"], case["input_sha256"], status=status, attempts=[attempt], **fields)


async def run_live(output_dir, inputs, cases, provenance, *, credentials, max_usd, max_requests,
                   wall_seconds=3600, transport=None):
    plan = execution_plan(inputs, cases, provenance, credentials)
    if plan["missing_credentials"]:
        raise ValueError("m6_live_missing_credentials")
    required = plan["required_generation_requests"]
    try:
        max_usd = Decimal(max_usd)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("m6_live_cost_limit") from exc
    if not max_usd.is_finite() or max_usd < Decimal(plan["max_reserved_usd"]):
        raise ValueError("m6_live_cost_limit")
    if type(max_requests) is not int or max_requests < required:
        raise ValueError("m6_live_request_limit")
    if type(wall_seconds) is not int or wall_seconds <= 0:
        raise ValueError("m6_live_wall_limit")

    output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    m6.write_report(output_dir / "plan.json", plan | {
        "mode": "live", "authorized_usd_limit": str(max_usd),
        "authorized_generation_limit": max_requests, "wall_seconds": wall_seconds,
    })
    deadline = time.monotonic() + wall_seconds
    per_request = cost(providers.INPUT_LIMIT, providers.OUTPUT_LIMIT)
    counters, rows = {}, {model: {} for model in providers.MODELS}
    count_requests = generated = 0
    reserved = known_cost = unreconciled = Decimal(0)
    stop = None
    async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False) as client:
        for _, payload, case in inputs:
            for model in providers.MODELS:
                timeout = min(REQUEST_SECONDS, deadline - time.monotonic())
                if timeout <= 0:
                    stop = "wall_limit"
                    break
                count_requests += 1
                try:
                    count = await asyncio.wait_for(
                        providers.count_input(client, model, credentials[model], payload, timeout), timeout,
                    )
                except (providers.ProviderError, TimeoutError):
                    stop = "token_count_unavailable"
                    break
                if type(count) is not int or not 0 < count <= providers.INPUT_LIMIT:
                    stop = "input_limit"
                    break
                counters[model, case["case_id"]] = count
            if stop:
                break

        with (output_dir / "requests.jsonl").open("x", encoding="utf-8") as ledger:
            for request, payload, case in inputs:
                if stop:
                    break
                for model in providers.MODELS:
                    timeout = min(REQUEST_SECONDS, deadline - time.monotonic())
                    if timeout <= 0 or generated >= max_requests or reserved + per_request > max_usd:
                        stop = "execution_limit"
                        break
                    generated += 1
                    reserved += per_request
                    attempt = {
                        "started_at": datetime.now(UTC).isoformat(),
                        "input_tokens_preflight": counters[model, case["case_id"]],
                        "reserved_usd": str(per_request),
                    }
                    identity = {"model": model, "case_id": case["case_id"], "input_sha256": case["input_sha256"]}
                    write_ledger(ledger, {"kind": "reserved", **identity, **attempt})
                    started = time.monotonic()
                    try:
                        receipt = await asyncio.wait_for(
                            providers.infer(client, model, credentials[model], payload, timeout), timeout,
                        )
                    except TimeoutError:
                        receipt = {"status": "timeout"}
                    attempt["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
                    for name in ("resolved_model", "http_status", "input_tokens", "output_tokens", "request_id"):
                        attempt[name] = receipt.get(name)
                    input_used, output_used = attempt["input_tokens"], attempt["output_tokens"]
                    if type(input_used) is int and type(output_used) is int and min(input_used, output_used) >= 0:
                        charged = cost(input_used, output_used)
                        known_cost += charged
                        attempt["usage_cost_usd"] = str(charged)
                        if input_used > providers.INPUT_LIMIT or output_used > providers.OUTPUT_LIMIT:
                            receipt = {"status": "usage_limit"}
                            stop = "usage_limit"
                    else:
                        unreconciled += per_request
                        attempt["usage_cost_usd"] = None
                    row = result_for(request, case, receipt, attempt)
                    rows[model][case["case_id"]] = row
                    write_ledger(ledger, {"kind": "result", **identity, "result": row})
                    if attempt["http_status"] in {400, 401, 403, 404, 429}:
                        stop = "provider_rejected"
                    if stop:
                        break

    models = {}
    for model in providers.MODELS:
        results = [rows[model].get(case["case_id"]) or m6.result(
            case["case_id"], case["input_sha256"], status="not_run",
        ) for case in cases]
        models[model] = {"results": results, "summary": summarize_live(results, cases)}
    report = {
        "schema": "m6-m7-live-report-1", **provenance,
        "mode": "live", "stop_reason": stop, "cases": cases, "models": models,
        "budget": {
            "actual_provider_requests": generated, "token_count_requests": count_requests,
            "required_generation_requests": required, "reserved_usd": str(reserved),
            "usage_cost_estimate_usd": str(known_cost), "unreconciled_max_usd": str(unreconciled),
        },
    }
    m6.write_report(output_dir / "report.json", report)
    return report


def run_cli(args):
    inputs, cases, provenance = prepare_cases(args.m7_local)
    credentials = configured_credentials()
    if not args.live:
        plan = execution_plan(inputs, cases, provenance, credentials)
        args.output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        m6.write_report(args.output_dir / "plan.json", plan)
        print(json.dumps({key: plan[key] for key in (
            "mode", "cases", "required_generation_requests", "max_reserved_usd", "missing_credentials",
        )}))
        return 0
    report = asyncio.run(run_live(
        args.output_dir, inputs, cases, provenance, credentials=credentials,
        max_usd=args.live_max_usd, max_requests=args.max_requests,
        wall_seconds=3600 if args.wall_seconds is None else args.wall_seconds,
    ))
    summary = {model: output["summary"] for model, output in report["models"].items()}
    print(json.dumps({"stop_reason": report["stop_reason"], "models": summary}))
    return 1 if report["stop_reason"] or any(row["failed_count"] or row["not_run_count"]
                                             for row in summary.values()) else 0
