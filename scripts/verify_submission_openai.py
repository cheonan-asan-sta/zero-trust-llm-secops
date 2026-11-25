"""Exercise the eight synthetic submission cases against a bounded live provider."""
import argparse
import json
import logging
import math
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from tempfile import TemporaryDirectory
from time import perf_counter
from unittest.mock import patch
from uuid import uuid4

import httpx
from dotenv import dotenv_values
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY
from pydantic import SecretStr, ValidationError

from app.analyzers import openai_analyzer
from app.models import AnalysisResult, ScenarioSummary
from scripts.serve_dashboard_demo import isolated_app

METRIC = "secops_analysis_phase_duration_seconds"
PHASES = ("provider_request", "structured_validation", "analyzer", "precheck", "audit_write")
IDS = {"NORMAL-01", "NORMAL-02", "NORMAL-03", "ZT-S01", "ZT-S02", "ZT-S03", "ZT-S04", "ZT-S05"}
LIMIT = len(IDS)
TRACE_PHASES = {
    "connection.connect_tcp", "connection.start_tls",
    "http11.send_request_headers", "http11.send_request_body",
    "http11.receive_response_headers", "http11.receive_response_body",
}


class BoundedProvider:
    def __init__(self):
        self.receipts = []
        self.clients = []
        self.sdk_type = openai_analyzer.AsyncOpenAI

    async def request(self, request):
        allowed = (
            request.method == "POST" and request.url.scheme == "https"
            and request.url.host == "api.openai.com" and request.url.path == "/v1/responses"
            and request.url.port in {None, 443}
        )
        if not allowed or len(self.receipts) >= LIMIT:
            raise RuntimeError("live endpoint or request cap rejected")
        payload = json.loads(request.content)
        token_limit = payload.get("max_output_tokens")
        if payload.get("store") is not False or type(token_limit) is not int or not 1 <= token_limit <= 800:
            raise RuntimeError("live request exceeded the explicit budget")
        receipt = {"request": len(self.receipts) + 1, "transport_ms": {}}
        self.receipts.append(receipt)
        starts = {}

        async def trace(event, _details):
            phase, _, status = event.rpartition(".")
            if phase in TRACE_PHASES:
                if status == "started":
                    starts[phase] = perf_counter()
                elif status == "complete" and phase in starts:
                    receipt["transport_ms"][phase] = round((perf_counter() - starts.pop(phase)) * 1000, 3)

        request.extensions["trace"] = trace

    async def response(self, response):
        receipt = self.receipts[-1]
        receipt["status_code"] = response.status_code
        await response.aread()
        try:
            body = response.json()
        except ValueError:
            return
        if not isinstance(body, dict):
            return
        error = body.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,60}", code):
                receipt["error_code"] = code
        model = body.get("model")
        if isinstance(model, str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", model):
            receipt["resolved_model"] = model
        tier = body.get("service_tier")
        if isinstance(tier, str) and tier in {"default", "priority", "fast", "flex", "scale"}:
            receipt["service_tier"] = tier
        usage = body.get("usage")
        if isinstance(usage, dict):
            for field in ("input_tokens", "output_tokens"):
                value = usage.get(field)
                if type(value) is int and value >= 0:
                    receipt[field] = value
            input_details = usage.get("input_tokens_details")
            if isinstance(input_details, dict):
                cached = input_details.get("cached_tokens")
                if type(cached) is int and 0 <= cached <= receipt.get("input_tokens", 0):
                    receipt["cached_input_tokens"] = cached

    def sdk(self, **kwargs):
        client = self.sdk_type(**(kwargs | {
            "base_url": "https://api.openai.com/v1", "max_retries": 0, "timeout": 30.0,
            "http_client": httpx.AsyncClient(
                trust_env=False, timeout=30, follow_redirects=False,
                event_hooks={"request": [self.request], "response": [self.response]},
            ),
        }))
        self.clients.append(client)
        return client


def snapshots():
    return {
        phase: tuple(REGISTRY.get_sample_value(f"{METRIC}_{kind}", {"phase": phase}) or 0
                     for kind in ("sum", "count"))
        for phase in PHASES
    }


def evaluate(client, scenario):
    simulation = client.post("/events/simulate", json={"scenario_id": scenario.scenario_id, "count": 1})
    if simulation.status_code != 200 or simulation.headers.get("X-Secops-Data-Scope") != "synthetic-dashboard-demo":
        raise RuntimeError("isolated simulator did not return a synthetic event")
    event, = simulation.json()
    event.pop("ground_truth")
    event["event_id"] = uuid4().hex
    before = snapshots()
    started = perf_counter()
    api_response = client.post("/analysis", json=event)
    result = None
    try:
        if api_response.status_code == 200 and api_response.headers.get("X-Secops-Data-Scope") == "synthetic-dashboard-demo":
            result = AnalysisResult.model_validate(api_response.json())
    except (ValidationError, ValueError):
        pass
    total_ms = (perf_counter() - started) * 1000
    after = snapshots()
    return {
        "scenario_id": scenario.scenario_id,
        "app_status": api_response.status_code,
        "json_valid": result is not None,
        "risk_correct": result is not None and result.assessment.risk_level == scenario.expected_risk,
        "action_correct": result is not None and result.policy_decision.action == scenario.expected_action,
        "risk_level": result.assessment.risk_level.value if result else None,
        "policy_action": result.policy_decision.action.value if result else None,
        "human_review": result is not None and result.policy_decision.requires_human_review,
        "elapsed_ms": round(total_ms, 3),
        "stage_ms": {
            phase: round((after[phase][0] - before[phase][0]) * 1000, 3)
            for phase in PHASES if after[phase][1] - before[phase][1] == 1
        },
    }


def run(args, key, provider, report):
    with TemporaryDirectory(prefix="secops-live-submission-") as directory:
        app = isolated_app(Path(directory))
        from app import main as api
        api.settings.analyzer_mode = "openai"
        api.settings.openai_api_key = SecretStr(key)
        api.settings.openai_model = args.model
        api.settings.openai_service_tier = args.service_tier
        api.settings.openai_prompt_mode = args.prompt_mode
        api.settings.openai_compact_legacy_output = args.compact_legacy_output
        api.settings.openai_reasoning_effort = args.effort
        api.settings.openai_temperature = args.temperature
        api.settings.openai_max_output_tokens = 800
        api.settings.openai_incomplete_retries = 0

        starting = perf_counter()
        with (
            patch.object(openai_analyzer, "AsyncOpenAI", provider.sdk),
            TestClient(app, raise_server_exceptions=False) as client,
        ):
            report["asgi_startup_ms"] = round((perf_counter() - starting) * 1000, 3)
            health = client.get("/health").json()
            assert health["analyzer_mode"] == "openai" and health["audit_backend"] == "jsonl"
            scenarios = [ScenarioSummary.model_validate(row) for row in client.get("/scenarios").json()]
            assert len(scenarios) == LIMIT and {row.scenario_id for row in scenarios} == IDS
            try:
                for scenario in scenarios:
                    expected_calls = len(provider.receipts) + 1
                    row = evaluate(client, scenario)
                    report["cases"].append(row)
                    if len(provider.receipts) != expected_calls:
                        report["stop"] = "unexpected_provider_request_count"
                        break
                    receipt = provider.receipts[-1]
                    if receipt.get("status_code") != 200:
                        report["stop"] = "provider_unavailable_or_rejected_request"
                        break
                state = client.get("/health/ready").json()
                report["audit_verified_rows"] = state["audit"]["verified_lines"]
                report["audit_integrity_ok"] = state["audit"]["ok"]
                report["external_delivery_enabled"] = state["integration_outbox"]["external_delivery_enabled"]
            finally:
                for sdk in provider.clients:
                    client.portal.call(sdk.close)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--service-tier", choices=("auto", "default", "priority"), default="auto")
    parser.add_argument("--effort", choices=("none", "low"), default="none")
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--prompt-mode", choices=("legacy", "grounded"), default="legacy")
    parser.add_argument("--compact-legacy-output", action="store_true")
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", args.model):
        parser.error("provide a model identifier")
    if args.compact_legacy_output and args.prompt_mode != "legacy":
        parser.error("compact output requires the legacy prompt mode")
    if args.temperature is not None and (args.effort != "none" or not 0 <= args.temperature <= 2):
        parser.error("temperature requires --effort none and a value from 0 to 2")
    if args.report.exists():
        parser.error("select an unused output file")
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--", "app", "scripts/serve_dashboard_demo.py"], text=True,
    )
    if status.strip():
        parser.error("verify a clean application and demo launcher at the reported commit")
    key = dotenv_values(args.key_file, interpolate=False).get("OPENAI_API_KEY") or ""
    if not re.fullmatch(r"sk-[A-Za-z0-9_-]{18,}", key):
        parser.error("the configured credential is unavailable")

    for name in tuple(os.environ):
        if name.startswith("OPENAI_"):
            os.environ.pop(name)
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    logging.disable(logging.CRITICAL)
    provider = BoundedProvider()
    report = {
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "scope": "isolated FastAPI ASGI and JSONL, synthetic submission cases only, real OpenAI SDK",
        "model": args.model, "effort": args.effort, "prompt_mode": args.prompt_mode,
        "requested_service_tier": args.service_tier,
        "temperature": args.temperature,
        "compact_legacy_output": args.compact_legacy_output,
        "event_id_policy": "opaque_uuid",
        "planned_cases": LIMIT, "request_cap": LIMIT, "sdk_retries": 0,
        "max_output_tokens": 800, "store": False, "aws_calls": 0, "cases": [], "stop": None,
    }
    try:
        output = args.report.open("x", encoding="utf-8", newline="\n")
    except FileExistsError:
        parser.error("select an unused output file")
    with output:
        try:
            run(args, key, provider, report)
        except Exception as exc:  # noqa: BLE001 - SDK diagnostics may contain private request data.
            report["stop"] = type(exc).__name__
        rows = report["cases"]
        report["provider_attempts"] = provider.receipts
        report["complete"] = len(rows) == LIMIT and report["stop"] is None
        if report["complete"]:
            times = sorted(row["elapsed_ms"] for row in rows)
            report.update({
                "risk_correct": sum(row["risk_correct"] for row in rows),
                "action_correct": sum(row["action_correct"] for row in rows),
                "json_valid": sum(row["json_valid"] for row in rows),
                "mean_response_ms": round(mean(times), 3),
                "p95_response_ms": times[math.ceil(len(times) * 0.95) - 1],
            })
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps({k: v for k, v in report.items() if k not in {"cases", "provider_attempts"}}))
    raise SystemExit(0 if report["complete"] else 2)


if __name__ == "__main__":
    main()
