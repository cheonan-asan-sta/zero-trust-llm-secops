"""Run a bounded paid evaluation through the production grounded Hybrid path."""

import argparse
import asyncio
import json
import logging
import os
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from dotenv import dotenv_values
from openai import AsyncOpenAI, AuthenticationError, PermissionDeniedError, RateLimitError

from app.analyzers import openai_analyzer
from app.analyzers.hybrid import HybridAnalyzer
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.models import SecurityAssessment, SecurityEvent
from app.services.session_analysis_evidence import (
    VerifiedSessionContext,
    collect_session_evidence,
    event_digest,
)
from scripts import local_session_analysis_lab
from scripts.evaluate_llm_grounded import MODEL, metrics, prediction, reservation
from scripts.evaluate_local_remote_holdout import (
    collect,
    fingerprint,
    git,
    local_policy,
    read,
    write,
)
from scripts.local_session_analysis_lab import LocalSessionAnalysisLab

COHORT_PLAN = "a7dc038004dfe6ec81249604e4db3dea5f952128eaf6d5c2b54a5d8599d873e4"
OUTPUT_LIMIT = 800
BUDGET_USD = 1.50
CONCURRENCY = 4
CACHED_INPUT_RATE = 0.075 / 1_000_000
ACTIVE_ROW = ContextVar("remote_eval_active_row")
BLOCKING_FAILURES = (AuthenticationError, PermissionDeniedError, RateLimitError)


class RecordedAnalyzer(OpenAIAnalyzer):
    async def analyze_with_evidence(self, event, context):
        row = ACTIVE_ROW.get()
        try:
            result = await super().analyze_with_evidence(event, context)
        except Exception as error:
            row["provider_or_validation_error"] = (
                getattr(error, "code", None) or type(error).__name__
            )
            raise
        row["model_assessment"] = result.model_dump(mode="json")
        row["model_prediction"] = prediction(result)
        return result


async def capture(source, output, key_file):
    source_plan = source / "plan.json"
    if fingerprint(source_plan) != COHORT_PLAN:
        raise ValueError("expected the frozen follow-up cohort")
    plan = read(source_plan)
    if len(plan["cases"]) != 64 or plan["cohort"] != "followup":
        raise ValueError("invalid frozen cohort")
    key = os.getenv("OPENAI_API_KEY") or (
        dotenv_values(key_file).get("OPENAI_API_KEY") if key_file else None
    )
    if not key:
        raise ValueError("OPENAI_API_KEY is required")
    output.mkdir()
    revision = git("rev-parse", "HEAD").decode().strip()
    write(
        output / "protocol.json",
        {
            "revision": revision,
            "cohort_plan_sha256": COHORT_PLAN,
            "truth_sha256": plan["truth_sha256"],
            "model": MODEL,
            "reasoning_effort": "none",
            "output_token_limit": OUTPUT_LIMIT,
            "reservation_limit_usd": BUDGET_USD,
            "requests_per_case": 1,
            "concurrency": CONCURRENCY,
            "hybrid_timeout_seconds": 30,
        },
    )
    settings = Settings(
        _env_file=None,
        openai_api_key=key,
        openai_model=MODEL,
        openai_prompt_mode="grounded",
        openai_reasoning_effort="none",
        openai_max_output_tokens=OUTPUT_LIMIT,
        openai_incomplete_retries=0,
        hybrid_llm_timeout_seconds=30,
    )
    parse = openai_analyzer.parse_structured_response
    reserved = 0.0
    stopped = None
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def metered(client, **kwargs):
        nonlocal reserved, stopped
        row = ACTIVE_ROW.get()
        if stopped:
            raise RuntimeError(stopped)
        amount = reservation(kwargs["input"], output_limit=OUTPUT_LIMIT)
        if reserved + amount > BUDGET_USD:
            stopped = "reservation_limit"
            raise RuntimeError(stopped)
        reserved += amount
        row["reserved_usd"] = amount
        row["attempted"] = True
        try:
            response, diagnostics = await parse(client, **kwargs)
        except BLOCKING_FAILURES as error:
            stopped = type(error).__name__
            raise
        except Exception as error:
            diagnostics = getattr(error, "diagnostics", None)
            if diagnostics is not None:
                row["response_diagnostics"] = diagnostics.as_dict()
            raise
        row["response_diagnostics"] = diagnostics.as_dict()
        row["resolved_model"] = response.model
        if response.usage:
            usage = response.usage
            cached = usage.input_tokens_details.cached_tokens if usage.input_tokens_details else 0
            row["usage"] = {
                "input": usage.input_tokens,
                "cached_input": cached,
                "output": usage.output_tokens,
                "estimated_usd": (
                    (usage.input_tokens - cached) * 0.75 / 1_000_000
                    + cached * CACHED_INPUT_RATE
                    + usage.output_tokens * 4.5 / 1_000_000
                ),
            }
        return response, diagnostics

    async def run_case(case_id, case, labs, hybrid, journal):
        async with semaphore:
            row = {"id": case_id, "attempted": False, "model_prediction": None}
            token = ACTIVE_ROW.set(row)
            try:
                lab = labs[case["profile"]]
                signed = collect(lab, case_id, case)
                context = collect_session_evidence(lab.service, signed, lab.principal)
                history = lab.service.history(signed.session_id, lab.principal)
                row["event"] = signed.event.model_dump(mode="json", exclude={"ground_truth"})
                row["event_sha256"] = event_digest(signed.event)
                row["facts"] = context.for_event(signed.event)
                result = await hybrid.analyze_with_evidence(signed.event, context)
                row["hybrid_assessment"] = result.model_dump(mode="json")
                row["hybrid_prediction"] = prediction(result)
                if lab.service.history(signed.session_id, lab.principal) != history:
                    raise ValueError("unexpected policy journal write")
                journal.write(json.dumps(row, ensure_ascii=False) + "\n")
                journal.flush()
                return row
            finally:
                ACTIVE_ROW.reset(token)

    logging.getLogger("app.analyzers.openai_analyzer").setLevel(logging.CRITICAL)
    async with AsyncOpenAI(
        api_key=key,
        base_url="https://api.openai.com/v1",
        timeout=25,
        max_retries=0,
    ) as client:
        with (
            TemporaryDirectory(prefix="live-remote-holdout-") as scratch,
            patch.object(openai_analyzer, "AsyncOpenAI", return_value=client),
            patch.object(openai_analyzer, "parse_structured_response", side_effect=metered),
            (output / "responses.jsonl").open("x", encoding="utf-8", newline="\n") as journal,
        ):
            labs = {}
            for profile in sorted({case["profile"] for case in plan["cases"].values()}):
                with patch.object(
                    local_session_analysis_lab,
                    "remote_policy_bundle",
                    return_value=local_policy(profile),
                ):
                    labs[profile] = LocalSessionAnalysisLab(Path(scratch) / profile)
            hybrid = HybridAnalyzer(settings, RecordedAnalyzer(settings))
            rows = await asyncio.gather(
                *(
                    run_case(case_id, case, labs, hybrid, journal)
                    for case_id, case in plan["cases"].items()
                )
            )
    write(
        output / "predictions.json",
        {
            "rows": rows,
            "reserved_usd": reserved,
            "stopped": stopped,
            "protocol_sha256": fingerprint(output / "protocol.json"),
        },
    )
    print(fingerprint(output / "predictions.json"))


def score(source, output, sealed):
    packet = output / "predictions.json"
    if fingerprint(packet) != sealed:
        raise ValueError("prediction seal mismatch")
    data = read(packet)
    protocol = output / "protocol.json"
    if fingerprint(protocol) != data["protocol_sha256"]:
        raise ValueError("protocol seal mismatch")
    truth_file = source / "truth.json"
    if fingerprint(truth_file) != read(protocol)["truth_sha256"]:
        raise ValueError("truth seal mismatch")
    truth = read(truth_file)
    rows = data["rows"]
    if len(rows) != len(truth) or {r["id"] for r in rows} != set(truth):
        raise ValueError("evaluation coverage mismatch")
    report = {
        "prediction_sha256": sealed,
        "stopped": data["stopped"],
        "attempts": sum(r["attempted"] for r in rows),
        "fresh_api_requests": 0
        if read(protocol).get("replay_of")
        else sum(r["attempted"] for r in rows),
        "valid_model_responses": sum("model_assessment" in r for r in rows),
        "estimated_usage_usd": sum(r.get("usage", {}).get("estimated_usd", 0.0) for r in rows),
        "reserved_usd": data["reserved_usd"],
    }
    for arm in ("model", "hybrid"):
        scored = [
            {
                "id": r["id"],
                "truth": truth[r["id"]]["threat"],
                "prediction": r[f"{arm}_prediction"] if r["attempted"] else None,
            }
            for r in rows
        ]
        report[arm] = metrics(scored)
        report[f"{arm}_errors"] = [
            {"id": item["id"], **truth[item["id"]], "prediction": item["prediction"]}
            for item in scored
            if item["truth"] is not item["prediction"]
        ]
    write(output / "report.json", report)
    print(json.dumps({key: value for key, value in report.items() if not key.endswith("_errors")}))


class FrozenAssessment:
    def __init__(self, assessment):
        self.assessment = assessment

    async def analyze_with_evidence(self, event, context):
        if self.assessment is None:
            raise RuntimeError("frozen response unavailable")
        return SecurityAssessment.model_validate(self.assessment)


async def replay(original, output, sealed):
    packet = original / "predictions.json"
    protocol_path = original / "protocol.json"
    if fingerprint(packet) != sealed:
        raise ValueError("original prediction seal mismatch")
    data, protocol = read(packet), read(protocol_path)
    if fingerprint(protocol_path) != data["protocol_sha256"] or protocol.get("replay_of"):
        raise ValueError("original protocol mismatch")
    output.mkdir()
    write(
        output / "protocol.json",
        {
            **protocol,
            "original_revision": protocol["revision"],
            "revision": git("rev-parse", "HEAD").decode().strip(),
            "replay_of": sealed,
        },
    )
    settings = Settings(_env_file=None, hybrid_llm_timeout_seconds=30)
    for row in data["rows"]:
        event = SecurityEvent.model_validate(row["event"])
        if event_digest(event) != row["event_sha256"]:
            raise ValueError("original event binding changed")
        # Replay only: keep captured facts and bypass live expiry without using a provider or PEP.
        context = VerifiedSessionContext(
            row["event_sha256"],
            datetime.now(UTC) + timedelta(minutes=1),
            json.dumps(row["facts"]).encode(),
        )
        analyzer = HybridAnalyzer(settings, FrozenAssessment(row.get("model_assessment")))
        assessment = await analyzer.analyze_with_evidence(event, context)
        row["hybrid_assessment"] = assessment.model_dump(mode="json")
        row["hybrid_prediction"] = prediction(assessment)
    write(
        output / "predictions.json",
        {**data, "protocol_sha256": fingerprint(output / "protocol.json")},
    )
    print(fingerprint(output / "predictions.json"))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("phase", choices=("capture", "score", "replay"))
    cli.add_argument("source", type=Path)
    cli.add_argument("output", type=Path)
    cli.add_argument("--key-file", type=Path)
    cli.add_argument("--prediction-sha256")
    args = cli.parse_args()
    if args.phase == "capture":
        asyncio.run(capture(args.source, args.output, args.key_file))
    elif args.phase == "replay" and args.prediction_sha256:
        asyncio.run(replay(args.source, args.output, args.prediction_sha256))
    elif args.phase == "score" and args.prediction_sha256:
        score(args.source, args.output, args.prediction_sha256)
    else:
        cli.error("score and replay require --prediction-sha256")
