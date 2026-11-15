"""Run M6 simulations or prepare a paired live comparison on local M7 sessions."""

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from app.models import StrictModel
from app.services.detection_benchmark import DetectionBenchmark, confusion, metrics
from scripts.prepare_m7 import FILES as M7_PILOT_FILES
from scripts.prepare_m7 import load_development

CONTRACT = Path(__file__).resolve().parents[1] / "infra/model-evaluation-contract.json"
BASELINE = "rule-frozen-v0.17.0"
MOCK_MODELS = ("gpt-6.1-sol", "claude-sonnet-5-5")
LABELS = ("normal", "threat", "unknown")
QUESTION = "Classify the observed event as normal, threat, or unknown using the supplied evidence."
M7_QUESTION = (
    "Classify the observed authentication session as normal, threat, or unknown "
    "using the supplied events in order."
)
M7_ENRICHED_QUESTION = (
    M7_QUESTION + " Use auth_stage and any recorded failure_reason as operational evidence. "
    "since_previous_ms is the interval between records, and duration_ms is request duration. "
    "A null value means that a field is unknown or does not apply."
)
MAX_RESPONSE_BYTES = 65_536

Label = Literal["normal", "threat", "unknown"]
EvidenceIDs = Annotated[list[str], Field(max_length=16)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class Limits(StrictModel):
    enabled: Literal[False]
    aggregate_usd: Annotated[Decimal, Field(ge=0, le=5)]
    aggregate_requests_including_retries: Annotated[int, Field(strict=True, ge=0, le=120)]
    wall_seconds: Annotated[float, Field(gt=0, le=1200)]
    per_request_timeout_seconds: Annotated[float, Field(gt=0, le=30)]
    concurrency: Literal[1]
    max_explicit_retries: Literal[0, 1]
    sdk_automatic_retries: Literal[0]
    max_input_tokens_per_provider: Annotated[int, Field(strict=True, gt=0, le=4096)]
    max_billed_output_tokens: Annotated[int, Field(strict=True, gt=0, le=1024)]
    charge_unknown_price: Literal["do_not_call"]
    reserve_worst_case_cost_before_dispatch: Literal[True]
    release_reservation_only_after_usage_is_reconciled: Literal[True]


class Classification(StrictModel):
    case_id: str
    predicted_label: Label
    evidence_ids: EvidenceIDs = Field(default_factory=list)
    class_probabilities: dict[Label, Probability] | None = None


class Explanation(StrictModel):
    case_id: str
    summary: Annotated[str, Field(min_length=1, max_length=4096)]
    evidence_ids: EvidenceIDs
    limitations: Annotated[str, Field(min_length=1, max_length=4096)]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def select_cases(benchmark, pilot):
    if (pilot["split"] != "development_only" or pilot["repeat_each_case"] != 1
            or pilot["unique_cases"] != 24 or pilot["normal_cases"] != 12
            or pilot["threat_cases"] != 12):
        raise ValueError("unsupported_m6_pilot")

    families = {}
    for case in sorted(benchmark.cases, key=lambda row: row.case_id):
        if case.split == "development":
            families.setdefault(case.family_id, case)
    groups = defaultdict(list)
    for case in families.values():
        groups[(case.domain, case.threat)].append(case)
    selected = [case for group in groups.values() for case in group[:2]]
    if Counter(case.threat for case in selected) != {False: 12, True: 12}:
        raise ValueError("m6_pilot_requires_12_cases_per_label")

    inputs = []
    for case in selected:
        event = case.event.model_dump(mode="json", exclude={"ground_truth"})
        request = {
            "case_id": "m6-" + digest(case.case_id.encode())[:24],
            "event": event,
            "evidence_ids": [event["event_id"]],
            "question": QUESTION,
            "labels": LABELS,
        }
        payload = canonical(request)
        evidence = {"case_id": request["case_id"], "benchmark_case_id": case.case_id,
                    "input_sha256": digest(payload),
                    "expected_label": "threat" if case.threat else "normal"}
        inputs.append((case, request, payload, evidence))
    return sorted(inputs, key=lambda item: item[1]["case_id"])


class Budget:
    def __init__(self, limits, max_requests, clock):
        ceiling = limits.aggregate_requests_including_retries
        self.max_requests = ceiling if max_requests is None else max_requests
        if type(self.max_requests) is not int or not 0 <= self.max_requests <= ceiling:
            raise ValueError("m6_request_limit_outside_contract")
        self.limits, self.clock = limits, clock
        self.started = clock()
        self.requests_used = 0
        self.reserved = Decimal(0)

    def reserve(self, cost):
        remaining = self.limits.wall_seconds - (self.clock() - self.started)
        if remaining <= 0:
            return "wall_limit", 0.0
        if self.requests_used >= self.max_requests:
            return "request_limit", 0.0
        if self.reserved + cost > self.limits.aggregate_usd:
            return "cost_limit", 0.0
        # The pilot dispatches sequentially. No await separates admission and reservation.
        self.requests_used += 1
        self.reserved += cost
        return None, min(remaining, self.limits.per_request_timeout_seconds)


def unique_fields(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate_response_fields")
    return value


def validate_reply(raw, request):
    value = json.loads(raw, object_pairs_hook=unique_fields)
    if not isinstance(value, dict):
        raise TypeError("object_required")
    explanation = value.pop("explanation", None)
    classification = Classification.model_validate(value, strict=True)
    allowed = set(request["evidence_ids"])
    if classification.case_id != request["case_id"] or not set(classification.evidence_ids) <= allowed:
        raise ValueError("classification_input_mismatch")

    explanation_status = "missing"
    if explanation is not None:
        try:
            detail = Explanation.model_validate(explanation, strict=True)
            if (detail.case_id != request["case_id"] or not detail.evidence_ids
                    or not set(detail.evidence_ids) <= allowed):
                raise ValueError("explanation_input_mismatch")
        except ValueError:
            explanation_status = "response_error"
        else:
            explanation_status = "ok"
    return classification, explanation_status


async def mock_reply(model_id, payload, timeout):
    """Synthetic fixture with deterministic variation and no access to labels."""
    request = json.loads(payload)
    marker = int(digest(model_id.encode() + payload)[:2], 16)
    return json.dumps({
        "case_id": request["case_id"],
        "predicted_label": LABELS[marker % len(LABELS)],
        "evidence_ids": request["evidence_ids"],
        "explanation": {"case_id": request["case_id"], "summary": "Simulated response",
                        "evidence_ids": request["evidence_ids"], "limitations": "Mock only"},
    })


def result(case_id, input_sha256, *, status, label="unknown", attempts=None, **fields):
    return {
        "case_id": case_id, "input_sha256": input_sha256, "status": status,
        "predicted_label": label, "attempts": attempts if attempts is not None else [],
        "output_schema_valid": False, "evidence_ids": [], "explanation_status": "not_evaluated",
        **fields,
    }


async def evaluate_mock(model_id, request, payload, input_sha256, cost, budget, dispatch):
    attempts = []
    row = {"case_id": request["case_id"], "input_sha256": input_sha256, "attempts": attempts}
    if len(payload) > budget.limits.max_input_tokens_per_provider:
        # Conservative byte ceiling for mock inputs. A live adapter needs its own tokenizer.
        return result(**row, status="input_limit")
    for attempt in range(1, budget.limits.max_explicit_retries + 2):
        stop, timeout = budget.reserve(cost)
        if stop:
            return result(**row, status=attempts[-1]["status"] if attempts else stop,
                          budget_stop=stop)
        started = budget.clock()
        record = {"attempt": attempt, "started_at": datetime.now(UTC).isoformat(),
                  "reserved_usd": str(cost), "usage": None, "response_sha256": None}
        attempts.append(record)
        try:
            raw = await asyncio.wait_for(dispatch(model_id, payload, timeout), timeout=timeout)
            if budget.clock() - started > timeout:
                raise TimeoutError
            if not isinstance(raw, str) or len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("response_size_or_type")
            raw = raw.encode()
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("response_too_large")
            record["response_sha256"] = digest(raw)
            classification, explanation_status = validate_reply(raw, request)
        except TimeoutError:
            record["status"] = "timeout"
        except (OSError, ValueError, TypeError, RecursionError):
            record["status"] = "response_error"
        else:
            status = "abstained" if classification.predicted_label == "unknown" else "ok"
            record["status"] = status
            return result(**row, status=status, label=classification.predicted_label,
                          output_schema_valid=True, evidence_ids=classification.evidence_ids,
                          class_probabilities=classification.class_probabilities,
                          explanation_status=explanation_status)
        finally:
            record["elapsed_ms"] = round((budget.clock() - started) * 1000, 3)
        if record["status"] != "timeout":
            break
    return result(**row, status=attempts[-1]["status"])


def summarize(rows, cases):
    truth = {case["case_id"]: case["expected_label"] == "threat" for case in cases}
    covered = [row for row in rows if row["status"] == "ok"]
    counts = confusion([truth[row["case_id"]] for row in covered],
                       [row["predicted_label"] == "threat" for row in covered])
    threats = sum(truth.values())
    attempts = [attempt for row in rows for attempt in row["attempts"]]
    reserved = sum((Decimal(attempt["reserved_usd"]) for attempt in attempts), Decimal(0))
    return {
        "case_count": len(cases), "threat_count": threats, "normal_count": len(cases) - threats,
        "classified_count": len(covered), "coverage": len(covered) / len(cases),
        "requests_used": len(attempts), "simulated_reserved_usd": str(reserved),
        "confusion": counts, "metrics": metrics(counts),
        "conservative_recall": counts["tp"] / threats,
        "status_counts": dict(Counter(row["status"] for row in rows)),
        "explanation_status_counts": dict(Counter(row["explanation_status"] for row in rows)),
    }


def worst_case_price(candidate, limits):
    prices = candidate["standard_usd_per_million"]
    try:
        input_price, output_price = (Decimal(str(prices[name])) for name in ("input", "output"))
    except InvalidOperation:
        raise ValueError("m6_price_unavailable") from None
    if any(not value.is_finite() or value <= 0 for value in (input_price, output_price)):
        raise ValueError("m6_price_unavailable")
    return (input_price * limits.max_input_tokens_per_provider
            + output_price * limits.max_billed_output_tokens) / 1_000_000


def mock_budget(contract, max_requests, clock):
    safety = contract["safety"]
    disabled = ("allow_external_tools", "allow_policy_write", "allow_permission_grant_or_restore",
                "allow_real_identity_data", "change_detection_baseline")
    if (contract["schema"] != "m6-evaluation-contract-1" or safety["mode"] != "shadow_only"
            or any(safety[key] is not False for key in disabled)):
        raise ValueError("unsupported_m6_contract")
    if tuple(contract["tasks"]["classification"]["labels"]) != LABELS:
        raise ValueError("unsupported_m6_labels")
    return Budget(Limits.model_validate(contract["budget_proposal"]), max_requests, clock)


async def run_pilot(benchmark, contract, *, dispatch=mock_reply, max_requests=None,
                    clock=time.monotonic, source_commit=None):
    """Evaluate the original benchmark with the frozen rule baseline and model mocks."""
    budget = mock_budget(contract, max_requests, clock)
    inputs = select_cases(benchmark, contract["pilot"])
    cases = [evidence for _, _, _, evidence in inputs]
    baseline = []
    for case, _, _, evidence in inputs:
        detected = benchmark.engine.evaluate(benchmark.normalizer.normalize(case.event)).matches
        baseline.append(result(evidence["case_id"], evidence["input_sha256"], status="ok",
                               label="threat" if detected else "normal", output_schema_valid=True))
    models = {BASELINE: {"mode": "frozen_rule", "results": baseline,
                         "summary": summarize(baseline, cases)}}
    dataset = {
        "schema": "m6-development-pilot-1",
        "dataset_sha256": benchmark.manifest["cases_sha256"],
        "split_manifest_sha256": benchmark.manifest_digest,
    }
    return await mock_report(
        [entry[1:] for entry in inputs], cases, contract, budget, dispatch, models,
        question=QUESTION, dataset=dataset, source_commit=source_commit,
    )


def m7_request(session, question):
    return {
        "case_id": session.session_id,
        "events": [event.model_dump(mode="json") for event in session.events],
        "evidence_ids": [event.evidence_id for event in session.events],
        "question": question,
        "labels": LABELS,
    }


async def run_m7_development(pilot_directory, contract, *, source=None, dispatch=mock_reply,
                             max_requests=None, clock=time.monotonic, source_commit=None):
    """Evaluate ordered M7 development observations with offline model mocks."""
    budget = mock_budget(contract, max_requests, clock)
    sessions, labels, fingerprints = load_development(pilot_directory, source=source)
    question = M7_QUESTION if source is None else M7_ENRICHED_QUESTION
    schema = ("m6-m7-development-pilot-1" if source is None else
              "m6-m7-enriched-development-pilot-1")
    inputs = []
    cases = []
    for session in sessions:
        request = m7_request(session, question)
        payload = canonical(request)
        case = {
            "case_id": session.session_id,
            "input_sha256": digest(payload),
            "event_count": len(session.events),
            "expected_label": labels[session.session_id],
        }
        cases.append(case)
        inputs.append((request, payload, case))
    return await mock_report(
        inputs, cases, contract, budget, dispatch, {},
        question=question, dataset={"schema": schema, **fingerprints},
        source_commit=source_commit,
    )


async def mock_report(inputs, cases, contract, budget, dispatch, models, *,
                      question, dataset, source_commit):
    limits = budget.limits
    candidates = {candidate["id"]: candidate for candidate in contract["candidates"]}
    prices = {model: worst_case_price(candidates[model], limits) for model in MOCK_MODELS}
    for model in MOCK_MODELS:
        rows = []
        for request, payload, evidence in inputs:
            rows.append(await evaluate_mock(model, request, payload, evidence["input_sha256"],
                                            prices[model], budget, dispatch))
        models[model] = {"mode": "mock", "results": rows, "summary": summarize(rows, cases)}

    return {
        **dataset, "mode": "offline_mock_pilot",
        "run_id": uuid.uuid4().hex, "source_commit": source_commit, "split": "development",
        "prompt_contract_sha256": digest(canonical({"question": question, "tasks": contract["tasks"]})),
        "contract_sha256": digest(canonical(contract)), "cases": cases, "models": models,
        "budget": {"requests_used": budget.requests_used, "request_limit": budget.max_requests,
                   "simulated_reserved_usd": str(budget.reserved),
                   "simulated_usd_limit": str(limits.aggregate_usd), "actual_provider_requests": 0,
                   "actual_usd": "0", "settings": limits.model_dump(mode="json")},
    }


def write_report(output, report):
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".m6-report-", dir=output.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def source_commit():
    try:
        git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=CONTRACT.parents[1],
                             check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return (git.stdout.strip() or None) if git.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Report path (default depends on the input)")
    parser.add_argument("--m7-development", type=Path, metavar="DIRECTORY",
                        help="Use the prepared M7 development sessions in this pilot directory")
    parser.add_argument("--m7-source", type=Path, metavar="FILE",
                        help="Enrich M7 development observations using the pinned publisher file")
    parser.add_argument("--max-requests", type=int, help="Aggregate mock or live generation limit")
    parser.add_argument("--m7-local", type=Path, metavar="DIRECTORY",
                        help="Verify the local 200-session M7 bundle and prepare a paired comparison")
    parser.add_argument("--m7-public", type=Path, metavar="DIRECTORY",
                        help="Verify the public 12-session evidence bundle and compare three models")
    parser.add_argument("--m7-paired", type=Path, metavar="DIRECTORY",
                        help="Compare three models on the paired 200-session M7 bundle")
    parser.add_argument("--output-dir", type=Path, help="New directory for the M7 run")
    parser.add_argument("--live", action="store_true", help="Enable provider API requests")
    parser.add_argument("--live-max-usd", help="Approved generation budget in USD")
    parser.add_argument("--wall-seconds", type=int, help="Live run deadline (default: 3600)")
    args = parser.parse_args()
    if args.m7_paired is not None:
        if any(option is not None for option in (
            args.m7_public, args.m7_local, args.m7_development, args.m7_source, args.output,
        )):
            parser.error("--m7-paired is separate from the other evaluation modes")
        if args.output_dir is None:
            parser.error("--m7-paired requires --output-dir")
        if args.live and (args.max_requests != 600 or args.live_max_usd is None):
            parser.error("paired live mode requires --max-requests 600 and --live-max-usd")
        if not args.live and (args.live_max_usd is not None or args.wall_seconds is not None):
            parser.error("paired cost and time limits require --live")
        from scripts.evaluate_m6_paired import run_cli

        try:
            return run_cli(args)
        except (OSError, ValueError, KeyError, TypeError):
            parser.exit(1, "m6 paired evaluation unavailable: check bundle, output, and limits\n")
    if args.m7_public is not None:
        if args.m7_local is not None or args.m7_development is not None or args.output is not None:
            parser.error("--m7-public is separate from the local and development comparisons")
        if args.m7_source is None or args.output_dir is None:
            parser.error("--m7-public requires --m7-source and --output-dir")
        if args.live and (args.live_max_usd is None or args.max_requests is None):
            parser.error("--live requires --max-requests and --live-max-usd")
        if not args.live and any(option is not None for option in (
            args.live_max_usd, args.max_requests, args.wall_seconds,
        )):
            parser.error("public M7 request, cost, and time limits require --live")
        from scripts.evaluate_m6_public import run_cli

        try:
            return run_cli(args)
        except (OSError, ValueError, KeyError, TypeError):
            parser.exit(1, "m6 public evaluation unavailable: check bundle, credentials, and limits\n")
    if args.m7_local is not None:
        if args.m7_development is not None or args.m7_source is not None or args.output is not None:
            parser.error("--m7-local is separate from the offline pilot options")
        if args.output_dir is None:
            parser.error("--m7-local requires --output-dir")
        if args.live and (args.live_max_usd is None or args.max_requests is None):
            parser.error("--live requires --max-requests and --live-max-usd")
        if not args.live and any(option is not None for option in (
            args.live_max_usd, args.max_requests, args.wall_seconds,
        )):
            parser.error("local M7 request, cost, and time limits require --live")
        from scripts.evaluate_m6_live import run_cli

        try:
            return run_cli(args)
        except (OSError, ValueError, KeyError, TypeError):
            parser.exit(1, "m6 local evaluation unavailable: check bundle, credentials, and limits\n")
    if args.live or any(option is not None for option in (
        args.output_dir, args.live_max_usd, args.wall_seconds,
    )):
        parser.error("live comparison options require --m7-local or --m7-public")
    if args.m7_source is not None and args.m7_development is None:
        parser.error("--m7-source requires --m7-development or --m7-public")
    try:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        options = {"max_requests": args.max_requests, "source_commit": source_commit()}
        if args.m7_development is None:
            output = args.output or Path("runtime/m6/pilot.json")
            report = asyncio.run(run_pilot(DetectionBenchmark(), contract, **options))
        else:
            default_name = ("m7-development.json" if args.m7_source is None else
                            "m7-enriched-development.json")
            output = args.output or Path("runtime/m6") / default_name
            protected = {args.m7_development / name for name in (*M7_PILOT_FILES, "manifest.json")}
            if args.m7_source is not None:
                protected.add(args.m7_source)
            if output.resolve() in {path.resolve() for path in protected}:
                raise ValueError("m7_report_would_replace_pilot_file")
            report = asyncio.run(run_m7_development(
                args.m7_development, contract, source=args.m7_source, **options,
            ))
        write_report(output, report)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "m6 pilot unavailable\n")
    print(json.dumps({"mode": report["mode"], "cases": len(report["cases"]),
                      "requests_used": report["budget"]["requests_used"], "report": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
