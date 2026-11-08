"""Run the M6 development pilot with frozen rules and offline model simulations."""

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

CONTRACT = Path(__file__).resolve().parents[1] / "infra/model-evaluation-contract.json"
BASELINE = "rule-frozen-v0.17.0"
MOCK_MODELS = ("gpt-6.1-sol", "claude-sonnet-5-5")
LABELS = ("normal", "threat", "unknown")
QUESTION = "Classify the observed event as normal, threat, or unknown using the supplied evidence."
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


async def run_pilot(benchmark, contract, *, dispatch=mock_reply, max_requests=None,
                    clock=time.monotonic, source_commit=None):
    """Evaluate only with an offline mock dispatch function."""
    safety = contract["safety"]
    disabled = ("allow_external_tools", "allow_policy_write", "allow_permission_grant_or_restore",
                "allow_real_identity_data", "change_detection_baseline")
    if (contract["schema"] != "m6-evaluation-contract-1" or safety["mode"] != "shadow_only"
            or any(safety[key] is not False for key in disabled)):
        raise ValueError("unsupported_m6_contract")
    if tuple(contract["tasks"]["classification"]["labels"]) != LABELS:
        raise ValueError("unsupported_m6_labels")
    limits = Limits.model_validate(contract["budget_proposal"])
    budget = Budget(limits, max_requests, clock)
    inputs = select_cases(benchmark, contract["pilot"])
    cases = [evidence for _, _, _, evidence in inputs]
    candidates = {candidate["id"]: candidate for candidate in contract["candidates"]}
    prices = {model: worst_case_price(candidates[model], limits) for model in MOCK_MODELS}
    models = {}
    baseline = []
    for case, _, _, evidence in inputs:
        detected = benchmark.engine.evaluate(benchmark.normalizer.normalize(case.event)).matches
        baseline.append(result(evidence["case_id"], evidence["input_sha256"], status="ok",
                               label="threat" if detected else "normal", output_schema_valid=True))
    models[BASELINE] = {"mode": "frozen_rule", "results": baseline,
                        "summary": summarize(baseline, cases)}

    for model in MOCK_MODELS:
        rows = []
        for _, request, payload, evidence in inputs:
            rows.append(await evaluate_mock(model, request, payload, evidence["input_sha256"],
                                            prices[model], budget, dispatch))
        models[model] = {"mode": "mock", "results": rows, "summary": summarize(rows, cases)}

    return {
        "schema": "m6-development-pilot-1", "mode": "offline_mock_pilot",
        "run_id": uuid.uuid4().hex, "source_commit": source_commit, "split": "development",
        "dataset_sha256": benchmark.manifest["cases_sha256"],
        "split_manifest_sha256": benchmark.manifest_digest,
        "prompt_contract_sha256": digest(canonical({"question": QUESTION, "tasks": contract["tasks"]})),
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
    parser.add_argument("--output", type=Path, default=Path("runtime/m6/pilot.json"))
    parser.add_argument("--max-requests", type=int, help="Lower the aggregate mock request limit")
    args = parser.parse_args()
    try:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        report = asyncio.run(run_pilot(DetectionBenchmark(), contract, max_requests=args.max_requests,
                                       source_commit=source_commit()))
        write_report(args.output, report)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "m6 pilot unavailable\n")
    print(json.dumps({"mode": report["mode"], "cases": len(report["cases"]),
                      "requests_used": report["budget"]["requests_used"], "report": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
