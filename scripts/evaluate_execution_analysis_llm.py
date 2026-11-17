"""Paired real OIDC -> verified-session API -> OpenAI execution-scope lab.

No AWS calls, production state, actual compromise, or historical backfill. Labels
are predeclared local scenario intent. They are never sent as model input.
"""

import argparse
import hashlib
import json
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from dotenv import dotenv_values
from fastapi.testclient import TestClient
from openai import AsyncOpenAI

from app import main
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.analyzers.structured_response import StructuredResponseFailure, parse_structured_response
from app.config import Settings
from app.models import SecurityAssessment
from app.security import get_principal
from app.services.audit import AuditStore
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_development import write_json
from scripts.evaluate_llm_grounded import (
    INPUT_RATE,
    MODEL,
    OUTPUT_RATE,
    metrics,
    prediction,
    reservation,
)
from scripts.local_execution_analysis_lab import EXECUTION_SCENARIOS, LocalExecutionAnalysisLab
from scripts.local_oidc_authority import LocalOIDCAuthority


def run(directory, key_file, *, max_budget=2.0):
    if not 0 < max_budget <= 2.0:
        raise ValueError("evaluation_options")
    directory = Path(directory)
    if directory.exists():
        raise ValueError("output_exists")
    key = dotenv_values(key_file).get("OPENAI_API_KEY")
    if not key:
        raise ValueError("missing_credential")
    if get_principal in main.app.dependency_overrides:
        raise ValueError("refusing_principal_override")
    directory.mkdir(parents=True)
    private = directory / "private"
    private.mkdir()
    root = Path(__file__).resolve().parents[1]
    source_files = [
        "scripts/evaluate_execution_analysis_llm.py",
        "scripts/local_execution_analysis_lab.py",
        "scripts/local_oidc_authority.py",
        "app/analyzers/openai_analyzer.py",
        "app/analyzers/structured_response.py",
        "app/services/execution_analysis_evidence.py",
        "app/services/session_analysis_evidence.py",
        "app/services/behavior_context.py",
        "app/services/behavior_context_trust.py",
        "app/services/behavior_execution.py",
        "app/services/trusted_signals.py",
        "app/grounded_prompting.py",
        "app/main.py",
        "app/models.py",
        "app/config.py",
        "app/security.py",
    ]
    plan = {
        "schema": "oidc-execution-analysis-paired-development-1",
        "scenarios": EXECUTION_SCENARIOS,
        "model": MODEL,
        "reasoning_effort": "low",
        "max_output_tokens": 2400,
        "max_requests": 48,
        "repetitions": 2,
        "cases_per_repeat": 12,
        "normal_per_repeat": 4,
        "threat_per_repeat": 8,
        "max_budget_usd": max_budget,
        "max_retries": 0,
        "principal_injected": False,
        "jwks_fetch_mocked": False,
        "independent_acceptance": False,
        "actual_OS_process_attestation": False,
        "AWS_calls": False,
        "historical_metrics_replaced": False,
        "source_pins": {},
    }
    for name in source_files:
        content = (root / name).read_bytes()
        plan["source_pins"][name] = hashlib.sha256(content).hexdigest()
        target = directory / "source-snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    write_json(directory / "plan.json", plan)
    lab = LocalExecutionAnalysisLab(private / "authority")
    lab.prepare()
    receipts, rows, reserved, fatal = [], [], 0.0, None
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
            openai_api_key=key,
            openai_model=MODEL,
            openai_prompt_mode="grounded",
            openai_reasoning_effort="low",
            openai_max_output_tokens=2400,
            openai_incomplete_retries=0,
        )
        adapter = OpenAIAnalyzer(config)
        unused = adapter._client
        adapter._client = AsyncOpenAI(
            api_key=key, base_url="https://api.openai.com/v1", timeout=30, max_retries=0
        )

        async def capture(provider, **kwargs):
            nonlocal reserved, fatal
            amount = reservation(kwargs["input"], INPUT_RATE, OUTPUT_RATE, 2400)
            if len(receipts) >= 48 or reserved + amount > max_budget:
                fatal = "budget_or_request_limit"
                raise ValueError(fatal)
            reserved += amount
            receipt = {"reserved_usd": amount, "input_tokens": None, "output_tokens": None}
            receipts.append(receipt)
            with (private / "inputs.jsonl").open("ab") as stream:
                stream.write(
                    (
                        json.dumps(
                            {"request": len(receipts), "messages": kwargs["input"]},
                            ensure_ascii=False,
                        )
                        + "\n"
                    ).encode()
                )
            write_json(directory / "receipts.json", receipts)
            try:
                response, diagnostic = await parse_structured_response(provider, **kwargs)
                receipt.update(
                    input_tokens=diagnostic.input_tokens,
                    output_tokens=diagnostic.output_tokens,
                    response_diagnostics=diagnostic.as_dict(),
                )
                return response, diagnostic
            except Exception as error:
                receipt["error"] = type(error).__name__
                if isinstance(error, StructuredResponseFailure):
                    receipt.update(
                        error_code=error.code,
                        input_tokens=error.diagnostics.input_tokens,
                        output_tokens=error.diagnostics.output_tokens,
                        response_diagnostics=error.diagnostics.as_dict(),
                    )
                if type(error).__name__ in {
                    "AuthenticationError",
                    "PermissionDeniedError",
                    "RateLimitError",
                    "NotFoundError",
                }:
                    fatal = type(error).__name__
                raise
            finally:
                write_json(directory / "receipts.json", receipts)

        with ExitStack() as stack:
            for name, value in {
                "zero_trust_operations": lab.service,
                "behavior_context_service": lab.behavior,
                "get_settings": lambda: config,
                "get_analyzer": lambda: adapter,
                "audit_store": AuditStore(directory / "audit.jsonl"),
            }.items():
                stack.enter_context(patch.object(main, name, value))
            stack.enter_context(patch("app.security.get_settings", return_value=config))
            stack.enter_context(
                patch("app.analyzers.openai_analyzer.parse_structured_response", capture)
            )
            client = stack.enter_context(TestClient(main.app))
            try:
                for repeat in range(2):
                    for index, (name, truth) in enumerate(EXECUTION_SCENARIOS):
                        signal, observed, _ = lab.create_execution_case(name)
                        identity = hashlib.sha256(f"{repeat}:{index}".encode()).hexdigest()
                        arms = (
                            ("session", "execution")
                            if (repeat + index) % 2
                            else ("execution", "session")
                        )
                        for arm in arms:
                            before, journal = (
                                lab.behavior.store.read(lab.principal.tenant_id),
                                lab.service.journal_status(),
                            )
                            first_receipt = len(receipts)
                            response = client.post(
                                "/analysis/verified-session",
                                json=signal.model_dump(mode="json"),
                                params={"behavior_capture_id": observed.capture_id}
                                if arm == "execution"
                                else {},
                                headers={"Authorization": "Bearer " + authority.issue()},
                            )
                            body = response.json()
                            row = {
                                "id": identity,
                                "repeat": repeat,
                                "scenario": name,
                                "arm": arm,
                                "truth": truth,
                                "prediction": None,
                                "error": None,
                                "http_status": response.status_code,
                                "api_receipt_indexes": list(range(first_receipt, len(receipts))),
                                "behavior_store_unchanged": before
                                == lab.behavior.store.read(lab.principal.tenant_id),
                                "session_journal_unchanged": journal
                                == lab.service.journal_status(),
                            }
                            if response.status_code == 200:
                                row.update(
                                    prediction=prediction(
                                        SecurityAssessment.model_validate(body["assessment"])
                                    ),
                                    response=body,
                                )
                                row["snapshot_audited"] = (
                                    main.audit_store.get(
                                        signal.event.event_id, lab.principal.tenant_id
                                    ).verification_context
                                    == body["verification_context"]
                                )
                            else:
                                row["error"] = f"HTTP_{response.status_code}"
                            rows.append(row)
                            with (private / "predictions.jsonl").open("ab") as stream:
                                stream.write((json.dumps(row, ensure_ascii=False) + "\n").encode())
                            print(
                                json.dumps(
                                    {
                                        "rows": len(rows),
                                        "requests": len(receipts),
                                        "status": response.status_code,
                                    }
                                ),
                                flush=True,
                            )
                            if fatal:
                                break
                        if fatal:
                            break
                    if fatal:
                        break
            finally:
                client.portal.call(adapter._client.close)
                client.portal.call(unused.close)
        jwks_fetches = authority.fetches
    seen = {(r["repeat"], r["scenario"], r["arm"]) for r in rows}
    for repeat in range(2):
        for index, (name, truth) in enumerate(EXECUTION_SCENARIOS):
            for arm in ("session", "execution"):
                if (repeat, name, arm) not in seen:
                    rows.append(
                        {
                            "id": hashlib.sha256(f"{repeat}:{index}".encode()).hexdigest(),
                            "repeat": repeat,
                            "scenario": name,
                            "arm": arm,
                            "truth": truth,
                            "prediction": None,
                            "error": "not_attempted",
                        }
                    )
    parts = {
        str(repeat): {
            arm: [r for r in rows if r["repeat"] == repeat and r["arm"] == arm]
            for arm in ("session", "execution")
        }
        for repeat in range(2)
    }
    report = {
        "schema": plan["schema"],
        "completed": fatal is None and len(receipts) == 48,
        "fatal": fatal,
        "attempts": len(receipts),
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
        "by_repeat": {
            n: {
                "metrics": {a: metrics(rs) for a, rs in arms.items()},
                "comparison": compare_rows(arms["session"], arms["execution"]),
            }
            for n, arms in parts.items()
        },
        "real_loopback_jwks_fetches": jwks_fetches,
        "principal_injected": False,
        "all_state_reads_unchanged": all(
            r.get("behavior_store_unchanged") and r.get("session_journal_unchanged") for r in rows
        ),
        "independent_acceptance": False,
        "actual_OS_process_attestation": False,
        "historical_metrics_replaced": False,
        "plan_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    }
    write_json(directory / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--key-env-file", type=Path, required=True)
    parser.add_argument("--max-budget", type=float, default=2.0)
    args = parser.parse_args()
    try:
        result = run(args.directory, args.key_env_file, max_budget=args.max_budget)
        print(json.dumps(result))
        if not result["completed"]:
            raise SystemExit(1)
    except Exception as error:  # noqa: BLE001 -- safe CLI output
        print(json.dumps({"completed": False, "error_code": type(error).__name__}))
        raise SystemExit(1) from None
