"""Real OIDC and paid static/tool-review comparison on all twelve local scope cases.

Scenario intent is fixed before requests. This is a development integration lab,
not independent attack ground truth or OS process attestation.
"""

import argparse
import hashlib
import json
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from dotenv import dotenv_values
from fastapi.testclient import TestClient

from app import main
from app.analyzers.evidence_agent import EvidenceReviewAgent
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.models import SecurityAssessment
from app.security import get_principal
from app.services.audit import AuditStore
from scripts.bounded_llm_requests import BoundedRequests
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_development import write_json
from scripts.evaluate_llm_grounded import MODEL, metrics, prediction
from scripts.local_execution_analysis_lab import EXECUTION_SCENARIOS, LocalExecutionAnalysisLab
from scripts.local_oidc_authority import LocalOIDCAuthority
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab


def run(directory, key_file, *, max_budget=0.75, stop_at, suite="execution"):
    directory = Path(directory)
    deadline = datetime.fromisoformat(stop_at)
    if directory.exists() or deadline.tzinfo is None or suite not in {"execution", "session"}:
        raise ValueError("evaluation_options")
    if get_principal in main.app.dependency_overrides:
        raise ValueError("refusing_principal_override")
    key = dotenv_values(key_file).get("OPENAI_API_KEY")
    if not key:
        raise ValueError("missing_credential")
    directory.mkdir(parents=True)
    (directory / "private").mkdir()
    root = Path(__file__).resolve().parents[1]
    source_names = [
        "scripts/evaluate_evidence_review_llm.py",
        "scripts/bounded_llm_requests.py",
        "scripts/local_execution_analysis_lab.py",
        "scripts/local_oidc_authority.py",
        "scripts/local_session_analysis_lab.py",
        "app/main.py",
        "app/models.py",
        "app/security.py",
        "app/config.py",
        "app/grounded_prompting.py",
        "app/analyzers/evidence_agent.py",
        "app/analyzers/openai_analyzer.py",
        "app/analyzers/structured_response.py",
        "app/analyzers/hybrid.py",
        "app/services/session_analysis_evidence.py",
        "app/services/execution_analysis_evidence.py",
    ]
    scenarios = EXECUTION_SCENARIOS if suite == "execution" else SCENARIOS
    plan = {
        "schema": "bounded-read-only-evidence-review-development-1",
        "scenarios": scenarios,
        "suite": suite,
        "arms": ["static", "agent"],
        "repetitions": 1,
        "model": MODEL,
        "max_budget_usd": max_budget,
        "stop_at": stop_at,
        "max_provider_calls": 48,
        "SDK_retries": 0,
        "max_calls_per_agent_review": 3,
        "predicate_context": False,
        "principal_injected": False,
        "jwks_fetch_mocked": False,
        "independent_acceptance": False,
        "actual_OS_process_attestation": False,
        "historical_metrics_replaced": False,
        "source_pins": {},
    }
    for name in source_names:
        content = (root / name).read_bytes()
        plan["source_pins"][name] = hashlib.sha256(content).hexdigest()
        target = directory / "source-snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    write_json(directory / "plan.json", plan)
    ledger = BoundedRequests(directory, max_budget=max_budget, max_requests=48, deadline=deadline)
    lab = (LocalExecutionAnalysisLab if suite == "execution" else LocalSessionAnalysisLab)(
        directory / "private" / "authority"
    )
    if suite == "execution":
        lab.prepare()
    rows = []
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
            analyzer_mode="openai",
            openai_api_key=key,
            openai_model=MODEL,
            openai_prompt_mode="grounded",
            openai_reasoning_effort="low",
            openai_max_output_tokens=2400,
            openai_evidence_agent_enabled=True,
        )
        adapter, agent = OpenAIAnalyzer(config), EvidenceReviewAgent(config)
        # Static adapter normally has HTTP retries; the paid lab must never retry invisibly.
        adapter._client.max_retries = 0
        with ExitStack() as stack:
            for name, value in {
                "zero_trust_operations": lab.service,
                "behavior_context_service": getattr(lab, "behavior", None),
                "get_settings": lambda: config,
                "get_analyzer": lambda: adapter,
                "get_evidence_agent": lambda: agent,
                "audit_store": AuditStore(directory / "private" / "audit.jsonl"),
            }.items():
                stack.enter_context(patch.object(main, name, value))
            stack.enter_context(patch("app.security.get_settings", return_value=config))
            for module in ("openai_analyzer", "evidence_agent"):
                stack.enter_context(
                    patch(f"app.analyzers.{module}.parse_structured_response", ledger.capture)
                )
            client = stack.enter_context(TestClient(main.app))
            try:
                for index, scenario in enumerate(scenarios):
                    name, truth = scenario[:2]
                    if suite == "execution":
                        signal, observed, _ = lab.create_execution_case(name)
                        params = {"behavior_capture_id": observed.capture_id}
                    else:
                        signal, _ = lab.create(scenario)
                        params = {}
                    arms = ("static", "agent") if index % 2 else ("agent", "static")
                    for arm in arms:
                        before = (
                            lab.behavior.store.read(lab.principal.tenant_id)
                            if suite == "execution"
                            else None
                        )
                        journal = lab.service.journal_status()
                        first = len(ledger.receipts)
                        response = client.post(
                            "/analysis/evidence-review"
                            if arm == "agent"
                            else "/analysis/verified-session",
                            json=signal.model_dump(mode="json"),
                            params=params,
                            headers={"Authorization": "Bearer " + authority.issue()},
                        )
                        row = {
                            "id": hashlib.sha256(str(index).encode()).hexdigest(),
                            "scenario": name,
                            "arm": arm,
                            "truth": truth,
                            "prediction": None,
                            "error": None,
                            "http_status": response.status_code,
                            "provider_receipt_indexes": list(range(first, len(ledger.receipts))),
                            "behavior_store_unchanged": suite != "execution"
                            or before == lab.behavior.store.read(lab.principal.tenant_id),
                            "session_journal_unchanged": journal == lab.service.journal_status(),
                        }
                        if response.status_code == 200:
                            body = response.json()
                            row.update(
                                prediction=prediction(
                                    SecurityAssessment.model_validate(body["assessment"])
                                ),
                                response=body,
                            )
                            audited = main.audit_store.get(
                                signal.event.event_id, lab.principal.tenant_id
                            )
                            row["snapshot_audited"] = (
                                audited.verification_context == body["verification_context"]
                            )
                            row["trace_audited"] = audited.llm_trace == body.get("llm_trace")
                        else:
                            row["error"] = f"HTTP_{response.status_code}"
                        rows.append(row)
                        write_json(directory / "private" / "predictions.json", rows)
                        print(
                            json.dumps(
                                {
                                    "rows": len(rows),
                                    "requests": len(ledger.receipts),
                                    "status": response.status_code,
                                }
                            ),
                            flush=True,
                        )
                        if ledger.fatal:
                            break
                    if ledger.fatal:
                        break
            finally:
                client.portal.call(agent.close)
                client.portal.call(adapter._client.close)
        fetches = authority.fetches
    seen = {(r["scenario"], r["arm"]) for r in rows}
    for index, scenario in enumerate(scenarios):
        name, truth = scenario[:2]
        for arm in ("static", "agent"):
            if (name, arm) not in seen:
                rows.append(
                    {
                        "id": hashlib.sha256(str(index).encode()).hexdigest(),
                        "scenario": name,
                        "arm": arm,
                        "truth": truth,
                        "prediction": None,
                        "error": "not_attempted",
                    }
                )
    arms = {a: [r for r in rows if r["arm"] == a] for a in ("static", "agent")}
    known, unknown = ledger.totals()
    report = {
        "schema": plan["schema"],
        "suite": suite,
        "completed": ledger.fatal is None and len(seen) == 24,
        "fatal": ledger.fatal,
        "attempts": len(ledger.receipts),
        "known_usage_estimated_usd": known,
        "unknown_usage_reserved_usd": unknown,
        "metrics": {a: metrics(rs) for a, rs in arms.items()},
        "comparison": compare_rows(arms["static"], arms["agent"]),
        "real_loopback_jwks_fetches": fetches,
        "principal_injected": False,
        "all_state_reads_unchanged": all(
            r.get("behavior_store_unchanged") and r.get("session_journal_unchanged") for r in rows
        ),
        "independent_acceptance": False,
        "actual_OS_process_attestation": False,
        "historical_metrics_replaced": False,
        "rows": rows,
        "plan_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    }
    write_json(directory / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--key-env-file", type=Path, required=True)
    parser.add_argument("--max-budget", type=float, default=0.75)
    parser.add_argument("--stop-at", required=True)
    parser.add_argument("--suite", choices=["execution", "session"], default="execution")
    args = parser.parse_args()
    try:
        report = run(
            args.directory,
            args.key_env_file,
            max_budget=args.max_budget,
            stop_at=args.stop_at,
            suite=args.suite,
        )
        print(json.dumps({k: v for k, v in report.items() if k != "rows"}))
        if not report["completed"]:
            raise SystemExit(1)
    except Exception as error:  # noqa: BLE001 -- never expose provider response text
        print(json.dumps({"completed": False, "error_code": type(error).__name__}))
        raise SystemExit(1) from None
