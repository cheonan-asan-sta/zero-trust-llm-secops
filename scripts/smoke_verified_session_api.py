"""Two bounded real-provider calls through the actual local ASGI analysis route.

Uses local authority fixtures. The default injects a principal; --oidc instead
verifies an actual local JWT and loopback JWKS through the application auth path.
Neither mode establishes enterprise login or uses production state.
"""

import argparse
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
from app.security import get_principal
from app.services.audit import AuditStore
from scripts.evaluate_llm_grounded import INPUT_RATE, MODEL, OUTPUT_RATE, reservation
from scripts.local_oidc_authority import LocalOIDCAuthority
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab


def run(directory, key_file, *, use_oidc=False):
    with ExitStack() as stack:
        authority = stack.enter_context(LocalOIDCAuthority()) if use_oidc else None
        return _run(directory, key_file, authority)


def _run(directory, key_file, authority):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    key = dotenv_values(key_file).get("OPENAI_API_KEY")
    if not key:
        raise ValueError("missing_credential")
    lab = LocalSessionAnalysisLab(directory / "private-authority")
    config = Settings(
        **(
            {
                "app_environment": "test",
                "auth_mode": "oidc",
                "oidc_issuer": authority.issuer,
                "oidc_audience": authority.audience,
                "oidc_jwks_url": authority.jwks_url,
            }
            if authority
            else {}
        ),
        openai_api_key=key,
        openai_model=MODEL,
        openai_prompt_mode="grounded",
        openai_reasoning_effort="low",
        openai_max_output_tokens=2400,
    )
    adapter = OpenAIAnalyzer(config)
    unused = adapter._client
    adapter._client = AsyncOpenAI(api_key=key, timeout=30, max_retries=0)
    receipts = []
    reserved = 0.0

    async def capture(provider_client, **kwargs):
        nonlocal reserved
        amount = reservation(kwargs["input"], INPUT_RATE, OUTPUT_RATE, 2400)
        if len(receipts) >= 2 or reserved + amount > 0.08:
            raise ValueError("smoke_budget_limit")
        reserved += amount
        receipt = {"input_tokens": None, "output_tokens": None, "reserved_usd": amount}
        receipts.append(receipt)
        try:
            response, diagnostics = await parse_structured_response(provider_client, **kwargs)
            receipt.update(
                input_tokens=diagnostics.input_tokens,
                output_tokens=diagnostics.output_tokens,
                model=response.model,
                response_diagnostics=diagnostics.as_dict(),
            )
            return response, diagnostics
        except Exception as error:
            receipt["error_type"] = type(error).__name__
            if isinstance(error, StructuredResponseFailure):
                receipt.update(
                    error_code=error.code,
                    response_diagnostics=error.diagnostics.as_dict(),
                    input_tokens=error.diagnostics.input_tokens,
                    output_tokens=error.diagnostics.output_tokens,
                )
            raise

    originals = (main.zero_trust_operations, main.get_analyzer, main.get_settings, main.audit_store)
    old_override = main.app.dependency_overrides.get(get_principal)
    if authority and old_override is not None:
        raise ValueError("oidc_smoke_refuses_principal_override")
    main.zero_trust_operations = lab.service
    main.get_analyzer = lambda: adapter
    main.get_settings = lambda: config
    audit = AuditStore(directory / "audit.jsonl")
    main.audit_store = audit
    if not authority:
        main.app.dependency_overrides[get_principal] = lambda: lab.principal
    rows = []
    try:
        with ExitStack() as stack:
            stack.enter_context(
                patch("app.analyzers.openai_analyzer.parse_structured_response", capture)
            )
            if authority:
                stack.enter_context(patch("app.security.get_settings", return_value=config))
            client = stack.enter_context(TestClient(main.app))
            for name in ["required_mfa_unknown", "mfa_not_required"]:
                signal, _ = lab.create(next(s for s in SCENARIOS if s[0] == name))
                history = lab.service.history(signal.session_id, lab.principal)
                response = client.post(
                    "/analysis/verified-session",
                    json=signal.model_dump(mode="json"),
                    headers={"Authorization": "Bearer " + authority.issue()} if authority else {},
                )
                body = response.json()
                row = {
                    "scenario": name,
                    "status_code": response.status_code,
                    "response": body,
                    "session_history_unchanged": history
                    == lab.service.history(signal.session_id, lab.principal),
                }
                if response.status_code == 200:
                    saved = audit.get(signal.event.event_id, lab.principal.tenant_id)
                    row["snapshot_audited"] = (
                        saved is not None
                        and saved.verification_context == body["verification_context"]
                    )
                    row["human_review"] = body["assessment"]["requires_human_review"]
                rows.append(row)
                print(
                    json.dumps({"scenario": name, "status_code": response.status_code}), flush=True
                )
            client.portal.call(adapter._client.close)
            client.portal.call(unused.close)
    finally:
        main.zero_trust_operations, main.get_analyzer, main.get_settings, main.audit_store = (
            originals
        )
        if old_override is None:
            main.app.dependency_overrides.pop(get_principal, None)
        else:
            main.app.dependency_overrides[get_principal] = old_override
    estimate = sum(
        (x["input_tokens"] or 0) * INPUT_RATE + (x["output_tokens"] or 0) * OUTPUT_RATE
        for x in receipts
    )
    result = {
        "schema": "verified-session-real-provider-ASGI-smoke-1",
        "rows": rows,
        "receipts": receipts,
        "completed": all(
            r["status_code"] == 200
            and r["session_history_unchanged"]
            and r.get("snapshot_audited")
            and r.get("human_review")
            for r in rows
        ),
        "attempts": len(receipts),
        "reserved_upper_usd": reserved,
        "known_usage_estimated_usd": estimate,
        "unknown_usage_attempts": sum(x["input_tokens"] is None for x in receipts),
        "real_provider": True,
        "local_principal_injected": authority is None,
        "real_loopback_jwks_fetches": authority.fetches if authority else 0,
        "bearer_token_persisted": False,
        "enterprise_identity_verified": False,
        "production_state_used": False,
    }
    (directory / "report.json").write_bytes(
        (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode()
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--key-env-file", type=Path, required=True)
    parser.add_argument("--oidc", action="store_true")
    args = parser.parse_args()
    try:
        report = run(args.directory, args.key_env_file, use_oidc=args.oidc)
        print(json.dumps({k: v for k, v in report.items() if k not in {"rows", "receipts"}}))
        if not report["completed"]:
            raise SystemExit(1)
    except Exception as error:  # noqa: BLE001 -- never print provider/secret-bearing exceptions
        print(json.dumps({"completed": False, "error_code": type(error).__name__}))
        raise SystemExit(1) from None
