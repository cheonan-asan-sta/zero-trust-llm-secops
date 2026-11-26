"""Loopback-only, synthetic authenticated server for browser acceptance."""

import argparse
import json
from pathlib import Path

from pydantic import SecretStr

from scripts.serve_dashboard_demo import isolated_app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--sqlite-audit", action="store_true")
    parser.add_argument("--caller-bound-reviews", action="store_true")
    parser.add_argument("--audit-records", type=int, default=0)
    parser.add_argument("--collection-records", action="store_true")
    args = parser.parse_args()
    if not 0 <= args.audit_records <= 1000:
        parser.error("audit-records must be between 0 and 1000")
    if args.caller_bound_reviews and not args.sqlite_audit:
        parser.error("caller-bound-reviews requires sqlite-audit")
    args.directory.mkdir(mode=0o700)
    app = isolated_app(args.directory)
    from app.main import settings

    if args.sqlite_audit:
        from app import main as api
        from app.services.sqlite_audit import SQLiteAuditStore

        api.audit_store = SQLiteAuditStore(args.directory / "audit.sqlite3")
        settings.audit_backend = "sqlite"
        settings.audit_review_require_if_match = True
    from tests.test_api_key_accounts import account, sha

    settings.auth_mode = "api_key"
    settings.api_key_sha256 = SecretStr(sha("synthetic-requester-key"))
    settings.api_key_subject = "operator"
    settings.api_key_tenant_id = "tenant-a"
    settings.api_key_roles = "admin"
    settings.audit_review_require_identity = args.caller_bound_reviews
    settings.api_key_accounts_path = args.directory / "accounts.json"
    settings.api_key_accounts_path.write_text(
        json.dumps(
            {
                "schema": "api-key-accounts-1",
                "accounts": [
                    account("reviewer-a", "synthetic-reviewer-a-key"),
                    account("reviewer-b", "synthetic-reviewer-b-key"),
                    account("viewer", "synthetic-viewer-key", roles=["viewer"]),
                    account(
                        "foreign", "synthetic-foreign-key", tenant_id="tenant-b", roles=["admin"]
                    ),
                ],
            }
        )
    )
    settings.dashboard_operations_directory = args.directory / "jobs"
    settings.dashboard_operations_tenant = "tenant-a"
    if args.audit_records:
        import asyncio
        from datetime import UTC, datetime, timedelta

        from app import main as api
        from app.models import ReviewStatus, RiskLevel
        from tests.test_audit_cancellation import record

        async def seed_audit():
            for index in range(1, args.audit_records + 1):
                original = record(index)
                row = original.model_copy(
                    update={
                        "analysis_id": f"{index:032x}",
                        "event_id": f"page-event-{index:03d}",
                        "tenant_id": "tenant-a",
                        "actor_id": "synthetic-operator",
                        "analyzed_at": datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index),
                        "review_status": ReviewStatus.PENDING,
                        "assessment": original.assessment.model_copy(
                            update={
                                "risk_level": RiskLevel.CRITICAL if index == 1 else RiskLevel.HIGH,
                            }
                        ),
                    }
                )
                await api.audit_store.save(row)
            foreign = record(999).model_copy(update={"tenant_id": "tenant-b"})
            await api.audit_store.save(foreign)

        asyncio.run(seed_audit())
    if args.collection_records:
        import asyncio
        from dataclasses import replace
        from datetime import UTC, datetime

        from app import main as api
        from app.services.cases import IncidentCaseService
        from tests.test_incident_cases import _correlation
        from tests.test_trusted_signals import OPERATOR, setup, signal
        from tests.test_zero_trust_operations import evaluate, event

        signed_directory = args.directory / "signed-seed"
        signed_directory.mkdir()
        verifier_service, private_key, _, _ = setup.__wrapped__(signed_directory)
        operations = api.zero_trust_operations
        operations.signal_verifier = verifier_service.signal_verifier
        for index in range(103):
            request = signal(
                private_key,
                when=datetime.now(UTC),
                session=f"signed-page-{index:03d}",
                event_id=f"signed-page-event-{index:03d}",
            )
            operations.evaluate_signed(request, OPERATOR)
        evaluate(
            operations,
            e=event("foreign-page-event", when=datetime.now(UTC)),
            session_id="foreign-page-session",
            principal=replace(OPERATOR, tenant_id="tenant-b"),
            now=datetime.now(UTC),
        )
        records, _, _ = asyncio.run(
            IncidentCaseService(api.case_store).create_from_correlation(
                _correlation("page-cases", "tenant-a"),
                "tenant-a",
                "synthetic-operator",
                "Local page fixture",
            )
        )
        for index in range(26):
            asyncio.run(
                api.case_store.save(records[0].model_copy(update={"case_id": f"case-{index:032x}"}))
            )
        asyncio.run(
            IncidentCaseService(api.case_store).create_from_correlation(
                _correlation("foreign-page-cases", "tenant-b"),
                "tenant-b",
                "synthetic-foreign",
                "Foreign local page fixture",
            )
        )
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
