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
    parser.add_argument("--audit-records", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.audit_records <= 1000:
        parser.error("audit-records must be between 0 and 1000")
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
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
