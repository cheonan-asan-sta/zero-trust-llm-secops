"""Synthetic journal handoff between old/new runtime containers; no service calls.

Use prepare under the old runtime, then verify under the new one on the same
owned scratch directory. Tokens are synthetic, private to that directory, and
never printed. This checks compatibility, not resilience against DB rollback.
"""

import argparse
import json
import platform
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.policy_journal import JournalLimits
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionEvaluationRequest,
    SessionRevocationRequest,
)

LIMITS = JournalLimits(max_active_records=8, archive_batch_size=4, max_archive_records=200)
PRINCIPAL = Principal("runtime-test", "runtime-tenant", frozenset({Role.ADMIN}), "api_key")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def service(path):
    return ZeroTrustOperations(path, journal_limits=LIMITS)


def access(operations, session, token, now, principal=PRINCIPAL):
    return operations.access(ProtectedAccessRequest(session_id=session, resource_id="zt-demo-documents",
        action="READ", grant_token=token), principal, now=now).allowed


def prepare(directory):
    require(not any(directory.iterdir()), "fresh_scratch_directory_required")
    now = datetime.now(UTC)
    operations = service(directory / "journal.db")
    tokens = {}
    for session in ("consumed", "revoked", "pending"):
        data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
        data.update(event_id="runtime-" + session, timestamp=now.isoformat())
        data["user"].update(role="employee", active=True)
        data["resource"].update(resource_id="zt-demo-documents", required_role=None)
        data["auth_context"].update(authentication_result="success", mfa="success")
        result = operations.evaluate(SessionEvaluationRequest(session_id=session, expected_version=0,
            event=SecurityEvent.model_validate(data)), PRINCIPAL, now=now)
        require(result.session.decision == "ALLOW", "fixture_not_allowed")
        tokens[session] = result.grant_token
    require(access(operations, "consumed", tokens["consumed"], now), "fixture_consumption")
    operations.revoke("revoked", SessionRevocationRequest(expected_version=1, note="runtime patch fixture"),
                      PRINCIPAL, now=now)
    # Push the security decisions into the immutable archived prefix.
    for _ in range(12):
        require(not access(operations, "consumed", tokens["consumed"], now), "fixture_replay")
    integrity = operations.integrity()
    require(integrity["ok"], "fixture_integrity")
    with closing(sqlite3.connect(operations.path)) as db:
        require(db.execute("SELECT count(*) FROM journal_archive_segments").fetchone()[0] > 0,
                "fixture_archive_missing")
        with closing(sqlite3.connect(directory / "backup.db")) as backup:
            db.backup(backup)
    fixture = {"now": now.isoformat(), "tokens": tokens, "verified_entries": integrity["verified_entries"],
               "runtime": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version}}
    path = directory / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    path.chmod(0o600)
    return {"prepared": True, "old_runtime": fixture["runtime"], "archived_history": True}


def verify(directory):
    fixture = json.loads((directory / "fixture.json").read_text(encoding="utf-8"))
    # Fixed synthetic clock prevents a slow build from turning this into a mere
    # TTL-expiry test. Pending access must succeed once after the upgrade.
    now = datetime.fromisoformat(fixture["now"]) + timedelta(seconds=1)
    checks = {}
    for name in ("journal.db", "backup.db"):
        operations = service(directory / name)
        with closing(sqlite3.connect(operations.path)) as db:
            checks[name + ":sqlite_integrity"] = db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            checks[name + ":archive_retained"] = db.execute("SELECT count(*) FROM journal_archive_segments").fetchone()[0] > 0
        checks[name + ":chain_retained"] = operations.integrity()["verified_entries"] == fixture["verified_entries"]
        for session in ("consumed", "revoked"):
            checks[name + ":deny_" + session] = not access(operations, session, fixture["tokens"][session], now)
        other = Principal(PRINCIPAL.subject, "other-tenant", PRINCIPAL.roles, "api_key")
        checks[name + ":tenant_boundary"] = not access(operations, "pending", fixture["tokens"]["pending"], now, other)
        checks[name + ":pending_once"] = access(operations, "pending", fixture["tokens"]["pending"], now)
        checks[name + ":pending_replay_denied"] = not access(operations, "pending", fixture["tokens"]["pending"], now)
        checks[name + ":final_chain"] = operations.integrity()["ok"]
    return {"schema": "secops-runtime-upgrade-1", "old_runtime": fixture["runtime"],
            "new_runtime": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version},
            "checks": checks, "passed": all(checks.values()),
            "limits": "Synthetic fixed-clock DB and SQLite backup compatibility; no production rollback/HA claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "verify"])
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    result = prepare(args.directory) if args.operation == "prepare" else verify(args.directory)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
