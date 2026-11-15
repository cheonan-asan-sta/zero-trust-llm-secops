"""Stopped-writer snapshot and fail-closed recovery of the local approval ledger."""

import hashlib
import json
import sqlite3
import tempfile
import time
from contextlib import closing
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from app.response_workflow import ResponseWorkflow

FILE = "response-workflow.sqlite3"
MAX_BYTES = 32 * 1024**2
MAX_PLANS = 10000


def require(condition, code):
    if not condition:
        raise ValueError(code)


def schema(db):
    return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()


@lru_cache(maxsize=1)
def expected_schema():
    with tempfile.TemporaryDirectory(prefix="response-schema-") as temp:
        service = ResponseWorkflow(Path(temp) / FILE)
        with service.transaction() as db:
            return schema(db)


def inspect(directory):
    path = Path(directory) / FILE
    if not path.exists() and not path.is_symlink():
        return None
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES,
            "response_regular_bounded_file_required")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "response_integrity")
        require(db.execute("PRAGMA application_id").fetchone()[0] == 1515475536
                and schema(db) == expected_schema(), "response_schema")
        rows = db.execute("SELECT tenant,id,request_key,body FROM response_plans ORDER BY tenant,id").fetchmany(MAX_PLANS + 1)
    require(len(rows) <= MAX_PLANS, "response_capacity")
    plans = {}
    for tenant, ident, request_key, body in rows:
        require(all(isinstance(v, str) and v for v in (tenant, ident, request_key, body))
                and len(body.encode()) <= 1024**2, "response_row")
        plan = json.loads(body)
        require(isinstance(plan, dict) and plan.get("id") == ident and plan.get("tenant_id") == tenant
                and plan.get("mode") == "simulation" and plan.get("state") in {
                    "PENDING", "APPROVED", "REJECTED", "SIMULATED"}, "response_identity")
        history = plan.get("history")
        require(isinstance(history, list) and history and type(plan.get("version")) is int
                and len(history) == plan["version"] and isinstance(history[-1], dict)
                and history[-1].get("state") == plan["state"], "response_history")
        if plan["state"] == "SIMULATED":
            require(plan.get("result") == {"mode": "simulation", "external_calls": 0,
                    "session_changes": 0, "action": plan.get("action")}, "response_simulation_only")
        else:
            require(plan.get("result") is None, "response_unexecuted_result")
        key = json.dumps([tenant, ident], separators=(",", ":"))
        plans[key] = hashlib.sha256(json.dumps([tenant, ident, request_key, body],
                                              separators=(",", ":")).encode()).hexdigest()
    return {"schema": "response-storage-1", "plans": plans, "count": len(plans)}


def snapshot(source, destination):
    before = inspect(source)
    if before is None:
        return
    path = Path(source) / FILE
    started = time.monotonic()

    def progress(_status, _remaining, _total):
        require(time.monotonic() - started <= 15, "response_snapshot_deadline")

    with (closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)) as db,
          closing(sqlite3.connect(Path(destination) / FILE)) as output):
        db.backup(output, pages=256, progress=progress, sleep=.05)
    require(inspect(source) == before == inspect(destination), "response_changed_during_snapshot")


def fence(directory):
    """Keep history/receipts, terminally reject every old unfinished approval."""
    before = inspect(directory)
    require(before is not None, "response_ledger_missing")
    count = 0
    with ResponseWorkflow(Path(directory) / FILE).transaction() as db:
        rows = db.execute("SELECT tenant,id,body FROM response_plans").fetchall()
        for tenant, ident, body in rows:
            plan = json.loads(body)
            if plan["state"] not in {"PENDING", "APPROVED"}:
                continue
            plan["state"] = "REJECTED"
            plan["approved_by"] = None
            plan["version"] += 1
            plan["history"].append({"state": "REJECTED", "actor": "infra-recovery",
                "at": datetime.now(UTC).timestamp(), "note": "Recovery: old approval invalidated"})
            db.execute("UPDATE response_plans SET body=? WHERE tenant=? AND id=?",
                       (json.dumps(plan), tenant, ident))
            count += 1
    after = inspect(directory)
    require(after["plans"].keys() == before["plans"].keys(), "response_fence_identity")
    return count


def verify_baseline(directory, witness):
    current = inspect(directory)
    require(current is not None and witness.get("schema") == current["schema"]
            and all(current["plans"].get(key) == value for key, value in witness["plans"].items()),
            "response_admission_baseline_changed")
