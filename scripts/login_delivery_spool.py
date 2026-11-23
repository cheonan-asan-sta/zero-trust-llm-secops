"""SQLite queue for the gateway's original login event and optional signed evidence."""

import argparse
import hashlib
import json
import math
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import time
from uuid import uuid4

from app.services.collector_spool import (
    SpoolBindingMismatch,
    SpoolConflict,
    SpoolFull,
    SpoolUnavailable,
)
from app.services.login_delivery import LoginDeliveryIdentity
from app.zero_trust_models import LoginDeliveryRequest

MAX_LOGIN_QUEUE_RECORDS = 10_000


class LoginRetryReviewConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LoginRetryPolicy:
    base_delay: float = 1
    max_delay: float = 60
    max_attempts: int = 8
    success_interval: float = 0.05

    def __post_init__(self):
        if (
            not all(math.isfinite(value) for value in (self.base_delay, self.max_delay, self.success_interval))
            or not 0 < self.base_delay <= self.max_delay <= 3600
            or not 0 <= self.success_interval <= 60
            or type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 100
        ):
            raise ValueError("invalid login retry policy")

    def delay(self, failures):
        return min(self.max_delay, self.base_delay * 2 ** min(32, failures - 1))


class LoginDeliverySpool:
    def __init__(self, path, *, origin, tenant_id, collector_subject, create=True):
        self.path = Path(path)
        self.tenant_id = tenant_id
        self.collector_subject = collector_subject
        self._binding = json.dumps([origin, tenant_id, collector_subject])
        if not create:
            with self._transaction(read_only=True) as con:
                con.execute("SELECT hold_id,approval_id FROM login_queue LIMIT 0")
                con.execute("SELECT approval_id FROM login_queue_review_history LIMIT 0")
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction(create=True) as con:
            tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            base = {"login_queue_binding", "login_queue"}
            if tables and tables not in (base, base | {"login_queue_review_history"}):
                raise SpoolUnavailable("login queue database schema mismatch")
            con.execute("CREATE TABLE IF NOT EXISTS login_queue_binding (id INTEGER PRIMARY KEY, binding TEXT NOT NULL)")
            con.execute(
                "CREATE TABLE IF NOT EXISTS login_queue ("
                "seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, "
                "payload_sha256 TEXT NOT NULL, held_status INTEGER)"
            )
            con.execute("INSERT OR IGNORE INTO login_queue_binding(id,binding) VALUES (1,?)", (self._binding,))
            self._check_binding(con)
            self._migrate(con)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def _transaction(self, *, create=False, read_only=False):
        try:
            if self.path.is_symlink():
                raise SpoolUnavailable("login queue link rejected")
            mode = "ro" if read_only else "rw"
            target = self.path if create else self.path.resolve().as_uri() + f"?mode={mode}"
            with closing(sqlite3.connect(target, uri=not create, timeout=5)) as con, con:
                if not read_only:
                    con.execute("PRAGMA synchronous=FULL")
                con.execute("BEGIN" if read_only else "BEGIN IMMEDIATE")
                if not create:
                    self._check_binding(con)
                yield con
        except sqlite3.Error as exc:
            raise SpoolUnavailable("login queue unavailable") from exc

    def _check_binding(self, con):
        if con.execute("SELECT binding FROM login_queue_binding WHERE id=1").fetchone() != (self._binding,):
            raise SpoolBindingMismatch("login queue belongs to another origin or collector")

    @staticmethod
    def _migrate(con):
        additions = {
            "login_queue_binding": {"next_send_at": "REAL NOT NULL DEFAULT 0", "failures": "INTEGER NOT NULL DEFAULT 0"},
            "login_queue": {
                "attempts": "INTEGER NOT NULL DEFAULT 0", "available_at": "REAL NOT NULL DEFAULT 0",
                "last_attempt_at": "REAL", "failure_code": "TEXT", "last_http_status": "INTEGER",
                "enqueued_at": "REAL",
                "hold_id": "TEXT", "approval_id": "TEXT",
            },
        }
        for table, columns in additions.items():
            existing = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in existing:
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        con.execute("CREATE INDEX IF NOT EXISTS login_queue_ready ON login_queue(held_status, available_at, seq)")
        con.execute("UPDATE login_queue SET hold_id=lower(hex(randomblob(16))) WHERE held_status IS NOT NULL AND hold_id IS NULL")
        con.execute(
            "CREATE TABLE IF NOT EXISTS login_queue_review_history ("
            "seq INTEGER PRIMARY KEY, approval_id TEXT NOT NULL, event_id TEXT NOT NULL, "
            "outcome TEXT NOT NULL, observed_at REAL NOT NULL, actor TEXT, note TEXT, "
            "failure_code TEXT, http_status INTEGER, analysis_id TEXT, duplicate INTEGER)"
        )
        con.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS login_queue_approval_once "
            "ON login_queue_review_history(approval_id) WHERE outcome='approved'"
        )
        con.execute("CREATE INDEX IF NOT EXISTS login_queue_review_event ON login_queue_review_history(event_id,seq)")

    def enqueue(self, body, *, now=None):
        self._check_owner(body)
        identity = LoginDeliveryIdentity.from_request(body)
        raw = body.model_dump_json()
        if len(raw.encode()) > 1_048_576:
            raise SpoolFull("login queue record too large")
        with self._transaction() as con:
            event_id = body.event.event_id
            stored = con.execute(
                "SELECT payload_sha256 FROM login_queue WHERE event_id=?", (event_id,),
            ).fetchone()
            if stored is not None:
                if stored[0] != identity.payload_sha256:
                    raise SpoolConflict("login event already queued with another payload")
                return
            if con.execute("SELECT count(*) FROM login_queue").fetchone()[0] >= MAX_LOGIN_QUEUE_RECORDS:
                raise SpoolFull("login queue capacity reached")
            con.execute(
                "INSERT INTO login_queue(event_id,payload,payload_sha256,enqueued_at) VALUES (?,?,?,?)",
                (event_id, raw, identity.payload_sha256, time() if now is None else now),
            )

    def _check_owner(self, body):
        if body.tenant_id != self.tenant_id or body.collector_subject != self.collector_subject:
            raise SpoolBindingMismatch("login queue payload belongs to another collector")

    def peek(self, *, now=None):
        now = time() if now is None else now
        with self._transaction() as con:
            if con.execute("SELECT next_send_at FROM login_queue_binding WHERE id=1").fetchone()[0] > now:
                return None
            row = con.execute(
                "SELECT event_id,payload,payload_sha256 FROM login_queue "
                "WHERE held_status IS NULL AND available_at<=? ORDER BY seq LIMIT 1", (now,),
            ).fetchone()
        if row is None:
            return None
        event_id, raw, digest = row
        try:
            body = LoginDeliveryRequest.model_validate_json(raw)
            self._check_owner(body)
            if body.event.event_id != event_id or LoginDeliveryIdentity.from_request(body).payload_sha256 != digest:
                raise ValueError("login queue payload changed")
        except ValueError as exc:
            raise SpoolUnavailable("login queue payload integrity failed") from exc
        return body

    def acknowledge(self, body, *, now, policy, receipt=None):
        with self._transaction() as con:
            row = con.execute("SELECT approval_id FROM login_queue WHERE event_id=? AND payload_sha256=?",
                              self._key(body)).fetchone()
            if row is not None and row[0] is not None:
                if receipt is None:
                    raise SpoolConflict("approved login resend requires a confirmed analysis receipt")
                self._record_review(con, row[0], body.event.event_id, "delivered", now,
                                    analysis_id=receipt.result.analysis_id, duplicate=int(receipt.duplicate))
            con.execute("DELETE FROM login_queue WHERE event_id=? AND payload_sha256=?", self._key(body))
            self._schedule(con, now + policy.success_interval, 0)

    def fail(self, body, *, now, policy, code, status=None, delay_hint=0, outage=False, permanent=False):
        key = self._key(body)
        with self._transaction() as con:
            row = con.execute(
                "SELECT attempts,approval_id FROM login_queue WHERE event_id=? AND payload_sha256=? AND held_status IS NULL", key,
            ).fetchone()
            if row is None:
                return
            attempts = row[0] + 1
            failures = 0
            spacing = policy.success_interval
            delay = policy.delay(attempts)
            if outage:
                failures = min(33, con.execute("SELECT failures FROM login_queue_binding WHERE id=1").fetchone()[0] + 1)
                delay = spacing = max(policy.delay(failures), delay_hint)
            held = permanent or attempts >= policy.max_attempts
            if row[1] is not None:
                self._record_review(con, row[1], body.event.event_id, "held_again" if held else "deferred",
                                    now, failure_code=code, http_status=status)
            con.execute(
                "UPDATE login_queue SET attempts=?, available_at=?, last_attempt_at=?, failure_code=?, "
                "last_http_status=?, held_status=?, hold_id=?, approval_id=? WHERE event_id=? AND payload_sha256=?",
                (attempts, now + delay, now, code, status, (status or 0) if held else None,
                 uuid4().hex if held else None, None if held else row[1], *key),
            )
            self._schedule(con, now + spacing, failures)

    @staticmethod
    def _key(body):
        return body.event.event_id, LoginDeliveryIdentity.from_request(body).payload_sha256

    @staticmethod
    def _schedule(con, when, failures):
        con.execute("UPDATE login_queue_binding SET next_send_at=?,failures=? WHERE id=1", (when, failures))

    def next_attempt(self):
        with self._transaction() as con:
            available = con.execute("SELECT min(available_at) FROM login_queue WHERE held_status IS NULL").fetchone()[0]
            if available is None:
                return None
            return max(available, con.execute("SELECT next_send_at FROM login_queue_binding WHERE id=1").fetchone()[0])

    def held(self, *, limit=50):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("held login listing limit must be between 1 and 1000")
        with self._transaction() as con:
            rows = con.execute(
                "SELECT event_id,attempts,coalesce(failure_code,'http_' || held_status),"
                "coalesce(last_http_status,nullif(held_status,0)),last_attempt_at "
                "FROM login_queue WHERE held_status IS NOT NULL ORDER BY seq LIMIT ?", (limit,),
            ).fetchall()
        return [
            {"event_id": event_id, "attempts": attempts, "failure_code": code, "http_status": status,
             "last_attempt_at": _utc(attempted)}
            for event_id, attempts, code, status, attempted in rows
        ]

    def requeue(self, event_id, *, now=None):
        with self._transaction() as con:
            changed = con.execute(
                "UPDATE login_queue SET held_status=NULL, hold_id=NULL, attempts=0, available_at=? "
                "WHERE event_id=? AND held_status IS NOT NULL", (time() if now is None else now, event_id),
            ).rowcount
        return bool(changed)

    def review_page(self, *, after=0, limit=20, event_id=None):
        with self._transaction(read_only=True) as con:
            rows = con.execute(
                "SELECT seq,event_id,hold_id,attempts,coalesce(failure_code,'http_' || held_status),"
                "coalesce(last_http_status,nullif(held_status,0)),last_attempt_at FROM login_queue "
                "WHERE held_status IS NOT NULL AND seq>? AND (? IS NULL OR event_id=?) ORDER BY seq LIMIT ?",
                (after, event_id, event_id, limit + 1),
            ).fetchall()
            history = con.execute(
                "SELECT approval_id,event_id,outcome,observed_at,actor,note,failure_code,http_status,analysis_id,duplicate "
                "FROM login_queue_review_history WHERE (? IS NULL OR event_id=?) ORDER BY seq DESC LIMIT 30",
                (event_id, event_id),
            ).fetchall()
        return {
            "held": [
                {"event_id": eid, "hold_id": hold, "attempts": attempts, "failure_code": code,
                 "http_status": status, "last_attempt_at": _utc(attempted)}
                for _, eid, hold, attempts, code, status, attempted in rows[:limit]
            ],
            "next_after": rows[limit - 1][0] if len(rows) > limit else None,
            "history": [
                {"approval_id": approval, "event_id": eid, "outcome": outcome, "observed_at": _utc(at),
                 "actor": actor, "note": note, "failure_code": code, "http_status": status,
                 "analysis_id": analysis, "duplicate": bool(duplicate) if duplicate is not None else None}
                for approval, eid, outcome, at, actor, note, code, status, analysis, duplicate in history
            ],
        }

    def approve_retry(self, event_id, hold_id, *, actor, note, authorize, now=None):
        now = time() if now is None else now
        with self._transaction() as con:
            authorize()
            existing = con.execute(
                "SELECT event_id,actor,note FROM login_queue_review_history WHERE approval_id=? AND outcome='approved'",
                (hold_id,),
            ).fetchone()
            if existing is not None:
                if existing != (event_id, actor, note):
                    raise LoginRetryReviewConflict("login hold already reviewed")
                return {"approval_id": hold_id, "duplicate": True}
            held = con.execute(
                "SELECT coalesce(failure_code,'http_' || held_status),coalesce(last_http_status,nullif(held_status,0)) "
                "FROM login_queue WHERE event_id=? AND hold_id=? AND held_status IS NOT NULL", (event_id, hold_id),
            ).fetchone()
            if held is None:
                raise LoginRetryReviewConflict("login hold changed")
            con.execute("UPDATE login_queue SET held_status=NULL,hold_id=NULL,approval_id=?,attempts=0,available_at=? "
                        "WHERE event_id=? AND hold_id=?", (hold_id, now, event_id, hold_id))
            self._record_review(con, hold_id, event_id, "approved", now, actor=actor, note=note,
                                failure_code=held[0], http_status=held[1])
            authorize()
        return {"approval_id": hold_id, "duplicate": False}

    @staticmethod
    def _record_review(con, approval_id, event_id, outcome, now, *, actor=None, note=None,
                       failure_code=None, http_status=None, analysis_id=None, duplicate=None):
        con.execute(
            "INSERT INTO login_queue_review_history(approval_id,event_id,outcome,observed_at,actor,note,"
            "failure_code,http_status,analysis_id,duplicate) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (approval_id, event_id, outcome, now, actor, note, failure_code, http_status, analysis_id, duplicate),
        )

    def counts(self):
        with self._transaction() as con:
            pending, held = con.execute(
                "SELECT count(*) - count(held_status),count(held_status) FROM login_queue"
            ).fetchone()
        return {"pending": pending, "held": held}

    @property
    def status_scope_sha256(self):
        scope = json.dumps([self.path.resolve().as_posix(), self._binding])
        return hashlib.sha256(scope.encode()).hexdigest()

    def status_snapshot(self):
        """Read counts and times from one snapshot without reading any login bodies."""
        with self._transaction(read_only=True) as con:
            pending, pending_known, first_enqueued, next_due = con.execute(
                "SELECT count(*),count(enqueued_at),min(enqueued_at),min(available_at) "
                "FROM login_queue WHERE held_status IS NULL"
            ).fetchone()
            held, held_known, first_held = con.execute(
                "SELECT count(*),count(last_attempt_at),min(last_attempt_at) "
                "FROM login_queue WHERE held_status IS NOT NULL"
            ).fetchone()
            next_send = con.execute("SELECT next_send_at FROM login_queue_binding WHERE id=1").fetchone()[0]
        return {
            "pending": pending, "held": held,
            "pending_age_unknown": pending - pending_known, "held_age_unknown": held - held_known,
            "oldest_pending_at": _utc(first_enqueued), "oldest_held_at": _utc(first_held),
            "retry_at": _utc(max(next_send, next_due)) if next_due is not None else None,
        }


def _utc(value):
    return None if value is None else datetime.fromtimestamp(value, UTC).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--collector-subject", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("publish-status").add_argument("output", type=Path)
    commands.add_parser("held").add_argument("--limit", type=int, default=50)
    commands.add_parser("requeue").add_argument("event_id")
    args = parser.parse_args()
    if not args.database.is_file():
        parser.error("existing login queue database is required")
    queue = LoginDeliverySpool(args.database, origin=args.origin.rstrip("/") + "/",
                               tenant_id=args.tenant_id, collector_subject=args.collector_subject)
    if args.command == "publish-status":
        from scripts.f1_lab.login_queue_status import publish_queue_status

        publish_queue_status(queue, args.output)
        result = {"scope_sha256": queue.status_scope_sha256}
    elif args.command == "status":
        result = queue.counts() | {"next_attempt_at": _utc(queue.next_attempt())}
    elif args.command == "held":
        result = queue.held(limit=args.limit)
    else:
        if not queue.requeue(args.event_id):
            parser.error("held login event not found")
        result = {"requeued": args.event_id}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
