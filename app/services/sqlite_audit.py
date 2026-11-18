"""Opt-in local transactional audit chain for independent processes.

Each transaction verifies the chain and durable head. This detects corruption,
not a privileged attacker restoring/resealing the entire database and head.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.models import AnalysisResult
from app.services.audit import _record_hash, _summarize
from app.services.federated_audit import AuditQueryUnavailable
from app.services.settled_io import settled_io

MUTABLE_REVIEW = {"review_status", "reviewer", "review_note", "review_updated_at"}
TRANSITIONS = {
    "PENDING": {"IN_REVIEW", "RESOLVED", "DISMISSED"},
    "IN_REVIEW": {"IN_REVIEW", "RESOLVED", "DISMISSED"},
    "RESOLVED": {"IN_REVIEW"},
    "DISMISSED": {"IN_REVIEW"},
}


class AuditReviewConflict(RuntimeError):
    pass


class SQLiteAuditStore:
    MAX_ROWS = 100000
    MAX_BYTES = 256 * 1024 * 1024

    @classmethod
    def open_existing(cls, path):
        """Validate an existing audit DB without initializing or repairing its schema."""
        store = cls.__new__(cls)
        store.path = Path(path)
        with store._transaction() as con:
            tables = {
                r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if tables != {"audit_entries", "audit_head"}:
                raise AuditQueryUnavailable("existing audit schema required")
            store._read(con)
        return store

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction(create=True, write=True) as con:
            tables = {
                r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not tables <= {"audit_entries", "audit_head"}:
                raise AuditQueryUnavailable("audit database contains another service schema")
            con.execute(
                "CREATE TABLE IF NOT EXISTS audit_entries (seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS audit_head (id INTEGER PRIMARY KEY CHECK(id=1), seq INTEGER NOT NULL, digest TEXT NOT NULL)"
            )
            con.execute("INSERT OR IGNORE INTO audit_head VALUES (1,0,?)", ("0" * 64,))
            self._read(con)

    @contextmanager
    def _transaction(self, *, create=False, write=False):
        con = None
        try:
            if self.path.is_symlink():
                raise AuditQueryUnavailable("audit database link rejected")
            con = sqlite3.connect(
                self.path
                if create
                else self.path.resolve().as_uri() + ("?mode=rw" if write else "?mode=ro"),
                uri=not create,
                timeout=5,
            )
            if write:
                con.execute("PRAGMA synchronous=FULL")
            else:
                con.execute("PRAGMA query_only=ON")
            con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            with con:
                yield con
        except (OSError, sqlite3.Error, ValueError, TypeError) as error:
            raise AuditQueryUnavailable("transactional audit unavailable") from error
        finally:
            if con is not None:
                con.close()

    @staticmethod
    def _review_fits(old, new):
        if old.model_dump(exclude=MUTABLE_REVIEW) != new.model_dump(exclude=MUTABLE_REVIEW):
            return False
        return (
            new.review_status.value in TRANSITIONS.get(old.review_status.value, set())
            and new.review_updated_at is not None
            and new.review_updated_at > (old.review_updated_at or old.analyzed_at)
        )

    def _read(self, con):
        size, count = con.execute(
            "SELECT coalesce(sum(length(CAST(payload AS BLOB))),0),count(*) FROM audit_entries"
        ).fetchone()
        if count > self.MAX_ROWS or size > self.MAX_BYTES:
            raise AuditQueryUnavailable("audit capacity exceeded")
        records, previous, seq = {}, "0" * 64, 0
        for number, parent, digest, payload in con.execute(
            "SELECT seq,previous,digest,payload FROM audit_entries ORDER BY seq"
        ):
            if number != seq + 1 or parent != previous or digest != _record_hash(parent, payload):
                raise AuditQueryUnavailable("audit chain integrity failed")
            record = AnalysisResult.model_validate_json(payload)
            old = records.get(record.analysis_id)
            if old is None and record.review_updated_at is not None:
                raise AuditQueryUnavailable("persisted review has no original analysis")
            if old is not None and not self._review_fits(old, record):
                raise AuditQueryUnavailable("invalid persisted review transition")
            records[record.analysis_id] = record
            previous, seq = digest, number
        if con.execute("SELECT seq,digest FROM audit_head WHERE id=1").fetchone() != (
            seq,
            previous,
        ):
            raise AuditQueryUnavailable("audit durable head mismatch")
        return records, seq, previous, size

    @staticmethod
    def _latest(records, event_id, tenant):
        matches = [r for r in records.values() if (r.event_id, r.tenant_id) == (event_id, tenant)]
        return max(matches, key=lambda r: (r.analyzed_at, r.analysis_id)) if matches else None

    def _write(self, record, expected=None):
        record = AnalysisResult.model_validate(record.model_dump(mode="json"))
        with self._transaction(write=True) as con:
            records, seq, previous, size = self._read(con)
            old = records.get(record.analysis_id)
            if old is None and record.review_updated_at is not None:
                raise AuditReviewConflict("review requires an existing analysis")
            if expected is not None:
                latest = self._latest(records, record.event_id, record.tenant_id)
                if old != expected or latest != expected or not self._review_fits(old, record):
                    raise AuditReviewConflict("audit review changed; reload current record")
            elif old is not None:
                if old == record:
                    return
                raise AuditReviewConflict("review update requires expected current record")
            payload = record.model_dump_json()
            if seq >= self.MAX_ROWS or size + len(payload.encode()) > self.MAX_BYTES:
                raise AuditQueryUnavailable("audit capacity exhausted")
            digest = _record_hash(previous, payload)
            con.execute(
                "INSERT INTO audit_entries VALUES (?,?,?,?)", (seq + 1, previous, digest, payload)
            )
            con.execute("UPDATE audit_head SET seq=?,digest=? WHERE id=1", (seq + 1, digest))

    async def save(self, record):
        # Cancellation does not revoke a committed audit; no mutable in-memory
        # head exists to diverge from the settled filesystem transaction.
        await settled_io(self._write, record.model_copy(deep=True))

    async def save_review(self, record, expected):
        await settled_io(
            self._write, record.model_copy(deep=True), expected.model_copy(deep=True)
        )

    def _records(self):
        with self._transaction() as con:
            return sorted(self._read(con)[0].values(), key=lambda r: (r.analyzed_at, r.analysis_id))

    def get(self, event_id, tenant_id="local"):
        return next(
            (
                r
                for r in reversed(self._records())
                if (r.event_id, r.tenant_id) == (event_id, tenant_id)
            ),
            None,
        )

    def recent(self, limit=20, tenant_id="local"):
        records = [r for r in self._records() if r.tenant_id == tenant_id]
        return list(reversed(records[-limit:])) if limit > 0 else []

    def metrics(self, tenant_id="local"):
        return _summarize([r for r in self._records() if r.tenant_id == tenant_id])

    def integrity(self):
        try:
            with self._transaction() as con:
                _, seq, _, _ = self._read(con)
            return {
                "backend": "sqlite_transactional_hash_chain",
                "ok": True,
                "verified_lines": seq,
                "legacy_lines": 0,
            }
        except AuditQueryUnavailable:
            return {
                "backend": "sqlite_transactional_hash_chain",
                "ok": False,
                "verified_lines": 0,
                "legacy_lines": 0,
            }
