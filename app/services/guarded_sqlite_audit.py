"""Opt-in runtime minimum history, pinned outside the mutable audit database."""

from contextlib import contextmanager
from pathlib import Path

from app.services.audit_checkpoint import load_checkpoint
from app.services.audit_transfer import AuditTransferError
from app.services.federated_audit import AuditQueryUnavailable
from app.services.sqlite_audit import SQLiteAuditStore


class GuardedSQLiteAuditStore(SQLiteAuditStore):
    def __init__(self, *args, **kwargs):
        raise ValueError("use open_guarded with an external checkpoint pin")

    @classmethod
    def open_existing(cls, path):
        raise ValueError("use open_guarded with an external checkpoint pin")

    @classmethod
    def open_guarded(cls, path, checkpoint_path, checkpoint_sha256):
        store = cls.__new__(cls)
        store.path = Path(path)
        store.checkpoint_path = Path(checkpoint_path)
        store.checkpoint_sha256 = checkpoint_sha256
        # No schema creation/repair or fallback to an unguarded empty database.
        with store._transaction() as con:
            tables = {
                r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if tables != {"audit_entries", "audit_head"}:
                raise AuditQueryUnavailable("existing audit schema required")
            store._read(con, retain_records=False)
        return store

    def _checkpoint(self):
        try:
            return load_checkpoint(self.checkpoint_path, self.checkpoint_sha256)
        except (OSError, ValueError, TypeError, AuditTransferError) as error:
            raise AuditQueryUnavailable("runtime audit checkpoint unavailable") from error

    def _require_prefix(self, con, checkpoint):
        minimum = checkpoint["head"]
        seq, _ = con.execute("SELECT seq,digest FROM audit_head WHERE id=1").fetchone()
        row = (
            ("0" * 64,)
            if minimum["seq"] == 0
            else con.execute(
                "SELECT digest FROM audit_entries WHERE seq=?", (minimum["seq"],)
            ).fetchone()
        )
        if seq < minimum["seq"] or row is None or row[0] != minimum["digest"]:
            raise AuditQueryUnavailable("runtime audit checkpoint history not satisfied")

    def _read(self, con, *, retain_records=True, row_observer=None):
        checkpoint = self._checkpoint()
        result = super()._read(con, retain_records=retain_records, row_observer=row_observer)
        self._require_prefix(con, checkpoint)
        # Withdrawal or replacement during a long full-chain read denies delivery.
        if self._checkpoint() != checkpoint:
            raise AuditQueryUnavailable("runtime audit checkpoint changed")
        return result

    @contextmanager
    def _transaction(self, *, create=False, write=False):
        if create:
            raise AuditQueryUnavailable("guarded audit cannot initialize a database")
        with super()._transaction(create=False, write=write) as con:
            yield con
            if write:
                # This runs before the parent's context commits. Failure rolls back.
                self._require_prefix(con, self._checkpoint())

    def integrity(self):
        result = super().integrity()
        result["checkpoint_guard"] = {
            "configured": True,
            "minimum_head_verified": result["ok"],
            "latest_live_state_verified": False,
            "independent_storage_verified": False,
        }
        return result
