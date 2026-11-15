"""Stopped-writer snapshots and admission pins for durable behavior context.

The original database is only opened immutable and read-only. Writers must stop
cleanly: SQLite sidecars are refused, and this workflow does not automate their
recovery. A pin commits to the exact append-only prefix, allowing legitimate
later records.
"""

import hashlib
import json
import sqlite3
import tempfile
import time
import zlib
from contextlib import closing
from functools import cache
from pathlib import Path

from app.services.behavior_context_store import (
    HASH,
    MAX_ACTIVE_RECORDS,
    MAX_RECORDS,
    MAX_TOTAL_BYTES,
    ZERO_HASH,
    BehaviorContextStore,
    ContextStoreUnavailable,
    canonical,
    digest,
)

NAME = "app-behavior-context.sqlite3"
# The local recovery envelope is intentionally smaller than the live store's
# logical capacity. Larger files fail explicitly; history is never truncated.
MAX_DATABASE = 32 * 1024**2
SIDECARS = ("-journal", "-wal", "-shm")
PIN_FIELDS = {"format", "schema_sha256", "records", "bytes", "head_sha256"}


def _require(condition, code):
    if not condition:
        raise ContextStoreUnavailable(code)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _schema(connection):
    return connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
    ).fetchall()


@cache
def _expected_schema(version=2):
    with tempfile.TemporaryDirectory(prefix="behavior-context-schema-") as temporary:
        path = Path(temporary) / NAME
        BehaviorContextStore(path)
        with closing(sqlite3.connect(path)) as connection:
            if version == 1:
                connection.execute("DROP TABLE behavior_context_archive")
            return _schema(connection)


def _stamp(path):
    _require(not path.parent.is_symlink(), "context_directory_symlink")
    _require(not any(Path(str(path) + suffix).exists() or Path(str(path) + suffix).is_symlink()
                     for suffix in SIDECARS), "context_unrecovered_sidecars")
    if not path.exists() and not path.is_symlink():
        return None
    _require(path.is_file() and not path.is_symlink(), "context_regular_file_required")
    status = path.stat()
    _require(0 < status.st_size <= MAX_DATABASE, "context_database_size_limit")
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns)


def _read(path, *, prefix=None):
    before = _stamp(path)
    _require(before is not None, "context_database_missing")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        _require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                 "context_sqlite_integrity_failed")
        actual = _schema(connection)
        _require(actual in (_expected_schema(1), _expected_schema(2)), "context_database_schema")
        probe = object.__new__(BehaviorContextStore)
        probe.max_records, probe.max_bytes = MAX_RECORDS, MAX_TOTAL_BYTES
        probe.max_active_records = MAX_ACTIVE_RECORDS
        entries, head, size = probe._load(connection)
        pin = {"format": 1, "schema_sha256": _digest(actual), "records": len(entries),
               "bytes": size, "head_sha256": head}
        if prefix is not None:
            _require(prefix["records"] <= pin["records"], "context_admission_prefix_missing")
            head, size = ZERO_HASH, 0
            for entry in entries[:prefix["records"]]:
                encoded = canonical(entry)
                size += len(encoded.encode())
                head = digest(head + "." + encoded)
            # Both known layouts retain the same logical chain. A v1 admission
            # pin therefore survives the transactional v1-to-v2 migration.
            _require(prefix["schema_sha256"] in {_digest(_expected_schema(1)), _digest(_expected_schema(2))}
                     and head == prefix["head_sha256"] and size == prefix["bytes"],
                     "context_admission_prefix_changed")
    _require(_stamp(path) == before, "context_changed_during_inspection")
    return pin, before


def inspect(directory, *, allow_missing=False):
    """Validate without writes; only source inspection may admit logical absence."""
    try:
        _require(type(allow_missing) is bool, "context_missing_mode_invalid")
        path = Path(directory) / NAME
        if allow_missing and _stamp(path) is None:
            return {"format": 1, "schema_sha256": _digest(_expected_schema()),
                    "records": 0, "bytes": 0, "head_sha256": ZERO_HASH}
        return _read(path)[0]
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, IndexError, zlib.error) as exc:
        raise ContextStoreUnavailable("context_recovery_inspection_failed") from exc


def capture(source_dir, target_dir, *, timeout=15):
    """Copy a stable source, or materialize an empty store only in the destination."""
    source, target = Path(source_dir) / NAME, Path(target_dir) / NAME
    try:
        _require(type(timeout) in {int, float} and 0 < timeout <= 3600, "context_backup_timeout")
        _require(source.resolve() != target.resolve(), "context_snapshot_source_is_target")
        _require(_stamp(target) is None, "fresh_context_snapshot_required")
        _require(target.parent.is_dir(), "context_snapshot_directory_missing")
        started = time.monotonic()
        before = _stamp(source)
        initial = _read(source)[0] if before is not None else None

        def progress(_status, _remaining, _total):
            _require(time.monotonic() - started <= timeout, "context_backup_deadline")

        progress(0, 0, 0)
        if before is None:
            BehaviorContextStore(target)
        else:
            with (closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as connection,
                  closing(sqlite3.connect(target)) as destination):
                destination.execute("PRAGMA synchronous=FULL")
                connection.backup(destination, pages=256, progress=progress, sleep=.05)
        copied = inspect(target.parent)
        after = _stamp(source)
        _require(before == after, "context_changed_during_snapshot")
        if before is not None:
            _require(initial == copied == inspect(source.parent), "context_changed_during_snapshot")
        else:
            _require(copied["records"] == copied["bytes"] == 0 and copied["head_sha256"] == ZERO_HASH,
                     "context_empty_snapshot_invalid")
        progress(0, 0, 0)
        return copied
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, IndexError, zlib.error) as exc:
        raise ContextStoreUnavailable("context_recovery_snapshot_failed") from exc


def verify_prefix(directory, pin):
    """Require an intact admitted prefix while allowing valid append-only growth."""
    try:
        _require(isinstance(pin, dict) and set(pin) == PIN_FIELDS
                 and type(pin["format"]) is int and pin["format"] == 1
                 and type(pin["records"]) is int and 0 <= pin["records"] <= MAX_RECORDS
                 and type(pin["bytes"]) is int and 0 <= pin["bytes"] <= MAX_TOTAL_BYTES
                 and all(isinstance(pin[key], str) and HASH.fullmatch(pin[key])
                         for key in ("schema_sha256", "head_sha256")), "context_admission_pin_invalid")
        return _read(Path(directory) / NAME, prefix=pin)[0]
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, IndexError, zlib.error) as exc:
        raise ContextStoreUnavailable("context_recovery_admission_failed") from exc
