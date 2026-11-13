"""Bounded append-only context history in a separate, transactionally verified SQLite file.

The chain detects damaged or removed records; it is not protection against a privileged
writer replacing the entire database and its anchors. Authorization belongs to the service.
"""

import hashlib
import hmac
import json
import re
import sqlite3
import zlib
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from itertools import chain
from pathlib import Path

from app.services import context_archive as archive

ZERO_HASH = "0" * 64
MAX_ENTRY_BYTES = 1024 * 1024
MAX_ACTIVE_RECORDS = 10_000
MAX_RECORDS = 100_000
MAX_TOTAL_BYTES = 128 * 1024 * 1024
KINDS = frozenset({"capture", "baseline", "approval", "revocation", "evaluation", "execution",
                   "response_request", "response_approval", "response_cancel", "response_result"})
LEGACY_TABLES = {"behavior_context_entries", "behavior_context_head"}
TABLES = LEGACY_TABLES | {archive.TABLE}
FIELDS = {"kind", "tenant_id", "record_id", "created_at", "actor", "payload"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
TENANT = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")


class ContextStoreUnavailable(RuntimeError):
    pass


class ContextRecordConflict(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _head_digest(count, size, last_hash):
    return digest(canonical({"format": 1, "count": count, "bytes": size, "last_hash": last_hash}))


def _validate_entry(entry):
    if not isinstance(entry, dict) or set(entry) != FIELDS:
        raise ValueError("invalid context entry fields")
    if entry["kind"] not in KINDS:
        raise ValueError("invalid context entry kind")
    if not isinstance(entry["tenant_id"], str) or not TENANT.fullmatch(entry["tenant_id"]):
        raise ValueError("invalid context tenant")
    if not isinstance(entry["record_id"], str) or not IDENTIFIER.fullmatch(entry["record_id"]):
        raise ValueError("invalid context identifier")
    if (not isinstance(entry["actor"], str) or not 1 <= len(entry["actor"]) <= 256
            or not entry["actor"].strip()):
        raise ValueError("invalid context actor")
    if not isinstance(entry["payload"], dict) or not isinstance(entry["created_at"], str):
        raise TypeError("invalid context payload or timestamp")
    timestamp = datetime.fromisoformat(entry["created_at"])
    if timestamp.utcoffset() is None:
        raise ValueError("context timestamp requires timezone")
    if entry["kind"] == "revocation":
        payload = entry["payload"]
        if (payload.get("target_kind") not in {"baseline", "approval"}
                or not isinstance(payload.get("target_id"), str)
                or not IDENTIFIER.fullmatch(payload["target_id"])
                or not isinstance(payload.get("reason"), str)
                or not 3 <= len(payload["reason"]) <= 500):
            raise ValueError("invalid context revocation")
    encoded = canonical(entry)
    if len(encoded.encode("utf-8")) > MAX_ENTRY_BYTES:
        raise ValueError("context entry exceeds size limit")
    return encoded


class ContextTransaction:
    def __init__(self, connection, entries, last_hash, total_bytes, store):
        self._connection = connection
        self._entries = entries
        self._index = {(entry["kind"], entry["tenant_id"], entry["record_id"]): entry
                       for entry in entries}
        self._last_hash = last_hash
        self._total_bytes = total_bytes
        self._store = store
        self._open = True

    def _assert_open(self):
        if not self._open:
            raise ContextStoreUnavailable("context transaction is closed")

    @property
    def entries(self):
        self._assert_open()
        return deepcopy(self._entries)

    def get(self, kind, tenant_id, record_id):
        self._assert_open()
        return deepcopy(self._index.get((kind, tenant_id, record_id)))

    find = get

    def revoked(self, kind, tenant_id, record_id):
        self._assert_open()
        return any(entry["kind"] == "revocation" and entry["tenant_id"] == tenant_id
                   and entry["payload"]["target_kind"] == kind
                   and entry["payload"]["target_id"] == record_id
                   for entry in self._entries)

    def put(self, kind, tenant_id, record_id, payload, actor, now):
        self._assert_open()
        if not isinstance(now, datetime):
            raise TypeError("context timestamp requires datetime")
        entry = {"kind": kind, "tenant_id": tenant_id, "record_id": record_id,
                 "created_at": now.isoformat(), "actor": actor, "payload": deepcopy(payload)}
        encoded = _validate_entry(entry)
        existing = self._index.get((kind, tenant_id, record_id))
        if existing is not None:
            if canonical(existing["payload"]) != canonical(payload):
                raise ContextRecordConflict("context identifier reused with different content")
            return {"entry": deepcopy(existing), "duplicate": True}
        byte_count = len(encoded.encode("utf-8"))
        if (len(self._entries) >= self._store.max_records
                or self._total_bytes + byte_count > self._store.max_bytes):
            raise ContextStoreUnavailable("context history capacity reached")
        active_count = self._connection.execute("SELECT COUNT(*) FROM behavior_context_entries").fetchone()[0]
        if active_count >= self._store.max_active_records:
            try:
                archive.compact(self._connection, max(1, self._store.max_active_records // 2))
            except (ValueError, zlib.error) as exc:
                raise ContextStoreUnavailable("context archive unavailable") from exc
        sequence = len(self._entries) + 1
        current_hash = digest(self._last_hash + "." + encoded)
        self._connection.execute(
            "INSERT INTO behavior_context_entries "
            "(seq,kind,tenant_id,record_id,payload,prior_hash,digest) VALUES (?,?,?,?,?,?,?)",
            (sequence, kind, tenant_id, record_id, encoded, self._last_hash, current_hash),
        )
        total_bytes = self._total_bytes + byte_count
        self._connection.execute(
            "UPDATE behavior_context_head SET record_count=?,total_bytes=?,last_hash=?,"
            "head_digest=? WHERE id=1",
            (sequence, total_bytes, current_hash, _head_digest(sequence, total_bytes, current_hash)),
        )
        self._entries.append(entry)
        self._index[(kind, tenant_id, record_id)] = entry
        self._last_hash, self._total_bytes = current_hash, total_bytes
        return {"entry": deepcopy(entry), "duplicate": False}

    def append(self, entry):
        _validate_entry(entry)
        return self.put(entry["kind"], entry["tenant_id"], entry["record_id"], entry["payload"],
                        entry["actor"], datetime.fromisoformat(entry["created_at"]))["entry"]


class BehaviorContextStore:
    def __init__(self, path: Path, *, max_records=MAX_RECORDS, max_bytes=MAX_TOTAL_BYTES,
                 max_active_records=MAX_ACTIVE_RECORDS):
        if (type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS
                or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_TOTAL_BYTES
                or type(max_active_records) is not int or not 1 <= max_active_records <= MAX_ACTIVE_RECORDS):
            raise ValueError("context limits must be bounded positive integers")
        self.path = Path(path)
        self.max_records, self.max_bytes = max_records, max_bytes
        self.max_active_records = max_active_records
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _tables(connection):
        return {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )}

    def _initialize(self):
        connection = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            tables = self._tables(connection)
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if not tables and version == 0:
                connection.execute(
                    "CREATE TABLE behavior_context_entries ("
                    "seq INTEGER PRIMARY KEY,kind TEXT NOT NULL,tenant_id TEXT NOT NULL,"
                    "record_id TEXT NOT NULL,payload TEXT NOT NULL,prior_hash TEXT NOT NULL,"
                    "digest TEXT NOT NULL,UNIQUE(kind,tenant_id,record_id))",
                )
                connection.execute(
                    "CREATE TABLE behavior_context_head (id INTEGER PRIMARY KEY CHECK(id=1),"
                    "record_count INTEGER NOT NULL,total_bytes INTEGER NOT NULL,"
                    "last_hash TEXT NOT NULL,head_digest TEXT NOT NULL)",
                )
                connection.execute(
                    "INSERT INTO behavior_context_head VALUES (1,0,0,?,?)",
                    (ZERO_HASH, _head_digest(0, 0, ZERO_HASH)),
                )
                connection.execute("PRAGMA user_version=1")
            elif not ((tables == LEGACY_TABLES and version == 1) or (tables == TABLES and version == 2)):
                raise ValueError("incompatible context database")
            self._load(connection)
            if connection.execute("PRAGMA user_version").fetchone()[0] == 1:
                archive.create(connection)
                connection.execute("PRAGMA user_version=2")
            self._load(connection)
            # A process can die before SQLite writes a hot-journal header. A
            # read-only transaction leaves that cold rollback journal behind.
            # After validating the history, let SQLite finish its own journal
            # lifecycle without changing any committed record or checkpoint.
            if Path(str(self.path) + "-journal").exists():
                # SQLite can optimize an assignment to the same value away.
                # Both writes share this transaction and restore the validated
                # checkpoint before commit; a crash rolls both back together.
                connection.execute("UPDATE behavior_context_head SET record_count=record_count+1 WHERE id=1")
                connection.execute("UPDATE behavior_context_head SET record_count=record_count-1 WHERE id=1")
            connection.commit()
        except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, zlib.error) as exc:
            if connection is not None:
                connection.rollback()
            raise ContextStoreUnavailable("context database unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def _load(self, connection):
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = self._tables(connection)
        if not ((version == 1 and tables == LEGACY_TABLES) or (version == 2 and tables == TABLES)):
            raise ValueError("incompatible context database")
        if connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]:
            raise ValueError("unexpected context database executable schema")
        heads = connection.execute("SELECT * FROM behavior_context_head").fetchall()
        if len(heads) != 1 or len(heads[0]) != 5 or heads[0][0] != 1:
            raise ValueError("context checkpoint missing")
        _, count, total_bytes, last_hash, head_hash = heads[0]
        if (type(count) is not int or not 0 <= count <= self.max_records
                or type(total_bytes) is not int or not 0 <= total_bytes <= self.max_bytes
                or not isinstance(last_hash, str) or not HASH.fullmatch(last_hash)
                or not isinstance(head_hash, str)
                or not hmac.compare_digest(head_hash, _head_digest(count, total_bytes, last_hash))):
            raise ValueError("context checkpoint invalid")
        active_count = connection.execute("SELECT COUNT(*) FROM behavior_context_entries").fetchone()[0]
        if active_count > (MAX_ACTIVE_RECORDS if version == 1 else self.max_active_records):
            raise ValueError("context active tail exceeds limit")
        entries, prior, size = [], ZERO_HASH, 0
        identities = set()
        archived = archive.read(connection) if version == 2 else ()
        for row in chain(archived, connection.execute("SELECT * FROM behavior_context_entries ORDER BY seq")):
            if len(row) != 7:
                raise ValueError("context row shape invalid")
            seq, kind, tenant, identifier, encoded, previous, row_hash = row
            if (type(seq) is not int or seq != len(entries) + 1
                    or not isinstance(encoded, str) or len(encoded.encode()) > MAX_ENTRY_BYTES
                    or previous != prior or not isinstance(row_hash, str)
                    or not hmac.compare_digest(row_hash, digest(prior + "." + encoded))):
                raise ValueError("context hash chain invalid")
            entry = json.loads(encoded)
            if (_validate_entry(entry) != encoded
                    or (kind, tenant, identifier) != (entry["kind"], entry["tenant_id"], entry["record_id"])
                    or (kind, tenant, identifier) in identities):
                raise ValueError("context stored identity invalid")
            identities.add((kind, tenant, identifier))
            size += len(encoded.encode())
            prior = row_hash
            entries.append(entry)
        if prior != last_hash or size != total_bytes or len(entries) != count:
            raise ValueError("context terminal checkpoint invalid")
        return entries, last_hash, total_bytes

    @contextmanager
    def transaction(self):
        connection, transaction = None, None
        try:
            try:
                connection = self._connect()
                connection.execute("BEGIN IMMEDIATE")
                entries, last_hash, size = self._load(connection)
            except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, zlib.error) as exc:
                raise ContextStoreUnavailable("context database unavailable") from exc
            transaction = ContextTransaction(connection, entries, last_hash, size, self)
            yield transaction
            connection.commit()
        except (sqlite3.Error, OSError) as exc:
            if connection is not None:
                connection.rollback()
            raise ContextStoreUnavailable("context database unavailable") from exc
        except BaseException:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if transaction is not None:
                transaction._open = False
            if connection is not None:
                connection.close()

    def read(self, tenant_id):
        with self.transaction() as transaction:
            return [entry for entry in transaction.entries if entry["tenant_id"] == tenant_id]

    def storage_status(self):
        with self.transaction() as transaction:
            active = transaction._connection.execute("SELECT COUNT(*) FROM behavior_context_entries").fetchone()[0]
            segments = transaction._connection.execute(f"SELECT COUNT(*) FROM {archive.TABLE}").fetchone()[0]
            return {"active_records": active, "archived_records": len(transaction._entries) - active,
                    "total_records": len(transaction._entries), "archive_segments": segments,
                    "logical_bytes": transaction._total_bytes, "max_active_records": self.max_active_records,
                    "max_records": self.max_records, "max_bytes": self.max_bytes}

    def compact(self, *, limit=1000):
        if type(limit) is not int or not 1 <= limit <= MAX_ACTIVE_RECORDS:
            raise ValueError("context archive batch invalid")
        with self.transaction() as transaction:
            try:
                moved = archive.compact(transaction._connection, limit)
            except (ValueError, zlib.error) as exc:
                raise ContextStoreUnavailable("context archive unavailable") from exc
        return {"compacted": moved}
