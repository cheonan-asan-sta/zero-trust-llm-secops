"""Bounded SQLite journal tail and immutable compressed prefix segments.

Every read reconstructs and verifies the original complete hash chain. Archiving
does not summarize policy state, erase history, promise secure deletion or protect
against a privileged writer restoring the whole database. Segment plaintext is
limited to 16 MiB; combined archive plaintext and active payloads to 128 MiB.
"""

import hashlib
import hmac
import json
import re
import sqlite3
import zlib
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

ZERO_HASH = "0" * 64
MAX_ENTRY_BYTES = 1024 * 1024
MAX_SEGMENT_BYTES = 16 * 1024 * 1024
MAX_COMPRESSED_BYTES = MAX_SEGMENT_BYTES + 65536
MAX_TOTAL_BYTES = 128 * 1024 * 1024
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_TABLES = {"journal", "journal_archive_segments", "journal_storage_metadata"}
_KINDS = {"decision", "observation", "access"}
_LIMIT_MAX = {"max_active_records": 100000, "archive_batch_size": 100000,
              "max_archive_records": 1000000, "max_archive_segments": 10000}


class JournalUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class JournalLimits:
    max_active_records: int = 10000
    archive_batch_size: int = 5000
    max_archive_records: int = 100000
    max_archive_segments: int = 1000

    def __post_init__(self):
        for name, value in asdict(self).items():
            if (type(value) is not int or value < (0 if name == "max_archive_records" else 1)
                    or value > _LIMIT_MAX[name]):
                raise ValueError("journal limits require bounded positive integers")


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _row(row, sequence, previous):
    if not isinstance(row, (list, tuple)) or len(row) != 4:
        raise ValueError("journal row invalid")
    seq, payload, prior, digest = row
    if (type(seq) is not int or seq != sequence or not isinstance(payload, str)
            or len(payload.encode("utf-8")) > MAX_ENTRY_BYTES
            or not _hash(prior) or not _hash(digest) or prior != previous
            or not hmac.compare_digest(digest, _digest(prior + "." + payload))):
        raise ValueError("journal chain integrity failed")
    entry = json.loads(payload)
    if (not isinstance(entry, dict) or entry.get("kind") not in _KINDS
            or _canonical(entry) != payload):
        raise ValueError("journal entry invalid")
    return entry


class JournalTransaction(list):
    """Legacy [connection, logical entries, terminal hash], plus storage counters."""

    def __init__(self, connection, entries, metadata, active_rows, limits):
        super().__init__([connection, entries, metadata["last_hash"]])
        self.metadata = metadata
        self.active_rows = active_rows
        self.limits = limits

    @property
    def active_records(self):
        return self.metadata["active_records"]

    @property
    def archived_records(self):
        return self.metadata["archive_records"]

    @property
    def archive_segments(self):
        return self.metadata["archive_segments"]


def _initial_metadata(rows):
    return {"version": 2, "archive_records": 0, "archive_segments": 0, "archive_bytes": 0,
            "archived_last_seq": 0, "archived_last_hash": ZERO_HASH,
            "active_records": len(rows), "active_bytes": sum(len(row[1].encode("utf-8")) for row in rows),
            "last_seq": len(rows), "last_hash": rows[-1][3] if rows else ZERO_HASH}


def _save(connection, metadata):
    payload = _canonical(metadata)
    connection.execute("UPDATE journal_storage_metadata SET metadata_json=?,metadata_digest=? WHERE id=1",
                       (payload, _digest(payload)))


def _segment_header(number, rows, raw):
    return {"segment_no": number, "start_seq": rows[0][0], "end_seq": rows[-1][0],
            "prior_hash": rows[0][2], "terminal_hash": rows[-1][3],
            "record_count": len(rows), "uncompressed_size": len(raw)}


def _segment_digest(header, compressed):
    return _digest(_canonical(header | {"payload_sha256": hashlib.sha256(compressed).hexdigest()}))


def _decompress(compressed, size):
    if (not isinstance(compressed, bytes) or len(compressed) > MAX_COMPRESSED_BYTES
            or type(size) is not int or not 1 <= size <= MAX_SEGMENT_BYTES):
        raise ValueError("journal archive size invalid")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, size + 1)
    if len(raw) != size or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
        raise ValueError("journal archive compression invalid")
    return raw


def _load(connection, limits):
    if connection.execute("PRAGMA user_version").fetchone()[0] != 2:
        raise ValueError("journal format version invalid")
    stored = connection.execute("SELECT * FROM journal_storage_metadata").fetchall()
    if len(stored) != 1 or stored[0][0] != 1:
        raise ValueError("journal storage checkpoint missing")
    payload, digest = stored[0][1:]
    if (not isinstance(payload, str) or len(payload.encode()) > MAX_ENTRY_BYTES
            or not _hash(digest) or not hmac.compare_digest(_digest(payload), digest)):
        raise ValueError("journal storage checkpoint integrity failed")
    metadata = json.loads(payload)
    fields = set(_initial_metadata([]))
    if not isinstance(metadata, dict) or set(metadata) != fields or _canonical(metadata) != payload:
        raise ValueError("journal storage checkpoint invalid")
    for field in fields - {"last_hash", "archived_last_hash"}:
        if type(metadata[field]) is not int or metadata[field] < 0:
            raise ValueError("journal storage counters invalid")
    if metadata["version"] != 2 or not _hash(metadata["last_hash"]) or not _hash(metadata["archived_last_hash"]):
        raise ValueError("journal storage anchors invalid")
    if (metadata["active_records"] > limits.max_active_records
            or metadata["archive_records"] > limits.max_archive_records
            or metadata["archive_segments"] > limits.max_archive_segments):
        raise ValueError("journal retained records exceed configured limits")
    if metadata["archive_bytes"] + metadata["active_bytes"] > MAX_TOTAL_BYTES:
        raise ValueError("journal aggregate size exceeded")
    count, byte_count, largest = connection.execute(
        "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0),"
        "coalesce(max(length(CAST(payload AS BLOB))),0) FROM journal"
    ).fetchone()
    segment_count = connection.execute("SELECT count(*) FROM journal_archive_segments").fetchone()[0]
    if (count != metadata["active_records"] or byte_count != metadata["active_bytes"]
            or largest > MAX_ENTRY_BYTES or segment_count != metadata["archive_segments"]):
        raise ValueError("journal physical counts or bytes changed")
    # Read BLOB lengths before loading a possibly corrupt oversized BLOB into RAM.
    segments = connection.execute(
        "SELECT segment_no,start_seq,end_seq,prior_hash,terminal_hash,record_count,"
        "uncompressed_size,length(payload),segment_digest FROM journal_archive_segments ORDER BY segment_no"
    ).fetchall()
    if len(segments) != metadata["archive_segments"]:
        raise ValueError("journal archive segment count changed")
    entries, sequence, previous, archive_bytes = [], 0, ZERO_HASH, 0
    for number, segment in enumerate(segments, 1):
        header = dict(zip(("segment_no", "start_seq", "end_seq", "prior_hash", "terminal_hash",
                           "record_count", "uncompressed_size"), segment[:7], strict=True))
        if (header["segment_no"] != number or type(header["start_seq"]) is not int
                or type(header["end_seq"]) is not int or type(header["record_count"]) is not int
                or header["record_count"] < 1 or header["start_seq"] != sequence + 1
                or header["end_seq"] != sequence + header["record_count"]
                or not _hash(header["prior_hash"]) or header["prior_hash"] != previous
                or not _hash(header["terminal_hash"]) or not _hash(segment[8])
                or type(segment[7]) is not int or not 1 <= segment[7] <= MAX_COMPRESSED_BYTES
                or type(header["uncompressed_size"]) is not int
                or not 1 <= header["uncompressed_size"] <= MAX_SEGMENT_BYTES):
            raise ValueError("journal archive header invalid")
        archive_bytes += header["uncompressed_size"]
        if archive_bytes + metadata["active_bytes"] > MAX_TOTAL_BYTES:
            raise ValueError("journal aggregate archive size exceeded")
        compressed = connection.execute("SELECT payload FROM journal_archive_segments WHERE segment_no=?",
                                        (number,)).fetchone()[0]
        if not hmac.compare_digest(_segment_digest(header, compressed), segment[8]):
            raise ValueError("journal archive integrity failed")
        raw = _decompress(compressed, header["uncompressed_size"])
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) != header["record_count"] or _canonical(rows).encode() != raw:
            raise ValueError("journal archive rows invalid")
        for row in rows:
            entries.append(_row(row, sequence + 1, previous))
            sequence, previous = row[0], row[3]
        if previous != header["terminal_hash"]:
            raise ValueError("journal archive terminal hash changed")
    if (sequence != metadata["archive_records"] or sequence != metadata["archived_last_seq"]
            or previous != metadata["archived_last_hash"] or archive_bytes != metadata["archive_bytes"]):
        raise ValueError("journal archive checkpoint changed")
    active_rows, active_bytes = [], 0
    for row in connection.execute("SELECT seq,payload,previous_hash,record_hash FROM journal ORDER BY seq"):
        entries.append(_row(row, sequence + 1, previous))
        active_bytes += len(row[1].encode("utf-8"))
        if archive_bytes + active_bytes > MAX_TOTAL_BYTES:
            raise ValueError("journal aggregate size exceeded")
        active_rows.append(row)
        sequence, previous = row[0], row[3]
    if (len(active_rows) != metadata["active_records"] or active_bytes != metadata["active_bytes"]
            or sequence != metadata["last_seq"] or previous != metadata["last_hash"]):
        raise ValueError("journal active checkpoint changed")
    return JournalTransaction(connection, entries, metadata, active_rows, limits)


def initialize(path: Path, limits: JournalLimits) -> None:
    connection = None
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=5)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables & (_TABLES - {"journal"}):
                raise ValueError("unmarked journal archive tables exist")
            connection.execute("CREATE TABLE IF NOT EXISTS journal (seq INTEGER PRIMARY KEY,"
                               "payload TEXT NOT NULL,previous_hash TEXT NOT NULL,record_hash TEXT NOT NULL)")
            count, byte_count, largest = connection.execute(
                "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0),"
                "coalesce(max(length(CAST(payload AS BLOB))),0) FROM journal"
            ).fetchone()
            if count > min(10000, limits.max_active_records) or byte_count > MAX_TOTAL_BYTES or largest > MAX_ENTRY_BYTES:
                raise ValueError("legacy journal capacity exceeded")
            rows = connection.execute("SELECT seq,payload,previous_hash,record_hash FROM journal ORDER BY seq").fetchall()
            previous = ZERO_HASH
            for sequence, row in enumerate(rows, 1):
                _row(row, sequence, previous)
                previous = row[3]
            metadata = _initial_metadata(rows)
            if metadata["active_bytes"] > MAX_TOTAL_BYTES:
                raise ValueError("legacy journal aggregate size exceeded")
            connection.execute("CREATE TABLE journal_storage_metadata (id INTEGER PRIMARY KEY CHECK(id=1),"
                               "metadata_json TEXT NOT NULL,metadata_digest TEXT NOT NULL)")
            connection.execute("CREATE TABLE journal_archive_segments (segment_no INTEGER PRIMARY KEY,"
                               "start_seq INTEGER NOT NULL UNIQUE,end_seq INTEGER NOT NULL UNIQUE,"
                               "prior_hash TEXT NOT NULL,terminal_hash TEXT NOT NULL,record_count INTEGER NOT NULL,"
                               "uncompressed_size INTEGER NOT NULL,payload BLOB NOT NULL,segment_digest TEXT NOT NULL)")
            serialized = _canonical(metadata)
            connection.execute("INSERT INTO journal_storage_metadata VALUES (1,?,?)", (serialized, _digest(serialized)))
            connection.execute("PRAGMA user_version=2")
        elif version != 2:
            raise ValueError("unsupported journal format version")
        _load(connection, limits)
        connection.commit()
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, OverflowError, zlib.error) as exc:
        if connection is not None:
            connection.rollback()
        raise JournalUnavailable("policy journal unavailable") from exc
    finally:
        if connection is not None:
            connection.close()


@contextmanager
def transaction(path: Path, limits: JournalLimits):
    connection = None
    try:
        connection = sqlite3.connect(path, timeout=5)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        try:
            txn = _load(connection, limits)
        except (ValueError, TypeError, KeyError, OverflowError, zlib.error) as exc:
            raise JournalUnavailable("policy journal unavailable") from exc
        yield txn
        connection.commit()
    except (sqlite3.Error, OSError) as exc:
        if connection is not None:
            connection.rollback()
        raise JournalUnavailable("policy journal unavailable") from exc
    except BaseException:
        if connection is not None:
            connection.rollback()
        raise
    finally:
        if connection is not None:
            connection.close()


def _archive(txn, requested, *, required=1, reserve_bytes=0):
    meta, limits = txn.metadata, txn.limits
    available = limits.max_archive_records - meta["archive_records"]
    segment_slots = limits.max_archive_segments - meta["archive_segments"]
    if available < required or segment_slots < 1:
        raise JournalUnavailable("policy journal archive capacity reached")
    selected = txn.active_rows[:min(requested, available)]
    groups, rows, chunks, size = [], [], [], 2
    for row in selected:
        chunk = _canonical(row).encode("utf-8")
        if len(chunk) + 2 > MAX_SEGMENT_BYTES:
            raise JournalUnavailable("policy journal archive row too large")
        if size + len(chunk) + bool(chunks) > MAX_SEGMENT_BYTES:
            groups.append((rows, b"[" + b",".join(chunks) + b"]"))
            rows, chunks, size = [], [], 2
        rows.append(row)
        chunks.append(chunk)
        size += len(chunk) + (len(chunks) > 1)
    if rows:
        groups.append((rows, b"[" + b",".join(chunks) + b"]"))
    groups = groups[:segment_slots]
    moved = sum(len(rows) for rows, _ in groups)
    if moved < required:
        raise JournalUnavailable("policy journal archive capacity reached")
    removed_bytes = sum(len(row[1].encode("utf-8")) for rows, _ in groups for row in rows)
    added_bytes = sum(len(raw) for _, raw in groups)
    if meta["archive_bytes"] + meta["active_bytes"] - removed_bytes + added_bytes + reserve_bytes > MAX_TOTAL_BYTES:
        raise JournalUnavailable("policy journal byte capacity reached")
    # All bounds are checked before the first archive insertion or active deletion.
    planned = []
    for offset, (rows, raw) in enumerate(groups, 1):
        header = _segment_header(meta["archive_segments"] + offset, rows, raw)
        compressed = zlib.compress(raw)
        if len(compressed) > MAX_COMPRESSED_BYTES:
            raise JournalUnavailable("policy journal compressed capacity reached")
        planned.append((header, compressed, _segment_digest(header, compressed)))
    for header, compressed, digest in planned:
        txn[0].execute("INSERT INTO journal_archive_segments VALUES (?,?,?,?,?,?,?,?,?)", (
            header["segment_no"], header["start_seq"], header["end_seq"], header["prior_hash"],
            header["terminal_hash"], header["record_count"], header["uncompressed_size"], compressed, digest))
    last = txn.active_rows[moved - 1]
    txn[0].execute("DELETE FROM journal WHERE seq<=?", (last[0],))
    meta.update(archive_records=meta["archive_records"] + moved,
                archive_segments=meta["archive_segments"] + len(planned),
                archive_bytes=meta["archive_bytes"] + added_bytes,
                archived_last_seq=last[0], archived_last_hash=last[3],
                active_records=meta["active_records"] - moved,
                active_bytes=meta["active_bytes"] - removed_bytes)
    txn.active_rows = txn.active_rows[moved:]
    _save(txn[0], meta)
    return moved, len(planned)


def _ensure_capacity(txn, additional, reserve_bytes=0):
    if type(additional) is not int or additional < 0 or additional > txn.limits.max_active_records:
        raise JournalUnavailable("policy journal batch capacity reached")
    required = txn.active_records + additional - txn.limits.max_active_records
    if required > 0:
        _archive(txn, max(required, txn.limits.archive_batch_size), required=required, reserve_bytes=reserve_bytes)
    elif txn.metadata["archive_bytes"] + txn.metadata["active_bytes"] + reserve_bytes > MAX_TOTAL_BYTES:
        raise JournalUnavailable("policy journal byte capacity reached")


def ensure_capacity(txn: JournalTransaction, additional: int) -> None:
    _ensure_capacity(txn, additional)


def append(txn: JournalTransaction, entry: dict) -> None:
    try:
        if not isinstance(entry, dict):
            raise TypeError("journal entry must be an object")
        payload = _canonical(entry)
        size = len(payload.encode("utf-8"))
        if size > MAX_ENTRY_BYTES:
            raise ValueError("journal entry too large")
    except (ValueError, TypeError, OverflowError) as exc:
        raise JournalUnavailable("policy journal entry invalid") from exc
    _ensure_capacity(txn, 1, size)
    meta = txn.metadata
    digest = _digest(txn[2] + "." + payload)
    row = (meta["last_seq"] + 1, payload, txn[2], digest)
    txn[0].execute("INSERT INTO journal VALUES (?,?,?,?)", row)
    txn.active_rows.append(row)
    txn[1].append(json.loads(payload))
    txn[2] = digest
    meta.update(active_records=meta["active_records"] + 1, active_bytes=meta["active_bytes"] + size,
                last_seq=row[0], last_hash=digest)
    _save(txn[0], meta)


def status(txn: JournalTransaction) -> dict:
    meta = txn.metadata
    return {"active_records": meta["active_records"], "archived_records": meta["archive_records"],
            "archive_segments": meta["archive_segments"], "total_records": len(txn[1]),
            **asdict(txn.limits), "active_bytes": meta["active_bytes"], "archive_bytes": meta["archive_bytes"],
            "max_entry_bytes": MAX_ENTRY_BYTES, "max_segment_bytes": MAX_SEGMENT_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES}


def compact(txn: JournalTransaction, limit: int | None = None) -> dict:
    if limit is None:
        limit = txn.limits.archive_batch_size
    if type(limit) is not int or limit < 1:
        raise JournalUnavailable("policy journal archive batch invalid")
    moved, segments = _archive(txn, limit) if txn.active_records else (0, 0)
    return status(txn) | {"compacted": moved, "segments_created": segments}
