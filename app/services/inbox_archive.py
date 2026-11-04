"""Lossless terminal receipt archives inside the inbox's own SQLite transaction.

The namespace marker is application_id, independent of the policy journal's
user_version. Checksums detect damage, not privileged whole-database rollback.
All reads remain proportional to retained logical rows; no history is discarded.
"""

import hashlib
import hmac
import json
import zlib
from collections import Counter
from dataclasses import dataclass

APPLICATION_ID = 0x5A544932
MAX_ROW_BYTES = 5 * 1024 * 1024
MAX_SEGMENT_BYTES = 16 * 1024 * 1024
MAX_COMPRESSED_BYTES = MAX_SEGMENT_BYTES + 65536
MAX_TOTAL_BYTES = 128 * 1024 * 1024
ZERO_HASH = "0" * 64
FIELDS = ("tenant_id", "event_id", "payload", "input_digest", "payload_digest", "submitted_by",
          "received_at", "state", "attempts", "next_attempt_at", "lease_token", "lease_expires_at",
          "completed_at", "result_json", "last_error")
TABLES = {"signal_inbox", "signal_inbox_format", "signal_inbox_archive_metadata", "signal_inbox_archive_segments"}


class ArchiveFull(RuntimeError):
    pass


@dataclass(frozen=True)
class ArchiveLimits:
    max_records: int
    max_records_per_tenant: int
    archive_batch_size: int = 5000
    max_archive_records: int = 100000
    max_archive_segments: int = 1000
    max_archive_records_per_tenant: int = 100000

    def __post_init__(self):
        bounds = {"max_records": 100000, "max_records_per_tenant": 100000,
                  "archive_batch_size": 100000, "max_archive_records": 1000000,
                  "max_archive_segments": 10000, "max_archive_records_per_tenant": 1000000}
        for name, maximum in bounds.items():
            value = getattr(self, name)
            minimum = 0 if name in {"max_archive_records", "max_archive_records_per_tenant"} else 1
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("inbox archive limits invalid")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _ordered(rows):
    return sorted(rows, key=lambda row: (row["received_at"], row["tenant_id"], row["event_id"]))


def _fingerprint(rows):
    checksum = hashlib.sha256(b"[")
    size = 0
    for index, row in enumerate(rows):
        raw = canonical(row).encode("utf-8")
        if len(raw) > MAX_ROW_BYTES:
            raise ValueError("inbox row size invalid")
        checksum.update(b"," if index else b"")
        checksum.update(raw)
        size += len(raw)
    checksum.update(b"]")
    return checksum.hexdigest(), size


def _validated(row, validator):
    if not isinstance(row, dict) or set(row) != set(FIELDS):
        raise ValueError("inbox row fields invalid")
    validator(row)
    if len(canonical(row).encode("utf-8")) > MAX_ROW_BYTES:
        raise ValueError("inbox row size invalid")
    return row


def _active(connection, validator):
    return [_validated(dict(row), validator) for row in connection.execute(
        "SELECT * FROM signal_inbox ORDER BY received_at,tenant_id,event_id")]


def _physical_active(connection):
    sizes = "+".join(f"coalesce(length(CAST({field} AS BLOB)),0)" for field in FIELDS)
    return connection.execute(
        "SELECT count(*),coalesce(max(length(CAST(payload AS BLOB))),0),"
        "coalesce(max(length(CAST(result_json AS BLOB))),0),coalesce(sum(" + sizes + "),0) FROM signal_inbox"
    ).fetchone()


def _metadata(connection):
    if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
        raise ValueError("inbox namespace marker invalid")
    marker = connection.execute("SELECT id,version FROM signal_inbox_format").fetchall()
    if len(marker) != 1 or tuple(marker[0]) != (1, 2):
        raise ValueError("inbox format marker invalid")
    stored = connection.execute("SELECT * FROM signal_inbox_archive_metadata").fetchall()
    if len(stored) != 1 or stored[0]["id"] != 1:
        raise ValueError("inbox checkpoint missing")
    raw, checksum = stored[0]["metadata_json"], stored[0]["metadata_digest"]
    if not isinstance(raw, str) or len(raw.encode()) > 4096 or not _hash(checksum) or not hmac.compare_digest(digest(raw), checksum):
        raise ValueError("inbox checkpoint integrity failed")
    meta = json.loads(raw)
    fields = {"version", "active_records", "archived_records", "archive_segments", "active_bytes",
              "archive_bytes", "active_digest", "archive_digest"}
    if not isinstance(meta, dict) or set(meta) != fields or canonical(meta) != raw:
        raise ValueError("inbox checkpoint invalid")
    for field in fields - {"active_digest", "archive_digest"}:
        if type(meta[field]) is not int or meta[field] < 0:
            raise ValueError("inbox checkpoint count invalid")
    if meta["version"] != 2 or not _hash(meta["active_digest"]) or not _hash(meta["archive_digest"]):
        raise ValueError("inbox checkpoint anchor invalid")
    return meta


def _save(connection, meta):
    raw = canonical(meta)
    connection.execute("UPDATE signal_inbox_archive_metadata SET metadata_json=?,metadata_digest=? WHERE id=1",
                       (raw, digest(raw)))


def _check_limits(meta, active, archived, limits):
    if (meta["active_records"] > limits.max_records or meta["archived_records"] > limits.max_archive_records
            or meta["archive_segments"] > limits.max_archive_segments
            or meta["active_bytes"] + meta["archive_bytes"] > MAX_TOTAL_BYTES
            or any(count > limits.max_records_per_tenant for count in Counter(row["tenant_id"] for row in active).values())
            or any(count > limits.max_archive_records_per_tenant for count in Counter(row["tenant_id"] for row in archived).values())):
        raise ValueError("inbox retained data exceeds configured limits")


def _segment_digest(number, count, raw_size, prior, blob):
    return digest(canonical({"segment_no": number, "record_count": count, "uncompressed_size": raw_size,
                             "prior_hash": prior, "payload_sha256": hashlib.sha256(blob).hexdigest()}))


def _decode(blob, size):
    if not isinstance(blob, bytes) or len(blob) > MAX_COMPRESSED_BYTES or type(size) is not int or not 1 <= size <= MAX_SEGMENT_BYTES:
        raise ValueError("inbox archive size invalid")
    decoder = zlib.decompressobj()
    try:
        raw = decoder.decompress(blob, size + 1)
    except zlib.error as exc:
        raise ValueError("inbox archive compressed format invalid") from exc
    if len(raw) != size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("inbox archive compressed data invalid")
    return raw


@dataclass
class ArchiveState:
    metadata: dict
    active: list[dict]
    archived: list[dict]

    @property
    def rows(self):
        return _ordered(self.active + self.archived)


def read(connection, validator, limits):
    meta = _metadata(connection)
    if (meta["active_records"] > limits.max_records or meta["archived_records"] > limits.max_archive_records
            or meta["archive_segments"] > limits.max_archive_segments
            or meta["active_bytes"] + meta["archive_bytes"] > MAX_TOTAL_BYTES):
        raise ValueError("inbox checkpoint exceeds configured limits")
    active_count, payload_max, result_max, text_bytes = _physical_active(connection)
    segment_count = connection.execute("SELECT count(*) FROM signal_inbox_archive_segments").fetchone()[0]
    if (active_count != meta["active_records"] or payload_max > 1048576 or result_max > 1048576
            or text_bytes > meta["active_bytes"] or segment_count != meta["archive_segments"]):
        raise ValueError("inbox physical counts or sizes changed")
    archived, raw_bytes, previous = [], 0, ZERO_HASH
    for expected, header in enumerate(connection.execute(
        "SELECT segment_no,record_count,uncompressed_size,prior_hash,length(payload) AS compressed_size,"
        "segment_digest FROM signal_inbox_archive_segments ORDER BY segment_no").fetchall(), 1):
        number = header["segment_no"]
        if (type(number) is not int or number != expected
                or type(header["record_count"]) is not int or header["record_count"] < 1
                or type(header["uncompressed_size"]) is not int or not 1 <= header["uncompressed_size"] <= MAX_SEGMENT_BYTES
                or type(header["compressed_size"]) is not int or not 1 <= header["compressed_size"] <= MAX_COMPRESSED_BYTES
                or header["prior_hash"] != previous or not _hash(header["segment_digest"])):
            raise ValueError("inbox archive header invalid")
        raw_bytes += header["uncompressed_size"]
        if raw_bytes + meta["active_bytes"] > MAX_TOTAL_BYTES or len(archived) + header["record_count"] > limits.max_archive_records:
            raise ValueError("inbox archive aggregate limit exceeded")
        blob = connection.execute("SELECT payload FROM signal_inbox_archive_segments WHERE segment_no=?", (number,)).fetchone()[0]
        actual = _segment_digest(number, header["record_count"], header["uncompressed_size"], previous, blob)
        if not hmac.compare_digest(actual, header["segment_digest"]):
            raise ValueError("inbox archive integrity failed")
        raw = _decode(blob, header["uncompressed_size"])
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) != header["record_count"] or canonical(rows).encode() != raw:
            raise ValueError("inbox archive rows invalid")
        for row in rows:
            _validated(row, validator)
            if row["state"] not in {"completed", "failed"}:
                raise ValueError("active receipt in inbox archive")
        archived.extend(rows)
        previous = actual
    active = _active(connection, validator)
    active_digest, active_bytes = _fingerprint(active)
    identities = [(row["tenant_id"], row["event_id"]) for row in active + archived]
    if (len(set(identities)) != len(identities) or len(archived) != meta["archived_records"]
            or previous != meta["archive_digest"] or raw_bytes != meta["archive_bytes"]
            or active_digest != meta["active_digest"] or active_bytes != meta["active_bytes"]):
        raise ValueError("inbox archive checkpoint changed")
    _check_limits(meta, active, archived, limits)
    return ArchiveState(meta, active, archived)


def initialize(connection, validator, limits):
    marker = connection.execute("PRAGMA application_id").fetchone()[0]
    if marker == 0:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables & (TABLES - {"signal_inbox"}):
            raise ValueError("unmarked inbox archive tables exist")
        connection.execute("CREATE TABLE IF NOT EXISTS signal_inbox (tenant_id TEXT NOT NULL,event_id TEXT NOT NULL,"
                           "payload TEXT NOT NULL,input_digest TEXT NOT NULL,payload_digest TEXT NOT NULL,"
                           "submitted_by TEXT NOT NULL,received_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN "
                           "('pending','processing','completed','failed')),attempts INTEGER NOT NULL CHECK(attempts>=0),"
                           "next_attempt_at TEXT,lease_token TEXT,lease_expires_at TEXT,completed_at TEXT,"
                           "result_json TEXT,last_error TEXT,PRIMARY KEY(tenant_id,event_id))")
        count, payload_max, result_max, text_bytes = _physical_active(connection)
        if count > limits.max_records or payload_max > 1048576 or result_max > 1048576 or text_bytes > MAX_TOTAL_BYTES:
            raise ValueError("legacy inbox exceeds active limit")
        rows = _active(connection, validator)
        checksum, size = _fingerprint(rows)
        meta = {"version": 2, "active_records": len(rows), "archived_records": 0, "archive_segments": 0,
                "active_bytes": size, "archive_bytes": 0, "active_digest": checksum, "archive_digest": ZERO_HASH}
        _check_limits(meta, rows, [], limits)
        connection.execute("CREATE TABLE signal_inbox_format (id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL)")
        connection.execute("INSERT INTO signal_inbox_format VALUES (1,2)")
        connection.execute("CREATE TABLE signal_inbox_archive_metadata (id INTEGER PRIMARY KEY CHECK(id=1),"
                           "metadata_json TEXT NOT NULL,metadata_digest TEXT NOT NULL)")
        connection.execute("CREATE TABLE signal_inbox_archive_segments (segment_no INTEGER PRIMARY KEY,"
                           "record_count INTEGER NOT NULL,uncompressed_size INTEGER NOT NULL,prior_hash TEXT NOT NULL,"
                           "payload BLOB NOT NULL,segment_digest TEXT NOT NULL)")
        raw = canonical(meta)
        connection.execute("INSERT INTO signal_inbox_archive_metadata VALUES (1,?,?)", (raw, digest(raw)))
        connection.execute("CREATE INDEX IF NOT EXISTS signal_inbox_delivery ON signal_inbox(state,next_attempt_at,received_at)")
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
    elif marker != APPLICATION_ID:
        raise ValueError("foreign inbox namespace marker")
    return read(connection, validator, limits)


def refresh(connection, validator, limits, *, added=0):
    """Checkpoint an already validated transaction's known active-row mutation."""
    if type(added) is not int or added < 0:
        raise ValueError("inbox count delta invalid")
    meta = _metadata(connection)
    active = _active(connection, validator)
    if len(active) != meta["active_records"] + added:
        raise ValueError("unexpected inbox row count mutation")
    checksum, size = _fingerprint(active)
    if len(active) > limits.max_records:
        raise ArchiveFull("inbox active storage capacity reached")
    if size + meta["archive_bytes"] > MAX_TOTAL_BYTES:
        if added:
            raise ArchiveFull("inbox active byte capacity reached")
        # Claim/completion failures are storage failures, preserving the existing
        # worker retry boundary rather than raising an intake-only 429 error.
        raise ValueError("inbox mutable row byte capacity reached")
    if any(count > limits.max_records_per_tenant for count in Counter(row["tenant_id"] for row in active).values()):
        raise ArchiveFull("inbox tenant active storage capacity reached")
    meta.update(active_records=len(active), active_bytes=size, active_digest=checksum)
    _save(connection, meta)


def status(state, limits):
    meta = state.metadata
    return {"active_records": meta["active_records"], "archived_records": meta["archived_records"],
            "archive_segments": meta["archive_segments"], "total_records": meta["active_records"] + meta["archived_records"],
            "max_records": limits.max_records, "archive_batch_size": limits.archive_batch_size,
            "max_archive_records": limits.max_archive_records, "max_archive_segments": limits.max_archive_segments,
            "max_archive_records_per_tenant": limits.max_archive_records_per_tenant,
            "active_bytes": meta["active_bytes"], "archive_bytes": meta["archive_bytes"],
            "max_row_bytes": MAX_ROW_BYTES, "max_segment_bytes": MAX_SEGMENT_BYTES, "max_total_bytes": MAX_TOTAL_BYTES}


def compact(connection, validator, limits, *, limit=None, tenant_id=None, reserve_bytes=0):
    limit = limits.archive_batch_size if limit is None else limit
    if type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError("inbox archive batch invalid")
    state = read(connection, validator, limits)
    meta = state.metadata
    eligible = [row for row in state.active if row["state"] in {"completed", "failed"}
                and (tenant_id is None or row["tenant_id"] == tenant_id)]
    if not eligible:
        return status(state, limits) | {"compacted": 0, "segments_created": 0}
    available = limits.max_archive_records - len(state.archived)
    slots = limits.max_archive_segments - meta["archive_segments"]
    if available <= 0 or slots <= 0:
        raise ArchiveFull("inbox archive capacity reached")
    tenant_counts = Counter(row["tenant_id"] for row in state.archived)
    selected = []
    for row in eligible:
        if tenant_counts[row["tenant_id"]] >= limits.max_archive_records_per_tenant:
            continue
        selected.append(row)
        tenant_counts[row["tenant_id"]] += 1
        if len(selected) >= min(limit, available):
            break
    if not selected:
        raise ArchiveFull("inbox tenant archive capacity reached")
    groups, rows, chunks, size = [], [], [], 2
    for row in selected:
        chunk = canonical(row).encode()
        if len(chunk) + 2 > MAX_SEGMENT_BYTES:
            raise ArchiveFull("inbox archive row capacity reached")
        if size + len(chunk) + bool(chunks) > MAX_SEGMENT_BYTES:
            groups.append((rows, b"[" + b",".join(chunks) + b"]"))
            rows, chunks, size = [], [], 2
        rows.append(row)
        chunks.append(chunk)
        size += len(chunk) + (len(chunks) > 1)
    if rows:
        groups.append((rows, b"[" + b",".join(chunks) + b"]"))
    groups = groups[:slots]
    moved = [row for rows, _ in groups for row in rows]
    keys = {(row["tenant_id"], row["event_id"]) for row in moved}
    remaining = [row for row in state.active if (row["tenant_id"], row["event_id"]) not in keys]
    checksum, active_bytes = _fingerprint(remaining)
    archive_bytes = meta["archive_bytes"] + sum(len(raw) for _, raw in groups)
    if archive_bytes + active_bytes + reserve_bytes > MAX_TOTAL_BYTES:
        raise ArchiveFull("inbox archive byte capacity reached")
    planned, previous = [], meta["archive_digest"]
    for offset, (rows, raw) in enumerate(groups, 1):
        number = meta["archive_segments"] + offset
        blob = zlib.compress(raw)
        if len(blob) > MAX_COMPRESSED_BYTES:
            raise ArchiveFull("inbox compressed capacity reached")
        current = _segment_digest(number, len(rows), len(raw), previous, blob)
        planned.append((number, len(rows), len(raw), previous, blob, current))
        previous = current
    for row in planned:
        connection.execute("INSERT INTO signal_inbox_archive_segments VALUES (?,?,?,?,?,?)", row)
    for key in sorted(keys):
        connection.execute("DELETE FROM signal_inbox WHERE tenant_id=? AND event_id=?", key)
    meta.update(active_records=len(remaining), archived_records=meta["archived_records"] + len(moved),
                archive_segments=meta["archive_segments"] + len(planned), active_bytes=active_bytes,
                archive_bytes=archive_bytes, active_digest=checksum, archive_digest=previous)
    _save(connection, meta)
    state = read(connection, validator, limits)
    return status(state, limits) | {"compacted": len(moved), "segments_created": len(planned)}


def ensure_capacity(connection, validator, limits, tenant_id, incoming_bytes):
    state = read(connection, validator, limits)
    tenant_count = sum(row["tenant_id"] == tenant_id for row in state.active)
    if len(state.active) >= limits.max_records or tenant_count >= limits.max_records_per_tenant:
        compact(connection, validator, limits, tenant_id=tenant_id if tenant_count >= limits.max_records_per_tenant else None,
                reserve_bytes=incoming_bytes)
        state = read(connection, validator, limits)
        if len(state.active) >= limits.max_records or sum(row["tenant_id"] == tenant_id for row in state.active) >= limits.max_records_per_tenant:
            raise ArchiveFull("inbox active capacity reached")
    if state.metadata["active_bytes"] + state.metadata["archive_bytes"] + incoming_bytes > MAX_TOTAL_BYTES:
        raise ArchiveFull("inbox byte capacity reached")
