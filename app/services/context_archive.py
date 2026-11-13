"""Lossless SQLite prefix segments, committed together with active-tail deletion.

These checks detect damage, not privileged replacement of an entire database.
Logical history stays available to authorization, duplicate checks and recovery.
"""

import hashlib
import json
import zlib

TABLE = "behavior_context_archive"
MAX_SEGMENT_BYTES = 16 * 1024 * 1024
MAX_SEGMENTS = 10_000
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode()


def create(connection):
    connection.execute(f"CREATE TABLE {TABLE} (segment_no INTEGER PRIMARY KEY,"
                       "record_count INTEGER NOT NULL,raw_bytes INTEGER NOT NULL,"
                       "payload BLOB NOT NULL,sha256 TEXT NOT NULL)")


def checksum(number, count, size, payload):
    return hashlib.sha256(encode([number, count, size]) + payload).hexdigest()


def read(connection):
    segments = connection.execute(
        f"SELECT segment_no,record_count,raw_bytes,length(payload),sha256 FROM {TABLE} ORDER BY segment_no",
    ).fetchall()
    if len(segments) > MAX_SEGMENTS:
        raise ValueError("context archive segment limit")
    total = 0
    for expected, (number, count, size, compressed_size, sha) in enumerate(segments, 1):
        if (number != expected or type(count) is not int or not 1 <= count <= 10_000
                or type(size) is not int or not 1 <= size <= MAX_SEGMENT_BYTES
                or type(compressed_size) is not int or not 1 <= compressed_size <= MAX_SEGMENT_BYTES + 65536):
            raise ValueError("context archive bounds invalid")
        total += size
        if total > MAX_ARCHIVE_BYTES:
            raise ValueError("context aggregate archive bound")
        payload = connection.execute(f"SELECT payload FROM {TABLE} WHERE segment_no=?", (number,)).fetchone()[0]
        if not isinstance(payload, bytes) or checksum(number, count, size, payload) != sha:
            raise ValueError("context archive checksum invalid")
        decoder = zlib.decompressobj()
        raw = decoder.decompress(payload, size + 1)
        if len(raw) != size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError("context archive compression invalid")
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) != count or encode(rows) != raw:
            raise ValueError("context archive records invalid")
        yield from rows


def compact(connection, limit):
    rows = connection.execute("SELECT * FROM behavior_context_entries ORDER BY seq LIMIT ?", (limit,)).fetchall()
    if not rows:
        return 0
    batch, size = [], 2
    for row in rows:
        cost = len(encode(row)) + 1
        if size + cost > MAX_SEGMENT_BYTES:
            break
        batch.append(row)
        size += cost
    if not batch:
        raise ValueError("context archive entry too large")
    count, total = connection.execute(f"SELECT COUNT(*),COALESCE(SUM(raw_bytes),0) FROM {TABLE}").fetchone()
    raw = encode(batch)
    if count >= MAX_SEGMENTS or total + len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("context archive capacity reached")
    payload = zlib.compress(raw)
    connection.execute(f"INSERT INTO {TABLE} VALUES (?,?,?,?,?)",
                       (count + 1, len(batch), len(raw), payload,
                        checksum(count + 1, len(batch), len(raw), payload)))
    connection.execute("DELETE FROM behavior_context_entries WHERE seq<=?", (batch[-1][0],))
    return len(batch)
