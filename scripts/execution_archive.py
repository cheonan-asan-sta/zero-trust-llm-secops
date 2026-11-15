"""Bounded, lossless terminal delivery history in the collector's SQLite transaction."""

import hashlib
import json
import zlib

MAX_RECORDS = 100_000
MAX_BYTES = 256 * 1024 * 1024
MAX_ITEM_BYTES = 4 * 1024 * 1024
ZERO = "0" * 64


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode()


def initialize(connection):
    connection.execute("CREATE TABLE IF NOT EXISTS execution_archive ("
                       "ordinal INTEGER PRIMARY KEY,evidence_id TEXT NOT NULL UNIQUE,"
                       "raw_bytes INTEGER NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL)")
    connection.execute("CREATE TABLE IF NOT EXISTS execution_archive_head ("
                       "id INTEGER PRIMARY KEY CHECK(id=1),records INTEGER NOT NULL,"
                       "raw_bytes INTEGER NOT NULL,head TEXT NOT NULL)")
    if connection.execute("SELECT COUNT(*) FROM execution_archive_head").fetchone()[0] == 0:
        connection.execute("INSERT INTO execution_archive_head VALUES (1,0,0,?)", (ZERO,))


def load(connection):
    header = connection.execute("SELECT * FROM execution_archive_head").fetchall()
    if len(header) != 1 or header[0][0] != 1:
        raise ValueError("execution archive checkpoint missing")
    expected_count, expected_size, expected_head = header[0][1:]
    if (type(expected_count) is not int or not 0 <= expected_count <= MAX_RECORDS
            or type(expected_size) is not int or not 0 <= expected_size <= MAX_BYTES):
        raise ValueError("execution archive capacity")
    count = connection.execute("SELECT COUNT(*) FROM execution_archive").fetchone()[0]
    if count != expected_count:
        raise ValueError("execution archive records missing")
    results, total, head = {}, 0, ZERO
    for expected, row in enumerate(connection.execute(
        "SELECT ordinal,evidence_id,raw_bytes,length(payload),digest FROM execution_archive ORDER BY ordinal",
    ), 1):
        ordinal, identifier, size, compressed_size, digest = row
        if (ordinal != expected or type(size) is not int or not 1 <= size <= MAX_ITEM_BYTES
                or type(compressed_size) is not int or not 1 <= compressed_size <= MAX_ITEM_BYTES + 65536):
            raise ValueError("execution archive bounds")
        total += size
        if total > MAX_BYTES:
            raise ValueError("execution archive size")
        payload = connection.execute("SELECT payload FROM execution_archive WHERE ordinal=?", (ordinal,)).fetchone()[0]
        if not isinstance(payload, bytes) or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("execution archive digest")
        try:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(payload, size + 1)
        except zlib.error as exc:
            raise ValueError("execution archive compression") from exc
        if len(raw) != size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError("execution archive compression")
        item = json.loads(raw)
        if (not isinstance(item, dict) or set(item) != {"record", "bundle", "evaluation"}
                or encode(item) != raw or item["record"]["evidence_id"] != identifier
                or item["record"]["status"] not in {"acknowledged", "rejected"}
                or identifier in results):
            raise ValueError("execution archive content")
        if item["bundle"] is not None:
            if (item["bundle"]["evidence_id"] != identifier or item["evaluation"] is None
                    or item["evaluation"]["evidence_id"] != identifier
                    or (item["record"]["status"] == "acknowledged"
                        and item["evaluation"]["status"] == "pending")):
                raise ValueError("execution archive unfinished bundle")
        elif item["evaluation"] is not None:
            raise ValueError("execution archive orphan evaluation")
        results[identifier] = item
        head = hashlib.sha256((head + "." + identifier + "." + digest).encode()).hexdigest()
    if total != expected_size or head != expected_head:
        raise ValueError("execution archive checkpoint changed")
    return results


def compact(connection, limit):
    candidates = connection.execute(
        "SELECT r.* FROM records r LEFT JOIN evaluations e USING(evidence_id) "
        "WHERE r.status='rejected' OR (r.status='acknowledged' AND "
        "(e.evidence_id IS NULL OR e.status IN ('acknowledged','rejected'))) ORDER BY r.seq LIMIT ?", (limit,),
    ).fetchall()
    count, total, head = connection.execute(
        "SELECT records,raw_bytes,head FROM execution_archive_head WHERE id=1",
    ).fetchone()
    for row in candidates:
        identifier = row["evidence_id"]
        bundle = connection.execute("SELECT * FROM bundles WHERE evidence_id=?", (identifier,)).fetchone()
        evaluation = connection.execute("SELECT * FROM evaluations WHERE evidence_id=?", (identifier,)).fetchone()
        raw = encode({"record": dict(row), "bundle": dict(bundle) if bundle else None,
                      "evaluation": dict(evaluation) if evaluation else None})
        if count >= MAX_RECORDS or len(raw) > MAX_ITEM_BYTES or total + len(raw) > MAX_BYTES:
            raise ValueError("execution archive capacity reached")
        payload = zlib.compress(raw)
        digest = hashlib.sha256(payload).hexdigest()
        count += 1
        total += len(raw)
        head = hashlib.sha256((head + "." + identifier + "." + digest).encode()).hexdigest()
        connection.execute("INSERT INTO execution_archive VALUES (?,?,?,?,?)",
                           (count, identifier, len(raw), payload, digest))
        connection.execute("DELETE FROM evaluations WHERE evidence_id=?", (identifier,))
        connection.execute("DELETE FROM bundles WHERE evidence_id=?", (identifier,))
        connection.execute("DELETE FROM records WHERE evidence_id=?", (identifier,))
    connection.execute("UPDATE execution_archive_head SET records=?,raw_bytes=?,head=? WHERE id=1",
                       (count, total, head))
    return len(candidates)
