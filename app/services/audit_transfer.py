"""Explicit fresh-destination audit migration; original files are never edited."""

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path

from app.models import AnalysisResult
from app.services.audit import _record_hash
from app.services.sqlite_audit import SQLiteAuditStore


class AuditTransferError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AuditTransferError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs)


@contextmanager
def fresh_stage(destination):
    destination = Path(destination).absolute()
    require(
        destination.parent.is_dir() and not destination.exists() and not destination.is_symlink(),
        "destination must be a new file in an existing directory",
    )
    with tempfile.TemporaryDirectory(
        prefix=".audit-transfer-", dir=destination.parent
    ) as temporary:
        yield Path(temporary) / "staged", destination


def publish(stage, destination):
    with stage.open("r+b") as stream:
        os.fsync(stream.fileno())
    # An exclusive same-filesystem link cannot replace a live or newly-created file.
    os.link(stage, destination)
    if os.name == "posix":
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def scan_jsonl(base_path, *, allow_legacy=False):
    base = Path(base_path).absolute()
    paths = sorted(base.parent.glob(f"{base.stem}.worker-*{base.suffix}"))
    if base.exists():
        paths.append(base)
        paths.sort()
    require(0 < len(paths) <= 128, "source inventory empty or too large")
    inventory, records, raw_files, total, hashed, legacy = [], [], {}, 0, 0, 0
    for path in paths:
        require(path.is_file() and not path.is_symlink(), "source must be a regular file")
        with path.open("rb") as stream:
            raw = stream.read(128 * 1024 * 1024 - total + 1)
        total += len(raw)
        require(total <= 128 * 1024 * 1024, "source byte capacity exceeded")
        inventory.append({"name": path.name, "bytes": len(raw), "sha256": sha(raw)})
        raw_files[path.name] = raw
        previous = "0" * 64
        for line in raw.splitlines():
            if not line.strip():
                continue
            require(len(line) <= 2 * 1024 * 1024, "source row too large")
            value = decode(line)
            require(type(value) is dict, "source row must be a JSON object")
            if value.get("schema_version") == 1:
                require(
                    set(value) == {"schema_version", "payload", "previous_hash", "record_hash"},
                    "unknown audit envelope fields",
                )
                payload = value["payload"]
                require(
                    type(payload) is str
                    and value["previous_hash"] == previous
                    and value["record_hash"] == _record_hash(previous, payload),
                    "source audit chain failed",
                )
                previous = value["record_hash"]
                record = AnalysisResult.model_validate(decode(payload))
                hashed += 1
            else:
                require(allow_legacy, "unhashed legacy record requires explicit opt-in")
                record = AnalysisResult.model_validate(value)
                legacy += 1
            records.append(record)
            require(len(records) <= SQLiteAuditStore.MAX_ROWS, "source row capacity exceeded")
    manifest = base.with_name(base.name + ".shards.sqlite3")
    checkpoints = []
    if manifest.exists():
        require(not manifest.is_symlink(), "source manifest link rejected")
        con = sqlite3.connect(manifest.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            checkpoints = con.execute(
                "SELECT name,size,digest FROM shards ORDER BY name"
            ).fetchall()
            require(len(checkpoints) <= 128, "source manifest too large")
            for name, size, digest in checkpoints:
                require(
                    name in raw_files
                    and type(size) is int
                    and 0 <= size <= len(raw_files[name])
                    and sha(raw_files[name][:size]) == digest,
                    "source manifest checkpoint failed",
                )
        finally:
            con.close()
    fingerprint = sha(canonical({"files": inventory, "checkpoints": checkpoints}))
    ordered = sorted(
        records, key=lambda r: (r.analyzed_at, r.analysis_id, r.review_updated_at or r.analyzed_at)
    )
    return ordered, {
        "inventory_sha256": fingerprint,
        "files": inventory,
        "hashed_rows": hashed,
        "legacy_rows": legacy,
        "input_rows": len(records),
    }


def migrate_jsonl(base_path, destination, expected_inventory_sha256, *, allow_legacy=False):
    records, inventory = scan_jsonl(base_path, allow_legacy=allow_legacy)
    require(
        inventory["inventory_sha256"] == expected_inventory_sha256, "source inventory pin mismatch"
    )
    with fresh_stage(destination) as (stage, target):
        store = SQLiteAuditStore(stage)
        with store._transaction(write=True) as con:
            known, seq, previous, size = store._read(con)
            for record in records:
                old = known.get(record.analysis_id)
                if old == record:
                    continue
                require(
                    (old is None and record.review_updated_at is None)
                    or (old is not None and store._review_fits(old, record)),
                    "source review history incomplete, conflicting, or invalid",
                )
                payload = record.model_dump_json()
                size += len(payload.encode())
                require(size <= store.MAX_BYTES, "destination payload capacity exceeded")
                digest = _record_hash(previous, payload)
                seq += 1
                con.execute(
                    "INSERT INTO audit_entries VALUES (?,?,?,?)", (seq, previous, digest, payload)
                )
                previous, known[record.analysis_id] = digest, record
            con.execute("UPDATE audit_head SET seq=?,digest=? WHERE id=1", (seq, previous))
            store._read(con, retain_records=False)
        _, current = scan_jsonl(base_path, allow_legacy=allow_legacy)
        require(current == inventory, "source changed during migration")
        publish(stage, target)
        return {
            **inventory,
            "imported_rows": seq,
            "distinct_analyses": len(known),
            "head_sha256": previous,
            "automatic_activation_allowed": False,
        }
