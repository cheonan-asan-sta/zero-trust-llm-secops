"""Lossless bounded capture archive, followed by recoverable hot-file cleanup.

This preserves bytes, not current trust. Historical signatures/timestamps are
never renewed. A restored capture still requires the normal trust/freshness
checks. Local digests detect corruption, not a privileged database rewrite.
"""

import hashlib
import os
import re
import sqlite3
import stat
import tempfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import Field

from app.models import StrictModel
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import MAX_CAPTURE, atomic_capture
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_evidence import ServiceEvent, ServiceProof, Unit, digest
from scripts.f1_lab.web_verified_context import Identifier

MAX_RECORDS = 10000
MAX_BYTES = 1024**3
MAX_SCAN = 10000
ZERO = "0" * 64
RUN = re.compile(r"^[a-f0-9]{32}$")


class ArchiveFull(ValueError):
    pass


class ArchiveScope(StrictModel):
    tenant_id: Identifier
    server_id: Identifier
    unit: Unit
    source_id: Identifier


class ArchivePolicy(StrictModel):
    max_hot_records: int = Field(default=100, strict=True, ge=1, le=MAX_RECORDS)
    max_hot_bytes: int = Field(default=16 * 1024**2, strict=True, ge=1, le=MAX_BYTES)
    max_records: int = Field(default=MAX_RECORDS, strict=True, ge=1, le=MAX_RECORDS)
    max_raw_bytes: int = Field(default=256 * 1024**2, strict=True, ge=1, le=MAX_BYTES)
    batch_size: int = Field(default=64, strict=True, ge=1, le=256)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_capture(path):
    require(not Path(path).is_symlink(), "archive_capture_link")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= MAX_CAPTURE,
            "archive_capture_file",
        )
        raw = stream.read(MAX_CAPTURE + 1)
        after = os.fstat(stream.fileno())
        require(
            len(raw) == before.st_size
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "archive_capture_changed",
        )
        return raw


@dataclass(frozen=True)
class HotCapture:
    run_id: str
    raw_sha256: str
    event_sha256: str
    observed_at: datetime
    raw_bytes: int


class CaptureArchive:
    def __init__(self, root, scope, *, policy=None):
        root = Path(root)
        require(root.is_absolute() and root.is_dir() and not root.is_symlink(), "archive_root")
        self.root = root.resolve(strict=True)
        self.scope = ArchiveScope.model_validate(scope.model_dump())
        self.policy = ArchivePolicy.model_validate((policy or ArchivePolicy()).model_dump())
        self.path = self.root / "archive.sqlite3"
        self.latest = self.root / "latest.json"

    def shape(self, raw):
        """Structural scope checks only; archival is not signature re-attestation."""
        payload = decode(raw)
        require(
            type(payload) is dict
            and set(payload) == {"schema", "event", "runtime_proof", "authorization_proof_included"}
            and payload["schema"] == "zt-service-capture-1"
            and payload["authorization_proof_included"] is False,
            "archive_capture_envelope",
        )
        event = ServiceEvent.model_validate(payload["event"])
        proof = ServiceProof.model_validate(payload["runtime_proof"])
        require(
            (event.tenant_id, event.server_id, event.unit, event.mode)
            == (self.scope.tenant_id, self.scope.server_id, self.scope.unit, "systemd")
            and (proof.tenant_id, proof.source_id, proof.observation.kind)
            == (self.scope.tenant_id, self.scope.source_id, "runtime")
            and proof.event_sha256 == event.sha256
            and proof.observation.pid == event.process_id,
            "archive_capture_scope",
        )
        return event

    def snapshot(self):
        latest_raw = raw_capture(self.latest)
        latest_event = self.shape(latest_raw)
        items, skipped = [], 0
        with os.scandir(self.root) as entries:
            for count, entry in enumerate(entries, 1):
                require(count <= MAX_SCAN, "archive_scan_capacity")
                if entry.name in {
                    "latest.json",
                    ".capture-store.lock",
                    "archive.sqlite3",
                    "archive.sqlite3-journal",
                }:
                    continue
                if not RUN.fullmatch(entry.name):
                    skipped += 1
                    continue
                try:
                    directory = Path(entry.path)
                    require(
                        entry.is_dir(follow_symlinks=False) and not entry.is_symlink(),
                        "archive_directory",
                    )
                    if set(os.listdir(directory)) != {"capture.json"}:
                        skipped += 1
                        continue
                    raw = raw_capture(directory / "capture.json")
                    event = self.shape(raw)
                    items.append(
                        HotCapture(entry.name, sha(raw), event.sha256, event.observed_at, len(raw))
                    )
                except (ValueError, OSError, RecursionError):
                    skipped += 1
        require(any(i.raw_sha256 == sha(latest_raw) for i in items), "archive_latest_hot_missing")
        require(raw_capture(self.latest) == latest_raw, "archive_latest_changed")
        return items, latest_raw, latest_event.sha256, skipped

    @staticmethod
    def chain(head, row):
        return digest([head, *row])

    @staticmethod
    def unpack(payload, size, expected):
        require(
            type(payload) is bytes
            and 0 < len(payload) <= MAX_CAPTURE + 1024
            and type(size) is int
            and 0 < size <= MAX_CAPTURE,
            "archive_compressed_bound",
        )
        decoder = zlib.decompressobj()
        raw = decoder.decompress(payload, size + 1)
        require(
            len(raw) == size
            and decoder.eof
            and not decoder.unused_data
            and not decoder.unconsumed_tail
            and sha(raw) == expected,
            "archive_decompression_or_hash",
        )
        return raw

    def load(self, con):
        headers = con.execute(
            "SELECT scope,records,raw_bytes,head FROM archive_head WHERE id=1"
        ).fetchall()
        require(len(headers) == 1, "archive_header")
        binding, count, total, expected = headers[0]
        require(
            binding == canonical(self.scope.model_dump(mode="json")).decode()
            and type(count) is int
            and 0 <= count <= MAX_RECORDS
            and type(total) is int
            and 0 <= total <= MAX_BYTES,
            "archive_header_binding",
        )
        records, raw_total, compressed_total, head = {}, 0, 0, ZERO
        for ordinal, row in enumerate(
            con.execute(
                "SELECT seq,run_id,raw_sha,event_sha,raw_bytes,payload,packed_sha,cleaned FROM captures ORDER BY seq"
            ),
            1,
        ):
            seq, rid, raw_sha, event_sha, size, payload, packed_sha, cleaned = row
            require(
                ordinal <= MAX_RECORDS
                and seq == ordinal
                and type(rid) is str
                and RUN.fullmatch(rid)
                and rid not in records
                and cleaned in (0, 1)
                and type(payload) is bytes
                and sha(payload) == packed_sha,
                "archive_record",
            )
            raw = self.unpack(payload, size, raw_sha)
            require(self.shape(raw).sha256 == event_sha, "archive_record_event")
            raw_total += size
            compressed_total += len(payload)
            require(raw_total <= MAX_BYTES, "archive_raw_capacity")
            head = self.chain(head, [seq, rid, raw_sha, event_sha, size, packed_sha])
            records[rid] = {
                "raw_sha": raw_sha,
                "event_sha": event_sha,
                "raw_bytes": size,
                "cleaned": cleaned,
            }
        require(
            len(records) == count and raw_total == total and head == expected, "archive_checkpoint"
        )
        return records, raw_total, compressed_total, head

    def database(self):
        require(self.path.is_file() and not self.path.is_symlink(), "archive_database_file")
        info = self.path.stat()
        require(
            info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1,
            "archive_database_owner",
        )
        con = sqlite3.connect(self.path, timeout=5)
        con.execute("PRAGMA synchronous=FULL")
        return con

    def initialize(self):
        if self.path.exists() or self.path.is_symlink():
            return
        fd, name = tempfile.mkstemp(prefix=".capture-archive-init-", dir=self.root)
        os.close(fd)
        try:
            con = sqlite3.connect(name, timeout=5)
            try:
                con.execute("PRAGMA synchronous=FULL")
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "CREATE TABLE archive_head (id INTEGER PRIMARY KEY CHECK(id=1),scope TEXT NOT NULL,records INTEGER NOT NULL,raw_bytes INTEGER NOT NULL,head TEXT NOT NULL)"
                )
                con.execute(
                    "CREATE TABLE captures (seq INTEGER PRIMARY KEY,run_id TEXT NOT NULL UNIQUE,raw_sha TEXT NOT NULL,event_sha TEXT NOT NULL,raw_bytes INTEGER NOT NULL,payload BLOB NOT NULL,packed_sha TEXT NOT NULL,cleaned INTEGER NOT NULL CHECK(cleaned IN (0,1)))"
                )
                con.execute(
                    "INSERT INTO archive_head VALUES (1,?,0,0,?)",
                    (canonical(self.scope.model_dump(mode="json")).decode(), ZERO),
                )
                con.commit()
            finally:
                con.close()
            require(not self.path.exists() and not self.path.is_symlink(), "archive_database_race")
            os.replace(name, self.path)
            self.sync_directory(self.root)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @staticmethod
    def sync_directory(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def connection(self):
        con = self.database()
        try:
            yield con
        finally:
            con.close()

    @staticmethod
    def commit_archive(con):
        con.commit()

    def after_archive_commit(self):
        """Crash boundary after durable byte preservation, before hot cleanup."""

    def after_unlink(self):
        """Crash boundary: payload exists in archive, directory may remain empty."""

    def remove_hot(self, rid, expected_sha):
        require(RUN.fullmatch(rid), "archive_cleanup_identifier")
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                directory_fd = os.open(
                    rid, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
                )
            except FileNotFoundError:
                return 0
            try:
                names = os.listdir(directory_fd)
                if names:
                    require(names == ["capture.json"], "archive_cleanup_extra_file")
                    fd = os.open(
                        "capture.json",
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=directory_fd,
                    )
                    with os.fdopen(fd, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        require(
                            stat.S_ISREG(info.st_mode)
                            and info.st_nlink == 1
                            and 0 < info.st_size <= MAX_CAPTURE,
                            "archive_cleanup_file",
                        )
                        raw = stream.read(MAX_CAPTURE + 1)
                        require(
                            sha(raw) == expected_sha and len(raw) == info.st_size,
                            "archive_cleanup_content_changed",
                        )
                        current = os.stat(
                            "capture.json", dir_fd=directory_fd, follow_symlinks=False
                        )
                        require(
                            (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns),
                            "archive_cleanup_replaced",
                        )
                    os.unlink("capture.json", dir_fd=directory_fd)
                    self.sync_directory(self.root / rid)
                    self.after_unlink()
                os.rmdir(rid, dir_fd=root_fd)
                os.fsync(root_fd)
                return int(bool(names))
            finally:
                os.close(directory_fd)
        finally:
            os.close(root_fd)

    def finish_pending(self, con, latest_raw):
        latest_event = self.shape(latest_raw).sha256
        deleted = 0
        for rid, raw_sha, event_sha, size, payload in con.execute(
            "SELECT run_id,raw_sha,event_sha,raw_bytes,payload FROM captures WHERE cleaned=0 ORDER BY seq LIMIT ?",
            (self.policy.batch_size,),
        ).fetchall():
            require(raw_capture(self.latest) == latest_raw, "archive_latest_changed")
            if event_sha == latest_event:
                continue
            self.unpack(
                payload, size, raw_sha
            )  # Read back committed bytes before removing a hot file.
            deleted += self.remove_hot(rid, raw_sha)
            con.execute("UPDATE captures SET cleaned=1 WHERE run_id=?", (rid,))
            con.commit()
        return deleted

    def compact(self, *, apply=False):
        require(type(apply) is bool, "archive_apply_flag")
        with capture_store_lock(self.root):
            items, latest_raw, latest_event, skipped = self.snapshot()
            records, total, compressed, head = {}, 0, 0, ZERO
            if self.path.exists() or self.path.is_symlink():
                with self.connection() as con:
                    records, total, compressed, head = self.load(con)
            protected = {i.run_id for i in items if i.event_sha256 == latest_event}
            protected.add(max(items, key=lambda i: (i.observed_at, i.run_id)).run_id)
            count, size = len(items), sum(i.raw_bytes for i in items)
            selected = []
            for item in sorted(items, key=lambda i: (i.observed_at, i.run_id)):
                if count <= self.policy.max_hot_records and size <= self.policy.max_hot_bytes:
                    break
                if item.run_id not in protected and len(selected) < self.policy.batch_size:
                    selected.append(item)
                    count -= 1
                    size -= item.raw_bytes
            new = [i for i in selected if i.run_id not in records]
            for item in selected:
                require(
                    item.run_id not in records
                    or records[item.run_id]["raw_sha"] == item.raw_sha256,
                    "archive_run_id_conflict",
                )
            capacity = (
                len(records) + len(new) <= self.policy.max_records
                and total + sum(i.raw_bytes for i in new) <= self.policy.max_raw_bytes
            )
            result = {
                "completed": True,
                "applied": apply,
                "hot_before_records": len(items),
                "hot_before_bytes": sum(i.raw_bytes for i in items),
                "planned": len(selected),
                "deleted_hot_files": 0,
                "archive_records": len(records),
                "archive_raw_bytes": total,
                "archive_compressed_payload_bytes": compressed,
                "skipped_entries": skipped,
                "archive_capacity_available": capacity,
                "latest_protected": True,
                "projected_hot_records": count,
                "projected_hot_bytes": size,
                "projected_budget_satisfied": count <= self.policy.max_hot_records
                and size <= self.policy.max_hot_bytes,
                "authenticity_or_freshness_asserted": False,
            }
            if apply:
                if not capacity:
                    raise ArchiveFull("capture_archive_capacity")
                if selected or records:
                    self.initialize()
                    with self.connection() as con:
                        try:
                            con.execute("BEGIN IMMEDIATE")
                            self.load(con)
                            for item in selected:
                                raw = raw_capture(self.root / item.run_id / "capture.json")
                                require(sha(raw) == item.raw_sha256, "archive_source_changed")
                                if item.run_id in records:
                                    con.execute(
                                        "UPDATE captures SET cleaned=0 WHERE run_id=?",
                                        (item.run_id,),
                                    )
                                    continue
                                packed = zlib.compress(raw)
                                packed_sha = sha(packed)
                                ordinal = len(records) + 1
                                con.execute(
                                    "INSERT INTO captures VALUES (?,?,?,?,?,?,?,0)",
                                    (
                                        ordinal,
                                        item.run_id,
                                        item.raw_sha256,
                                        item.event_sha256,
                                        item.raw_bytes,
                                        packed,
                                        packed_sha,
                                    ),
                                )
                                head = self.chain(
                                    head,
                                    [
                                        ordinal,
                                        item.run_id,
                                        item.raw_sha256,
                                        item.event_sha256,
                                        item.raw_bytes,
                                        packed_sha,
                                    ],
                                )
                                total += item.raw_bytes
                                records[item.run_id] = {"raw_sha": item.raw_sha256}
                            con.execute(
                                "UPDATE archive_head SET records=?,raw_bytes=?,head=? WHERE id=1",
                                (len(records), total, head),
                            )
                            self.commit_archive(con)
                        except Exception:
                            con.rollback()
                            raise
                        self.after_archive_commit()
                        self.load(con)
                        result["deleted_hot_files"] = self.finish_pending(con, latest_raw)
                        records, total, compressed, _ = self.load(con)
                        result.update(
                            archive_records=len(records),
                            archive_raw_bytes=total,
                            archive_compressed_payload_bytes=compressed,
                        )
            final, final_latest, _, _ = self.snapshot()
            require(final_latest == latest_raw, "archive_latest_changed")
            result.update(
                hot_after_records=len(final),
                hot_after_bytes=sum(i.raw_bytes for i in final),
                managed_budget_satisfied=len(final) <= self.policy.max_hot_records
                and sum(i.raw_bytes for i in final) <= self.policy.max_hot_bytes,
                archive_database_file_bytes=self.path.stat().st_size if self.path.exists() else 0,
            )
            return result

    def restore(self, run_id, output):
        require(type(run_id) is str and RUN.fullmatch(run_id), "archive_restore_identifier")
        original = Path(output)
        require(not original.is_symlink(), "archive_restore_directory_link")
        output = original.resolve()
        require(
            not output.exists()
            and not output.is_symlink()
            and output != self.root
            and self.root not in output.parents,
            "archive_restore_fresh_external_directory",
        )
        with capture_store_lock(self.root), self.connection() as con:
            records, _, _, _ = self.load(con)
            require(run_id in records, "archive_restore_missing")
            size, payload = con.execute(
                "SELECT raw_bytes,payload FROM captures WHERE run_id=?", (run_id,)
            ).fetchone()
            raw = self.unpack(payload, size, records[run_id]["raw_sha"])
            output.mkdir(mode=0o700, exist_ok=False)
            atomic_capture(output / "capture.json", raw)
            return {
                "completed": True,
                "raw_sha256": sha(raw),
                "raw_bytes": len(raw),
                "authenticity_or_freshness_asserted": False,
            }
