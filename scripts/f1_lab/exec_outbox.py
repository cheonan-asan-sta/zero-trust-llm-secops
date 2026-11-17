"""Bounded sealed-outbox inventory, independent recovery copy and safe pruning.

These are trusted local operator operations, never access grants or command
retries. A published byte-identical copy AND a pinned isolated restore are
required before a sealed outbox file is eligible for removal.
"""

import os
import re
import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.capture_archive import MAX_BYTES, MAX_RECORDS, ArchiveScope, CaptureArchive, sha
from scripts.f1_lab.capture_backup import (
    MAX_DATABASE,
    CaptureBackup,
    pinned,
    private_directory,
    private_file,
    reader,
)
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import MAX_CAPTURE
from scripts.f1_lab.managed_exec_capture import ManagedExecCapture, capture_parts, verify_managed
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.web_verified_context import Window

RECORD = re.compile(r"^([a-f0-9]{32})\.json$")


def distinct(*paths):
    paths = [Path(p).resolve() for p in paths]
    require(
        all(
            a != b and a not in b.parents and b not in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ),
        "outbox_path_overlap",
    )


def bounded_entries(path, limit=MAX_RECORDS):
    entries = []
    with os.scandir(path) as iterator:
        for count, entry in enumerate(iterator, 1):
            require(count <= limit + 1, "outbox_scan_capacity")
            if entry.name == ".capture-store.lock":
                continue
            match = RECORD.fullmatch(entry.name)
            require(
                match is not None
                and not entry.is_symlink()
                and entry.is_file(follow_symlinks=False),
                "outbox_inventory",
            )
            entries.append((match[1], Path(entry.path)))
    require(len(entries) <= limit, "outbox_record_capacity")
    return sorted(entries)


def iter_inventory(outbox, scope):
    """Caller holds the outbox lock. Preserve original bytes even if expired."""
    scope = ArchiveScope.model_validate(scope.model_dump())
    total = 0
    for rid, path in bounded_entries(outbox):
        raw = private_file(path, MAX_CAPTURE)
        capture = ManagedExecCapture.model_validate(decode(raw))
        event, proof = capture_parts(capture.model_dump(mode="json"))
        require(
            capture.request.request_id == rid
            and (event.tenant_id, event.server_id, event.unit, proof.source_id)
            == (scope.tenant_id, scope.server_id, scope.unit, scope.source_id),
            "outbox_record_scope",
        )
        total += len(raw)
        require(total <= MAX_BYTES, "outbox_total_bytes")
        yield rid, raw, capture


def inventory(outbox, scope):
    return list(iter_inventory(outbox, scope))


def publication_states(root, scope, records, *, cold=None):
    """Caller holds the live store lock; no latest refresh or cold rehydration."""
    if cold is None:
        cold = cold_records(root, scope)
    states = {}
    for rid, raw, _ in records:
        expected = sha(raw)
        if rid in cold:
            require(cold[rid]["raw_sha"] == expected, "outbox_cold_collision")
        directory = root / rid
        hot = False
        if directory.exists() or directory.is_symlink():
            private_directory(directory)
            capture = directory / "capture.json"
            if capture.exists() or capture.is_symlink():
                require(private_file(capture, MAX_CAPTURE) == raw, "outbox_hot_collision")
                hot = True
        states[rid] = hot or rid in cold
    return states


def cold_records(root, scope):
    archive = CaptureArchive(root, scope)
    if archive.path.exists() or archive.path.is_symlink():
        info = archive.path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and not archive.path.is_symlink()
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= MAX_DATABASE,
            "outbox_private_cold_database",
        )
        with reader(path=archive.path) as con:
            records, _, _, _ = archive.load(con)
            return records
    return {}


def inspect_outbox(outbox, root, scope, service_pin, caller_pin, *, now=None):
    now = datetime.now(UTC) if now is None else now
    Window.aware(now)
    outbox, root = private_directory(outbox), private_directory(root)
    distinct(outbox, root)
    with capture_store_lock(outbox), capture_store_lock(root):
        deadline = time.monotonic() + 15
        service, caller = service_pin.current(now), caller_pin.current(now)
        cold = cold_records(root, scope)
        count, total, published_count, pending_count, oldest = 0, 0, 0, 0, None
        for rid, raw, capture in iter_inventory(outbox, scope):
            require(time.monotonic() < deadline, "outbox_inspection_deadline")
            verify_managed(capture, service_pin, caller_pin, now=now)
            published = publication_states(root, scope, [(rid, raw, capture)], cold=cold)[rid]
            count += 1
            total += len(raw)
            published_count += int(published)
            pending_count += int(not published)
            if not published:
                oldest = min(oldest, capture.sealed_at) if oldest else capture.sealed_at
        checked_at = now + timedelta(seconds=max(0, 15 + time.monotonic() - deadline))
        require(
            time.monotonic() < deadline and service_pin.current(checked_at) == service,
            "outbox_current_service_or_deadline",
        )
        require(caller_pin.current(checked_at) == caller, "outbox_current_caller")
        return {
            "records": count,
            "raw_bytes": total,
            "published": published_count,
            "pending": pending_count,
            "oldest_pending_at": oldest,
        }


def snapshot_outbox(outbox, root, scope, mirror):
    """Lossless mirror of ALL sealed records, including newest and unpublished.

    Feed its cold DB to the existing checkpoint/AESGCM/isolated restore engine.
    No fake latest event is inserted to defeat the ordinary compactor's guard.
    The local mirror is plaintext private recovery staging, not remote storage.
    """
    outbox, root = private_directory(outbox), private_directory(root)
    mirror = Path(mirror)
    require(
        mirror.is_absolute() and not mirror.exists() and not mirror.is_symlink(),
        "outbox_mirror_fresh",
    )
    private_directory(mirror.parent)
    distinct(outbox, root, mirror)
    with capture_store_lock(outbox):
        mirror.mkdir(mode=0o700)
        result = CaptureArchive(mirror, scope).preserve(
            (rid, raw) for rid, raw, _ in iter_inventory(outbox, scope)
        )
    return {**result, "includes_newest_and_pending": True, "automatic_activation_allowed": False}


def prune_outbox(
    outbox,
    root,
    scope,
    review,
    receipt_sha256,
    checkpoint,
    checkpoint_sha256,
    *,
    now=None,
    min_age_seconds=86400,
    limit=64,
    apply=False,
):
    now = datetime.now(UTC) if now is None else now
    Window.aware(now)
    require(
        type(min_age_seconds) is int
        and 60 <= min_age_seconds <= 2592000
        and type(limit) is int
        and 1 <= limit <= 256
        and type(apply) is bool,
        "outbox_cleanup_policy",
    )
    outbox, root, review = [private_directory(p) for p in (outbox, root, review)]
    distinct(outbox, root, review, checkpoint)
    manager = CaptureBackup(scope)
    verified = manager.verify(review, receipt_sha256, checkpoint, checkpoint_sha256)
    receipt = decode(pinned(review / "restore.json", receipt_sha256, 16384))
    recovered = CaptureArchive(review / "review", scope)
    with capture_store_lock(outbox), capture_store_lock(root), capture_store_lock(recovered.root):
        # verify() owns this same lock internally; do not recursively reacquire
        # flock through another fd. Rebind its immutable reviewed bytes while
        # holding the cooperative lock and load the checked copy in memory.
        raw_database = private_file(recovered.path, MAX_DATABASE)
        require(sha(raw_database) == receipt["database_sha256"], "outbox_review_changed")
        manager.checkpoint_file(checkpoint, checkpoint_sha256)
        with reader(raw=raw_database) as con:
            backed, _, _, head = recovered.load(con)
        require(
            head == verified["head"] and len(backed) == verified["records"],
            "outbox_review_snapshot_changed",
        )
        cold = cold_records(root, scope)
        eligible, eligible_count, pending_count = [], 0, 0
        for rid, raw, capture in iter_inventory(outbox, scope):
            published = publication_states(root, scope, [(rid, raw, capture)], cold=cold)[rid]
            pending_count += int(not published)
            if (
                published
                and rid in backed
                and backed[rid]["raw_sha"] == sha(raw)
                and capture.sealed_at + timedelta(seconds=min_age_seconds) <= now
            ):
                eligible_count += 1
                if len(eligible) < limit:
                    eligible.append((rid, raw))
        deleted = 0
        if apply:
            directory_fd = os.open(outbox, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for rid, raw in eligible[:limit]:
                    name = rid + ".json"
                    fd = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
                    )
                    with os.fdopen(fd, "rb") as stream:
                        before = os.fstat(stream.fileno())
                        require(
                            stat.S_ISREG(before.st_mode)
                            and before.st_nlink == 1
                            and before.st_uid == os.geteuid()
                            and stat.S_IMODE(before.st_mode) == 0o600
                            and before.st_size == len(raw)
                            and stream.read(MAX_CAPTURE + 1) == raw,
                            "outbox_cleanup_changed",
                        )
                        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        require(
                            (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                            == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                            "outbox_cleanup_replaced",
                        )
                    os.unlink(name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    deleted += 1
            finally:
                os.close(directory_fd)
    return {
        "completed": True,
        "applied": apply,
        "eligible": eligible_count,
        "deleted": deleted,
        "pending_preserved": pending_count,
        "automatic_execution_allowed": False,
    }
