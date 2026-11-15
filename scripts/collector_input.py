"""Cooperating JSONL writers and recoverable, fully captured input rotation.

The caller owns feed_lock while capturing or rotating. Writers reopen the active
path under that same lock; retaining a descriptor across rotation is unsupported.
The sealed file is removed only after its complete checkpoint is in SQLite.
"""

import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path

from app.services.collector_spool import SpoolFull

MAX_LINE = 65536
MAX_FEED = 16 * 1024 * 1024
JOURNAL = "input.rotation.json"
PREPARATION = "input.rotation.next"
_IDENTIFIER = re.compile(r"[a-f0-9]{32}\Z")
_HEX = re.compile(r"[a-f0-9]{64}\Z")


class InputBusy(BlockingIOError):
    pass


@contextmanager
def feed_lock(directory):
    """Nonblocking OS lock, distinct from the long-lived single sender lock."""
    path = Path(directory) / "input.lock"
    file = os.fdopen(os.open(path, os.O_RDWR | os.O_CREAT, 0o600), "r+b")
    locked = False
    try:
        try:
            if os.name == "nt":
                import msvcrt
                if path.stat().st_size == 0:
                    file.write(b"0")
                    file.flush()
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise InputBusy("collector input is busy") from exc
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)
        file.close()


def _sync_directory(directory):
    # Windows does not expose POSIX directory fsync through this API. File and
    # SQLite durability still apply; host/power-loss guarantees are not inferred.
    if os.name != "nt":
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("collector input must be a regular file")


def _prefix(path, checkpoint, *, complete=False):
    _regular(path)
    with path.open("rb") as file:
        size = os.fstat(file.fileno()).st_size
        if size > MAX_FEED:
            raise ValueError("collector input size limit")
        prefix = file.read(checkpoint["offset"])
    if len(prefix) != checkpoint["offset"] or not hmac.compare_digest(
        hashlib.sha256(prefix).hexdigest(), checkpoint["prefix_sha256"],
    ):
        raise ValueError("collector input prefix changed")
    if complete and (size != checkpoint["offset"] or (prefix and not prefix.endswith(b"\n"))):
        raise ValueError("collector rotation requires completely captured input")
    return prefix, size


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _read_journal(path):
    _regular(path)
    if path.stat().st_size > 4096:
        raise ValueError("collector rotation journal size")
    record = json.loads(path.read_bytes())
    if not isinstance(record, dict) or set(record) != {"rotation", "sha256"}:
        raise ValueError("collector rotation journal format")
    data = record["rotation"]
    if (not isinstance(data, dict)
            or set(data) != {"schema_version", "rotation_id", "previous", "checkpoint"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or not isinstance(data["rotation_id"], str)
            or not _IDENTIFIER.fullmatch(data["rotation_id"])
            or not isinstance(record["sha256"], str)
            or not hmac.compare_digest(hashlib.sha256(_canonical(data)).hexdigest(), record["sha256"])):
        raise ValueError("collector rotation journal integrity")
    previous, checkpoint = data["previous"], data["checkpoint"]
    if (not isinstance(previous, dict) or set(previous) != {"generation", "rotation_id"}
            or type(previous["generation"]) is not int or previous["generation"] < 0
            or (previous["rotation_id"] is not None and (
                not isinstance(previous["rotation_id"], str)
                or not _IDENTIFIER.fullmatch(previous["rotation_id"])))
            or not isinstance(checkpoint, dict) or set(checkpoint) != {"offset", "prefix_sha256"}
            or type(checkpoint["offset"]) is not int or not 0 < checkpoint["offset"] <= MAX_FEED
            or not isinstance(checkpoint["prefix_sha256"], str)
            or not _HEX.fullmatch(checkpoint["prefix_sha256"])):
        raise ValueError("collector rotation checkpoint format")
    return data


def recover_rotation(directory, spool):
    """Resume a published rotation; the caller holds feed_lock throughout."""
    directory = Path(directory)
    journal = directory / JOURNAL
    preparation = directory / PREPARATION
    active = directory / "input.jsonl"
    if not journal.exists():
        if preparation.exists():
            # A preparation has no authority to rename or reset anything.
            _prefix(active, spool.checkpoint())
            _regular(preparation)
            preparation.unlink()
            _sync_directory(directory)
        return False
    data = _read_journal(journal)
    rotation_id = data["rotation_id"]
    sealed = directory / ("input.sealed." + rotation_id + ".jsonl")
    current = spool.rotation_checkpoint()
    committed = current == {"generation": data["previous"]["generation"] + 1,
                            "rotation_id": rotation_id}
    if not committed:
        if current != data["previous"] or spool.checkpoint() != data["checkpoint"]:
            raise ValueError("collector rotation generation mismatch")
        if not sealed.exists():
            _prefix(active, data["checkpoint"], complete=True)
            os.replace(active, sealed)
            _sync_directory(directory)
        else:
            _prefix(sealed, data["checkpoint"], complete=True)
        if not active.exists():
            with os.fdopen(os.open(active, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
                file.flush()
                os.fsync(file.fileno())
            _sync_directory(directory)
        else:
            _regular(active)
            if active.stat().st_size > MAX_FEED:
                raise ValueError("collector input size limit")
        spool.rotate_input(expected_checkpoint=data["checkpoint"], rotation_id=rotation_id)
    # A crash after SQLite commit must never reset a newer active-file cursor.
    _prefix(active, spool.checkpoint())
    if sealed.exists():
        _prefix(sealed, data["checkpoint"], complete=True)
        sealed.unlink()
        _sync_directory(directory)
    journal.unlink()
    _sync_directory(directory)
    return True


def rotate_input(directory, spool):
    """Rotate only a fully captured file; pending records already live in SQLite."""
    directory = Path(directory)
    recover_rotation(directory, spool)
    checkpoint = spool.checkpoint()
    _prefix(directory / "input.jsonl", checkpoint, complete=True)
    previous = spool.rotation_checkpoint()
    if checkpoint["offset"] == 0:
        return {"rotated": False, "generation": previous["generation"]}
    if previous["generation"] >= spool.max_rotations:
        raise SpoolFull("collector rotation history capacity reached")
    data = {"schema_version": 1, "rotation_id": uuid.uuid4().hex,
            "previous": previous, "checkpoint": checkpoint}
    record = {"rotation": data, "sha256": hashlib.sha256(_canonical(data)).hexdigest()}
    preparation = directory / PREPARATION
    with os.fdopen(os.open(preparation, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
        file.write(_canonical(record))
        file.flush()
        os.fsync(file.fileno())
    os.replace(preparation, directory / JOURNAL)
    _sync_directory(directory)
    recover_rotation(directory, spool)
    return {"rotated": True, "generation": spool.rotation_checkpoint()["generation"]}


def append_event(directory, event):
    """Append one bounded event, reopening the path inside the shared feed lock.

    A busy lock, unfinished rotation, partial input tail or size limit is explicit
    backpressure. Callers retain the same event ID and retry; they never truncate.
    """
    directory = Path(directory)
    raw = json.dumps(event, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(raw) > MAX_LINE:
        raise ValueError("collector record size limit")
    with feed_lock(directory):
        if (directory / JOURNAL).exists() or (directory / PREPARATION).exists():
            raise BlockingIOError("collector rotation requires recovery")
        path = directory / "input.jsonl"
        _regular(path)
        with os.fdopen(os.open(path, os.O_RDWR | os.O_APPEND), "r+b") as file:
            size = os.fstat(file.fileno()).st_size
            if size + len(raw) > MAX_FEED:
                raise BlockingIOError("collector input capacity reached")
            if size:
                file.seek(-1, os.SEEK_END)
                if file.read(1) != b"\n":
                    raise ValueError("collector input contains partial final line")
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
    return {"appended": True}
