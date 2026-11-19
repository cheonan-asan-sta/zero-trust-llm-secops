"""Typed encrypted observer control snapshots, never signer-key backups.

External package/profile/minimum pins remain required. Restored directories are
review candidates; source locators are preserved and no service is reconfigured.
An incomplete candidate is barred from normal observer operations.
"""

import base64
import os
import secrets
import sqlite3
import stat
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services.audit_transfer import (
    AuditTransferError,
    canonical,
    decode,
    fresh_stage,
    publish,
    require,
    sha,
)

MAGIC = b"ZTWOBS01"
SCHEMA = "local-witness-observer-backup-1"
RESTORE_SCHEMA = "local-witness-observer-restore-1"
MAX_DATABASE_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD = MAX_DATABASE_BYTES + observer.PROFILE_LIMIT + 32
MAX_HEADER = 8192
NAMES = ("profile.json", "public.key", "observer.sqlite3")


def _bytes(path, limit):
    path = Path(path)
    require(not path.is_symlink(), "observer backup file link rejected")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= limit, "observer backup file type/size rejected")
        if os.name == "posix":
            require(before.st_uid == os.geteuid() and not before.st_mode & 0o077,
                    "observer backup file ownership/permission rejected")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "observer backup file changed while reading")
    return raw


def _sync(path):
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _target(path, *, protected=()):
    path = Path(path).absolute()
    witness._directory(path.parent)
    require(all(not p.is_symlink() for p in (path, path.parent, *path.parent.parents)),
            "observer backup output link rejected")
    resolved = path.resolve()
    for item in protected:
        item = Path(item).resolve()
        require(not resolved.is_relative_to(item) and not item.is_relative_to(resolved),
                "observer backup output overlaps protected storage")
    require(not path.exists(), "observer backup destination must be fresh")
    return path


def _checked(directory, profile_pin, minimum, *, restoring=False):
    directory, profile, public = observer._load(directory, profile_pin, restoring=restoring)
    with observer._database(directory) as con:
        state = observer._read(con, profile, public, minimum)
        require(con.execute("PRAGMA quick_check").fetchall() == [("ok",)],
                "observer backup SQLite integrity rejected")
    return profile, state


def _lease(directory, profile_pin):
    # A reservation/lock is ephemeral; reconstruct the constrained profile row,
    # never a saved process owner, PID or live lock from another host.
    path = directory / "lease.sqlite3"
    observer._write(path, b"")
    con = sqlite3.connect(path)
    try:
        con.execute("CREATE TABLE lease (profile_sha256 TEXT NOT NULL)")
        con.execute("INSERT INTO lease VALUES (?)", (profile_pin,))
        con.commit()
    finally:
        con.close()
    with path.open("r+b") as stream:
        os.fsync(stream.fileno())


def _scope(state):
    return {"receipt_sha256": state["receipt_sha256"], "anchor_count": state["anchors"],
            "pending": state["pending"] is not None}


def backup(directory, profile_sha256, minimum_receipt, destination, key):
    require(type(key) is bytes and len(key) == 32, "observer backup 32-byte key required")
    directory, profile, public = observer._load(directory, profile_sha256)
    destination = _target(destination, protected=(directory, profile["witness_directory"],
                                                 profile["database"]))
    with observer._database(directory, lease=True, profile_pin=profile_sha256), fresh_stage(destination) as (stage, target):
        snapshot_dir = stage.parent / "control"
        snapshot_dir.mkdir(mode=0o700)
        for name in ("profile.json", "public.key"):
            observer._write(snapshot_dir / name, _bytes(directory / name, observer.PROFILE_LIMIT))
        snapshot = snapshot_dir / "observer.sqlite3"
        observer._write(snapshot, b"")
        deadline = time.monotonic() + 15
        with observer._database(directory) as source:
            original = observer._read(source, profile, public, minimum_receipt)
            page_size = source.execute("PRAGMA page_size").fetchone()[0]

            def progress(_status, _remaining, total):
                require(time.monotonic() < deadline and total * page_size <= MAX_DATABASE_BYTES,
                        "observer backup snapshot limit exceeded")

            dest = sqlite3.connect(snapshot)
            try:
                source.backup(dest, pages=128, progress=progress, sleep=0.05)
            finally:
                dest.close()
        copied_profile, copied = _checked(snapshot_dir, profile_sha256, minimum_receipt)
        require(copied_profile == profile and copied == original, "observer backup snapshot changed")
        created = datetime.now(UTC)
        for instant in (None if copied["receipt"] is None else copied["receipt"]["body"]["observed_at"],
                        None if copied["pending"] is None else copied["pending"]["started_at"]):
            require(instant is None or observer._time(instant) <= created, "observer backup clock regressed")
        files = []
        chunks = []
        for name in NAMES:
            raw = _bytes(snapshot_dir / name, MAX_PAYLOAD)
            files.append({"name": name, "bytes": len(raw), "sha256": sha(raw)})
            chunks.append(raw)
        payload = b"".join(chunks)
        require(0 < len(payload) <= MAX_PAYLOAD, "observer backup payload too large")
        nonce = secrets.token_bytes(12)
        header = {"schema": SCHEMA, "algorithm": "AES-256-GCM", "backup_id": secrets.token_hex(16),
                  "created_at": created.isoformat(), "profile_sha256": profile_sha256,
                  "minimum_receipt": minimum_receipt, "scope": _scope(copied), "files": files,
                  "payload_sha256": sha(payload), "payload_bytes": len(payload),
                  "nonce": base64.urlsafe_b64encode(nonce).decode()}
        raw_header = canonical(header)
        encrypted = AESGCM(key).encrypt(nonce, payload, MAGIC + raw_header)
        observer._write(stage, MAGIC + len(raw_header).to_bytes(4, "big") + raw_header + encrypted)
        # The lease prevents legitimate concurrent collection. Recheck the exact
        # current state/profile before publication rather than emitting a success
        # after a source mutation or pin withdrawal during encryption.
        final_profile, final = _checked(directory, profile_sha256, minimum_receipt)
        require(final_profile == profile and final == original, "observer changed before backup publication")
        digest = sha(_bytes(stage, MAX_PAYLOAD + MAX_HEADER + 28))
        publish(stage, target)
    return {"backup_sha256": digest, "profile_sha256": profile_sha256, **_scope(copied),
            "private_signing_key_included": False, "independent_storage_verified": False,
            "automatic_activation_allowed": False}


def _unpack(package, expected_backup_sha256, profile_sha256, key):
    require(type(key) is bytes and len(key) == 32 and witness._hex(expected_backup_sha256)
            and witness._hex(profile_sha256), "observer restore external pins/key required")
    package = Path(package)
    raw = _bytes(package, MAX_PAYLOAD + MAX_HEADER + 28)
    require(sha(raw) == expected_backup_sha256, "observer backup package pin mismatch")
    require(len(raw) >= 28 and raw[:8] == MAGIC, "observer backup format rejected")
    length = int.from_bytes(raw[8:12], "big")
    require(0 < length <= MAX_HEADER and 12 + length + 16 < len(raw), "observer backup header length rejected")
    raw_header = raw[12:12 + length]
    header = decode(raw_header)
    require(type(header) is dict and set(header) == {
        "schema", "algorithm", "backup_id", "created_at", "profile_sha256", "minimum_receipt",
        "scope", "files", "payload_sha256", "payload_bytes", "nonce"
    } and header["schema"] == SCHEMA and header["algorithm"] == "AES-256-GCM"
            and header["profile_sha256"] == profile_sha256 and witness._hex(header["minimum_receipt"])
            and witness._operation(header["backup_id"]) and witness._hex(header["payload_sha256"])
            and type(header["payload_bytes"]) is int and 0 < header["payload_bytes"] <= MAX_PAYLOAD,
            "observer backup manifest rejected")
    require(observer._time(header["created_at"]) <= datetime.now(UTC), "observer backup time is in future")
    scope = header["scope"]
    require(type(scope) is dict and set(scope) == {"receipt_sha256", "anchor_count", "pending"}
            and witness._hex(scope["receipt_sha256"]) and type(scope["anchor_count"]) is int
            and 0 <= scope["anchor_count"] <= witness.MAX_RECEIPTS and type(scope["pending"]) is bool,
            "observer backup scope rejected")
    require(type(header["files"]) is list and len(header["files"]) == len(NAMES),
            "observer backup inventory rejected")
    limits = (observer.PROFILE_LIMIT, 32, MAX_DATABASE_BYTES)
    for item, name, limit in zip(header["files"], NAMES, limits, strict=True):
        require(type(item) is dict and set(item) == {"name", "bytes", "sha256"}
                and item["name"] == name and type(item["bytes"]) is int
                and 0 < item["bytes"] <= limit and witness._hex(item["sha256"]),
                "observer backup file entry rejected")
    require(sum(item["bytes"] for item in header["files"]) == header["payload_bytes"],
            "observer backup inventory size mismatch")
    require(isinstance(header["nonce"], str) and len(header["nonce"]) == 16, "observer backup nonce rejected")
    nonce = base64.b64decode(header["nonce"], altchars=b"-_", validate=True)
    require(len(nonce) == 12 and len(raw) == 12 + length + header["payload_bytes"] + 16,
            "observer backup ciphertext size rejected")
    try:
        payload = AESGCM(key).decrypt(nonce, raw[12 + length:], MAGIC + raw_header)
    except InvalidTag:
        raise AuditTransferError("observer backup authentication failed") from None
    require(sha(payload) == header["payload_sha256"], "observer backup payload digest rejected")
    offset, files = 0, {}
    for item in header["files"]:
        content = payload[offset:offset + item["bytes"]]
        require(sha(content) == item["sha256"], "observer backup file digest rejected")
        files[item["name"]] = content
        offset += item["bytes"]
    return header, files


def restore(package, destination, expected_backup_sha256, profile_sha256, minimum_receipt, key):
    require(witness._hex(minimum_receipt), "observer restore explicit minimum receipt required")
    target = _target(destination, protected=(package,))
    header, files = _unpack(package, expected_backup_sha256, profile_sha256, key)
    with tempfile.TemporaryDirectory(prefix=".witness-restore-", dir=target.parent) as temporary:
        candidate = Path(temporary)
        for name, raw in files.items():
            observer._write(candidate / name, raw)
        profile, state = _checked(candidate, profile_sha256, minimum_receipt)
        # Also validate the package's original minimum; a caller cannot weaken
        # a corrupted manifest's claimed ancestry by choosing an older pin.
        _checked(candidate, profile_sha256, header["minimum_receipt"])
        require(_scope(state) == header["scope"], "observer backup signed snapshot scope mismatch")
        target = _target(target, protected=(package, profile["witness_directory"], profile["database"]))
        observer._separate(target, Path(profile["witness_directory"]), Path(profile["database"]))
        _lease(candidate, profile_sha256)
        target.mkdir(mode=0o700, exist_ok=False)
        _sync(target.parent)
        pending = {"schema": RESTORE_SCHEMA, "backup_sha256": expected_backup_sha256,
                   "profile_sha256": profile_sha256, "minimum_receipt": minimum_receipt,
                   "started_at": datetime.now(UTC).isoformat()}
        observer._write(target / "restore.pending", canonical(pending) + b"\n")
        _sync(target)
        for name in (*NAMES, "lease.sqlite3"):
            observer._write(target / name, _bytes(candidate / name, MAX_PAYLOAD))
        final_profile, final = _checked(target, profile_sha256, minimum_receipt, restoring=True)
        require(final_profile == profile and final == state, "observer restored candidate changed")
        receipt = {**pending, "scope": _scope(final), "private_signing_key_included": False,
                   "source_locators_preserved": True, "independent_storage_verified": False,
                   "automatic_activation_allowed": False}
        raw_receipt = canonical(receipt) + b"\n"
        observer._write(target / "restore.receipt.json", raw_receipt)
        _sync(target)
        (target / "restore.pending").unlink()
        _sync(target)
    return {"restore_receipt_sha256": sha(raw_receipt), "profile_sha256": profile_sha256,
            **_scope(final), "private_signing_key_included": False,
            "independent_storage_verified": False, "automatic_activation_allowed": False}
