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


def _target(path, *, protected=(), fresh=True):
    path = Path(path).absolute()
    witness._directory(path.parent)
    require(all(not p.is_symlink() for p in (path, path.parent, *path.parent.parents)),
            "observer backup output link rejected")
    resolved = path.resolve()
    for item in protected:
        item = Path(item).resolve()
        require(not resolved.is_relative_to(item) and not item.is_relative_to(resolved),
                "observer backup output overlaps protected storage")
    if fresh:
        require(not path.exists(), "observer backup destination must be fresh")
    else:
        witness._directory(path)
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


def _package(package, expected_backup_sha256, profile_sha256):
    require(witness._hex(expected_backup_sha256) and witness._hex(profile_sha256),
            "observer backup external package/profile pins required")
    package = Path(package)
    raw = _bytes(package, MAX_PAYLOAD + MAX_HEADER + 28)
    require(sha(raw) == expected_backup_sha256, "observer backup package pin mismatch")
    require(len(raw) >= 28 and raw[:8] == MAGIC, "observer backup format rejected")
    length = int.from_bytes(raw[8:12], "big")
    require(0 < length <= MAX_HEADER and 12 + length + 16 < len(raw), "observer backup header length rejected")
    raw_header = raw[12:12 + length]
    try:
        header = decode(raw_header)
    except (ValueError, UnicodeError, RecursionError):
        raise AuditTransferError("observer backup header JSON rejected") from None
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
    return header, raw_header, nonce, raw[12 + length:]


def _unpack(package, expected_backup_sha256, profile_sha256, key):
    require(type(key) is bytes and len(key) == 32, "observer restore 32-byte key required")
    header, raw_header, nonce, encrypted = _package(package, expected_backup_sha256, profile_sha256)
    try:
        payload = AESGCM(key).decrypt(nonce, encrypted, MAGIC + raw_header)
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


def restore(package, destination, expected_backup_sha256, profile_sha256, minimum_receipt, key,
            *, resume=False):
    require(type(resume) is bool, "observer restore explicit resume flag required")
    require(witness._hex(minimum_receipt), "observer restore explicit minimum receipt required")
    target = _target(destination, protected=(package,), fresh=not resume)
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
        target = _target(target, protected=(package, profile["witness_directory"], profile["database"]),
                         fresh=not resume)
        observer._separate(target, Path(profile["witness_directory"]), Path(profile["database"]))
        _lease(candidate, profile_sha256)
        if resume:
            marker = _bytes(target / "restore.pending", 4096)
            pending = decode(marker)
            require(type(pending) is dict and set(pending) == {
                "schema", "backup_sha256", "profile_sha256", "minimum_receipt", "started_at"
            } and pending["schema"] == RESTORE_SCHEMA
                    and pending["backup_sha256"] == expected_backup_sha256
                    and pending["profile_sha256"] == profile_sha256
                    and pending["minimum_receipt"] == minimum_receipt,
                    "observer restore resume scope/pin changed")
            require(observer._time(header["created_at"]) <= observer._time(pending["started_at"])
                    <= datetime.now(UTC), "observer restore resume chronology rejected")
            require(set(os.listdir(target)) <= {*NAMES, "lease.sqlite3", "restore.pending", "restore.receipt.json"},
                    "observer restore resume inventory rejected")
        else:
            target.mkdir(mode=0o700, exist_ok=False)
            _sync(target.parent)
            pending = {"schema": RESTORE_SCHEMA, "backup_sha256": expected_backup_sha256,
                       "profile_sha256": profile_sha256, "minimum_receipt": minimum_receipt,
                       "started_at": datetime.now(UTC).isoformat()}
            marker = canonical(pending) + b"\n"
            observer._write(target / "restore.pending", marker)
            _sync(target)
        for name in (*NAMES, "lease.sqlite3"):
            content = _bytes(candidate / name, MAX_PAYLOAD)
            path = target / name
            if resume and path.exists():
                if name != "lease.sqlite3":
                    require(_bytes(path, MAX_PAYLOAD) == content,
                            "observer restore resume refuses changed/partial file")
                # The ephemeral lease is validated/acquired below. Its SQLite
                # file bytes need not match a different interpreter's new DB.
            else:
                observer._write(path, content)
        with observer._database(target, lease=True, profile_pin=profile_sha256):
            require(_bytes(target / "restore.pending", 4096) == marker,
                    "observer restore pending changed before completion")
            final_profile, final = _checked(target, profile_sha256, minimum_receipt, restoring=True)
            require(final_profile == profile and final == state, "observer restored candidate changed")
            receipt = {**pending, "scope": _scope(final), "private_signing_key_included": False,
                       "source_locators_preserved": True, "independent_storage_verified": False,
                       "automatic_activation_allowed": False}
            raw_receipt = canonical(receipt) + b"\n"
            path = target / "restore.receipt.json"
            if resume and path.exists():
                require(_bytes(path, 16384) == raw_receipt, "observer restore resume receipt changed")
            else:
                observer._write(path, raw_receipt)
            _sync(target)
            require(_bytes(target / "restore.pending", 4096) == marker,
                    "observer restore pending changed before admission")
            (target / "restore.pending").unlink()
            _sync(target)
    result = {"restore_receipt_sha256": sha(raw_receipt), "profile_sha256": profile_sha256,
              **_scope(final), "private_signing_key_included": False,
              "independent_storage_verified": False, "automatic_activation_allowed": False}
    if resume:
        result["resumed"] = True
    return result


def inspect_restore(package, directory, expected_backup_sha256, expected_restore_receipt_sha256,
                    profile_sha256, minimum_receipt):
    """Keyless immutable-byte and signed-ancestry checks, not a decryption test.

Package/receipt pins must have been retained from an approved backup/restore.
Never discover a new receipt pin, sign a new observation, refresh the original
restore time or require custody of a recovery/signing key for monitoring.
"""
    require(witness._hex(expected_restore_receipt_sha256) and witness._hex(minimum_receipt),
            "observer restore external receipt/minimum pins required")
    header, _raw_header, _nonce, _encrypted = _package(package, expected_backup_sha256, profile_sha256)
    directory, profile, public = observer._load(directory, profile_sha256)
    raw = _bytes(directory / "restore.receipt.json", 16384)
    require(sha(raw) == expected_restore_receipt_sha256, "observer restore receipt pin mismatch")
    value = decode(raw)
    require(type(value) is dict and set(value) == {
        "schema", "backup_sha256", "profile_sha256", "minimum_receipt", "started_at", "scope",
        "private_signing_key_included", "source_locators_preserved", "independent_storage_verified",
        "automatic_activation_allowed"
    } and value["schema"] == RESTORE_SCHEMA and value["backup_sha256"] == expected_backup_sha256
            and value["profile_sha256"] == profile_sha256 and witness._hex(value["minimum_receipt"])
            and value["scope"] == header["scope"] and value["source_locators_preserved"] is True
            and all(value[k] is False for k in ("private_signing_key_included",
                                               "independent_storage_verified", "automatic_activation_allowed")),
            "observer restore receipt binding rejected")
    require(observer._time(header["created_at"]) <= observer._time(value["started_at"])
            <= datetime.now(UTC), "observer restore receipt chronology rejected")
    # A normal collector may have appended signed descendants after restore.
    # Require every retained minimum, not byte equality with a historical DB.
    # One read transaction fixes all ancestry checks. Monitoring needs no write
    # reservation and cannot block the collector by taking its execution lease.
    with observer._database(directory) as con:
        current = observer._read(con, profile, public, minimum_receipt)
        for minimum in (header["minimum_receipt"], header["scope"]["receipt_sha256"], value["minimum_receipt"]):
            observer._read(con, profile, public, minimum)
        require(current["anchors"] >= header["scope"]["anchor_count"],
                "observer restore signed history behind snapshot")
        require(con.execute("PRAGMA quick_check").fetchall() == [("ok",)],
                "observer restore SQLite integrity rejected")
    return {"backup_created_at": header["created_at"], "restore_started_at": value["started_at"],
            "snapshot_scope": header["scope"], "current_scope": _scope(current),
            "ciphertext_pin_verified": True, "restore_receipt_pin_verified": True,
            "signed_snapshot_minimum_present": True, "decryption_checked": False,
            "live_source_checked": False, "restore_completion_time_attested": False,
            "independent_storage_verified": False, "automatic_activation_allowed": False}
