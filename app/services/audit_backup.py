"""Streaming authenticated local SQLite audit backup, fresh restore, pinned heads."""

import base64
import hashlib
import os
import secrets
import sqlite3
import stat
import time
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.services.audit_transfer import canonical, decode, fresh_stage, publish, require, sha
from app.services.sqlite_audit import SQLiteAuditStore

MAGIC = b"ZTAUDIT1"
MAX_DATABASE_BYTES = 512 * 1024 * 1024


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def read_key(path, expected_sha256):
    path = Path(path)
    require(not path.is_symlink(), "backup key link rejected")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 32,
            "backup key file invalid",
        )
        if os.name == "posix":
            require(
                info.st_mode & 0o077 == 0 and info.st_uid in {0, os.geteuid()},
                "backup key permission rejected",
            )
        key = stream.read(33)
    require(len(key) == 32 and sha(key) == expected_sha256, "backup key pin mismatch")
    return key


def validate_head(con, store, minimum_head=None):
    _, seq, digest, _ = store._read(con, retain_records=False)
    if minimum_head is not None:
        require(
            type(minimum_head) is dict
            and set(minimum_head) == {"seq", "digest"}
            and type(minimum_head["seq"]) is int
            and 0 <= minimum_head["seq"] <= seq,
            "backup older than required checkpoint",
        )
        prior = (
            "0" * 64
            if minimum_head["seq"] == 0
            else con.execute(
                "SELECT digest FROM audit_entries WHERE seq=?", (minimum_head["seq"],)
            ).fetchone()[0]
        )
        require(prior == minimum_head["digest"], "backup checkpoint history conflict")
    return seq, digest


def backup_sqlite(store, destination, key, *, minimum_head=None):
    require(type(key) is bytes and len(key) == 32, "backup key must be 32 bytes")
    with fresh_stage(destination) as (stage, target):
        snapshot = stage.with_name("snapshot.sqlite3")
        require(store.path.is_file() and not store.path.is_symlink(), "backup source must exist")
        deadline = time.monotonic() + 30
        with closing(
            sqlite3.connect(store.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        ) as source:
            page_size = source.execute("PRAGMA page_size").fetchone()[0]

            def progress(_status, _remaining, total):
                require(time.monotonic() < deadline, "SQLite backup time limit exceeded")
                require(total * page_size <= MAX_DATABASE_BYTES, "backup database too large")

            with closing(sqlite3.connect(snapshot)) as dest:
                source.backup(dest, pages=128, progress=progress, sleep=0.05)
        require(snapshot.stat().st_size <= MAX_DATABASE_BYTES, "backup database too large")
        checked = SQLiteAuditStore.open_existing(snapshot)
        with checked._transaction() as con:
            # Preserve optional runtime checkpoint constraints on the copied view.
            seq, head = validate_head(con, store, minimum_head)
        nonce = secrets.token_bytes(12)
        header = {
            "schema": "sqlite-audit-backup-1",
            "algorithm": "AES-256-GCM",
            "snapshot_id": secrets.token_hex(16),
            "created_at": datetime.now(UTC).isoformat(),
            "database_bytes": snapshot.stat().st_size,
            "database_sha256": file_hash(snapshot),
            "seq": seq,
            "head": head,
            "nonce": base64.urlsafe_b64encode(nonce).decode(),
        }
        raw_header = canonical(header)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(raw_header)
        with stage.open("wb") as output, snapshot.open("rb") as source:
            output.write(MAGIC + len(raw_header).to_bytes(4, "big") + raw_header)
            while chunk := source.read(65536):
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize() + encryptor.tag)
        package_sha256 = file_hash(stage)
        # Encryption/hashing may take time. Revalidate the exact copied view
        # through the selected store so a runtime anchor withdrawal denies
        # publication. Current source appends do not redefine this snapshot.
        with checked._transaction() as con:
            final_seq, final_head = validate_head(con, store, minimum_head)
            require((final_seq, final_head) == (seq, head), "backup snapshot changed")
        publish(stage, target)
        return {
            "backup_sha256": package_sha256,
            "snapshot_id": header["snapshot_id"],
            "database_sha256": header["database_sha256"],
            "head": {"seq": seq, "digest": head},
            "automatic_activation_allowed": False,
        }


def restore_sqlite(package, destination, expected_backup_sha256, key, *, minimum_head=None):
    package = Path(package)
    require(type(key) is bytes and len(key) == 32, "restore key must be 32 bytes")
    require(
        isinstance(expected_backup_sha256, str)
        and len(expected_backup_sha256) == 64
        and set(expected_backup_sha256) <= set("0123456789abcdef"),
        "backup external pin required",
    )
    require(
        package.is_file()
        and not package.is_symlink()
        and package.stat().st_size <= MAX_DATABASE_BYTES + 16412,
        "backup package invalid",
    )
    with fresh_stage(destination) as (stage, target), package.open("rb") as source:
        prefix = source.read(12)
        require(len(prefix) == 12 and prefix[:8] == MAGIC, "backup format rejected")
        header_length = int.from_bytes(prefix[8:], "big")
        require(0 < header_length <= 16384, "backup header length invalid")
        raw_header = source.read(header_length)
        header = decode(raw_header)
        require(
            type(header) is dict
            and set(header)
            == {
                "schema",
                "algorithm",
                "snapshot_id",
                "created_at",
                "database_bytes",
                "database_sha256",
                "seq",
                "head",
                "nonce",
            }
            and header["schema"] == "sqlite-audit-backup-1"
            and header["algorithm"] == "AES-256-GCM"
            and type(header["database_bytes"]) is int
            and 0 < header["database_bytes"] <= MAX_DATABASE_BYTES
            and type(header["seq"]) is int
            and 0 <= header["seq"] <= SQLiteAuditStore.MAX_ROWS
            and isinstance(header["snapshot_id"], str)
            and len(header["snapshot_id"]) == 32
            and set(header["snapshot_id"]) <= set("0123456789abcdef"),
            "backup manifest rejected",
        )
        require(
            datetime.fromisoformat(header["created_at"]).utcoffset() is not None,
            "backup time must have timezone",
        )
        for field in ("database_sha256", "head"):
            require(
                isinstance(header[field], str)
                and len(header[field]) == 64
                and set(header[field]) <= set("0123456789abcdef"),
                "backup digest malformed",
            )
        nonce = base64.b64decode(header["nonce"], altchars=b"-_", validate=True)
        require(
            len(nonce) == 12 and base64.urlsafe_b64encode(nonce).decode() == header["nonce"],
            "backup nonce rejected",
        )
        digest = hashlib.sha256(prefix + raw_header)
        plain_hash = hashlib.sha256()
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        decryptor.authenticate_additional_data(raw_header)
        remaining = header["database_bytes"]
        with stage.open("wb") as output:
            while remaining:
                chunk = source.read(min(65536, remaining))
                require(chunk, "backup truncated")
                remaining -= len(chunk)
                digest.update(chunk)
                plain = decryptor.update(chunk)
                plain_hash.update(plain)
                output.write(plain)
            tag = source.read(16)
            digest.update(tag)
            require(len(tag) == 16 and not source.read(1), "backup trailing/truncated bytes")
            final = decryptor.finalize_with_tag(tag)
            output.write(final)
            plain_hash.update(final)
        require(
            digest.hexdigest() == expected_backup_sha256
            and plain_hash.hexdigest() == header["database_sha256"],
            "backup external/database pin mismatch",
        )
        checked = SQLiteAuditStore.open_existing(stage)
        with checked._transaction() as con:
            seq, head = validate_head(con, checked, minimum_head)
        require((seq, head) == (header["seq"], header["head"]), "backup head mismatch")
        publish(stage, target)
        return {
            "backup_sha256": expected_backup_sha256,
            "snapshot_id": header["snapshot_id"],
            "head": {"seq": seq, "digest": head},
            "automatic_activation_allowed": False,
        }
