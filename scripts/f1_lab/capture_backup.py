"""Encrypted cold-archive backup and pinned, isolated review restore.

The host, writer and external checkpoint pins remain trusted. No signing key,
hot/latest capture or monitor ledger is included. Restore never renews trust.
"""

import base64
import hashlib
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import time
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field

from app.models import StrictModel
from scripts.f1_lab.capture_archive import ZERO, ArchiveScope, CaptureArchive
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.web_verified_context import SHA, Identifier

MAX_DATABASE = 64 * 1024**2
MAX_CIPHERTEXT = MAX_DATABASE + 16
MAX_PACKAGES = 16


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def aware(text):
    require(type(text) is str and len(text) <= 40, "capture_backup_time")
    value = datetime.fromisoformat(text)
    require(
        value.tzinfo is not None and value.utcoffset().total_seconds() == 0, "capture_backup_UTC"
    )
    return value


class Checkpoint(StrictModel):
    schema_version: Literal["zt-capture-checkpoint-1"] = "zt-capture-checkpoint-1"
    scope_sha256: SHA
    records: int = Field(strict=True, ge=0, le=10000)
    raw_bytes: int = Field(strict=True, ge=0, le=1024**3)
    head: SHA
    issued_at: str


class Manifest(StrictModel):
    schema_version: Literal["zt-capture-backup-1"] = "zt-capture-backup-1"
    algorithm: Literal["AES-256-GCM"] = "AES-256-GCM"
    key_id: Identifier
    source_root: str = Field(min_length=1, max_length=4096)
    snapshot: Checkpoint
    created_at: str
    nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{16}$")
    database_sha256: SHA
    database_bytes: int = Field(strict=True, ge=1, le=MAX_DATABASE)
    payload_sha256: SHA
    payload_bytes: int = Field(strict=True, ge=17, le=MAX_CIPHERTEXT)


def private_file(path, maximum):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == os.geteuid()
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= maximum,
            "capture_backup_private_file",
        )
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(
            len(raw) == before.st_size
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "capture_backup_file_changed",
        )
    return raw


def pinned(path, expected, maximum):
    require(type(expected) is str and re.fullmatch(r"[a-f0-9]{64}", expected), "capture_backup_pin")
    raw = private_file(path, maximum)
    require(sha(raw) == expected, "capture_backup_pin_mismatch")
    return raw


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    require(
        path.is_absolute()
        and stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "capture_backup_private_directory",
    )
    return path.resolve(strict=True)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fresh_file(path, raw):
    """Exclusive file in a private directory, never replace an existing object."""
    private_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".capture-backup-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-filesystem link publishes complete bytes without replacing a
        # pre-existing destination. A crash before unlink leaves an incomplete
        # inventory/link count, which readers refuse rather than activate.
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        sync(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def reserve(path, forbidden=(), *, capacity=None):
    original = Path(path)
    require(original.is_absolute() and not original.is_symlink(), "capture_backup_output_absolute")
    parent = private_directory(original.parent)
    output = parent / original.name
    for other in forbidden:
        other = Path(other).resolve()
        require(
            output != other and output not in other.parents and other not in output.parents,
            "capture_backup_output_overlap",
        )
    if capacity is not None:
        with capture_store_lock(parent):
            require(
                sum(name != ".capture-store.lock" for name in os.listdir(parent)) < capacity,
                "capture_backup_package_capacity",
            )
            output.mkdir(mode=0o700, exist_ok=False)
            sync(parent)
    else:
        output.mkdir(mode=0o700, exist_ok=False)
        sync(parent)
    return output


@contextmanager
def reader(path=None, raw=None):
    require((path is None) != (raw is None), "capture_backup_reader_input")
    con = sqlite3.connect(
        ":memory:" if raw is not None else Path(path).as_uri() + "?mode=ro",
        uri=path is not None,
        timeout=5,
    )
    try:
        if raw is not None:
            require(
                type(raw) is bytes and 0 < len(raw) <= MAX_DATABASE, "capture_backup_database_bound"
            )
            con.deserialize(raw)
        con.enable_load_extension(False)
        con.execute("PRAGMA temp_store=MEMORY")
        con.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        con.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 128 * 1024)
        con.execute("PRAGMA trusted_schema=OFF")
        con.execute("PRAGMA query_only=ON")
        deadline = time.monotonic() + 20
        con.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        yield con
    finally:
        con.close()


class CaptureBackup:
    def __init__(self, scope):
        self.scope = ArchiveScope.model_validate(scope.model_dump())
        self.binding = sha(canonical(self.scope.model_dump(mode="json")))

    def phase(self, _name):
        """Real-process interruption boundary; no CLI injection option."""

    def validate_checkpoint(self, checkpoint):
        require(checkpoint.scope_sha256 == self.binding, "capture_backup_checkpoint_scope")
        aware(checkpoint.issued_at)
        require(
            (checkpoint.records == 0 and checkpoint.raw_bytes == 0 and checkpoint.head == ZERO)
            or (checkpoint.records > 0 and checkpoint.raw_bytes > 0 and checkpoint.head != ZERO),
            "capture_backup_checkpoint_head",
        )
        return checkpoint

    def checkpoint_file(self, path, expected):
        return self.validate_checkpoint(
            Checkpoint.model_validate(decode(pinned(path, expected, 8192)))
        )

    def inspect(self, con, minimum=None):
        # No view, trigger or caller-supplied SQL is accepted from a backup.
        inventory = {
            (kind, name) for kind, name in con.execute("SELECT type,name FROM sqlite_schema")
        }
        require(
            inventory
            == {
                ("table", "archive_head"),
                ("table", "captures"),
                ("index", "sqlite_autoindex_captures_1"),
            },
            "capture_backup_schema_inventory",
        )
        for name in ("archive_head", "captures"):
            sql = con.execute("SELECT sql FROM sqlite_schema WHERE name=?", (name,)).fetchone()[0]
            require(
                type(sql) is str
                and sql.upper().startswith("CREATE TABLE " + name.upper())
                and "REFERENCES" not in sql.upper(),
                "capture_backup_schema_type",
            )
        require(
            con.execute("PRAGMA quick_check").fetchall() == [("ok",)],
            "capture_backup_sqlite_integrity",
        )
        # load() uses only fixed SELECT statements and bounded decompression.
        archive = object.__new__(CaptureArchive)
        archive.scope = self.scope
        records, total, _, head = archive.load(con)
        if minimum is not None:
            self.validate_checkpoint(minimum)
            require(len(records) >= minimum.records, "capture_backup_rollback")
            prefix, raw_total = ZERO, 0
            for row in con.execute(
                "SELECT seq,run_id,raw_sha,event_sha,raw_bytes,packed_sha FROM captures WHERE seq<=? ORDER BY seq",
                (minimum.records,),
            ):
                prefix = CaptureArchive.chain(prefix, list(row))
                raw_total += row[4]
            require(
                prefix == minimum.head and raw_total == minimum.raw_bytes,
                "capture_backup_history_conflict",
            )
        return len(records), total, head

    def current(self, con):
        count, total, head = self.inspect(con)
        return Checkpoint(
            scope_sha256=self.binding,
            records=count,
            raw_bytes=total,
            head=head,
            issued_at=datetime.now(UTC).isoformat(),
        )

    def checkpoint(self, root, output, *, previous=None, previous_sha256=None):
        root = private_directory(root)
        output = Path(output)
        require(
            output.is_absolute()
            and not output.is_symlink()
            and root not in output.resolve().parents,
            "capture_backup_external_checkpoint",
        )
        require((previous is None) == (previous_sha256 is None), "capture_backup_previous_pin")
        minimum = self.checkpoint_file(previous, previous_sha256) if previous is not None else None
        require(
            previous is None or root not in Path(previous).resolve().parents,
            "capture_backup_previous_checkpoint_inside_source",
        )
        with capture_store_lock(root):
            private_file(root / "archive.sqlite3", MAX_DATABASE)
            with reader(path=root / "archive.sqlite3") as con:
                if minimum is not None:
                    self.inspect(con, minimum)
                checkpoint = self.current(con)
        require(
            minimum is None or aware(checkpoint.issued_at) >= aware(minimum.issued_at),
            "capture_backup_checkpoint_clock",
        )
        raw = canonical(checkpoint.model_dump(mode="json")) + b"\n"
        fresh_file(output, raw)
        return {
            "completed": True,
            "checkpoint_sha256": sha(raw),
            "checkpoint": checkpoint.model_dump(mode="json"),
        }

    @staticmethod
    def aad(manifest):
        return canonical(
            manifest.model_dump(mode="json", exclude={"payload_sha256", "payload_bytes"})
        )

    def backup(self, root, output, checkpoint_path, checkpoint_sha256, key, key_id):
        require(type(key) is bytes and len(key) == 32, "capture_backup_recovery_key")
        root = private_directory(root)
        checkpoint = self.checkpoint_file(checkpoint_path, checkpoint_sha256)
        require(
            root not in Path(checkpoint_path).resolve().parents,
            "capture_backup_checkpoint_inside_source",
        )
        now = datetime.now(UTC)
        require(now >= aware(checkpoint.issued_at), "capture_backup_future_checkpoint")
        with capture_store_lock(root):
            private_file(root / "archive.sqlite3", MAX_DATABASE)
            with (
                reader(path=root / "archive.sqlite3") as source,
                closing(sqlite3.connect(":memory:")) as copy,
            ):
                copy.execute("PRAGMA temp_store=MEMORY")
                self.inspect(source, checkpoint)
                require(
                    source.execute("PRAGMA page_count").fetchone()[0]
                    * source.execute("PRAGMA page_size").fetchone()[0]
                    <= MAX_DATABASE,
                    "capture_backup_page_bound",
                )
                deadline = time.monotonic() + 20

                def progress(_status, _remaining, _total):
                    require(time.monotonic() <= deadline, "capture_backup_copy_deadline")

                source.backup(copy, pages=256, progress=progress, sleep=0.005)
                count, total, head = self.inspect(copy, checkpoint)
                require(
                    (count, total, head)
                    == (checkpoint.records, checkpoint.raw_bytes, checkpoint.head),
                    "capture_backup_checkpoint_not_current",
                )
                raw = copy.serialize()
                require(0 < len(raw) <= MAX_DATABASE, "capture_backup_copy_bound")
        nonce = secrets.token_bytes(12)
        manifest = Manifest(
            key_id=key_id,
            source_root=str(root),
            snapshot=checkpoint,
            created_at=now.isoformat(),
            nonce=base64.urlsafe_b64encode(nonce).decode(),
            database_sha256=sha(raw),
            database_bytes=len(raw),
            payload_sha256=ZERO,
            payload_bytes=17,
        )
        payload = AESGCM(key).encrypt(nonce, raw, self.aad(manifest))
        manifest = manifest.model_copy(
            update={"payload_sha256": sha(payload), "payload_bytes": len(payload)}
        )
        output = reserve(output, [root, checkpoint_path], capacity=MAX_PACKAGES)
        fresh_file(output / "payload.aesgcm", payload)
        self.phase("after_backup_payload")
        raw_manifest = canonical(manifest.model_dump(mode="json")) + b"\n"
        fresh_file(output / "manifest.json", raw_manifest)
        self.phase("after_backup_publish")
        return {
            "completed": True,
            "manifest_sha256": sha(raw_manifest),
            "checkpoint_sha256": checkpoint_sha256,
            "records": count,
            "database_bytes": len(raw),
            "payload_bytes": len(payload),
            "automatic_activation_allowed": False,
        }

    def restore(
        self, package, manifest_sha256, checkpoint_path, checkpoint_sha256, output, key, key_id
    ):
        require(type(key) is bytes and len(key) == 32, "capture_backup_recovery_key")
        package = private_directory(package)
        require(
            set(os.listdir(package)) == {"manifest.json", "payload.aesgcm"},
            "capture_backup_inventory",
        )
        checkpoint_path = Path(checkpoint_path)
        require(
            package not in checkpoint_path.resolve().parents,
            "capture_backup_checkpoint_inside_package",
        )
        checkpoint = self.checkpoint_file(checkpoint_path, checkpoint_sha256)
        manifest = Manifest.model_validate(
            decode(pinned(package / "manifest.json", manifest_sha256, 16384))
        )
        self.validate_checkpoint(manifest.snapshot)
        now = datetime.now(UTC)
        require(
            manifest.key_id == key_id
            and aware(checkpoint.issued_at) <= now
            and aware(manifest.created_at) <= now
            and Path(manifest.source_root).is_absolute()
            and aware(manifest.snapshot.issued_at) <= aware(manifest.created_at),
            "capture_backup_manifest_binding",
        )
        payload = pinned(package / "payload.aesgcm", manifest.payload_sha256, MAX_CIPHERTEXT)
        require(len(payload) == manifest.payload_bytes, "capture_backup_payload_size")
        nonce = base64.urlsafe_b64decode(manifest.nonce)
        try:
            raw = AESGCM(key).decrypt(nonce, payload, self.aad(manifest))
        except InvalidTag:
            raise ValueError("capture_backup_authentication_failed") from None
        require(
            len(raw) == manifest.database_bytes and sha(raw) == manifest.database_sha256,
            "capture_backup_database_digest",
        )
        with reader(raw=raw) as con:
            count, total, head = self.inspect(con, checkpoint)
            require(
                (count, total, head)
                == (manifest.snapshot.records, manifest.snapshot.raw_bytes, manifest.snapshot.head),
                "capture_backup_snapshot_mismatch",
            )
        output = reserve(output, [package, checkpoint_path, manifest.source_root])
        stage = output / ".restore-incomplete"
        stage.mkdir(mode=0o700)
        self.phase("before_restore_state")
        fresh_file(stage / "archive.sqlite3", raw)
        require(
            sha(private_file(stage / "archive.sqlite3", MAX_DATABASE)) == manifest.database_sha256,
            "capture_backup_restore_readback",
        )
        self.phase("before_restore_publish")
        stage.rename(output / "review")
        sync(output)
        self.phase("after_restore_state")
        receipt = {
            "schema": "zt-capture-restore-1",
            "scope_sha256": self.binding,
            "manifest_sha256": manifest_sha256,
            "checkpoint_sha256": checkpoint_sha256,
            "database_sha256": manifest.database_sha256,
            "records": count,
            "raw_bytes": total,
            "head": head,
            "restored_at": now.isoformat(),
            "automatic_activation_allowed": False,
        }
        encoded = canonical(receipt) + b"\n"
        fresh_file(output / "restore.json", encoded)
        self.phase("after_restore_publish")
        return {
            "completed": True,
            "receipt_sha256": sha(encoded),
            "records": count,
            "automatic_activation_allowed": False,
        }

    def verify(self, output, receipt_sha256, checkpoint_path, checkpoint_sha256):
        output = private_directory(output)
        checkpoint_path = Path(checkpoint_path)
        require(
            output not in checkpoint_path.resolve().parents,
            "capture_backup_checkpoint_inside_restore",
        )
        checkpoint = self.checkpoint_file(checkpoint_path, checkpoint_sha256)
        require(
            set(os.listdir(output)) == {"review", "restore.json"},
            "capture_backup_restore_inventory",
        )
        review = private_directory(output / "review")
        require(
            set(os.listdir(review)) <= {"archive.sqlite3", ".capture-store.lock"}
            and (review / "archive.sqlite3").exists(),
            "capture_backup_review_inventory",
        )
        receipt = decode(pinned(output / "restore.json", receipt_sha256, 16384))
        require(
            type(receipt) is dict
            and set(receipt)
            == {
                "schema",
                "scope_sha256",
                "manifest_sha256",
                "checkpoint_sha256",
                "database_sha256",
                "records",
                "raw_bytes",
                "head",
                "restored_at",
                "automatic_activation_allowed",
            }
            and receipt["schema"] == "zt-capture-restore-1"
            and receipt["scope_sha256"] == self.binding
            and receipt["checkpoint_sha256"] == checkpoint_sha256
            and receipt["automatic_activation_allowed"] is False,
            "capture_backup_restore_receipt",
        )
        require(
            aware(receipt["restored_at"]) >= aware(checkpoint.issued_at),
            "capture_backup_restore_time",
        )
        with capture_store_lock(review):
            raw = private_file(review / "archive.sqlite3", MAX_DATABASE)
            require(
                sha(raw) == receipt["database_sha256"], "capture_backup_restored_database_changed"
            )
            with reader(raw=raw) as con:
                count, total, head = self.inspect(con, checkpoint)
                require(
                    (count, total, head)
                    == (receipt["records"], receipt["raw_bytes"], receipt["head"]),
                    "capture_backup_restored_head",
                )
        return {
            "completed": True,
            "records": count,
            "head": head,
            "automatic_activation_allowed": False,
        }
