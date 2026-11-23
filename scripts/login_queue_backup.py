"""Create and restore a private, encrypted online SQLite backup of login delivery."""

import argparse
import json
import os
import sqlite3
import stat
import struct
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.login_delivery import LoginDeliveryIdentity
from app.services.sqlite_audit import SQLiteAuditStore
from app.zero_trust_models import LoginDeliveryRequest
from scripts.f1_lab.capture_backup import (
    fresh_file,
    pinned,
    private_directory,
    private_file,
    reserve,
    sha,
)
from scripts.login_delivery_spool import MAX_LOGIN_QUEUE_RECORDS, LoginDeliverySpool

FORMAT = b"ZT-LOGIN-BACKUP-1\x00"
MAX_DATABASE = 64 * 1024**2
MAX_PACKAGE = len(FORMAT) + 12 + 8 + MAX_DATABASE * 2 + 16
QUEUE = "login-queue.sqlite3"
AUDIT = "analysis-audit.sqlite3"


def source_identity(path):
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Login backup requires a standalone regular source file")
    return info.st_dev, info.st_ino


def copy_database(source, target):
    deadline = monotonic() + 15

    target.touch(mode=0o600, exist_ok=False)
    with (
        closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=1)) as reader,
        closing(sqlite3.connect(target)) as writer,
    ):
        page_size = reader.execute("PRAGMA page_size").fetchone()[0]
        if not 0 < page_size * reader.execute("PRAGMA page_count").fetchone()[0] <= MAX_DATABASE:
            raise ValueError("Login backup database exceeds the supported size")

        def progress(_status, _remaining, total):
            if monotonic() >= deadline:
                raise TimeoutError("Login database online copy timed out")
            if total * page_size > MAX_DATABASE:
                raise ValueError("Login backup database exceeds the supported size")

        reader.backup(writer, pages=128, progress=progress, sleep=0.02)
        if writer.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
            raise ValueError("Login backup database is not standalone")
        if writer.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("Login backup database integrity check failed")


def validate_pair(directory, *, origin, tenant_id, collector_subject):
    spool = LoginDeliverySpool(
        directory / QUEUE, origin=origin, tenant_id=tenant_id, collector_subject=collector_subject, create=False,
    )
    pending = {}
    with spool._transaction(read_only=True) as con:
        if con.execute("SELECT count(*) FROM login_queue").fetchone()[0] > MAX_LOGIN_QUEUE_RECORDS:
            raise ValueError("Invalid login queue size")
        for event_id, raw, digest in con.execute("SELECT event_id,payload,payload_sha256 FROM login_queue"):
            if len(raw.encode()) > 1_048_576:
                raise ValueError("Login backup queue entry exceeds the supported size")
            body = LoginDeliveryRequest.model_validate_json(raw)
            identity = LoginDeliveryIdentity.from_request(body)
            if (
                body.tenant_id != tenant_id or body.collector_subject != collector_subject
                or body.event.event_id != event_id or digest != identity.payload_sha256
            ):
                raise ValueError("Login backup queue entry binding failed")
            pending[identity.analysis_id] = (event_id, digest)
        completed = {}
        for analysis_id, event_id in con.execute(
            "SELECT analysis_id,event_id FROM login_queue_review_history WHERE outcome='delivered'"
        ):
            if not analysis_id or completed.setdefault(analysis_id, event_id) != event_id:
                raise ValueError("Conflicting login backup completion reference")
            if len(completed) > SQLiteAuditStore.MAX_ROWS:
                raise ValueError("Login backup completion references exceed audit capacity")

    original = {}

    def observe(record, _):
        identifier = record.analysis_id
        if identifier in pending or identifier in completed:
            original.setdefault(identifier, (
                record.tenant_id, record.actor_id, record.event_id, record.login_delivery_sha256,
            ))

    audit = SQLiteAuditStore.open_existing(directory / AUDIT)
    with audit._transaction() as con:
        audit._read(con, retain_records=False, row_observer=observe)
    scope = (tenant_id, collector_subject)
    for identifier, event_id in completed.items():
        saved = original.get(identifier)
        if saved is None or saved[:3] != (*scope, event_id) or saved[3] is None:
            raise ValueError("Login backup completion has no matching analysis audit")
    for identifier, (event_id, digest) in pending.items():
        if identifier in original and original[identifier] != (*scope, event_id, digest):
            raise ValueError("Login backup pending event conflicts with the analysis audit")


def encryption(key_file, origin, tenant_id, collector_subject):
    key = private_file(key_file, 32)
    if len(key) != 32:
        raise ValueError("Login backup requires a 32-byte AES key")
    scope = json.dumps([origin, tenant_id, collector_subject], ensure_ascii=False, separators=(",", ":")).encode()
    return AESGCM(key), FORMAT + scope


def backup(queue_path, audit_path, output, key_file, *, origin, tenant_id, collector_subject):
    sources = (queue_path, audit_path)
    before = [source_identity(path) for path in sources]
    if before[0] == before[1]:
        raise ValueError("Login backup requires two distinct source databases")
    destination = private_directory(output.parent) / output.name
    cipher, binding = encryption(key_file, origin, tenant_id, collector_subject)
    with TemporaryDirectory(prefix=".login-copy-", dir=destination.parent) as temporary:
        directory = Path(temporary)
        # Queue acknowledgements follow durable analysis. Snapshot the queue
        # first so a completion row cannot point beyond the audit snapshot.
        for source, name in zip(sources, (QUEUE, AUDIT), strict=True):
            copy_database(source, directory / name)
        if before != [source_identity(path) for path in sources]:
            raise ValueError("Login backup source was replaced during capture")
        validate_pair(directory, origin=origin, tenant_id=tenant_id, collector_subject=collector_subject)
        queue, audit = (private_file(directory / name, MAX_DATABASE) for name in (QUEUE, AUDIT))
        nonce = os.urandom(12)
        plaintext = struct.pack(">II", len(queue), len(audit)) + queue + audit
        package = FORMAT + nonce + cipher.encrypt(nonce, plaintext, binding)
        fresh_file(destination, package)
    return {"package_sha256": sha(package), "package_bytes": len(package)}


def package_files(package_path, package_sha256, key_file, *, origin, tenant_id, collector_subject):
    package = pinned(package_path, package_sha256, MAX_PACKAGE)
    if not package.startswith(FORMAT) or len(package) < len(FORMAT) + 12 + 8 + 16:
        raise ValueError("Invalid login backup format")
    cipher, binding = encryption(key_file, origin, tenant_id, collector_subject)
    start = len(FORMAT)
    nonce, encrypted = package[start:start + 12], package[start + 12:]
    try:
        plaintext = cipher.decrypt(nonce, encrypted, binding)
    except InvalidTag as error:
        raise ValueError("Login backup authentication failed") from error
    queue_bytes, audit_bytes = struct.unpack_from(">II", plaintext)
    if (
        not 0 < queue_bytes <= MAX_DATABASE or not 0 < audit_bytes <= MAX_DATABASE
        or len(plaintext) != 8 + queue_bytes + audit_bytes
    ):
        raise ValueError("Invalid login backup database lengths")
    return {QUEUE: plaintext[8:8 + queue_bytes], AUDIT: plaintext[8 + queue_bytes:]}


def restore(package_path, package_sha256, target, key_file, **scope):
    files = package_files(package_path, package_sha256, key_file, **scope)
    parent = private_directory(target.parent)
    with TemporaryDirectory(prefix=".login-restore-", dir=parent) as temporary:
        staging = Path(temporary)
        for name, content in files.items():
            fresh_file(staging / name, content)
        validate_pair(staging, **scope)
        destination = reserve(target, (package_path, key_file))
        for name, content in files.items():
            fresh_file(destination / name, content)
        # The marker is written last. This command stages only and never starts a service.
        fresh_file(destination / "RESTORE_READY", (package_sha256 + "\n").encode())
    return {"package_sha256": package_sha256, "restored_databases": len(files)}


def verify_candidate(package_path, package_sha256, target, key_file, **scope):
    """Check the exact staged files shortly before the operator selects them."""
    files = package_files(package_path, package_sha256, key_file, **scope)
    directory = private_directory(target)
    if (
        {entry.name for entry in directory.iterdir()} != {*files, "RESTORE_READY"}
        or private_file(directory / "RESTORE_READY", 65) != (package_sha256 + "\n").encode()
    ):
        raise ValueError("Login restore candidate is incomplete")
    for name, content in files.items():
        if private_file(directory / name, MAX_DATABASE) != content:
            raise ValueError("Login restore candidate differs from the authenticated backup")
    return {"package_sha256": package_sha256, "verified_databases": len(files)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    capture = actions.add_parser("backup")
    capture.add_argument("queue", type=Path)
    capture.add_argument("audit", type=Path)
    capture.add_argument("output", type=Path)
    recovery = actions.add_parser("restore")
    verify = actions.add_parser("verify")
    for action in (recovery, verify):
        action.add_argument("package", type=Path)
        action.add_argument("sha256")
        action.add_argument("target", type=Path)
    for action in (capture, recovery, verify):
        action.add_argument("--key-file", type=Path, required=True)
        action.add_argument("--origin", required=True)
        action.add_argument("--tenant-id", required=True)
        action.add_argument("--collector-subject", required=True)
    args = parser.parse_args()
    scope = {"origin": args.origin, "tenant_id": args.tenant_id, "collector_subject": args.collector_subject}
    if args.action == "backup":
        result = backup(args.queue, args.audit, args.output, args.key_file, **scope)
    elif args.action == "restore":
        result = restore(args.package, args.sha256, args.target, args.key_file, **scope)
    else:
        result = verify_candidate(args.package, args.sha256, args.target, args.key_file, **scope)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
