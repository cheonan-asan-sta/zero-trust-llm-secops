"""Offline cold archive checkpoint, encrypted backup and isolated review restore."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.capture_backup import CaptureBackup
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.systemd_credential_reader import read_systemd_key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("checkpoint", "backup", "restore", "verify"))
    for name in ("tenant", "server", "unit", "source", "output"):
        parser.add_argument("--" + name, required=True)
    for name in ("root", "checkpoint", "previous-checkpoint", "backup"):
        parser.add_argument("--" + name, type=Path)
    for name in (
        "checkpoint-sha256",
        "previous-checkpoint-sha256",
        "manifest-sha256",
        "receipt-sha256",
        "key-id",
    ):
        parser.add_argument("--" + name)
    parser.add_argument("--systemd-credential", action="store_true")
    args = parser.parse_args()
    if args.mode in {"checkpoint", "backup"} and args.root is None:
        parser.error("--root is required for source operations")
    if args.mode != "checkpoint" and not (args.checkpoint and args.checkpoint_sha256):
        parser.error("--checkpoint and --checkpoint-sha256 are required")
    if args.mode == "restore" and not (args.backup and args.manifest_sha256):
        parser.error("--backup and --manifest-sha256 are required for restore")
    if args.mode == "verify" and not args.receipt_sha256:
        parser.error("--receipt-sha256 is required for verify")
    if args.mode in {"backup", "restore"} and not args.key_id:
        parser.error("--key-id is required for encryption operations")
    try:
        manager = CaptureBackup(
            ArchiveScope(
                tenant_id=args.tenant, server_id=args.server, unit=args.unit, source_id=args.source
            )
        )
        if args.mode in {"backup", "restore"}:
            key = (
                read_systemd_key(credential_name="capture-backup-key")
                if args.systemd_credential
                else sys.stdin.buffer.read(33)
            )
            require(type(key) is bytes and len(key) == 32, "capture_backup_private_stdin_key")
        if args.mode == "checkpoint":
            result = manager.checkpoint(
                args.root,
                args.output,
                previous=args.previous_checkpoint,
                previous_sha256=args.previous_checkpoint_sha256,
            )
        elif args.mode == "backup":
            result = manager.backup(
                args.root, args.output, args.checkpoint, args.checkpoint_sha256, key, args.key_id
            )
        elif args.mode == "restore":
            result = manager.restore(
                args.backup,
                args.manifest_sha256,
                args.checkpoint,
                args.checkpoint_sha256,
                args.output,
                key,
                args.key_id,
            )
        else:
            result = manager.verify(
                args.output, args.receipt_sha256, args.checkpoint, args.checkpoint_sha256
            )
        result.update(
            automatic_activation_allowed=False,
            authenticity_or_freshness_asserted=False,
            worker_security=current_security_status(),
        )
        print(json.dumps(result))
        return 0
    except (ValueError, OSError, sqlite3.Error, RecursionError):
        print(
            json.dumps(
                {
                    "completed": False,
                    "state": "unavailable",
                    "mode": args.mode,
                    "automatic_activation_allowed": False,
                    "authenticity_or_freshness_asserted": False,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
