"""Explicit encrypted witness-control backup/restore, no service activation."""

import argparse
import json
import sqlite3
import sys

from app.services import audit_witness_observer_backup as backup
from app.services.audit_backup import read_key
from app.services.audit_transfer import AuditTransferError
from app.services.federated_audit import AuditQueryUnavailable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("backup", "restore", "resume-restore", "inspect-restore"):
        command = commands.add_parser(name)
        command.add_argument("--profile-sha256", required=True)
        command.add_argument("--minimum-receipt", required=True)
        if name != "inspect-restore":
            command.add_argument("--destination", required=True)
            command.add_argument("--key-file", required=True)
            command.add_argument("--key-sha256", required=True)
        if name == "backup":
            command.add_argument("--directory", required=True)
        else:
            command.add_argument("--package", required=True)
            command.add_argument("--backup-sha256", required=True)
            if name == "inspect-restore":
                command.add_argument("--directory", required=True)
                command.add_argument("--restore-receipt-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.action == "inspect-restore":
            result = backup.inspect_restore(args.package, args.directory, args.backup_sha256,
                                            args.restore_receipt_sha256, args.profile_sha256,
                                            args.minimum_receipt)
        elif args.action == "backup":
            key = read_key(args.key_file, args.key_sha256)
            result = backup.backup(args.directory, args.profile_sha256, args.minimum_receipt,
                                   args.destination, key)
        else:
            key = read_key(args.key_file, args.key_sha256)
            result = backup.restore(args.package, args.destination, args.backup_sha256,
                                    args.profile_sha256, args.minimum_receipt, key,
                                    resume=args.action == "resume-restore")
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError, RecursionError, sqlite3.Error):
        print("Observer backup/restore refused; no pin reset or service activation.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
