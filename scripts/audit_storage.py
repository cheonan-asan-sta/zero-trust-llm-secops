"""Offline audit inspection, explicit migration, encrypted backup and fresh restore."""

import argparse
import json
import sqlite3

from cryptography.exceptions import InvalidTag

from app.services.audit_backup import backup_sqlite, read_key, restore_sqlite
from app.services.audit_transfer import AuditTransferError, migrate_jsonl, scan_jsonl
from app.services.federated_audit import AuditQueryUnavailable
from app.services.sqlite_audit import SQLiteAuditStore


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    scan = actions.add_parser("scan")
    scan.add_argument("--source", required=True)
    scan.add_argument("--allow-legacy", action="store_true")
    migrate = actions.add_parser("migrate")
    migrate.add_argument("--source", required=True)
    migrate.add_argument("--destination", required=True)
    migrate.add_argument("--inventory-sha256", required=True)
    migrate.add_argument("--allow-legacy", action="store_true")
    for action in ("backup", "restore"):
        command = actions.add_parser(action)
        command.add_argument("--database" if action == "backup" else "--package", required=True)
        command.add_argument("--destination", required=True)
        command.add_argument("--key-file", required=True)
        command.add_argument("--key-sha256", required=True)
        command.add_argument("--minimum-seq", type=int)
        command.add_argument("--minimum-head")
        if action == "restore":
            command.add_argument("--backup-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "scan":
            _, result = scan_jsonl(args.source, allow_legacy=args.allow_legacy)
        elif args.action == "migrate":
            result = migrate_jsonl(
                args.source, args.destination, args.inventory_sha256, allow_legacy=args.allow_legacy
            )
        else:
            if (args.minimum_seq is None) != (args.minimum_head is None):
                parser.error("minimum-seq and minimum-head must be provided together")
            minimum = (
                None
                if args.minimum_seq is None
                else {"seq": args.minimum_seq, "digest": args.minimum_head}
            )
            key = read_key(args.key_file, args.key_sha256)
            if args.action == "backup":
                result = backup_sqlite(
                    SQLiteAuditStore.open_existing(args.database),
                    args.destination,
                    key,
                    minimum_head=minimum,
                )
            else:
                result = restore_sqlite(
                    args.package, args.destination, args.backup_sha256, key, minimum_head=minimum
                )
    except (
        OSError,
        sqlite3.Error,
        ValueError,
        TypeError,
        InvalidTag,
        AuditTransferError,
        AuditQueryUnavailable,
    ):
        parser.exit(1, "Audit operation failed; automatic activation is disabled.\n")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
