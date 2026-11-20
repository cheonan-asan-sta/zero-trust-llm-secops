"""Export, inspect and recover closed witness generations."""

import argparse
import json
import sqlite3
import sys
from datetime import datetime

from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import InvalidTag

from app.services import audit_witness_archive as archive
from app.services import audit_witness_worm as worm
from app.services.audit_backup import read_key
from app.services.audit_transfer import AuditTransferError
from app.services.federated_audit import AuditQueryUnavailable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("export", "inspect", "upload-worm", "fetch-worm", "restore-audit"):
        command = commands.add_parser(action)
        command.add_argument("--terminal-sha256", required=True)
        if action == "export":
            command.add_argument("--control", required=True)
            command.add_argument("--profile-sha256", required=True)
        else:
            command.add_argument("--archive-sha256", required=True)
            command.add_argument("--public-key-sha256", required=True)
        if action in {"inspect", "upload-worm", "restore-audit"}:
            command.add_argument("--archive", required=True)
        if action in {"export", "fetch-worm", "restore-audit"}:
            command.add_argument("--destination", required=True)
        if action in {"upload-worm", "fetch-worm"}:
            command.add_argument("--bucket", required=True)
            command.add_argument("--bucket-owner", required=True)
            command.add_argument("--region", required=True)
            command.add_argument("--retain-until", type=datetime.fromisoformat, required=True)
        if action == "fetch-worm":
            command.add_argument("--version-id", required=True)
        if action == "restore-audit":
            command.add_argument("--backup", required=True)
            command.add_argument("--backup-sha256", required=True)
            command.add_argument("--key-file", required=True)
            command.add_argument("--key-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.action == "export":
            result = archive.export(args.control, args.profile_sha256, args.terminal_sha256,
                                    args.destination)
        elif args.action == "inspect":
            result = archive.inspect(archive.read(args.archive), args.archive_sha256,
                                     args.public_key_sha256, args.terminal_sha256)
        elif args.action == "restore-audit":
            result = archive.restore_audit(
                archive.read(args.archive), args.archive_sha256, args.public_key_sha256,
                args.terminal_sha256, args.backup, args.backup_sha256,
                read_key(args.key_file, args.key_sha256), args.destination,
            )
        else:
            import boto3
            from botocore.config import Config

            client = boto3.client("s3", region_name=args.region,
                                  config=Config(ignore_configured_endpoint_urls=True))
            pins = {"archive_pin": args.archive_sha256, "key_pin": args.public_key_sha256,
                    "terminal_pin": args.terminal_sha256}
            if args.action == "upload-worm":
                result = worm.upload(client, args.bucket, args.bucket_owner, args.retain_until,
                                     archive.read(args.archive), **pins)
            else:
                raw, result = worm.fetch(client, args.bucket, args.bucket_owner, args.version_id,
                                         args.retain_until, **pins)
                archive.write(raw, args.destination)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError,
            KeyError, RecursionError, sqlite3.Error, BotoCoreError, ClientError, InvalidTag) as error:
        detail = str(error) if isinstance(error, AuditTransferError) else type(error).__name__
        print(f"Generation archive operation refused ({detail}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
