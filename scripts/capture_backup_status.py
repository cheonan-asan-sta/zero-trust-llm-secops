"""Publish advisory pinned backup/recovery verification; never decrypt, repin or activate."""

import argparse
import json
import sqlite3
from pathlib import Path

from scripts.f1_lab import backup_recovery_status as status
from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.collector_security import current_security_status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "tenant",
        "server",
        "unit",
        "source",
        "manifest-sha256",
        "checkpoint-sha256",
        "receipt-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    for name in ("backup", "review", "checkpoint", "status-file"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    completed = False
    try:
        scope = ArchiveScope(
            tenant_id=args.tenant, server_id=args.server, unit=args.unit, source_id=args.source
        )
        destination = status.public_destination(
            args.status_file, args.backup, args.review, args.checkpoint
        )
        try:
            value = status.inspect(
                scope,
                args.backup,
                args.manifest_sha256,
                args.checkpoint,
                args.checkpoint_sha256,
                args.review,
                args.receipt_sha256,
            )
            completed = True
        except (ValueError, OSError, sqlite3.Error, RecursionError):
            value = status.report(scope)
        status.publish(destination, value)
    except (ValueError, OSError, sqlite3.Error, RecursionError):
        completed = False
    print(
        json.dumps(
            {
                "completed": completed,
                "state": "verified" if completed else "unavailable",
                "automatic_activation_allowed": False,
                "authenticity_or_freshness_asserted": False,
                "worker_security": current_security_status(),
            }
        )
    )
    return 0 if completed else 2


if __name__ == "__main__":
    raise SystemExit(main())
