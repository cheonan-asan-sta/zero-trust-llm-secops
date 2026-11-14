"""Preview or explicitly compact owned capture files, or restore exact old bytes."""

import argparse
import json
import sqlite3
import zlib
from pathlib import Path

from scripts.f1_lab.capture_archive import ArchiveFull, ArchivePolicy, ArchiveScope, CaptureArchive
from scripts.f1_lab.collector_security import current_security_status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "tenant", "server", "unit", "source"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--max-hot-records", type=int, default=100)
    parser.add_argument("--max-hot-bytes", type=int, default=16 * 1024**2)
    parser.add_argument("--max-records", type=int, default=10000)
    parser.add_argument("--max-raw-bytes", type=int, default=256 * 1024**2)
    parser.add_argument("--batch-size", type=int, default=64)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--restore", help="Exact32hex collector invocation directory ID")
    parser.add_argument(
        "--output", type=Path, help="New directory outside the managed root, required for restore"
    )
    parser.add_argument(
        "--status-output", type=Path, help="Optional public aggregate snapshot for apply"
    )
    args = parser.parse_args()
    if args.status_output and not args.apply:
        parser.error("--status-output requires --apply")
    if bool(args.restore) != bool(args.output):
        parser.error("--restore and --output must be supplied together")
    scope = None
    try:
        scope = ArchiveScope(
            tenant_id=args.tenant, server_id=args.server, unit=args.unit, source_id=args.source
        )
        archive = CaptureArchive(
            Path(args.root),
            scope,
            policy=ArchivePolicy(
                max_hot_records=args.max_hot_records,
                max_hot_bytes=args.max_hot_bytes,
                max_records=args.max_records,
                max_raw_bytes=args.max_raw_bytes,
                batch_size=args.batch_size,
            ),
        )
        if args.restore:
            result = archive.restore(args.restore, args.output)
            result["mode"] = "restore"
            result["state"] = "restored_for_review"
        else:
            result = archive.compact(apply=args.apply)
            result["mode"] = "apply" if args.apply else "preview"
            met = (
                result["managed_budget_satisfied"]
                if args.apply
                else result["projected_budget_satisfied"]
            )
            result["state"] = (
                "ready" if met and result["archive_capacity_available"] else "storage_pressure"
            )
        result["worker_security"] = current_security_status()
        if args.status_output:
            from scripts.f1_lab.collector_status_bridge import archive_report, publish

            publish(args.status_output, archive_report(scope, result))
        print(json.dumps(result))
        return 0 if result["state"] in {"ready", "restored_for_review"} else 2
    except (ValueError, OSError, sqlite3.Error, zlib.error, RecursionError) as error:
        state = "storage_pressure" if isinstance(error, ArchiveFull) else "unavailable"
        if args.status_output and scope is not None:
            try:
                from scripts.f1_lab.collector_status_bridge import archive_report, publish

                publish(
                    args.status_output, archive_report(scope, {"completed": False, "state": state})
                )
            except (ValueError, OSError, RecursionError):
                pass  # Previous report expires; never retain an indefinitely healthy value.
        print(
            json.dumps(
                {
                    "completed": False,
                    "state": state,
                    "error_type": type(error).__name__,
                    "authenticity_or_freshness_asserted": False,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
