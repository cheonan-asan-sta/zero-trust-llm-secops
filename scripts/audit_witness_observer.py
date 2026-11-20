"""Local pinned witness collector. Does not install services or activate restores."""

import argparse
import json
import sqlite3
import sys
import time

from app.services import audit_witness_observer as observer
from app.services.audit_transfer import AuditTransferError
from app.services.federated_audit import AuditQueryUnavailable

ERRORS = (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError, sqlite3.Error)


def watch(directory, profile_sha256, *, minimum_receipt, cycles=None, status_file=None,
          record_sha256=None):
    if cycles is not None and (type(cycles) is not int or not 1 <= cycles <= 10000):
        raise ValueError("observer watch cycles rejected")
    _directory, profile, _public = observer._load(directory, profile_sha256)
    completed, failures = 0, 0
    while cycles is None or completed < cycles:
        started = time.monotonic()
        try:
            result = observer.cycle(directory, profile_sha256, minimum_receipt=minimum_receipt)
            state = observer.status(directory, profile_sha256, minimum_receipt=minimum_receipt)
            state["recovered"] = result["recovered"]
            state["cycle_success"] = True
        except ERRORS:
            # A durable pending ID is retained. Do not replace the profile,
            # expected receipt or signing key to make the next cycle succeed.
            failures += 1
            try:
                state = observer.status(directory, profile_sha256, minimum_receipt=minimum_receipt)
            except ERRORS:
                state = {"state": "unavailable", "healthy": False,
                         "independent_storage_verified": False, "automatic_activation_allowed": False}
            # A successful read after a failed collection does not prove the
            # signing capability or erase the failed cycle.
            state["cycle_success"] = False
        if status_file is not None:
            from scripts.f1_lab import witness_observer_status as bridge

            bridge.publish(status_file, bridge.inspect(
                directory, profile_sha256, minimum_receipt, cycle_success=state["cycle_success"],
                record_sha256=record_sha256,
            ))
        completed += 1
        print(json.dumps(state, ensure_ascii=False, allow_nan=False), flush=True)
        if cycles is None or completed < cycles:
            time.sleep(max(0, profile["interval_seconds"] - (time.monotonic() - started)))
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init")
    init.add_argument("--directory", required=True)
    init.add_argument("--witness-directory", required=True)
    init.add_argument("--database", required=True)
    init.add_argument("--public-key-sha256", required=True)
    init.add_argument("--expected-receipt", required=True)
    init.add_argument("--interval-seconds", type=int, default=60)
    init.add_argument("--max-age-seconds", type=int, default=180)
    init.add_argument("--capacity-warning", type=int, default=16)
    for action in ("cycle", "status", "watch", "export-status"):
        command = commands.add_parser(action)
        command.add_argument("--directory", required=True)
        command.add_argument("--profile-sha256", required=True)
        command.add_argument("--minimum-receipt", required=True)
        if action == "status":
            command.add_argument("--offline", action="store_true")
        elif action == "watch":
            command.add_argument("--cycles", type=int)
            command.add_argument("--status-file")
        elif action == "export-status":
            command.add_argument("--status-file", required=True)
    args = parser.parse_args()
    try:
        if args.action == "init":
            result = observer.initialize(
                args.directory,
                args.witness_directory,
                args.database,
                args.public_key_sha256,
                expected_receipt=args.expected_receipt,
                interval_seconds=args.interval_seconds,
                max_age_seconds=args.max_age_seconds,
                capacity_warning=args.capacity_warning,
            )
        elif args.action == "cycle":
            result = observer.cycle(
                args.directory, args.profile_sha256, minimum_receipt=args.minimum_receipt
            )
        elif args.action == "status":
            result = observer.status(
                args.directory,
                args.profile_sha256,
                minimum_receipt=args.minimum_receipt,
                offline=args.offline,
            )
        elif args.action == "export-status":
            from scripts.f1_lab import witness_observer_status as bridge

            value = bridge.inspect(args.directory, args.profile_sha256, args.minimum_receipt)
            bridge.publish(args.status_file, value)
            result = {"published": True, "healthy": value["values"].get("state") == "healthy",
                      "automatic_activation_allowed": False, "independent_storage_verified": False}
        else:
            return watch(
                args.directory,
                args.profile_sha256,
                minimum_receipt=args.minimum_receipt,
                cycles=args.cycles,
                status_file=args.status_file,
            )
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0 if args.action not in {"status", "export-status"} or result["healthy"] else 1
    except ERRORS:
        print(
            "Local observer refused operation; pins and pending state were not reset.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        # Committed pending state remains available for the next owned process.
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
