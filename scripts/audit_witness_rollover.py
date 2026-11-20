"""Plan, approve, verify, or continue a local audit witness generation."""

import argparse
import json
import sqlite3
import sys

from app.services import audit_witness_rollover as rollover
from app.services.audit_transfer import AuditTransferError
from app.services.federated_audit import AuditQueryUnavailable
from scripts.audit_witness_observer import watch
from scripts.f1_lab import witness_observer_status as bridge
from scripts.witness_rollover_systemd import configuration

ERRORS = (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError,
          KeyError, RecursionError, sqlite3.Error)


def watch_generation(args):
    try:
        directory, pin, _ = rollover.collection_target(
            args.record, args.record_sha256, args.minimum_receipt,
            expected_profile=args.profile_sha256,
        )
        return watch(
            directory, pin, minimum_receipt=args.minimum_receipt, cycles=args.cycles,
            status_file=args.status_file, record_sha256=args.record_sha256,
        )
    except ERRORS:
        if args.status_file and args.profile_sha256:
            try:
                bridge.publish(args.status_file, bridge.report(
                    args.profile_sha256, args.minimum_receipt, cycle_success=False,
                    record_sha256=args.record_sha256,
                ))
            except ERRORS:
                print("Witness generation failure status could not be published.", file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "approve"):
        command = commands.add_parser(name)
        command.add_argument("--old-control", required=True)
        command.add_argument("--old-profile-sha256", required=True)
        command.add_argument("--old-terminal-sha256", required=True)
        command.add_argument("--new-signer", required=True)
        command.add_argument("--new-key-sha256", required=True)
        command.add_argument("--record", required=True)
        if name == "approve":
            command.add_argument("--approval-sha256", required=True)
    for name in ("verify", "watch", "systemd-config"):
        command = commands.add_parser(name)
        command.add_argument("--record", required=True)
        command.add_argument("--record-sha256", required=True)
        if name != "verify":
            command.add_argument("--minimum-receipt", required=True)
        if name == "watch":
            command.add_argument("--profile-sha256")
            command.add_argument("--cycles", type=int)
            command.add_argument("--status-file")
        if name == "systemd-config":
            command.add_argument("--status-directory", required=True)
    args = parser.parse_args()
    try:
        if args.action in {"plan", "approve"}:
            parameters = (args.old_control, args.old_profile_sha256, args.old_terminal_sha256,
                          args.new_signer, args.new_key_sha256, args.record)
            result = (rollover.plan(*parameters) if args.action == "plan"
                      else rollover.approve(*parameters, args.approval_sha256))
        elif args.action == "watch":
            return watch_generation(args)
        elif args.action == "systemd-config":
            result = configuration(args.record, args.record_sha256, args.minimum_receipt,
                                   args.status_directory)
        else:
            result = rollover.verify(args.record, args.record_sha256)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except ERRORS:
        print("Witness generation operation refused. Check the pinned inputs and journals.",
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
