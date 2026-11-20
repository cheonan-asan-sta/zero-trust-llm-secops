"""Plan, approve, verify, or continue a local audit witness generation."""

import argparse
import json
import sqlite3
import sys

from app.services import audit_witness_rollover as rollover
from app.services.audit_transfer import AuditTransferError
from app.services.federated_audit import AuditQueryUnavailable
from scripts.audit_witness_observer import watch


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
    for name in ("verify", "watch"):
        command = commands.add_parser(name)
        command.add_argument("--record", required=True)
        command.add_argument("--record-sha256", required=True)
        if name == "watch":
            command.add_argument("--minimum-receipt", required=True)
            command.add_argument("--cycles", type=int)
            command.add_argument("--status-file")
    args = parser.parse_args()
    try:
        if args.action in {"plan", "approve"}:
            parameters = (args.old_control, args.old_profile_sha256, args.old_terminal_sha256,
                          args.new_signer, args.new_key_sha256, args.record)
            result = (rollover.plan(*parameters) if args.action == "plan"
                      else rollover.approve(*parameters, args.approval_sha256))
        else:
            result = rollover.verify(args.record, args.record_sha256)
            if args.action == "watch":
                # An explicit newer minimum is checked by the normal observer.
                from app.services import audit_witness_observer as observer

                directory, profile, public = observer._load(
                    result["directory"], result["profile_sha256"],
                )
                with observer._database(directory) as con:
                    observer._read(con, profile, public, args.minimum_receipt)
                return watch(
                    directory, result["profile_sha256"], minimum_receipt=args.minimum_receipt,
                    cycles=args.cycles, status_file=args.status_file,
                )
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError,
            KeyError, RecursionError, sqlite3.Error):
        print("Witness generation operation refused. Check the pinned inputs and journals.",
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
