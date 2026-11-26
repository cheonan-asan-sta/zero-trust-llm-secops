"""Approve a verified restore and run the selected witness collector."""

import argparse
import json
import sys
from pathlib import Path

from app.services import audit_witness as witness
from app.services import audit_witness_activation as activation
from app.services.audit_transfer import require
from scripts.audit_witness_observer import watch
from scripts.f1_lab import witness_observer_status as bridge
from scripts.witness_rollover_systemd import render_configuration, unit_path


def managed_watch(args):
    try:
        directory, pin, _ = activation.target(
            args.journal, args.activation_sha256, args.minimum_receipt,
        )
        require(args.profile_sha256 is None or args.profile_sha256 == pin,
                "active restore profile pin mismatch")
    except activation.ERRORS as error:
        activation.record_failure(args.journal, args.activation_sha256, error, kind="startup_failed")
        raise
    return watch(
        directory, pin, minimum_receipt=args.minimum_receipt, cycles=args.cycles,
        status_file=args.status_file, record_sha256=args.activation_sha256,
        collect=lambda: activation.cycle(args.journal, args.activation_sha256, args.minimum_receipt),
    )


def configuration(journal, activation_pin, minimum, cache):
    journal = unit_path(journal)
    directory, pin, profile = activation.target(journal, activation_pin, minimum)
    for path in (directory, Path(profile["witness_directory"]), Path(profile["database"])):
        require(not path.resolve().is_relative_to(journal.parent)
                and not journal.parent.is_relative_to(path.resolve()),
                "use a dedicated activation journal directory")
    return render_configuration(
        directory, pin, profile, cache, activation_pin, minimum,
        f"scripts.audit_witness_activation watch --journal {journal} --activation-sha256 {activation_pin}",
        writable=(journal.parent,),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("init", "plan", "activate", "history", "watch", "cycle", "systemd-config"):
        command = commands.add_parser(action)
        command.add_argument("--journal", required=True)
        if action in {"plan", "activate"}:
            for flag in ("directory", "package", "backup-sha256", "restore-receipt-sha256",
                         "profile-sha256", "minimum-receipt", "expected-active-sha256"):
                command.add_argument(f"--{flag}", required=True)
        if action == "activate":
            command.add_argument("--approval-sha256", required=True)
            command.add_argument("--operator", required=True)
        if action == "history":
            command.add_argument("--expected-head-sha256")
        if action in {"watch", "cycle", "systemd-config"}:
            command.add_argument("--activation-sha256", required=True)
            command.add_argument("--minimum-receipt", required=True)
        if action == "watch":
            command.add_argument("--cycles", type=int)
            command.add_argument("--status-file")
            command.add_argument("--profile-sha256")
        if action == "systemd-config":
            command.add_argument("--status-directory", required=True)
    args = parser.parse_args()
    try:
        if args.action == "init":
            activation.initialize(args.journal)
            result = {"active_sha256": witness.GENESIS}
        elif args.action == "history":
            result = activation.history(args.journal, args.expected_head_sha256)
        elif args.action == "cycle":
            result = activation.cycle(args.journal, args.activation_sha256, args.minimum_receipt)
        elif args.action == "systemd-config":
            result = configuration(args.journal, args.activation_sha256,
                                   args.minimum_receipt, args.status_directory)
        elif args.action == "watch":
            try:
                return managed_watch(args)
            except activation.ERRORS:
                if args.status_file and args.profile_sha256:
                    bridge.publish(args.status_file, bridge.report(
                        args.profile_sha256, args.minimum_receipt, cycle_success=False,
                        record_sha256=args.activation_sha256,
                    ))
                raise
        else:
            params = (args.journal, args.directory, args.package, args.backup_sha256,
                      args.restore_receipt_sha256, args.profile_sha256, args.minimum_receipt,
                      args.expected_active_sha256)
            result = (activation.plan(*params) if args.action == "plan"
                      else activation.activate(*params, args.approval_sha256, args.operator))
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except activation.ERRORS as error:
        print(f"Witness restore operation refused ({type(error).__name__}).", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
