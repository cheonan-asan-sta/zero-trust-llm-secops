"""Explicit local witness commands. Never launches an app or activates a restore."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from app.services import audit_witness as witness
from app.services.audit_transfer import AuditTransferError, decode, require
from app.services.federated_audit import AuditQueryUnavailable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init")
    init.add_argument("--state-dir", required=True)
    init.add_argument("--database", required=True)
    init.add_argument("--stream-id", required=True)
    for name in ("observe", "status"):
        command = sub.add_parser(name)
        command.add_argument("--state-dir", required=True)
        command.add_argument("--public-key-sha256", required=True)
        if name == "observe":
            command.add_argument("--database", required=True)
            command.add_argument("--expected-receipt", required=True)
        else:
            command.add_argument("--minimum-receipt", required=True)
    command = sub.add_parser("inspect")
    command.add_argument("--database", required=True)
    command.add_argument("--receipt-file", required=True)
    command.add_argument("--expected-receipt", required=True)
    command.add_argument("--public-key-file", required=True)
    command.add_argument("--public-key-sha256", required=True)
    command.add_argument("--stream-id", required=True)
    args = parser.parse_args()
    try:
        if args.action == "init":
            result = witness.initialize(args.state_dir, args.database, args.stream_id)
        elif args.action == "observe":
            result = witness.observe(
                args.state_dir,
                args.database,
                args.public_key_sha256,
                expected_receipt=args.expected_receipt,
            )
        elif args.action == "status":
            result = witness.status(
                args.state_dir, args.public_key_sha256, minimum_receipt=args.minimum_receipt
            )
        else:
            receipt_file, public_file = Path(args.receipt_file), Path(args.public_key_file)
            require(
                not receipt_file.is_symlink() and receipt_file.stat().st_size <= 16384,
                "receipt file rejected",
            )
            require(
                not public_file.is_symlink() and public_file.stat().st_size == 32,
                "public key file rejected",
            )
            # Observe/status output wraps the signed receipt; inspect only accepts
            # the signed envelope itself, so export it explicitly for the caller.
            receipt = decode(receipt_file.read_bytes())
            result = witness.inspect(
                args.database,
                receipt,
                public_file.read_bytes(),
                public_key_sha256=args.public_key_sha256,
                stream_id=args.stream_id,
                expected_receipt=args.expected_receipt,
            )
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (
        AuditTransferError,
        AuditQueryUnavailable,
        OSError,
        ValueError,
        TypeError,
        sqlite3.Error,
    ):
        # Do not echo supplied paths, credentials, source payload or key material.
        print(
            "Local audit witness refused this operation; no automatic retry or activation.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
