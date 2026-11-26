"""Publish a pinned keyless restore check; cannot grant or activate services."""

import argparse
import json
import sys
from pathlib import Path

from app.services.audit_transfer import require
from scripts.f1_lab import witness_restore_status as status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--status-file", required=True)
    for key in status.PINS:
        parser.add_argument("--" + key.replace("_", "-"), required=True)
    args = parser.parse_args()
    try:
        output = Path(args.status_file)
        require(output.is_absolute() and not output.resolve().is_relative_to(Path(args.directory).resolve())
                and output.resolve() != Path(args.package).resolve(), "witness_restore_public_overlap")
        binding = {k: getattr(args, k) for k in status.PINS}
        value = status.inspect(args.package, args.directory, binding)
        status.publish(output, value)
        verified = bool(value["values"])
        print(json.dumps({"published": True, "verified": verified, "decryption_checked": False,
                          "live_source_checked": False, "automatic_activation_allowed": False}))
        return 0 if verified else 1
    except status.ERRORS:
        print("Witness restore status refused; no pin or service changes.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
