"""Retry publication of one private sealed outbox record, never its execution."""

import argparse
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from scripts.f1_lab.capture_backup import private_directory, private_file
from scripts.f1_lab.collector_freshness import MAX_CAPTURE
from scripts.f1_lab.managed_exec_retention import publish_sealed
from scripts.f1_lab.service_caller_identity import PinnedCallerRegistry
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "root", "registry", "caller-registry"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--registry-sha256", required=True)
    parser.add_argument("--caller-registry-sha256", required=True)
    parser.add_argument("--caller-environment", choices=("oidc", "local_oidc"), default="oidc")
    args = parser.parse_args()
    try:
        private_directory(args.capture.parent)
        result = publish_sealed(
            private_file(args.capture, MAX_CAPTURE),
            args.root,
            PinnedServiceRegistry(args.registry, args.registry_sha256),
            PinnedCallerRegistry(
                args.caller_registry,
                args.caller_registry_sha256,
                expected_environment=args.caller_environment,
            ),
        )
    except (ValueError, OSError, InvalidSignature):
        result = {
            "completed": False,
            "automatic_execution_allowed": False,
            "reason": "sealed_publication_unavailable",
        }
    print(json.dumps(result))
    return 0 if result["completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
