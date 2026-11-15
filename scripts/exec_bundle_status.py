"""Publish advisory bundle integrity without recovery/signing keys or activation."""

import argparse
import json
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from scripts.f1_lab import exec_bundle_status as status
from scripts.f1_lab.backup_recovery_status import public_destination
from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.service_caller_identity import PinnedCallerRegistry
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tenant', 'server', 'unit', 'source', 'registry-sha256', 'caller-registry-sha256',
                 'checkpoint-sha256', 'receipt-sha256'):
        parser.add_argument('--'+name, required=True)
    for name in ('registry', 'caller-registry', 'package', 'checkpoint', 'review', 'status-output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--caller-environment', choices=('oidc', 'local_oidc'), default='oidc')
    parser.add_argument('--observe-worker-security', action='store_true')
    args = parser.parse_args()
    completed = False
    try:
        scope = ArchiveScope(tenant_id=args.tenant, server_id=args.server, unit=args.unit, source_id=args.source)
        output = public_destination(args.status_output, args.package, args.review, args.checkpoint)
        try:
            value = status.inspect(scope, args.package, args.checkpoint, args.checkpoint_sha256,
                args.review, args.receipt_sha256, PinnedServiceRegistry(args.registry, args.registry_sha256),
                PinnedCallerRegistry(args.caller_registry, args.caller_registry_sha256,
                                     expected_environment=args.caller_environment))
            completed = True
        except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, RuntimeError, InvalidSignature, RecursionError):
            value = status.report(scope)
        status.publish(output, value)
    except (ValueError, TypeError, KeyError, OSError, RuntimeError):
        completed = False
    result = {'completed': completed, 'state': 'verified' if completed else 'unavailable',
              'automatic_activation_allowed': False, 'automatic_execution_allowed': False,
              'authorization_asserted': False}
    if args.observe_worker_security:
        result['worker_security'] = current_security_status()
    print(json.dumps(result))
    return 0 if completed else 2


if __name__ == '__main__':
    raise SystemExit(main())
