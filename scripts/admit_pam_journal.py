"""Admit an explicitly pinned, current PAM capture without any signing key."""

import argparse
import json
import sqlite3

from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.pam_journal import verify
from scripts.f1_lab.pam_observation_ledger import PamObservationLedger
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry
from scripts.verify_pam_journal import read_pinned


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tenant', 'server', 'unit', 'source', 'key-id', 'registry', 'registry-sha256',
                 'capture', 'capture-sha256', 'boot-id', 'invocation-id', 'ledger-directory'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--initialize', action='store_true', help='Create a fresh private ledger; never replace an existing one')
    args = parser.parse_args(argv)
    try:
        scope = CollectorScope(tenant_id=args.tenant, server_id=args.server, unit=args.unit,
                               source_id=args.source, key_id=args.key_id)
        pinned = PinnedServiceRegistry(args.registry, args.registry_sha256)
        capture = read_pinned(args.capture, args.capture_sha256)
        verify(capture, scope, pinned, boot=args.boot_id, invocation=args.invocation_id)
        ledger = PamObservationLedger(args.ledger_directory, scope)
        if args.initialize:
            ledger.initialize()
        result = ledger.admit(capture, pinned, boot=args.boot_id, invocation=args.invocation_id)
        result['worker_security'] = current_security_status()
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, sqlite3.Error):
        print(json.dumps({'schema': 'zt-pam-observation-admission-1', 'completed': False,
            'state': 'unavailable', 'human_authenticated': False, 'authorization_asserted': False,
            'automatic_enforcement_allowed': False, 'goal_qualified': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
