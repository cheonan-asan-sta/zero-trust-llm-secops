"""Inspect historical PAM storage against an independently retained SHA256 pin.

No capture admission, signing key, current trust renewal or activation occurs.
Save the reported checkpoint SHA outside the observation DB's trust boundary.
"""

import argparse
import json
import sqlite3

from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.pam_observation_ledger import PamObservationLedger


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tenant', 'server', 'unit', 'source', 'key-id', 'ledger-directory'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--expected-sha256', help='Previously retained external checkpoint; never infer from the DB')
    parser.add_argument('--capacity', type=int, default=1000)
    parser.add_argument('--event-capacity', type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        scope = CollectorScope(tenant_id=args.tenant, server_id=args.server, unit=args.unit,
                               source_id=args.source, key_id=args.key_id)
        ledger = PamObservationLedger(args.ledger_directory, scope,
            capacity=args.capacity, event_capacity=args.event_capacity)
        result = ledger.checkpoint(args.expected_sha256)
        result['worker_security'] = current_security_status()
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, sqlite3.Error):
        print(json.dumps({'schema': 'zt-pam-observation-checkpoint-1', 'completed': False,
            'state': 'unavailable', 'external_pin_matched': False,
            'current_freshness_verified': False, 'human_authenticated': False,
            'authorization_asserted': False, 'automatic_enforcement_allowed': False,
            'goal_qualified': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
