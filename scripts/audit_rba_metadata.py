"""Run the pinned, metadata-only RBA support audit without a classifier."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.rba_metadata import audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--protocol', type=Path, required=True)
    parser.add_argument('--expected-protocol-sha256', required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.archive, args.protocol, args.expected_protocol_sha256, args.probe, args.output)
    print(json.dumps({key: result[key] for key in ('completed', 'records', 'structural_errors',
                                                   'classifier_fitted', 'goal_qualified')}))
    return 0 if result['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
