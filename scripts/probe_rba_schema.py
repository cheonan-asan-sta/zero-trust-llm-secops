"""Inspect at most128 RBA development CSV records after external archive anchoring."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.rba_probe import probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--member', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.archive, args.expected_sha256, args.member, args.output)
    print(json.dumps({key: result[key] for key in ('completed', 'header', 'development_records_parsed',
                                                   'literal_boolean_states', 'timestamp_shapes', 'goal_qualified')}))


if __name__ == '__main__':
    main()
