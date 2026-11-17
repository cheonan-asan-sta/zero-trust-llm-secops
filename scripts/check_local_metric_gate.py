"""Check pinned evaluator counts locally, without starting CI or deployment."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.local_metric_gate import evaluate
from scripts.f1_lab.native_jsonl import decode, require


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--track', choices=['observed_log_kinds', 'original_security_domains'], required=True)
    args = parser.parse_args(argv)
    try:
        require(args.report.is_file() and not args.report.is_symlink()
                and args.report.stat().st_size <= 2*1024**2, 'metric_gate_report_bound')
        with args.report.open('rb') as stream:
            raw = stream.read(2*1024**2+1)
        require(0 < len(raw) <= 2*1024**2 and hashlib.sha256(raw).hexdigest() == args.sha256,
                'metric_gate_report_pin')
        value = decode(raw)
        require(type(value) is dict and set(value) == {'schema', 'track', 'rows'}
            and value['schema'] == 'local-metric-counts-1' and value['track'] == args.track,
            'metric_gate_report_schema')
        result = evaluate(value['rows'], track=args.track)
        result['input_sha256'] = args.sha256
        print(json.dumps(result))
        return 0 if result['local_metric_gate_passed'] else 1
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({'schema': 'local-metric-gate-1', 'completed': False,
            'local_metric_gate_passed': False, 'goal_qualified': False, 'ci_or_merge_started': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
