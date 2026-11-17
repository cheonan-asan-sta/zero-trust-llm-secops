"""Pinned observed-development candidate; no truth is read in prediction."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.sensitive_auth_context import SensitiveAuthReview
from scripts.run_ordered_audit_review import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.plan, args.sha256, args.output, auth_review_factory=SensitiveAuthReview)
    print(json.dumps({'completed':report['completed'],'goal_qualified':False,
                      'new_independent_evaluation':False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
