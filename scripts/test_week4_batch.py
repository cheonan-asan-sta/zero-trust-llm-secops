"""Offline M5/M6/M7 plus existing Linux/mTLS/CA acceptance in one invocation."""

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from scripts.freeze_m7 import SOURCE, freeze_candidate, verify_frozen
from scripts.test_infra_preflight_batch import ROOT, Batch


def run(directory):
    directory = Path(directory).resolve()
    allowed = (ROOT / 'runtime/c02/infra-batches').resolve()
    if not directory.is_relative_to(allowed) or directory == allowed or directory.exists():
        raise ValueError('fresh_in_scope_directory_required')
    directory.mkdir(parents=True)
    report = {'schema': 'week4-local-batch-1', 'completed': False, 'stages': [],
              'started_at': datetime.now(UTC).isoformat(), 'cloud_calls': 0,
              'paid_model_calls': 0, 'independent_review': 'pending'}

    def save():
        (directory / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        anchor = freeze_candidate(SOURCE.parent / 'pilot', directory / 'm7-candidate')
        verify_frozen(directory / 'm7-candidate', anchor)
        report['stages'].append({'name': 'm7-freeze', 'passed': True, 'anchor': anchor})
        # evaluate_m6's dispatch is an offline mock; no provider can be selected here.
        env = dict(os.environ, ANALYZER_MODE='rule', APP_ENVIRONMENT='test',
                   AUTH_MODE='disabled', AWS_EC2_METADATA_DISABLED='true')
        with (directory / 'm6.log').open('w', encoding='utf8') as log:
            result = subprocess.run([sys.executable, '-m', 'scripts.evaluate_m6', '--output',
                str(directory / 'm6-mock.json')], cwd=ROOT, env=env, stdout=log,
                stderr=subprocess.STDOUT, timeout=120, check=False)
        report['stages'].append({'name': 'm6-offline-contract', 'passed': result.returncode == 0,
                                 'actual_model_comparison': False})
        save()
        batch = Batch(directory / 'infrastructure')
        report['stages'].append({'name': 'linux-monitoring-authority', 'passed': batch.run(),
                                 'report': 'infrastructure/verification.json'})
        report['completed'] = all(s['passed'] for s in report['stages'])
    finally:
        report['finished_at'] = datetime.now(UTC).isoformat()
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/infra-batches' /
                        ('week4-' + uuid4().hex[:12]))
    args = parser.parse_args()
    try:
        report = run(args.directory)
    except (ValueError, OSError, subprocess.SubprocessError):
        print(json.dumps({'completed': False, 'reason': 'see_local_report'}))
        return 1
    print(json.dumps(report))
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
