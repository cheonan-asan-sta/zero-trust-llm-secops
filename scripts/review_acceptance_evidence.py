"""Offline review of one complete CI run; never records human approval.

Inputs are locally supplied GitHub CLI exports, not signed attestations. Keep the
original CI URL/log hashes so a reviewer can independently inspect the source.
"""

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from scripts.runtime_release import digest

RUNTIME_REPORTS = {
    'application': ('app-maintenance-recovery-1', 25),
    'application-mtls': ('recoverable-mtls-verification-1', 13),
    'response-mtls': ('response-mtls-verification-1', 16),
    'execution-mtls': ('execution-mtls-verification-1', 25),
    'monitored': ('monitored-continuous-mtls-verification-1', 75),
    'authority': ('authority-continuous-mtls-verification-1', 30),
    'rekey': ('persistent-leaf-rekey-verification-1', 22),
    'authority-ha': ('persistent-authority-ha-verification-1', 38),
    'database-transport': ('database-transport-rotation-verification-1', 54),
    'database-backup': ('database-backup-verification-1', 67),
    'database-recovery': ('database-recovery-checkpoint-verification-1', 17),
    'selection': ('infrastructure-selection-verification-2', 37),
}
SHA = re.compile(r'[a-f0-9]{40}\Z')
LABEL = re.compile(r'[a-zA-Z0-9_.:-]{1,180}\Z')
RUN_URL = re.compile(r'https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+\Z')
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
LIMITS = ('Local Docker fixtures and supplied CI exports only. Not a human review, '
          'production approval, independent detection benchmark or cloud deployment.')


def require(condition, code):
    if not condition:
        raise ValueError(code)


def extract_reports(log):
    """Read gh run view --log output, retaining the runtime/Report step binding."""
    groups = defaultdict(list)
    for line in ANSI.sub('', log).splitlines():
        parts = line.split('\t', 2)
        if len(parts) != 3 or not parts[0].startswith('runtime (') or not parts[1].startswith('Report '):
            continue
        kind = parts[0][9:-1]
        if kind in RUNTIME_REPORTS:
            groups[(kind, parts[1])].append(re.sub(r'^\S+Z ', '', parts[2]))
    reports = {}
    for (kind, _), lines in groups.items():
        raw = '\n'.join(lines)
        candidates = []
        for match in re.finditer(r'^\{', raw, re.MULTILINE):
            try:
                value, _ = json.JSONDecoder().raw_decode(raw[match.start():])
            except ValueError:
                continue
            if isinstance(value, dict) and isinstance(value.get('checks'), (list, dict)):
                candidates.append(value)
        require(len(candidates) == 1 and kind not in reports, 'ambiguous_or_missing_runtime_report')
        reports[kind] = candidates[0]
    require(set(reports) == set(RUNTIME_REPORTS), 'missing_runtime_report')
    return reports


def review(ci, reports, expected_commit):
    require(isinstance(expected_commit, str) and SHA.fullmatch(expected_commit), 'invalid_expected_commit')
    require(isinstance(ci, dict) and ci.get('headSha') == expected_commit, 'ci_commit_mismatch')
    require(ci.get('status') == 'completed' and ci.get('conclusion') == 'success', 'ci_not_successful')
    url = ci.get('url')
    require(isinstance(url, str) and RUN_URL.fullmatch(url), 'invalid_ci_url')
    jobs = ci.get('jobs')
    require(isinstance(jobs, list) and all(isinstance(row, dict) for row in jobs), 'invalid_ci_jobs')
    names = [row.get('name') for row in jobs]
    required = {'unit', 'docker', 'lambda', 'test'} | {'runtime (' + kind + ')' for kind in RUNTIME_REPORTS}
    require(all(isinstance(name, str) for name in names) and len(names) == len(required)
            and set(names) == required, 'missing_or_duplicate_ci_job')
    require(all(row.get('status') == 'completed' and row.get('conclusion') == 'success'
                and isinstance(row.get('url'), str) and row['url'].startswith(url + '/job/')
                for row in jobs), 'ci_job_not_successful_or_unbound')
    require(set(reports) == set(RUNTIME_REPORTS), 'missing_runtime_report')
    rows = []
    for kind, (schema, minimum) in RUNTIME_REPORTS.items():
        report = reports[kind]
        require(isinstance(report, dict) and report.get('schema') == schema, 'report_schema_mismatch')
        require(report.get('completed' if kind != 'application' else 'passed') is True,
                'runtime_not_successful')
        require('error' not in report and 'failure_diagnostics' not in report, 'runtime_has_failure')
        require(report.get('source_dirty', False) is False, 'dirty_report_source')
        commit = report.get('base_git_head' if kind == 'application' else 'source_commit')
        require(commit == expected_commit or (kind == 'execution-mtls' and commit is None),
                'report_commit_mismatch')
        checks = report.get('checks')
        if isinstance(checks, dict):
            require(all(value is True for value in checks.values()), 'runtime_check_failed')
            labels = list(checks)
        else:
            require(isinstance(checks, list) and all(isinstance(row, dict) and row.get('passed') is True
                                                    for row in checks), 'runtime_check_failed')
            labels = [row.get('label') for row in checks]
        require(all(isinstance(label, str) and LABEL.fullmatch(label) for label in labels)
                and len(labels) >= minimum and len(set(labels)) == len(labels),
                'runtime_checks_missing_or_invalid')
        cleanup = report.get('cleanup')
        require(isinstance(cleanup, dict), 'runtime_cleanup_missing')
        if kind == 'execution-mtls':
            require(cleanup.get('stopped') is True and cleanup.get('purged') is True, 'runtime_cleanup_failed')
            release = report.get('release')
            require(isinstance(release, dict) and isinstance(release.get('payload'), dict)
                    and release.get('sha256') == digest(release['payload']), 'runtime_release_invalid')
            source_binding = ('embedded Git SHA, CI job and internally consistent runtime release' if commit else
                              'CI job plus internally consistent runtime release; no embedded Git SHA')
        else:
            require(all(type(cleanup.get(key)) is int and cleanup[key] == 0 for key in
                        (('containers', 'volumes') if kind == 'application' else
                         ('containers', 'volumes', 'networks'))), 'runtime_cleanup_failed')
            source_binding = 'embedded Git SHA and CI job'
        rows.append({'kind': kind, 'schema': schema, 'checks': len(labels), 'labels': labels,
                     'report_sha256': digest(report), 'source_binding': source_binding,
                     'job_url': next(row['url'] for row in jobs if row['name'] == 'runtime (' + kind + ')')})
    return {'schema': 'app-acceptance-evidence-review-1', 'completed': True,
            'source_commit': expected_commit, 'ci_url': url, 'ci_jobs': len(jobs),
            'runtime_checks': sum(row['checks'] for row in rows), 'reports': rows,
            'human_independent_review': False, 'human_approval': None, 'limits': LIMITS}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ci-json', required=True, type=Path)
    parser.add_argument('--ci-log', required=True, type=Path)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(not args.directory.exists(), 'fresh_output_directory_required')
        raw = []
        for path, limit in ((args.ci_json, 4 * 1024**2), (args.ci_log, 64 * 1024**2)):
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
                    'invalid_or_oversized_input')
            with path.open('rb') as source:
                contents = source.read(limit + 1)
            require(len(contents) <= limit, 'invalid_or_oversized_input')
            raw.append(contents)
        reports = extract_reports(raw[1].decode('utf-8'))
        result = review(json.loads(raw[0]), reports, args.expected_commit)
        result.update(reviewed_at=datetime.now(UTC).isoformat(),
                      input_sha256={'ci_json': hashlib.sha256(raw[0]).hexdigest(),
                                    'ci_log': hashlib.sha256(raw[1]).hexdigest()})
        args.directory.mkdir(parents=True)
        (args.directory / 'review.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({key: result[key] for key in ('completed', 'source_commit', 'ci_jobs',
                                                      'runtime_checks', 'human_independent_review')}))
    except (ValueError, OSError, UnicodeError) as error:
        # Input contents may contain credentials. Only bounded, owned codes escape.
        code = str(error) if type(error) is ValueError and str(error) in {
            'fresh_output_directory_required', 'invalid_or_oversized_input', 'missing_runtime_report',
            'ci_commit_mismatch', 'ci_not_successful', 'ci_job_not_successful_or_unbound',
        } else type(error).__name__
        print(json.dumps({'completed': False, 'error': code}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
