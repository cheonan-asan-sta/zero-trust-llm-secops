"""One frozen-source local batch: Linux regression, monitoring and authority HA.

No cloud or model calls. Stages are sequential to avoid shared download-cache
races and to limit load on a user's existing Docker workloads. No auto retry.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts import runtime_release as release
from scripts.continuous_mtls_runtime import ROOT

STAGES = (('linux', None, 0),
          ('monitored', 'scripts.test_continuous_mtls_runtime', 75),
          ('authority-ha', 'scripts.test_database_backup_runtime', 67))


def source_manifest():
    files = set(release.capture(ROOT, {})['payload']['files'])
    files.update(('Dockerfile.test', 'Dockerfile.lambda', 'compose.yaml', 'compose.signals.yaml'))
    for folder, suffixes in [('tests', {'.py'}), ('.github', {'.yml', '.yaml'})]:
        files.update(p.relative_to(ROOT).as_posix() for p in (ROOT / folder).rglob('*')
                     if p.is_file() and p.suffix in suffixes and '__pycache__' not in p.parts)
    return {name: release.file_digest(ROOT / name) for name in sorted(files)}


def output(*argv):
    return subprocess.check_output(argv, cwd=ROOT, text=True, encoding='utf-8', errors='replace', timeout=30).strip()


def validate_report(report, minimum, source, head):
    checks = report.get('checks')
    if (report.get('completed') is not True or not isinstance(checks, list) or len(checks) < minimum
            or not all(c.get('passed') is True for c in checks)
            or report.get('cleanup') != {'containers': 0, 'volumes': 0, 'networks': 0}
            or report.get('source_commit') != head or report.get('image_source_verified') is not True
            or report.get('release_image_payload_verified') is not True):
        raise ValueError('batch_acceptance_incomplete')
    inputs = report.get('source_input_sha256')
    expected = {name for name in source if name.startswith(('app/', 'scripts/')) and name.endswith('.py')}
    if not isinstance(inputs, dict) or not inputs or set(inputs) != expected:
        raise ValueError('batch_source_evidence_missing')
    for name, digest in inputs.items():
        if name not in source or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('batch_acceptance_source_mismatch')
    return len(checks)


class Batch:
    def __init__(self, directory):
        allowed = (ROOT / 'runtime/c02/infra-batches').resolve()
        self.directory = Path(directory).resolve()
        if self.directory == allowed or not self.directory.is_relative_to(allowed) or self.directory.exists():
            raise ValueError('batch_fresh_directory_required')
        self.directory.mkdir(parents=True)
        self.ident = 'infra-batch-' + uuid.uuid4().hex[:12]
        self.tag = 'secops-infra-batch:' + self.ident
        self.container = self.ident + '-tests'
        self.source = source_manifest()
        self.head = output('git', 'rev-parse', 'HEAD')
        self.engine = output('docker', 'info', '--format', '{{.ID}}')
        if not self.engine:
            raise ValueError('batch_engine_required')
        self.report = {'schema': 'local-infra-preflight-batch-1', 'completed': False,
            'started_at': datetime.now(UTC).isoformat(), 'source_commit': self.head,
            'source_dirty': bool(output('git', 'status', '--porcelain', '--untracked-files=normal')),
            'source_sha256': self.source, 'source_digest': release.digest(self.source),
            'engine_id': self.engine, 'stages': [], 'automatic_retry': False,
            'execution': 'local Docker, rule analyzer, synthetic inputs; no cloud/model calls'}
        self.save()

    def save(self):
        (self.directory / 'verification.json').write_text(json.dumps(self.report, indent=2) + '\n', encoding='utf-8')

    def admit(self):
        if (source_manifest() != self.source or output('git', 'rev-parse', 'HEAD') != self.head
                or output('docker', 'info', '--format', '{{.ID}}') != self.engine):
            raise ValueError('batch_source_or_engine_changed')

    def run_command(self, name, argv, *, timeout=3600):
        with (self.directory / (name + '.log')).open('w', encoding='utf-8') as log:
            result = subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                    encoding='utf-8', timeout=timeout, check=False)
        if result.returncode:
            raise ValueError('batch_stage_command_failed')

    def linux(self):
        self.run_command('linux-build', ['docker', 'build', '--file', 'Dockerfile.test', '--tag', self.tag, '.'])
        image = output('docker', 'image', 'inspect', '--format', '{{.Id}}', self.tag)
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise ValueError('batch_image_required')
        program = "import hashlib,json,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for p in json.load(sys.stdin)}))"
        actual = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--label', 'secops.infra-batch=' + self.ident,
            '--read-only', '--entrypoint', 'python', '-i', image, '-c', program], input=json.dumps(list(self.source)),
            capture_output=True, text=True, encoding='utf-8', timeout=30, check=False)
        if actual.returncode or json.loads(actual.stdout) != self.source:
            raise ValueError('batch_test_image_source_mismatch')
        self.report.update(test_image_id=image, test_image_source_verified=True)
        try:
            self.run_command('linux-tests', ['docker', 'run', '--rm', '--name', self.container, '--network', 'none',
                '--label', 'secops.infra-batch=' + self.ident, '--memory', '2g', '--cpus', '2', image])
        finally:
            # Only this batch's exact labeled test container can be removed.
            ids = output('docker', 'ps', '-aq', '--filter', 'label=secops.infra-batch=' + self.ident,
                         '--filter', 'name=^/' + self.container + '$').splitlines()
            for ident in ids:
                output('docker', 'rm', '--force', ident)
        body = (self.directory / 'linux-tests.log').read_text(encoding='utf-8')
        matches = re.findall(r'(\d+) passed(?:, (\d+) skipped)?(?:, (\d+) warnings)? in ([\d.]+)s', body)
        if len(matches) != 1 or int(matches[0][0]) < 2281 or 'All checks passed!' not in body:
            raise ValueError('batch_linux_summary_missing')
        return {'passed': int(matches[0][0]), 'skipped': int(matches[0][1] or 0), 'seconds': float(matches[0][3])}

    def acceptance(self, name, module, minimum):
        directory = self.directory / name
        runtime = None
        argv = [sys.executable, '-m', module, '--directory', str(directory)]
        if name == 'monitored':
            argv.append('--monitoring')
        try:
            self.run_command(name, argv)
        finally:
            # Child test drivers own cleanup; recover it after a command timeout.
            descriptor = directory / 'runtime.json'
            if descriptor.exists():
                if name == 'monitored':
                    from scripts.monitored_mtls_runtime import MonitoredRuntime as Runtime
                else:
                    from scripts.database_backup_runtime import (
                        BackupRuntime as Runtime,
                    )
                runtime = Runtime(directory)
                runtime.load()
                if output('docker', 'info', '--format', '{{.ID}}') != self.engine:
                    raise ValueError('batch_engine_changed_cleanup_refused')
                if not runtime.state.get('purged'):
                    runtime.down(purge=True)
                for argv in (['ps', '-aq'], ['volume', 'ls', '-q'], ['network', 'ls', '-q']):
                    if output('docker', *argv, '--filter', 'label=secops.runtime=' + runtime.state['project']):
                        raise ValueError('batch_owned_cleanup_incomplete')
        path = directory / 'verification.json'
        if runtime is None:
            raise ValueError('batch_child_descriptor_missing')
        report = json.loads(path.read_text(encoding='utf-8'))
        schema = ('monitored-continuous-mtls-verification-1' if name == 'monitored'
                  else 'database-backup-verification-1')
        if report.get('schema') != schema:
            raise ValueError('batch_child_schema_mismatch')
        release.verify(report.get('release_lock'), runtime.release_inputs())
        count = validate_report(report, minimum, self.source, self.head)
        return {'checks': count, 'report': path.relative_to(self.directory).as_posix(),
                'report_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'cleanup': report['cleanup']}

    def run(self):
        for name, module, minimum in STAGES:
            self.admit()
            started = time.monotonic()
            stage = {'name': name, 'passed': False}
            print(json.dumps({'stage': name, 'status': 'running'}), flush=True)
            try:
                stage['result'] = self.linux() if name == 'linux' else self.acceptance(name, module, minimum)
                stage['passed'] = True
            except (ValueError, OSError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
                stage['failure'] = 'batch_stage_failed_see_local_log'
            stage['seconds'] = round(time.monotonic() - started, 3)
            self.report['stages'].append(stage)
            self.save()
            self.admit()
            print(json.dumps({'stage': name, 'passed': stage['passed']}), flush=True)
        self.report['completed'] = len(self.report['stages']) == len(STAGES) and all(s['passed'] for s in self.report['stages'])
        self.report['finished_at'] = datetime.now(UTC).isoformat()
        self.save()
        return self.report['completed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/infra-batches' / uuid.uuid4().hex[:12])
    args = parser.parse_args()
    batch = None
    try:
        batch = Batch(args.directory)
        return 0 if batch.run() else 1
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt):
        if batch:
            batch.report.update(completed=False, failure='batch_admission_or_execution_failed')
            batch.save()
        print(json.dumps({'completed': False, 'reason': 'local_batch_failed_see_report'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
