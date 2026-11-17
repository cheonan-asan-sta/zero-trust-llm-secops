"""Actual keyless PID1-started nonroot checker on dedicated owned copies."""

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.shared_execution_collector import READ_ENV


def run(lab, package, review, checkpoint, checkpoint_sha256, receipt_sha256, scope, check):
    owned = Path('/run')/('zt-exec-bundle-status-owner-'+uuid.uuid4().hex)
    owned.mkdir(mode=0o755)
    unit = 'secops-bundle-status-'+uuid.uuid4().hex+'.service'
    unit_file = Path('/run/systemd/system')/unit
    uid, gid = 65534, 65534

    def command(*args):
        return subprocess.run(['/usr/bin/systemctl', *args], env=READ_ENV,
                              capture_output=True, timeout=25, check=False)

    try:
        replica, restored, pins, public = [owned/name for name in ('package', 'review', 'pins', 'public')]
        shutil.copytree(package, replica, symlinks=True)
        shutil.copytree(review, restored, symlinks=True)
        pins.mkdir(mode=0o700)
        (pins/'checkpoint.json').write_bytes(checkpoint.read_bytes())
        for root in (replica, restored, pins):
            for path in (root, *root.rglob('*')):
                require(not path.is_symlink(), 'bundle_owner_no_link')
                os.chown(path, uid, gid)
                path.chmod(0o700 if path.is_dir() else 0o600)
        public.mkdir(mode=0o755)
        os.chown(public, uid, gid)
        service, caller = owned/'service.json', owned/'caller.json'
        service.write_bytes(lab.broker.joiner.registry.path.read_bytes())
        caller.write_bytes(lab.broker.registry.path.read_bytes())
        service.chmod(0o644)
        caller.chmod(0o644)
        # No key, token, credential directory, broker/app live DB or worker path
        # is copied. The original app/broker/worker stores are already absent.
        probe = owned/'readonly-probe.py'
        protected = [str(replica/'payload.aesgcm'), str(restored/'app.sqlite3'),
                     str(pins/'checkpoint.json')]
        probe.write_text('import errno,json,os\nfor path in '+repr(protected)+':\n'
            '    try: fd=os.open(path,os.O_WRONLY|os.O_APPEND)\n'
            '    except OSError as error: assert error.errno in (errno.EROFS,errno.EACCES)\n'
            '    else:\n        os.close(fd)\n        raise AssertionError("recovery evidence writable")\n'
            'print(json.dumps({"readonly_evidence_probe":True}))\n', encoding='utf8')
        probe.chmod(0o644)
        python_path = os.environ['PYTHONPATH']
        require('"' not in python_path and '\n' not in python_path, 'bundle_owner_python_path')
        argv = (f'--tenant {scope.tenant_id} --server {scope.server_id} --unit {scope.unit} '
                f'--source {scope.source_id} --package {replica} --review {restored} '
                f'--checkpoint {pins/"checkpoint.json"} --checkpoint-sha256 {checkpoint_sha256} '
                f'--receipt-sha256 {receipt_sha256} --registry {service} '
                f'--registry-sha256 {lab.broker.joiner.registry.expected_sha256} --caller-registry {caller} '
                f'--caller-registry-sha256 {lab.broker.registry.sha256} --caller-environment local_oidc '
                f'--status-output {public/"status.json"} --observe-worker-security')
        unit_file.write_text(f'''[Service]
Type=oneshot
User=nobody
Group=nogroup
ExecStart=/usr/bin/python3 -m scripts.exec_bundle_status {argv}
ExecStartPost=/usr/bin/python3 {probe}
Environment="PYTHONPATH={python_path}" PYTHONDONTWRITEBYTECODE=1 AWS_EC2_METADATA_DISABLED=true
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths={replica} {restored} {pins}
ReadWritePaths={public}
RestrictAddressFamilies=AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
CPUQuota=50%
MemoryMax=768M
TasksMax=8
TimeoutStartSec=60
StandardOutput=journal
StandardError=journal
''', encoding='utf8')
        require(command('daemon-reload').returncode == 0, 'bundle_owner_reload')
        require(command('start', unit).returncode == 0, 'bundle_owner_start')
        diagnostic = subprocess.run(['/usr/bin/journalctl', '--no-pager', '-u', unit, '-n', '30', '-o', 'cat'],
            env=READ_ENV, capture_output=True, timeout=10, check=True).stdout
        require(len(diagnostic) <= 32768, 'bundle_owner_journal_bound')
        values = [json.loads(line) for line in diagnostic.decode().splitlines() if line.startswith('{')]
        statuses = [v for v in values if 'worker_security' in v]
        require(len(statuses) == 1 and statuses[0]['state'] == 'verified', 'bundle_owner_status')
        security = statuses[0]['worker_security']
        require(security == {'effective_uid': uid, 'effective_capabilities': 0,
                'bounding_capabilities': 0, 'no_new_privileges': True}, 'bundle_owner_security')
        check('actual_nonroot_bundle_checker_has_zero_capabilities_and_nnp')
        body = json.loads((public/'status.json').read_bytes())
        require(body['state'] == 'verified' and body['values']['indeterminate'] == 1
                and body['values']['sealed'] == 4 and body['values']['intents'] == 5,
                'bundle_owner_unknown_retained')
        check('separate_pid1_started_checker_revalidates_package_and_review_without_recovery_or_signing_keys')
        require(any(v.get('readonly_evidence_probe') is True for v in values), 'bundle_owner_readonly_probe')
        check('keyless_worker_publishes_aggregate_but_cannot_open_ciphertext_review_or_checkpoint_for_writing')
        return security
    finally:
        command('stop', unit)
        command('reset-failed', unit)
        unit_file.unlink(missing_ok=True)
        command('daemon-reload')
        require(owned.parent == Path('/run') and owned.name.startswith('zt-exec-bundle-status-owner-'),
                'bundle_owner_cleanup_scope')
        shutil.rmtree(owned)
        require(not owned.exists() and not unit_file.exists(), 'bundle_owner_cleanup')
