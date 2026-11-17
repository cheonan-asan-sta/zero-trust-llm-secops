import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_exec_bundle_backup import interrupted, setup

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='private POSIX operator CLI')


def command(g, mode, extra):
    scope = g.f.archive_scope
    args = [sys.executable, '-m', 'scripts.exec_recovery_bundle', mode,
            '--tenant', scope.tenant_id, '--server', scope.server_id, '--unit', scope.unit,
            '--source', scope.source_id, '--registry', str(g.f.lab.broker.joiner.registry.path),
            '--registry-sha256', g.f.lab.broker.joiner.registry.expected_sha256,
            '--caller-registry', str(g.f.lab.broker.registry.path),
            '--caller-registry-sha256', g.f.lab.broker.registry.sha256,
            '--checkpoint', str(g.checkpoint), *extra]
    return subprocess.run(args, cwd=Path(__file__).resolve().parents[1],
                          env={**os.environ, 'AWS_EC2_METADATA_DISABLED': 'true'},
                          capture_output=True, timeout=30, check=False)


def backup_args(g, key):
    return ['--key-file', str(key), '--key-id', g.key_id, '--output', str(g.package),
            '--intents', str(g.f.intents), '--broker-db', str(g.f.lab.broker.path),
            '--app-db', str(g.f.lab.operations.path), '--worker-directory', str(g.f.launcher.directory)]


def test_local_operator_backup_restore_and_keyless_verify_need_no_signing_credentials(tmp_path):
    g = setup(tmp_path)
    interrupted(g, 'preseal')
    g.f.execute()
    key = tmp_path/'recovery.key'
    key.write_bytes(g.key)
    key.chmod(0o600)
    before = {p: p.read_bytes() for p in (g.f.lab.broker.path, g.f.lab.operations.path,
                                          g.f.root/'latest.json')}
    saved = command(g, 'backup', [*backup_args(g, key), '--caller-environment', 'local_oidc'])
    assert saved.returncode == 0, saved.stderr.decode()
    result = json.loads(saved.stdout)
    assert result['indeterminate'] == 1 and result['sealed'] == 1
    assert all(p.read_bytes() == raw for p, raw in before.items()) and len(g.f.launches) == 2
    restored = command(g, 'restore', ['--key-file', str(key), '--key-id', g.key_id,
        '--output', str(g.review), '--package', str(g.package),
        '--checkpoint-sha256', result['checkpoint_sha256'], '--caller-environment', 'local_oidc'])
    assert restored.returncode == 0, restored.stderr.decode()
    recovery = json.loads(restored.stdout)
    key.unlink()
    verified = command(g, 'verify', ['--review', str(g.review),
        '--receipt-sha256', recovery['receipt_sha256'], '--checkpoint-sha256', result['checkpoint_sha256'],
        '--caller-environment', 'local_oidc'])
    assert verified.returncode == 0, verified.stderr.decode()
    value = json.loads(verified.stdout)
    assert value['indeterminate'] == 1 and value['automatic_activation_allowed'] is False
    assert g.key not in saved.stdout+restored.stdout+verified.stdout
    assert len(g.f.launches) == 2 and all(p.read_bytes() == raw for p, raw in before.items())


@pytest.mark.parametrize('unsafe', ['local_issuer_default', 'world_readable_key', 'short_key', 'absent_database'])
def test_operator_cli_refuses_unsafe_configuration_without_partial_package_or_secret_output(unsafe, tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    key = tmp_path/'recovery.key'
    key.write_bytes(g.key)
    key.chmod(0o600)
    extra = [] if unsafe == 'local_issuer_default' else ['--caller-environment', 'local_oidc']
    if unsafe == 'world_readable_key':
        key.chmod(0o644)
    elif unsafe == 'short_key':
        key.write_bytes(b'local-secret-not-32')
    elif unsafe == 'absent_database':
        g.f.lab.broker.path.unlink()
    result = command(g, 'backup', [*backup_args(g, key), *extra])
    assert result.returncode == 2, result.stderr.decode()
    assert json.loads(result.stdout) == {'completed': False, 'state': 'unavailable',
        'automatic_execution_allowed': False, 'automatic_activation_allowed': False}
    assert not g.package.exists() and not g.checkpoint.exists()
    assert b'local-secret' not in result.stdout and str(key).encode() not in result.stdout


def test_operator_interface_has_no_activation_dispatch_or_grant_reissue_command():
    result = subprocess.run([sys.executable, '-m', 'scripts.exec_recovery_bundle', '--help'],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0 and b'{backup,restore,verify}' in result.stdout
    assert b'--activate' not in result.stdout and b'--dispatch' not in result.stdout
