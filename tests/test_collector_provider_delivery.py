import json
import os
import selectors
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.f1_lab import collector_provider_ha as ha
from tests.test_collector_provider_ha import configured

__all__ = ['configured']

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='private Unix provider processes')


def test_fresh_provider_process_accepts_only_assigned_stdin_key_and_logs_no_secret(configured):
    f = configured
    secret = f.secret(f.keys['runtime'])
    process = subprocess.Popen([sys.executable, '-m', 'scripts.serve_collector_credential',
        '--socket', str(f.paths[0]), '--allowed-uid', str(os.geteuid()), '--maximum-connections', '2',
        '--lifetime-seconds', '10', '--local-uid-only-fixture'], cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ready = tail = errors = b''
    try:
        process.stdin.write(secret)
        process.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=10), 'provider readiness timeout'
            ready = process.stdout.readline(8193)
        value = json.loads(ready)
        assert value['ready'] is True and value['dumpable'] is False
        assert value['peer_authorization_basis'] == 'uid_only_local_fixture'
        assert value['worker_security']['effective_uid'] == os.geteuid()
        assert ha.read_key(f.profile.endpoints[0]) == secret
        process.terminate()
        assert process.wait(timeout=8) == 0
        tail, errors = process.stdout.read(), process.stderr.read()
        assert json.loads(tail)['delivered'] == 1
        assert not f.paths[0].exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
    assert secret not in ready+tail+errors and b'PRIVATE KEY' not in ready+tail+errors


@pytest.mark.parametrize('mode', ['both_offline', 'wrong_primary', 'missing_pin'])
def test_provider_cli_failure_never_falls_back_to_stdin_or_overwrites_latest(mode, configured):
    f = configured
    standby = None
    if mode == 'wrong_primary':
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        f.provider(0, key=Ed25519PrivateKey.generate())
        standby = f.provider(1)
    root = Path(__file__).resolve().parents[1]
    output = f.tmp/'never-published'
    before = f.latest.read_bytes()
    scope = f.scope
    args = [sys.executable, '-m', 'scripts.collect_shared_execution', '--tenant', scope.tenant_id,
            '--server', scope.server_id, '--unit', scope.unit, '--source', scope.source_id,
            '--key-id', scope.key_id, '--registry', str(f.pin.path), '--registry-sha256', f.pin.expected_sha256,
            '--output', str(output), '--latest', str(f.latest), '--provider-profile', str(f.path)]
    if mode != 'missing_pin':
        args.extend(['--provider-profile-sha256', f.sha])
    result = subprocess.run(args, cwd=root, input=f.secret(f.keys['runtime']),
                            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                            capture_output=True, timeout=15, check=False)
    assert result.returncode == 1
    value = json.loads(result.stdout)
    assert value['completed'] is False and value['execution_evidence_available'] is False
    assert value['failure_stage'] == ('key_input' if mode == 'missing_pin' else 'provider_selection')
    assert not output.exists() and f.latest.read_bytes() == before
    if standby is not None:
        assert standby.delivered == 0


def test_ha_templates_keep_one_collector_writer_and_no_stdin_or_unpinned_key_source():
    root = Path(__file__).resolve().parents[1]/'infra/systemd'
    collector = (root/'secops-execution-collector-ha@.service').read_text()
    assert '--provider-profile-sha256 ${PROVIDER_PROFILE_SHA256}' in collector
    assert 'StandardInput=null' in collector and 'LoadCredential=' not in collector
    assert 'CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH' in collector
    health = (root/'secops-capture-health-ha@.service').read_text()
    assert '--alternate-key-id ${STANDBY_RUNTIME_KEY_ID}' in health
    assert 'CapabilityBoundingSet=\n' in health and '--provider-profile' not in health


def test_provider_cli_requires_service_binding_or_explicit_uid_only_fixture():
    result = subprocess.run([sys.executable, '-m', 'scripts.serve_collector_credential',
        '--socket', '/tmp/not-created-ha-provider.sock', '--allowed-uid', str(os.geteuid())],
        input=b'not-consumed', capture_output=True, timeout=10, check=False)
    assert result.returncode == 2
    assert b'--allowed-service-unit' in result.stderr and b'not-consumed' not in result.stderr


def test_same_uid_rejection_never_calls_private_key_supplier(configured):
    import socket

    from scripts.f1_lab.systemd_credentials import CredentialSocket

    f = configured
    calls = []
    with CredentialSocket(f.paths[0], lambda: calls.append('supplied') or b'x'*32,
        allowed_uid=os.geteuid(), maximum_connections=1, peer_validator=lambda _peer: False) as provider:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(f.paths[0]))
            assert client.recv(33) == b''
        provider.thread.join(timeout=3)
        assert not calls and provider.rejected == 1 and provider.delivered == 0
        assert provider.last_rejection_code == 'native_source_credential_peer_service'
