import http.client
import json
import os
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts import signal_metrics_exporter as exporter
from scripts.f1_lab import exec_bundle_status as status
from tests.test_exec_bundle_status import fixture, profile

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='private POSIX bundle delivery')


@pytest.mark.parametrize('enabled', [False, True])
def test_authenticated_exporter_exposes_bundle_only_when_opted_in(enabled, tmp_path, monkeypatch):
    f = fixture(tmp_path)
    path = tmp_path/'status.json'
    status.publish(path, f.inspect())
    monkeypatch.setattr(exporter, 'metrics', lambda *_: 'secops_signal_collection_success 1\n')
    token = 'x'*32
    server = ThreadingHTTPServer(('127.0.0.1', 0), exporter.handler(
        'http://127.0.0.1:1/zero-trust/signals/inbox', 'local', token,
        bundle_profile=profile(f.g.f.archive_scope, path) if enabled else None))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        for headers, code in [({}, 401), ({'Authorization': 'Bearer '+token}, 200)]:
            client = http.client.HTTPConnection(*server.server_address, timeout=5)
            client.request('GET', '/metrics', headers=headers)
            result = client.getresponse()
            body = result.read().decode()
            assert result.status == code
            if code == 200:
                assert ('secops_exec_bundle_bridge_enabled' in body) is enabled
                if enabled:
                    assert 'secops_exec_bundle_indeterminate 1' in body
                    assert 'secops_exec_bundle_status_success 1' in body
            client.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_keyless_cli_actual_damage_and_repair_preserve_unknown_and_original_times(tmp_path):
    f = fixture(tmp_path)
    public = tmp_path/'public'
    public.mkdir(mode=0o755)
    output = public/'status.json'
    g, scope = f.g, f.g.f.archive_scope
    args = [sys.executable, '-m', 'scripts.exec_bundle_status',
            '--tenant', scope.tenant_id, '--server', scope.server_id, '--unit', scope.unit,
            '--source', scope.source_id, '--registry', str(g.f.lab.broker.joiner.registry.path),
            '--registry-sha256', g.f.lab.broker.joiner.registry.expected_sha256,
            '--caller-registry', str(g.f.lab.broker.registry.path),
            '--caller-registry-sha256', g.f.lab.broker.registry.sha256,
            '--package', str(g.package), '--review', str(g.review), '--checkpoint', str(g.checkpoint),
            '--checkpoint-sha256', f.saved['checkpoint_sha256'],
            '--receipt-sha256', f.recovered['receipt_sha256'], '--status-output', str(output)]
    payload = g.package/'payload.aesgcm'
    raw = payload.read_bytes()
    bodies = []
    for phase in ('local_issuer_default', 'verified', 'damaged', 'repaired'):
        if phase == 'damaged':
            payload.write_bytes(bytes([raw[0] ^ 1])+raw[1:])
        elif phase == 'repaired':
            payload.write_bytes(raw)
        extra = [] if phase == 'local_issuer_default' else ['--caller-environment', 'local_oidc']
        result = subprocess.run([*args, *extra], cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, 'AWS_EC2_METADATA_DISABLED': 'true'}, capture_output=True, timeout=30, check=False)
        expected = phase in {'verified', 'repaired'}
        assert result.returncode == (0 if expected else 2), result.stderr.decode()
        value = json.loads(output.read_bytes())
        assert value['state'] == ('verified' if expected else 'unavailable')
        if expected:
            assert value['values']['indeterminate'] == 1
            bodies.append(value['values'])
        else:
            assert value['values'] == {}
        assert g.key not in result.stdout and str(g.package).encode() not in result.stdout
    assert bodies[0] == bodies[1] and len(g.f.launches) == 2


def test_monitoring_cli_and_systemd_template_have_no_recovery_key_or_activation_inputs():
    result = subprocess.run([sys.executable, '-m', 'scripts.exec_bundle_status', '--help'],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0
    assert not any(value in result.stdout for value in (b'--key-file', b'--activate', b'--launch'))
    root = Path(__file__).resolve().parents[1]
    unit = (root/'infra/systemd/secops-exec-bundle-status@.service').read_text()
    assert 'NoNewPrivileges=yes' in unit and 'CapabilityBoundingSet=\n' in unit
    assert 'ReadWritePaths=' not in unit and 'CacheDirectory=secops-exec-bundle' in unit
    assert '[Install]' not in unit
