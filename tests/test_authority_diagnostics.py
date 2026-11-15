import importlib
import json
import socket
import ssl
import subprocess
from types import SimpleNamespace

import pytest

from scripts import authority_diagnostics as diag
from scripts import certificate_controller as controller
from scripts.certificate_reload_runner import watch_digest


@pytest.mark.parametrize(('error', 'reason'), [
    (controller.LifecycleError('reload_ack_missing'), 'reload_ack_missing'),
    (controller.LifecycleError('server_not_reloaded'), 'server_not_reloaded'),
    (controller.LifecycleError('secret-sentinel'), 'validation_failure'),
    (ValueError('secret-sentinel'), 'validation_failure'),
    (ssl.SSLError('secret-sentinel'), 'tls_failure'),
    (TimeoutError('secret-sentinel'), 'network_timeout'),
    (socket.gaierror('secret-sentinel'), 'dns_failure'),
    (ConnectionRefusedError('secret-sentinel'), 'connection_failure'),
    (OSError('secret-sentinel'), 'io_failure'),
    (subprocess.TimeoutExpired('secret-sentinel', 1), 'operation_failure')])
def test_public_controller_reason_never_emits_exception_body(error, reason):
    assert controller.failure_reason(error) == reason
    assert 'secret-sentinel' not in controller.failure_reason(error)


def test_controller_status_preserves_safe_reason_and_removes_unknown_text(tmp_path):
    state = {'credentials': {}, 'transaction': None, 'last_error_reason': 'reload_ack_missing'}
    controller.status(state, tmp_path)
    assert json.loads((tmp_path / 'status.json').read_text())['last_error_reason'] == 'reload_ack_missing'
    state['last_error_reason'] = 'secret-sentinel'
    controller.status(state, tmp_path)
    assert json.loads((tmp_path / 'status.json').read_text())['last_error_reason'] is None


@pytest.fixture
def files(tmp_path):
    state, managed, acks = [tmp_path / name for name in ('state', 'managed', 'ack')]
    for path in [state, managed / 'proxy-tls', acks / 'proxy']:
        path.mkdir(parents=True)
    cfg = {'reload_groups': [{'root': '/managed/proxy-tls', 'files': ['/managed/proxy-tls/proxy.pem'], 'ack': '/ack/proxy/ack'}],
           'token': 'secret-sentinel'}
    status = {'phase': 'activated', 'last_error': 'secret-sentinel', 'last_error_reason': 'reload_ack_missing',
              'credentials': {'id': {'generation': 0, 'token': 'secret-sentinel'}},
              'server_observations': {'core-a': {}, 'secret-sentinel': {}}}
    (state / 'config.json').write_text(json.dumps(cfg))
    (state / 'status.json').write_text(json.dumps(status))
    (managed / 'proxy-tls/proxy.pem').write_bytes(b'public-synthetic-certificate')
    (acks / 'proxy/ack').write_text('0' * 64)
    return state, managed, acks


def test_snapshot_captures_blocked_reload_and_drops_raw_status_or_config(files):
    result = diag.snapshot(*files)
    assert result['phase'] == 'activated' and result['generations'] == {'0': 1}
    assert result['reason'] == 'reload_ack_missing' and result['publication_failed']
    assert result['native_servers_observed'] == ['core-a']
    assert result['reloads'][0]['available'] and not result['reloads'][0]['matches']
    assert 'secret-sentinel' not in json.dumps(result)
    _state, managed, acks = files
    (acks / 'proxy/ack').write_text(watch_digest([managed / 'proxy-tls/proxy.pem']))
    assert diag.snapshot(*files)['reloads'][0]['matches']


def test_snapshot_refuses_foreign_file_without_reading_it(files):
    state, _, _ = files
    cfg = json.loads((state / 'config.json').read_text())
    cfg['reload_groups'][0]['files'] = ['/state/bootstrap.json']
    (state / 'config.json').write_text(json.dumps(cfg))
    (state / 'bootstrap.json').write_text('secret-sentinel')
    result = diag.snapshot(*files)
    assert result['reloads'] == [{'service': 'proxy', 'available': False}]
    assert 'secret-sentinel' not in json.dumps(result)


def test_snapshot_refuses_oversized_status(files):
    state, _, _ = files
    (state / 'status.json').write_bytes(b' ' * 131073)
    with pytest.raises(ValueError, match='diagnostic_asset_scope'):
        diag.snapshot(*files)


def test_rekey_snapshot_resolves_private_assets_without_emitting_them_and_caps_size(files):
    state, managed, acks = files
    cfg = json.loads((state / 'config.json').read_text())
    cfg['reload_groups'][0].update(files=['/managed/proxy-tls/nginx-rekey.conf'], resolve_tls=True)
    (state / 'config.json').write_text(json.dumps(cfg))
    configuration = managed / 'proxy-tls/nginx-rekey.conf'
    configuration.write_text('cert /service-tls/proxy.pem; key /service-tls/proxy.key;')
    key = managed / 'proxy-tls/proxy.key'
    key.write_bytes(b'secret-sentinel')
    (acks / 'proxy/ack').write_text(watch_digest([configuration], True))
    result = diag.snapshot(*files)
    assert result['reloads'][0]['matches'] and 'secret-sentinel' not in json.dumps(result)
    key.write_bytes(b'x' * 65537)
    assert diag.snapshot(*files)['reloads'] == [{'service': 'proxy', 'available': False}]


def runtime_state():
    project = 'kmtls-012345abcdef'
    return {'initialized': True, 'project': project, 'volumes': {name: project + '-' + name for name in diag.MOUNTS}}


def test_collect_uses_read_only_helper_with_timeout_and_keeps_errors_private(monkeypatch):
    state = runtime_state()
    calls = []
    def inspect(argv, **options):
        assert argv[:3] == ['docker', 'volume', 'inspect'] and options == {'timeout': 3}
        return '\n'.join(json.dumps({'name': name, 'project': state['project']}) for name in state['volumes'].values())
    monkeypatch.setattr(diag, 'command', inspect)
    def helper(program, **options):
        assert program == ['-m', 'scripts.authority_diagnostics']
        assert options == {'readonly': True, 'timeout': 8}
        calls.append('helper')
        raise subprocess.TimeoutExpired('secret-sentinel', 8)
    result = diag.collect(SimpleNamespace(state=state, helper=helper))
    assert calls == ['helper']
    assert result['snapshot'] == {'available': False}
    assert 'secret-sentinel' not in json.dumps(result)


@pytest.mark.parametrize('fault', ['not_initialized', 'missing', 'foreign'])
def test_failure_diagnostics_never_create_or_attach_unowned_volumes(fault, monkeypatch):
    state = runtime_state()
    if fault == 'not_initialized':
        state['initialized'] = False
    def inspect(argv, **options):
        assert fault != 'not_initialized'
        if fault == 'missing':
            raise RuntimeError('secret-sentinel')
        return '\n'.join(json.dumps({'name': name, 'project': 'foreign'}) for name in state['volumes'].values())
    def helper(*args, **kwargs):
        pytest.fail('diagnostics must not mount or auto-create storage')
    monkeypatch.setattr(diag, 'command', inspect)
    result = diag.collect(SimpleNamespace(state=state, helper=helper))
    assert result['snapshot'] == {'available': False}
    assert result['storage_initialized'] is (fault != 'not_initialized')
    assert not result['authority_initialized']
    assert 'secret-sentinel' not in json.dumps(result)


def test_acceptance_diagnostic_failure_keeps_original_failure(monkeypatch):
    from scripts.test_authority_mtls_runtime import AuthorityChecks
    checks = AuthorityChecks.__new__(AuthorityChecks)
    checks.report = {'completed': False, 'failure': 'runtime_wait_timeout'}
    checks.runtime = SimpleNamespace(state={})
    def broken(*args, **kwargs):
        raise OSError('secret-sentinel')
    monkeypatch.setattr(diag, 'collect', broken)
    checks.record_authority_failure()
    assert checks.report['failure'] == 'runtime_wait_timeout'
    assert checks.report['authority_failure_diagnostics']['snapshot'] == {'available': False}
    assert 'secret-sentinel' not in json.dumps(checks.report)


@pytest.mark.parametrize(('module', 'class_name'), [
    ('scripts.test_authority_mtls_runtime', 'AuthorityChecks'),
    ('scripts.test_rekey_mtls_runtime', 'RekeyChecks')])
def test_failure_before_first_assertion_is_diagnosed_before_cleanup(module, class_name, monkeypatch):
    mod = importlib.import_module(module)
    calls = []
    class Fake:
        def __init__(self, directory):
            self.report = {'checks': [], 'completed': False}
        def run(self):
            raise mod.RuntimeFailure('runtime_wait_timeout')
        def record_authority_failure(self):
            assert self.report['failure'] == 'runtime_wait_timeout'
            calls.append('diagnose')
        def cleanup(self):
            assert calls == ['diagnose']
            calls.append('cleanup')
        def save(self):
            pass
    monkeypatch.setattr(mod, class_name, Fake)
    monkeypatch.setattr('sys.argv', ['acceptance'])
    assert mod.main() == 1
    assert calls == ['diagnose', 'cleanup']
