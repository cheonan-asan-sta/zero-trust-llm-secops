import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts import execution_maintenance_probe as probe
from scripts.continuous_mtls_runtime import RuntimeFailure
from tests.test_execution_maintenance_probe import PRIVATE, success


@pytest.mark.parametrize('mode', ['success', 'child_failure', 'partial', 'invalid_report', 'timeout',
                                 'cleanup_failure', 'not_running', 'stop_failure', 'foreign_volume',
                                 'replaced_observer', 'start_failure'])
def test_one_offline_job_runs_only_after_owned_writer_stops_and_resumes_only_after_verified_success(mode, monkeypatch):
    calls = []
    state = {'running': mode != 'not_running', 'container_reads': 0}

    def container(service):
        assert service == 'execution-observer'
        calls.append('container')
        state['container_reads'] += 1
        return 'replaced' if mode == 'replaced_observer' and state['container_reads'] >= 3 else 'owned'

    def compose(action, *args, **kwargs):
        assert args[-1] == 'execution-observer' and kwargs['timeout'] == 30
        calls.append(action)
        if mode == action+'_failure':
            raise RuntimeFailure(PRIVATE)
        state['running'] = action == 'start'

    def unused(*labels):
        assert not state['running'] and labels == ('execution-state', 'execution-input')
        calls.append('unused')

    def volume(label):
        assert label in {'execution-state', 'execution-input', 'execution-tls'}
        if mode == 'foreign_volume':
            raise RuntimeFailure(PRIVATE)
        return 'owned-'+label

    runtime = SimpleNamespace(state={'project': 'kmtls-123456789abc', 'image_id': 'sha256:'+'a'*64},
        verify_release=lambda: calls.append('verify'), container=container, compose=compose,
        _assert_unused=unused, _volume=volume)
    monkeypatch.setattr(probe, 'running', lambda _: state['running'])

    def cleanup(*_):
        calls.append('cleanup')
        return mode != 'cleanup_failure'

    monkeypatch.setattr(probe, 'remove_job', cleanup)

    def child(argv, **kwargs):
        calls.append('job')
        assert not state['running'] and calls.index('stop') < calls.index('unused') < calls.index('job')
        assert argv[:2] == ['docker', 'run'] and argv[argv.index('--network')+1] == 'none'
        assert '--read-only' in argv and '--cap-drop=ALL' in argv and '--security-opt=no-new-privileges:true' in argv
        assert argv[-4:] == ['python', runtime.state['image_id'], '-m', 'scripts.execution_maintenance_probe']
        assert argv.count('--mount') == 3
        assert json.loads(kwargs['input']) == {'operation': 'observer_archive'}
        assert kwargs['timeout'] == 30 and kwargs['stderr'] == subprocess.DEVNULL
        if mode == 'timeout':
            raise subprocess.TimeoutExpired(PRIVATE, 30, output=PRIVATE, stderr=PRIVATE)
        if mode == 'invalid_report':
            return SimpleNamespace(returncode=1, stdout=PRIVATE.encode())
        receipt = success()
        if mode in {'child_failure', 'partial'}:
            receipt.update(completed=False, retired_inputs=None,
                compacted=5 if mode == 'partial' else None,
                issue={'phase': 'observer_retire' if mode == 'partial' else 'observer_init',
                       'category': 'collector_busy'})
        return SimpleNamespace(returncode=1 if mode in {'child_failure', 'partial'} else 0,
                               stdout=json.dumps(receipt).encode())

    monkeypatch.setattr(probe.subprocess, 'run', child)
    result = probe.execute_quiesced_observer(runtime)
    assert PRIVATE not in json.dumps(result) and calls.count('job') <= 1
    assert result['coordination']['observer_restarted'] == (mode == 'success')
    if mode == 'success':
        assert calls.index('cleanup') < calls.index('start')
        assert result['receipt'] == success() and result['issue'] is None and state['running'] is True
    else:
        assert result['issue'] is not None
        if mode != 'start_failure':
            assert 'start' not in calls
    if mode == 'partial':
        assert result['receipt']['compacted'] == 5 and result['receipt']['retired_inputs'] is None


@pytest.mark.parametrize('mode', ['gone', 'owned', 'daemon_down', 'bad_id', 'wrong_project', 'wrong_nonce'])
def test_cleanup_requires_successful_daemon_query_and_exact_job_identity(mode, monkeypatch):
    calls = []
    identity = 'b'*64

    def command(argv, **_kwargs):
        calls.append(argv)
        if argv[1] == 'ps':
            return SimpleNamespace(returncode=1 if mode == 'daemon_down' else 0,
                stdout=b'' if mode in {'gone', 'daemon_down'} else b'bad' if mode == 'bad_id' else identity.encode())
        if argv[1] == 'inspect':
            assert argv[-1] == identity
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                'secops.runtime': 'other' if mode == 'wrong_project' else 'kmtls-123456789abc',
                'secops.execution-maintenance': 'other' if mode == 'wrong_nonce' else 'nonce'}).encode())
        assert argv == ['docker', 'rm', '--force', identity]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(probe.subprocess, 'run', command)
    if mode in {'gone', 'owned'}:
        assert probe.remove_job('owned-job', 'kmtls-123456789abc', 'nonce') is True
    else:
        with pytest.raises((RuntimeFailure, ValueError)):
            probe.remove_job('owned-job', 'kmtls-123456789abc', 'nonce')
        assert not any(v[1] == 'rm' for v in calls)


def test_server_maintenance_preserves_existing_execution_path(monkeypatch):
    calls = []
    monkeypatch.setattr(probe, 'execute', lambda _runtime, operation: calls.append(operation) or {'legacy': True})
    assert probe.execute_for_runtime(object(), 'server_archive') == {'legacy': True}
    assert calls == ['server_archive']
