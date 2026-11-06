import copy
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import database_transport_custodian as custody
from scripts import database_transport_runtime as runtime
from scripts import test_transport_process_recovery as faults
from scripts.authority_rotation_coordinator import lease
from scripts.certificate_controller import LifecycleError


@pytest.mark.parametrize('mode', ['up', 'down', 'purge'])
def test_management_lease_denies_before_load_or_parent_docker_mutation(tmp_path, monkeypatch, mode):
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-transport-management')
    value.directory = tmp_path
    monkeypatch.setattr(value, 'load', lambda: pytest.fail('read before lock admission'))
    monkeypatch.setattr(runtime.PersistentAuthorityRuntime, 'up', lambda *a: pytest.fail('started competing writer'))
    monkeypatch.setattr(runtime.PersistentAuthorityRuntime, 'down', lambda *a, **kw: pytest.fail('stopped competing writer'))
    with lease(tmp_path), pytest.raises(runtime.RuntimeFailure, match='management_busy'):
        value.up() if mode == 'up' else value.down(purge=mode == 'purge')


@pytest.mark.parametrize('mode', ['tick', 'once', 'run', 'preflight'])
def test_cli_acquires_shared_lease_before_loading_or_regenerating_compose(tmp_path, monkeypatch, capsys, mode):
    monkeypatch.setattr(sys, 'argv', ['transport', mode])
    monkeypatch.setattr(runtime, 'TransportRuntime', lambda *a: SimpleNamespace(
        directory=tmp_path, load=lambda: pytest.fail('CLI loaded state before lease')))
    with lease(tmp_path):
        assert runtime.main() == 1
    assert json.loads(capsys.readouterr().out) == {'verified': False, 'reason': 'database_transport_runtime_failed'}


def test_management_lock_is_released_by_actual_process_kill_without_deleting_lockfile(tmp_path):
    program = "from pathlib import Path;import sys,time;from scripts.authority_rotation_coordinator import lease\nwith lease(Path(sys.argv[1])):\n print('ready',flush=True)\n time.sleep(30)"
    child = subprocess.Popen([sys.executable, '-u', '-c', program, str(tmp_path)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        path = tmp_path / 'authority-coordinator.lock'
        before = path.stat().st_ino
        with pytest.raises(runtime.RuntimeFailure, match='management_busy'), runtime.management_lease(tmp_path):
            pytest.fail('lock admitted competing process')
        faults.kill_worker(child)
        with runtime.management_lease(tmp_path):
            assert path.stat().st_ino == before
        assert path.read_bytes() == b'0'
    finally:
        if child.poll() is None:
            faults.kill_worker(child)
        child.stdout.close()
        child.stderr.close()


def test_body_io_failure_is_not_mislabeled_as_lock_contention(tmp_path):
    with pytest.raises(OSError, match='synthetic disk failure'), runtime.management_lease(tmp_path):
        raise OSError('synthetic disk failure')
    with runtime.management_lease(tmp_path):
        pass


def test_observation_validates_signed_journal_without_docker_or_compose_writes(monkeypatch):
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-readonly-observation')
    journal = {'phase': 'stopped', 'epoch': 1, 'last_error': 'untrusted raw secret text',
               'plan': {'public': 'plan'}, 'history': [{}]}
    monkeypatch.setattr(value, 'load', lambda: value.write_manifest())
    monkeypatch.setattr(runtime.PersistentAuthorityRuntime, 'write_manifest', lambda *a: pytest.fail('observation rewrote Compose'))
    monkeypatch.setattr(value, 'transport_journal', lambda: copy.deepcopy(journal))
    monkeypatch.setattr(runtime, 'command', lambda *a, **kw: pytest.fail('observation accessed Docker'))
    result = value.observation()
    assert result == {'phase': 'stopped', 'epoch': 1, 'last_error': 'pinned_resume_required',
                      'recovery_required': True, 'pending_plan_sha256': custody.custody.digest(journal['plan']),
                      'remaining_history_slots': 63, 'observation_only': True}
    assert not value._transport_observing


def test_invalid_observation_never_leaves_write_suppression_enabled(monkeypatch):
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-invalid-observation')
    monkeypatch.setattr(value, 'load', lambda: None)
    monkeypatch.setattr(value, 'transport_journal', lambda: (_ for _ in ()).throw(LifecycleError('transport_plan_signature')))
    with pytest.raises(LifecycleError, match='plan_signature'):
        value.observation()
    assert not value._transport_observing


@pytest.mark.parametrize('field,value', [
    ('restore_paused', 0), ('restore_paused', 'false'), ('restore_paused', None),
    ('next_due_at', float('inf')), ('next_due_at', float('nan')), ('next_due_at', -1),
    ('next_due_at', 'later'), ('next_due_at', True),
])
def test_malformed_pause_or_scheduler_time_cannot_authorize_resume(field, value):
    # Reject at the shape boundary, before accessing certificates or secret files.
    anchor = {'schema': 'transport-anchor-1', 'policy': custody.POLICY,
              'files': {v: dict.fromkeys(names, 'a' * 64) for v, names in custody.FILES.items()}}
    journal = custody.initial(anchor) | {field: value}
    with pytest.raises(LifecycleError, match='journal_shape'):
        custody.checked(anchor, journal)


@pytest.mark.parametrize('target', list(faults.CHECKPOINTS))
def test_fault_worker_stops_at_exact_side_effect_persistence_boundary(tmp_path, monkeypatch, target):
    persisted, markers = [], []
    worker = SimpleNamespace(state={'phase': 'prepared'})
    worker.persist = lambda: persisted.append(worker.state['phase'])
    phases = iter(['stopped', 'installed', 'started', 'committing', 'resuming', 'idle'])

    def tick():
        worker.state['phase'] = next(phases)
        worker.persist()

    worker.tick = tick
    monkeypatch.setattr(faults, 'runtime_type', lambda path: lambda *a: SimpleNamespace(directory=tmp_path, load=lambda: None))
    monkeypatch.setattr(faults, 'TransportCoordinator', lambda *a: worker)
    monkeypatch.setattr(faults, 'save', lambda p, s: markers.append(s))

    def sleep(seconds):
        if seconds == 45:
            raise RuntimeError('test checkpoint reached')

    monkeypatch.setattr(faults.time, 'sleep', sleep)
    with pytest.raises(RuntimeError, match='checkpoint reached'):
        faults.checkpoint_worker(tmp_path, target, 'a' * 24)
    assert markers == [{'token': 'a' * 24, 'phase': target, 'boundary': faults.CHECKPOINTS[target]}]
    assert (target in persisted) == (faults.CHECKPOINTS[target] == 'after')
    with lease(tmp_path):
        pass


@pytest.mark.parametrize('target,token', [('other', 'a' * 24), ('stopped', '../outside'), ('idle', 'b' * 25)])
def test_fault_worker_rejects_arbitrary_checkpoint_or_marker_path(tmp_path, target, token):
    with pytest.raises(runtime.RuntimeFailure, match='checkpoint_scope'):
        faults.checkpoint_worker(Path(tmp_path), target, token)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('message', ['private secret payload', 'authority_child_unapproved_secret', 'BEGIN PRIVATE KEY'])
def test_failure_report_never_includes_unapproved_exception_text(message):
    result = faults.public_failure(LifecycleError(message))
    assert result == {'reason': 'validation_failure', 'frames': []}
    assert message not in json.dumps(result)


def test_failure_report_keeps_known_remote_reason_but_not_external_traceback_path():
    try:
        raise LifecycleError('authority_child_reload_ack_missing')
    except LifecycleError as error:
        assert faults.public_failure(error) == {'reason': 'authority_child_reload_ack_missing', 'frames': []}


def test_failure_report_retains_repository_location_without_source_or_locals(tmp_path):
    try:
        faults.checkpoint_worker(tmp_path, 'unapproved-private-parameter', 'private-token')
    except runtime.RuntimeFailure as error:
        result = faults.public_failure(error)
    assert result['reason'] == 'validation_failure'
    assert result['frames'] and all(set(v) == {'file', 'line'} for v in result['frames'])
    assert result['frames'][-1]['file'] == 'scripts/test_transport_process_recovery.py'
    assert 'private' not in json.dumps(result) and str(tmp_path) not in json.dumps(result)
