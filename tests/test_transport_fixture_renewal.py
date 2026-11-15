import copy
import json
import sys
from types import SimpleNamespace

import pytest

from scripts import test_transport_process_recovery as fault_worker
from scripts.certificate_controller import LifecycleError
from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.test_database_transport_runtime import Checks, renewal_rows_preserved


def fixture(*, timed_out=False, retired_changed=False, active_unchanged=False):
    before = {'credentials': {
        'retired': {'name': 'collector', 'generation': 4, 'fingerprint': 'retired'},
        'active': {'name': 'core-a', 'generation': 5, 'fingerprint': 'old'},
        'renew': {'name': 'renew-core-a', 'generation': 5, 'fingerprint': 'renew-old'}}}
    after = copy.deepcopy(before)
    for uid in ('active', 'renew'):
        after['credentials'][uid]['generation'] += 0 if active_unchanged else 1
    if retired_changed:
        after['credentials']['retired']['fingerprint'] = 'unexpected-reissue'
    calls = []
    snapshots = iter((before, after))
    def wait(predicate, reason, timeout):
        assert timeout == 120
        if timed_out or not predicate():
            raise RuntimeFailure(reason)
    def require(ok, reason):
        if not ok:
            raise RuntimeFailure(reason)
    obj = SimpleNamespace(collector='retired',
        runtime=SimpleNamespace(controller_configuration=lambda: {'renew_before': {'original': 400}},
                                controller_status=lambda: after),
        pause=lambda: next(snapshots), configure=lambda **kw: calls.append(kw),
        wait=wait, require=require)
    return obj, calls


def test_fixture_renews_active_generations_and_restores_original_schedule():
    obj, calls = fixture()
    state = Checks.refresh_active_leaves(obj, label='transport')
    assert state['credentials']['retired']['fingerprint'] == 'retired'
    assert calls == [
        {'paused': False, 'renew_before': {'collector': 1199, 'core-a': 1199,
                                         'renew-core-a': 3599}},
        {'renew_before': {'original': 400}}]


@pytest.mark.parametrize('fault', ['timed_out', 'active_unchanged', 'retired_changed'])
def test_fixture_failure_is_not_silenced_and_schedule_is_restored(fault):
    obj, calls = fixture(**{fault: True})
    with pytest.raises(RuntimeFailure):
        Checks.refresh_active_leaves(obj, label='transport')
    assert calls[-1] == {'renew_before': {'original': 400}}


@pytest.mark.parametrize(('used', 'revoked', 'allowed'), [
    ({'original'}, {'revoked'}, True),
    ({'original', 'server-1', 'server-2'}, {'revoked'}, True),
    ({'server-1'}, {'revoked'}, False),
    ({'changed-original'}, {'revoked'}, False),
    ({'original', 'server-1'}, {'revoked', 'retired-old-client'}, True),
    ({'original', 'server-1'}, set(), False),
    ({'original', 'server-1', 'another-consumed-attempt'}, {'revoked'}, True),
    ({'original'}, {'changed-revocation'}, False),
    ({'original', 'new-nonce'}, {'revoked', 'retired-client'}, True),
])
def test_controlled_renewal_keeps_old_rows_while_new_nonce_counts_are_observations(
        used, revoked, allowed):
    before = {'used_ott': {'original'}, 'revoked_x509_certs': {'revoked'}}
    after = {'used_ott': used, 'revoked_x509_certs': revoked}
    assert renewal_rows_preserved(before, after) is allowed


def test_fault_failure_uses_known_code_without_arbitrary_exception_payload():
    assert fault_worker.public_failure(LifecycleError('transport_ca_not_ready'))['reason'] == 'transport_ca_not_ready'
    assert 'synthetic-sensitive' not in json.dumps(fault_worker.public_failure(
        RuntimeError('synthetic-sensitive-payload')))


def test_fault_worker_persists_bounded_public_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(fault_worker, 'ROOT', tmp_path)
    folder = tmp_path / 'runtime/c02/owned'
    folder.mkdir(parents=True)
    token = 'a' * 24
    monkeypatch.setattr(sys, 'argv', ['fault', '--directory', str(folder),
        '--checkpoint', 'resuming', '--token', token])
    def fail(*args):
        raise RuntimeError('synthetic-sensitive-payload')
    monkeypatch.setattr(fault_worker, 'checkpoint_worker', fail)
    assert fault_worker.main() == 1
    body = (folder / ('transport-fault-failure-' + token + '.json')).read_text()
    assert json.loads(body)['token'] == token
    assert 'synthetic-sensitive' not in body


def test_fault_worker_rejects_unowned_directory_before_writing(monkeypatch, tmp_path):
    monkeypatch.setattr(fault_worker, 'ROOT', tmp_path / 'root')
    folder = tmp_path / 'outside'
    monkeypatch.setattr(sys, 'argv', ['fault', '--directory', str(folder),
        '--checkpoint', 'resuming', '--token', 'a' * 24])
    assert fault_worker.main() == 1
    assert not folder.exists()
