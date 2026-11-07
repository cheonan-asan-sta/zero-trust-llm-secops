import copy
import json

import pytest

from scripts import database_recovery_checkpoint as checkpoint
from scripts.certificate_controller import LifecycleError
from scripts.database_backup_runtime import TABLES
from scripts.database_recovery_runtime import VOLUMES, RecoveryRuntime, definition


@pytest.fixture
def checkpoint_request(tmp_path):
    key = tmp_path / 'key.hex'
    key.write_text('a' * 64)
    manifest = {'schema': 'database-backup-1', 'id': 'b' * 24, 'project': 'kmtls-' + 'c' * 12,
                'profile': 'd' * 64, 'created_at': 1,
                'security': {n: {'rows': 1, 'sha256': 'e' * 64} for n in TABLES}}
    return {'operation': 'publish', 'manifest': manifest, 'expected': copy.deepcopy(checkpoint.ZERO)}, key


def run(checkpoint_request, tmp_path, key):
    return checkpoint.operation(checkpoint_request, tmp_path, key)


def test_lost_publish_ack_adopts_exact_authenticated_candidate(checkpoint_request, tmp_path):
    data, key = checkpoint_request
    first = run(data, tmp_path, key)
    raw = (tmp_path / 'latest.json').read_bytes()
    assert run(data, tmp_path, key) == first
    assert (tmp_path / 'latest.json').read_bytes() == raw
    data['expected'] = first['head']
    assert run(data, tmp_path, key) == first
    assert run(data | {'operation': 'assess'}, tmp_path, key)['checkpoint_compatible']


@pytest.mark.parametrize('table', TABLES)
def test_new_checkpoint_denies_rollback_of_each_security_table(checkpoint_request, tmp_path, table):
    data, key = checkpoint_request
    old = copy.deepcopy(data['manifest'])
    data['expected'] = run(data, tmp_path, key)['head']
    data['manifest']['id'] = 'f' * 24
    data['manifest']['security'][table] = {'rows': 2, 'sha256': 'f' * 64}
    data['expected'] = run(data, tmp_path, key)['head']
    assert run(data | {'operation': 'assess'}, tmp_path, key)['live_restore_authorized'] is False
    with pytest.raises(LifecycleError, match='security_rollback'):
        run(data | {'operation': 'assess', 'manifest': old}, tmp_path, key)


@pytest.mark.parametrize('fault', ['missing', 'tamper', 'wrong_key', 'rollback', 'ahead', 'project', 'candidate'])
def test_missing_tampered_or_unmatched_checkpoint_fails_closed(checkpoint_request, tmp_path, fault):
    data, key = checkpoint_request
    data['expected'] = run(data, tmp_path, key)['head']
    path = tmp_path / 'latest.json'
    old = path.read_bytes()
    if fault == 'missing':
        path.unlink()
    elif fault == 'tamper':
        value = json.loads(old); value['ciphertext'] = 'AAAA'; path.write_text(json.dumps(value))
    elif fault == 'wrong_key':
        key.write_text('f' * 64)
    elif fault == 'rollback':
        data['manifest']['id'] = 'f' * 24
        data['expected'] = run(data, tmp_path, key)['head']
        path.write_bytes(old)
    elif fault == 'ahead':
        data['expected']['sequence'] += 1
    elif fault == 'project':
        data['manifest']['project'] = 'kmtls-' + 'f' * 12
    else:
        data['expected'] = copy.deepcopy(checkpoint.ZERO)
        data['manifest']['id'] = 'f' * 24
        data['operation'] = 'publish'
    with pytest.raises(LifecycleError):
        run(data | {'operation': data['operation'] if fault == 'candidate' else 'assess'}, tmp_path, key)


@pytest.mark.parametrize('value', [None, {}, {'sequence': True, 'sha256': 'a' * 64},
    {'sequence': -1, 'sha256': 'a' * 64}, {'sequence': 0, 'sha256': 'a' * 64},
    {'sequence': 1, 'sha256': '0' * 64}, {'sequence': 1, 'sha256': '../key'},
    {'sequence': 2**53, 'sha256': 'a' * 64}])
def test_anchor_shape_is_strict(value):
    with pytest.raises(LifecycleError):
        checkpoint.anchor(value)


def test_checkpoint_volumes_absent_from_online_graph():
    spec = definition('kmtls-' + 'a' * 12, 'image', 'nginx')
    assert len(spec['volumes']) == 41
    for service in spec['services'].values():
        assert not any(m.split(':')[0] in VOLUMES for m in service['volumes'])


def test_missing_host_anchor_refuses_helper_before_docker(monkeypatch):
    r = object.__new__(RecoveryRuntime)
    r.state = {}
    r.verify_owned_volumes = lambda: None
    with pytest.raises(LifecycleError, match='anchor_invalid'):
        r.checkpoint_job('assess', {})
