import base64
import copy
import json
from types import SimpleNamespace

import pytest

from scripts import database_backup_runtime as runtime
from scripts import database_backup_store as store
from scripts.ca_recovery_state import save
from scripts.certificate_controller import LifecycleError
from tests.reviewer_credentials import assert_reviewer_isolation


@pytest.fixture
def archive_request(tmp_path):
    key = tmp_path / 'key.hex'
    key.write_text('a' * 64)
    return {'operation': 'seal', 'manifest': {'schema': 'database-backup-1', 'id': 'b' * 24,
        'project': 'kmtls-' + 'c' * 12, 'profile': 'd' * 64, 'created_at': 1,
        'security': {n: {'rows': 1, 'sha256': 'e' * 64} for n in runtime.TABLES}},
        'dump': base64.b64encode(b'PGDMP-secret-fixture').decode()}, key


def test_encrypted_archive_roundtrip_and_idempotent_publish(tmp_path, archive_request):
    data, key = archive_request
    first = store.operation(data, tmp_path, key)
    assert store.operation(data, tmp_path, key) == first
    raw = (tmp_path / (data['manifest']['id'] + '.json')).read_bytes()
    assert b'secret-fixture' not in raw and data['dump'].encode() not in raw
    read = store.operation(data | {'operation': 'read'}, tmp_path, key)
    assert read.pop('dump') == data['dump'] and read == first


@pytest.mark.parametrize('fault', ['ciphertext', 'nonce', 'aad', 'key', 'different_project', 'different_profile', 'different_content'])
def test_archive_integrity_and_context_fail_closed(tmp_path, archive_request, fault):
    data, key = archive_request
    store.operation(data, tmp_path, key)
    path = tmp_path / (data['manifest']['id'] + '.json')
    envelope = json.loads(path.read_bytes())
    if fault in {'ciphertext', 'nonce'}:
        envelope[fault] = 'AAAA'
        path.write_text(json.dumps(envelope))
    elif fault == 'aad':
        envelope['manifest']['created_at'] += 1
        path.write_text(json.dumps(envelope))
    elif fault == 'key':
        key.write_text('f' * 64)
    elif fault == 'different_content':
        data['dump'] = base64.b64encode(b'PGDMP-other').decode()
    else:
        field = 'project' if fault == 'different_project' else 'profile'
        data['manifest'][field] = 'kmtls-' + 'f' * 12 if field == 'project' else 'f' * 64
    with pytest.raises(LifecycleError):
        store.operation(data, tmp_path, key)


@pytest.mark.parametrize('fault', ['path', 'time_bool', 'time_negative', 'row_bool', 'rows_many', 'table', 'hash', 'extra'])
def test_manifest_refuses_unbounded_or_out_of_scope_values(archive_request, fault):
    data, _ = archive_request
    m = data['manifest']
    if fault == 'path':
        m['id'] = '../outside'
    elif fault.startswith('time'):
        m['created_at'] = True if fault == 'time_bool' else -1
    elif fault in {'row_bool', 'rows_many'}:
        m['security'][runtime.TABLES[0]]['rows'] = True if fault == 'row_bool' else 100001
    elif fault == 'table':
        m['security']['untrusted;SQL'] = m['security'].pop(runtime.TABLES[0])
    elif fault == 'hash':
        m['profile'] = 'not-a-digest'
    else:
        m['extra'] = 'unsupported'
    with pytest.raises(LifecycleError):
        store.validate_manifest(m)


def test_store_capacity_never_overwrites_old_archives(tmp_path, archive_request, monkeypatch):
    data, key = archive_request
    store.operation(data, tmp_path, key)
    monkeypatch.setattr(store, 'MAX_ARCHIVES', 1)
    data['manifest']['id'] = 'c' * 24
    with pytest.raises(LifecycleError, match='capacity'):
        store.operation(data, tmp_path, key)
    assert len(list(tmp_path.glob('*.json'))) == 1


def test_capacity_probe_reports_full_without_modifying_archives(tmp_path, archive_request, monkeypatch):
    data, key = archive_request
    store.operation(data, tmp_path, key)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    monkeypatch.setattr(store, 'MAX_ARCHIVES', 1)
    assert store.operation(data | {'operation': 'capacity'}, tmp_path, key) == {'available': 0}
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_full_store_refuses_new_backup_before_persist_pause_or_stop():
    worker = object.__new__(runtime.BackupCoordinator)
    worker.profile, worker.state = {}, None
    worker.admit = lambda: None
    worker.persist = lambda: pytest.fail('persisted intent for full store')
    worker.runtime = SimpleNamespace(state={'project': 'kmtls-' + 'a' * 12},
        controller_status=lambda: {'paused': False}, backup_store=lambda *a: {'available': 0},
        save=lambda: pytest.fail('changed descriptor for full store'))
    worker.backend = SimpleNamespace(leaf=lambda *a, **kw: pytest.fail('paused for full store'))
    with pytest.raises(LifecycleError, match='retention_capacity'):
        worker.tick(new=True)
    assert worker.runtime._backup_active is False


@pytest.mark.parametrize('phase', ['stopped', 'complete'])
def test_changed_profile_only_allowed_for_completed_historical_backup(phase):
    worker = object.__new__(runtime.BackupCoordinator)
    worker.profile = {'leaf': 'leaf', 'transport_database': 'db', 'ca_replicas': ['a', 'b']}
    worker.state = {'phase': phase, 'manifest': {'profile': 'old-profile'}}
    noop = lambda: None
    worker.runtime = SimpleNamespace(verify_release=noop, verify_owned_volumes=noop,
        journal=lambda: {'phase': 'idle'}, transport_journal=lambda: {'phase': 'idle'},
        make_profile=lambda: worker.profile, state={'authority_profile_sha256': runtime.custody.digest(worker.profile)},
        verify_monitoring_configuration=noop, verify_public_configuration=noop, verify_authority_public_assets=noop)
    worker.backend = SimpleNamespace(owned_container=lambda node: None)
    if phase == 'stopped':
        with pytest.raises(LifecycleError, match='pending_profile_changed'):
            worker.admit()
    else:
        worker.admit()


@pytest.mark.parametrize('body', ['!!!!', base64.b64encode(b'plain SQL').decode(), 'A' * 100])
def test_dump_requires_bounded_custom_archive(body, monkeypatch):
    monkeypatch.setattr(store, 'LIMIT', 16)
    with pytest.raises(LifecycleError):
        store.decode_dump(body)


def test_online_graph_never_mounts_backup_or_key():
    spec = runtime.definition('kmtls-' + 'a' * 12, 'app', 'nginx')
    assert_reviewer_isolation(spec)
    assert len(spec['volumes']) == 43 and len(spec['services']) == 18
    for service in spec['services'].values():
        assert not any(m.split(':')[0] in runtime.VOLUMES for m in service['volumes'])


@pytest.mark.parametrize('operation', ['seal', 'read'])
def test_crypto_helper_disables_plaintext_stdout_logs_and_container_swap(monkeypatch, operation):
    r = object.__new__(runtime.BackupRuntime)
    r.state = {'project': 'project', 'authority_image_id': 'image', 'volumes': dict.fromkeys(runtime.VOLUMES, 'volume')}
    r.verify_owned_volumes = lambda: None
    def command(argv, **kwargs):
        assert argv[argv.index('--log-driver') + 1] == 'none'
        assert argv[argv.index('--memory-swap') + 1] == argv[argv.index('--memory') + 1] == '512m'
        assert argv[argv.index('--network') + 1] == 'none'
        assert 'dst=/key,readonly' in ' '.join(argv)
        return '{}'
    monkeypatch.setattr(runtime, 'command', command)
    r.backup_store(operation, {})


@pytest.mark.parametrize('phase', ['quiescing', 'stopped', 'sealed', 'verified', 'resuming'])
def test_pending_backup_blocks_rotations_and_normal_management_before_parent(phase, monkeypatch):
    r = object.__new__(runtime.BackupRuntime)
    r.backup_journal = lambda: {'phase': phase}
    monkeypatch.setattr(runtime.TransportRuntime, 'transport_idle', lambda self: pytest.fail('passed pending backup'))
    with pytest.raises(LifecycleError, match='pinned_resume'):
        r.transport_idle()


@pytest.mark.parametrize('fault', ['phase', 'missing_archive', 'false_verification', 'pause', 'missing_journal'])
def test_journal_never_marks_incomplete_backup_complete(tmp_path, archive_request, fault):
    data, _ = archive_request
    r = object.__new__(runtime.BackupRuntime)
    r.directory, r.state = tmp_path, {'project': data['manifest']['project'], 'backup_started': True}
    value = {'phase': 'complete', 'manifest': data['manifest'], 'restore_paused': True,
        'archive': {'exists': True, 'archive_sha256': 'a' * 64, 'dump_sha256': 'b' * 64, 'bytes': 10}, 'verified': True}
    if fault == 'phase':
        value['phase'] = 'unknown'
    elif fault == 'missing_archive':
        value['archive'] = None
    elif fault == 'false_verification':
        value['verified'] = False
    elif fault == 'pause':
        value['restore_paused'] = 'false'
    if fault != 'missing_journal':
        save(r.backup_path, value)
    with pytest.raises(LifecycleError):
        r.backup_journal()


def sandbox_record():
    return {'Id': 'id', 'Name': '/project-backup-restore', 'Image': 'image', 'Mounts': [],
        'Config': {'Labels': {'secops.runtime': 'project', 'secops.backup': 'backup'}, 'User': '10001:10001',
            'Entrypoint': runtime.RESTORE_COMMAND[:1], 'Cmd': runtime.RESTORE_COMMAND[1:]},
        'HostConfig': {'NetworkMode': 'none', 'Privileged': False, 'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
            'SecurityOpt': ['no-new-privileges:true'], 'Tmpfs': dict.fromkeys(['/restore', '/tmp', '/var/lib/postgresql/data'], 'rw'),
            'Memory': 256 * 1024**2, 'MemorySwap': 256 * 1024**2, 'LogConfig': {'Type': 'none'},
            'NanoCpus': 1000000000, 'PidsLimit': 64}}


@pytest.mark.parametrize('fault', ['network', 'mount', 'image', 'label', 'command', 'user', 'privileged', 'writable', 'pids'])
def test_restore_refuses_foreign_or_weakened_sandbox_before_delete(monkeypatch, fault):
    record = copy.deepcopy(sandbox_record())
    if fault == 'network':
        record['HostConfig']['NetworkMode'] = 'host'
    elif fault == 'mount':
        record['Mounts'] = [{'Type': 'volume', 'Name': 'live-data'}]
    elif fault == 'image':
        record['Image'] = 'foreign'
    elif fault == 'label':
        record['Config']['Labels']['secops.backup'] = 'foreign'
    elif fault == 'command':
        record['Config']['Cmd'] = ['foreign']
    elif fault == 'user':
        record['Config']['User'] = '0'
    else:
        record['HostConfig'][{'privileged': 'Privileged', 'writable': 'ReadonlyRootfs', 'pids': 'PidsLimit'}[fault]] = (
            True if fault == 'privileged' else False if fault == 'writable' else -1)
    def command(argv):
        assert 'rm' not in argv
        return 'id' if argv[1] == 'ps' else json.dumps([record])
    monkeypatch.setattr(runtime, 'command', command)
    r = SimpleNamespace(state={'project': 'project', 'authority_database_image_id': 'image'})
    with pytest.raises(LifecycleError, match='container_scope'):
        runtime.RestoreDrill(r, {'id': 'backup'}).cleanup()
