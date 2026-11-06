import copy
import json
import os
import time
from types import SimpleNamespace

import pytest

from scripts import database_transport_custodian as t
from scripts import database_transport_runtime as runtime
from scripts import persistent_authority_assets as assets
from scripts import persistent_authority_runtime as parent
from scripts.certificate_controller import LifecycleError


class Hidden(SimpleNamespace):
    def __repr__(self):
        return '<ephemeral transport ceremony>'


def require(value):
    if not value:
        raise AssertionError('transport boundary mismatch')


@pytest.fixture
def lab(tmp_path, monkeypatch):
    if os.name == 'nt':
        monkeypatch.setattr(t.preflight, 'read', lambda p, **kwargs: p.read_bytes())
    files, vault, anchor = t.seed()
    directories = {}
    for volume, values in files.items():
        directory = tmp_path / volume
        directory.mkdir()
        directories[volume] = directory
        for name, body in values.items():
            path = directory / name
            path.write_text(body, encoding='utf-8')
            path.chmod(0o600)
    directory = tmp_path / 'vault'
    directory.mkdir()
    for name, body in vault.items():
        path = directory / name
        path.write_text(body, encoding='utf-8')
        path.chmod(0o600)
    worker = t.Custodian(directory, directories)
    request = {'anchor': anchor, 'journal': t.initial(anchor)}
    return Hidden(worker=worker, request=request, directories=directories, directory=directory)


def pending(lab):
    lab.worker.state['last_at'] = 0
    lab.worker.persist()
    plan = lab.worker.prepare(lab.request)['plan']
    lab.request['journal'].update(phase='prepared', plan=plan)
    return plan


def test_initial_vault_is_sealed_and_normal_timer_does_not_issue_early(lab):
    require(lab.worker.prepare(lab.request)['due'] is False)
    require(b'PRIVATE KEY' not in (lab.directory / 'g0.sealed').read_bytes())
    result = t.verify_files(**lab.request, directories=lab.directories)
    require(result['verified'] and len(result['transport']['credentials']) == 3)


def test_same_pending_candidate_survives_process_recreation_and_complete_commit(lab):
    plan = pending(lab)
    worker = t.Custodian(lab.directory, lab.directories)
    require(worker.prepare(lab.request)['plan'] == plan)
    lab.request['journal']['phase'] = 'stopped'
    require(worker.install(lab.request)['verified'])
    lab.request['journal']['phase'] = 'committing'
    require(worker.commit(lab.request)['sealed_bundles'] == 1)
    # The host may not have received the commit response; exact replay is safe.
    require(t.Custodian(lab.directory, lab.directories).commit(lab.request)['committed'])
    lab.request['journal'].update(epoch=1, manifest=t.custody.digest(plan), history=[plan], plan=None, phase='idle')
    require(t.verify_files(**lab.request, directories=lab.directories)['verified'])
    require(lab.request['anchor']['files'] != plan['after'])


def test_partial_multi_volume_publish_resumes_same_plan_without_new_keys(lab, monkeypatch):
    plan = pending(lab)
    lab.request['journal']['phase'] = 'stopped'
    original, count = t.atomic, []

    def interrupted(path, body):
        original(path, body)
        count.append(1)
        if len(count) == 4:
            raise OSError('synthetic interrupted response')

    monkeypatch.setattr(t, 'atomic', interrupted)
    with pytest.raises(OSError):
        lab.worker.install(lab.request)
    require(t.verify_files(**lab.request, directories=lab.directories, partial=True)['verified'])
    monkeypatch.setattr(t, 'atomic', original)
    worker = t.Custodian(lab.directory, lab.directories)
    require(worker.state['pending']['plan'] == plan and worker.install(lab.request)['verified'])


@pytest.mark.parametrize('fault', ['proof', 'epoch', 'previous', 'before', 'after', 'scope', 'policy', 'root', 'time'])
def test_plan_mutation_cannot_authorize_rotation(lab, fault):
    plan = copy.deepcopy(pending(lab))
    if fault == 'proof':
        plan['proof'] = 'AAAA'
    elif fault == 'epoch':
        plan['epoch'] = True
    elif fault == 'previous':
        plan['previous'] = 'old'
    elif fault == 'before':
        plan['before'][next(iter(t.FILES))]['root.pem'] = '0' * 64
    elif fault == 'after':
        plan['after'][next(iter(t.FILES))]['server.key'] = '0' * 64
    elif fault == 'scope':
        plan['after']['../foreign'] = {}
    elif fault == 'policy':
        plan['policy'] = dict(t.POLICY, root_days=999)
    elif fault == 'root':
        plan['root'] = lab.request['anchor']['root']
    else:
        plan['created_at'] = float('inf')
    with pytest.raises((ValueError, LifecycleError, OverflowError)):
        t.verify_plan(plan, lab.request['anchor']['root'], lab.request['anchor']['files'], 1, None)


@pytest.mark.parametrize('fault', ['phase', 'epoch', 'missing_plan', 'history', 'manifest', 'anchor'])
def test_journal_and_original_anchor_cannot_be_silently_resealed(lab, fault):
    pending(lab)
    request = copy.deepcopy(lab.request)
    j = request['journal']
    if fault == 'phase':
        j['phase'] = 'unknown'
    elif fault == 'epoch':
        j['epoch'] = 1
    elif fault == 'missing_plan':
        j['plan'] = None
    elif fault == 'history':
        j['history'] = [j['plan']] * 65
    elif fault == 'manifest':
        j['manifest'] = '0' * 64
    else:
        request['anchor']['policy']['root_days'] = 999
    with pytest.raises((LifecycleError, ValueError)):
        t.checked(**request)


def test_unapproved_private_file_is_denied_even_during_stopped_partial_resume(lab):
    pending(lab)
    lab.request['journal']['phase'] = 'stopped'
    path = lab.directories['authority-ca-b-db'] / 'client.key'
    path.write_text('synthetic-unapproved-value')
    with pytest.raises(LifecycleError, match='published_file_changed'):
        lab.worker.install(lab.request)


def test_ordinary_preflight_cannot_accept_half_published_transport_state(lab):
    pending(lab)
    lab.request['journal']['phase'] = 'installed'
    with pytest.raises(LifecycleError, match='published_file_changed'):
        t.verify_files(**lab.request, directories=lab.directories)


def test_expired_current_authority_is_not_automatically_resurrected(lab, monkeypatch):
    monkeypatch.setattr(t.time, 'time', lambda: 10**12)
    with pytest.raises(LifecycleError, match='expired_requires_explicit_recovery'):
        lab.worker.prepare(lab.request)


def test_opt_in_profile_adds_only_isolated_vault_no_online_mount():
    spec = runtime.definition('kmtls-012345abcdef', 'app', 'nginx')
    assert len(spec['services']) == 18 and len(spec['networks']) == 10 and len(spec['volumes']) == 37
    assert all(runtime.VAULT not in m for s in spec['services'].values() for m in s['volumes'])
    assert parent.PersistentAuthorityRuntime.volumes == runtime.TransportRuntime.volumes[:-1]


def test_dynamic_transport_certificates_are_checked_by_signed_manifest_not_new_hash_baselines():
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-transport')
    value.state = {'authority_public_sha256': {v: dict.fromkeys(names, 'approved') for v, names in assets.PUBLIC_FILES.items()}}
    inventory = value.authority_public_inventory()
    assert inventory['authority-db-tls'] == ('start.sh', 'pg_hba.conf', 'postgresql.conf')
    assert 'authority-ca-a-db' not in inventory and 'authority-ca-b-db' not in inventory
    assert set(value.authority_public_expected()) == set(inventory)


@pytest.mark.parametrize('phase', ['prepared', 'stopped', 'installed', 'committing', 'resuming'])
def test_pending_work_blocks_ordinary_startup_and_down(phase, monkeypatch):
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-pending-transport')
    monkeypatch.setattr(value, 'transport_journal', lambda: {'phase': phase})
    with pytest.raises(runtime.RuntimeFailure, match='requires_pinned_resume'):
        value.transport_idle()


def test_no_mutation_is_allowed_while_any_pinned_transport_service_runs(monkeypatch):
    worker = object.__new__(runtime.TransportCoordinator)
    worker.nodes = lambda: [{'id': 'approved'}]
    worker.backend = SimpleNamespace(owned_container=lambda n: None)
    monkeypatch.setattr(runtime, 'command', lambda *a, **kw: '{"Running":true}')
    with pytest.raises(LifecycleError, match='requires_stopped_nodes'):
        worker.stopped()


@pytest.mark.parametrize('operation', ['prepare', 'install', 'commit'])
def test_mutation_helper_cannot_be_called_outside_the_pinned_host_coordinator(operation, monkeypatch):
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-uncoordinated-transport')
    monkeypatch.setattr(value, 'verify_owned_volumes', lambda: None)
    monkeypatch.setattr(runtime, 'command', lambda *a, **kw: pytest.fail('uncoordinated secret mount'))
    with pytest.raises(LifecycleError, match='requires_host_coordinator'):
        value.transport_job(operation)


def test_verification_helper_cannot_mount_vault_or_database_data(monkeypatch):
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-transport-readonly')
    value.state = {'project': 'kmtls-012345abcdef', 'authority_image_id': 'sha256:' + 'a' * 64,
                   'transport_anchor': {}, 'volumes': {v: 'owned-' + v for v in t.FILES}}
    monkeypatch.setattr(value, 'verify_owned_volumes', lambda: None)
    monkeypatch.setattr(value, 'transport_journal', dict)

    def command(argv, **kwargs):
        assert argv[argv.index('--network') + 1] == 'none' and argv.count('--mount') == 3
        assert all(argv[i + 1].endswith(',readonly') for i, word in enumerate(argv) if word == '--mount')
        assert not any('/vault' in word or '/pgdata' in word or 'docker.sock' in word for word in argv)
        return '{"verified":true}'

    monkeypatch.setattr(runtime, 'command', command)
    assert value.transport_job('verify')['verified']


def test_acceptance_runtime_reuses_bootstrap_capture_and_new_transport_graph():
    from scripts.test_database_transport_runtime import AcceptanceTransport, Checks
    from scripts.test_persistent_authority_runtime import AcceptanceRuntime
    assert issubclass(AcceptanceTransport, runtime.TransportRuntime)
    assert AcceptanceTransport.helper is AcceptanceRuntime.helper
    assert AcceptanceTransport.seed_last_at == 0 and Checks.expected_volumes == 37


@pytest.mark.parametrize('phase', ['prepared', 'stopped', 'installed', 'started', 'committing'])
def test_foreign_container_or_mount_blocks_every_transition_before_mutation(tmp_path, monkeypatch, phase):
    worker = object.__new__(runtime.TransportCoordinator)
    worker.state = {'phase': phase}
    worker.runtime = SimpleNamespace(_transport_active=False)
    worker.persist = lambda: pytest.fail('persisted after scope failure')

    def deny():
        raise LifecycleError('transport_pinned_objects_changed')

    worker.admit = deny
    monkeypatch.setattr(runtime, 'command', lambda *a, **kw: pytest.fail('mutated after scope failure'))
    with pytest.raises(LifecycleError, match='pinned_objects_changed'):
        worker.tick()
    assert worker.runtime._transport_active is False


def test_failure_after_candidate_publish_does_not_advance_or_unpause(monkeypatch):
    worker = object.__new__(runtime.TransportCoordinator)
    worker.state = {'phase': 'stopped'}
    worker.admit = worker.stopped = lambda: None
    worker.persist = lambda: pytest.fail('advanced after unsuccessful publication')

    def failed(operation):
        assert operation == 'install'
        raise runtime.RuntimeFailure('synthetic_publish_failure')

    worker.runtime = SimpleNamespace(transport_job=failed)
    worker.leaf = lambda *a, **kw: pytest.fail('unpaused after unsuccessful publication')
    with pytest.raises(runtime.RuntimeFailure):
        worker.tick()
    assert worker.state['phase'] == 'stopped'


def test_failed_live_database_validation_never_commits_or_resumes(monkeypatch):
    worker = object.__new__(runtime.TransportCoordinator)
    worker.state = {'phase': 'committing'}
    worker.runtime = SimpleNamespace(transport_job=lambda *a: pytest.fail('committed without live validation'))
    worker.admit = lambda: None
    worker.persist = lambda: pytest.fail('persisted after failed live barrier')
    worker.live = lambda: (_ for _ in ()).throw(LifecycleError('transport_live_database_identity_failed'))
    with pytest.raises(LifecycleError, match='live_database_identity'):
        worker.tick()
    assert worker.state['phase'] == 'committing'


def test_idle_timer_does_not_spawn_helpers_before_next_due():
    worker = object.__new__(runtime.TransportCoordinator)
    worker.state = {'phase': 'idle', 'next_due_at': time.time() + 300}
    worker.runtime = SimpleNamespace()
    worker.admit = lambda: pytest.fail('idle timer launched Docker helper')
    worker.tick()


def test_executable_acceptance_probe_programs_parse_before_long_docker_run():
    import ast

    from scripts.test_database_transport_runtime import AcceptanceTransport
    assert AcceptanceTransport.__mro__.index(runtime.TransportRuntime) < AcceptanceTransport.__mro__.index(parent.PersistentAuthorityRuntime)
    source = (runtime.ROOT / 'scripts/test_database_transport_runtime.py').read_text(encoding='utf-8')
    programs = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and 'from scripts.' in node.value:
            programs.append(node.value)
            ast.parse(node.value)
    assert len(programs) == 2


def helper_runtime(monkeypatch, project='kmtls-012345abcdef'):
    value = runtime.TransportRuntime(runtime.ROOT / 'runtime/c02/unit-helper-fence')
    value.state = {'project': project, 'authority_image_id': 'sha256:' + 'a' * 64, 'transport_anchor': {},
                   'volumes': {v: project + '-' + v for v in (*t.FILES, runtime.VAULT)}}
    value._transport_active = True
    monkeypatch.setattr(value, 'verify_owned_volumes', lambda: None)
    monkeypatch.setattr(value, 'transport_journal', dict)
    return value


def test_surviving_prepare_helper_fences_commit_without_fallback_or_new_candidate(monkeypatch):
    value = helper_runtime(monkeypatch)
    reserved, calls = set(), []

    def command(argv, **kwargs):
        name = argv[argv.index('--name') + 1]
        calls.append(json.loads(kwargs['payload'])['operation'])
        assert name == value.state['project'] + '-database-transport-custodian'
        if name in reserved:
            raise runtime.RuntimeFailure('synthetic_existing_container_name')
        reserved.add(name)
        return '{"due":false}'

    monkeypatch.setattr(runtime, 'command', command)
    value.transport_job('prepare')
    with pytest.raises(runtime.RuntimeFailure, match='existing_container_name'):
        value.transport_job('commit')
    assert calls == ['prepare', 'commit'] and len(reserved) == 1


def test_helper_fence_is_project_scoped_and_public_verification_has_no_vault_name(monkeypatch):
    first = helper_runtime(monkeypatch)
    second = helper_runtime(monkeypatch, 'kmtls-fedcba543210')
    names = []

    def command(argv, **kwargs):
        if json.loads(kwargs['payload'])['operation'] == 'verify':
            assert '--name' not in argv and not any('/vault' in v for v in argv)
        else:
            names.append(argv[argv.index('--name') + 1])
        return '{"verified":true}'

    monkeypatch.setattr(runtime, 'command', command)
    first.transport_job('prepare')
    second.transport_job('prepare')
    first.transport_job('verify')
    assert len(set(names)) == 2


@pytest.mark.parametrize('phase', ['idle', 'stopped'])
def test_test_driver_wakeup_preserves_journal_and_policy_and_refuses_pending(phase, tmp_path, monkeypatch):
    from scripts.test_database_transport_runtime import Checks
    worker = object.__new__(Checks)
    journal = {'phase': phase, 'epoch': 2, 'history': ['preserved-public-history'], 'next_due_at': time.time() + 300}
    path = tmp_path / 'journal.json'
    path.write_text(json.dumps(journal))
    calls = []
    policy = copy.deepcopy(t.POLICY)
    worker.runtime = SimpleNamespace(transport_journal=lambda: copy.deepcopy(journal), transport_path=path,
        verify_owned_volumes=lambda: calls.append('scope'), state={'volumes': {runtime.VAULT: 'owned-vault'},
        'authority_image_id': 'sha256:' + 'a' * 64})
    monkeypatch.setattr('scripts.test_database_transport_runtime.command', lambda *a, **kw: calls.append('test-vault-timer'))
    if phase != 'idle':
        with pytest.raises(runtime.RuntimeFailure, match='force_requires_idle'):
            worker.force_transport_due()
        assert calls == [] and json.loads(path.read_text()) == journal
    else:
        worker.force_transport_due()
        assert json.loads(path.read_text()) == journal | {'next_due_at': 0}
        assert calls == ['scope', 'test-vault-timer'] and t.POLICY == policy
