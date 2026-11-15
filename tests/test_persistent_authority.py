import ast
import copy
import inspect
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from scripts import authority_custodian as custody
from scripts import certificate_authority as ca
from scripts import persistent_authority_assets as assets
from scripts import persistent_authority_control as control
from scripts import persistent_authority_runtime as runtime
from scripts.authority_rotation_coordinator import Coordinator
from scripts.certificate_controller import LifecycleError
from scripts.rekey_mtls_runtime import RekeyRuntime
from tests.reviewer_credentials import assert_reviewer_isolation


def require(value):
    if not value:
        raise AssertionError('ephemeral authority boundary')


class Hidden(SimpleNamespace):
    def __repr__(self):
        return '<ephemeral authority material in RAM>'


def test_optional_graph_is_isolated_and_online_services_never_mount_vault():
    spec = runtime.definition('kmtls-012345abcdef', 'app', 'nginx')
    assert_reviewer_isolation(spec)
    assert len(spec['services']) == 18 and len(spec['volumes']) == 40 and len(spec['networks']) == 10
    assert all(n['internal'] for n in spec['networks'].values())
    for service in spec['services'].values():
        assert service['user'] == '10001:10001' and service['read_only'] and not service.get('ports')
        assert service['cap_drop'] == ['ALL'] and not service.get('privileged')
        assert all('vault' not in path and 'docker.sock' not in path for path in service['volumes'])
    for name in ('ca', 'ca-secondary'):
        assert 'ca-state:/ca:ro' in spec['services'][name]['volumes']
        assert set(spec['services'][name]['networks']) == {'ca', 'ca-db'}
    assert set(spec['services']['ca-db']['networks']) == {'ca-db'}
    assert 'ca-db' not in spec['services']['certificate-controller']['networks']
    assert spec['services']['ca']['volumes'] != spec['services']['ca-secondary']['volumes']


def test_new_profile_release_is_distinct_and_retains_both_approved_locks():
    new = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-new-authority').release_inputs()
    old = RekeyRuntime(runtime.ROOT / 'runtime/c02/unit-old-rekey').release_inputs()
    assert new['sha256'] != old['sha256'] and set(assets.INPUTS) <= set(new['payload']['files'])


def test_fresh_authority_secrets_are_sealed_not_distributed_to_controller_or_ca():
    policy = {'periods': {'root': 3600, 'issuer': 3600, 'jwk': 3600}}
    material, providers = assets.material(policy)
    vault = material['authority-vault']
    bundle = custody.unseal(vault['authority-g0.sealed'].encode(), vault['password'].encode())
    require('PRIVATE KEY' not in vault['authority-g0.sealed'])
    require(len(bundle['keys']) == len(bundle['providers']) == 50 and len(providers) == 39)
    require(not any('root' in n and n.endswith('.key') for n in material['ca-state']))
    require('ENCRYPTED PRIVATE KEY' in material['ca-state']['issuer.key'])
    require(not any('PRIVATE KEY' in v for v in material['certificate-state'].values()))
    require(all('d' not in p['key'] for p in bundle['providers']))
    cfg = json.loads(material['ca-state']['ca.json'])
    require(cfg['db']['type'] == 'postgresql' and 'sslmode=verify-full' in cfg['db']['dataSource'])
    require(cfg['dnsNames'] == ['ca', 'ca-a', 'ca-b'])
    require(material['authority-ca-a-db']['client.key'] != material['authority-ca-b-db']['client.key'])
    require('initialize.once' not in material['ca-state'])
    require('test -f /pgdata/initialize.once' in material['authority-db-tls']['start.sh'])
    require('mv /pgdata/initialize.once /pgdata/initialized' in material['authority-db-tls']['start.sh'])


@pytest.fixture
def ceremony():
    root, issuer = ca.hierarchy()
    entry, key = ca.provisioner('collector', 'clientAuth')
    signer = ec.generate_private_key(ec.SECP256R1())
    server = ca.server_renewal_provisioner('server', signer.public_key())
    providers = [entry, server]
    files = ca.ca_files(root, issuer, providers)
    policy = {'periods': {'root': 1, 'issuer': 1, 'jwk': 1}, 'root_days': 2, 'issuer_days': 2}
    sealed = custody.seed_files(root, issuer, providers, {'collector-clientAuth': key, 'server-renewal-server': signer},
                                {'server': 'sign-server.key'}, policy=policy, last_at=0)
    state = json.loads(sealed['state.json'])
    bundle = custody.unseal(sealed['authority-g0.sealed'].encode(), sealed['password'].encode())
    candidate = custody.rotate_bundle(bundle, state, time.time())
    plan = custody.public_plan(bundle, candidate, json.loads(files['ca.json']), None)
    base = {'roots': ['/managed/renewal-tls', '/managed/client-tls'], 'paused': False, 'disabled': [], 'renew_before': {},
            'authority_epoch': 0, 'authority_manifest_hash': None, 'authority_signer_root': '/managed/renewal-tls',
            'server_signers': {'server': '/managed/renewal-tls/sign-server.key'}}
    request = {'initial_configuration': base, 'initial_configuration_sha256': custody.digest(control.assets.fixed_configuration(base)),
               'initial_ca': json.loads(files['ca.json']), 'initial_root': files['root.pem'],
               'initial_issuer': files['issuer.pem'], 'journal': control.initial_journal(files['root.pem']), 'rekey': {}}
    return Hidden(root=root, issuer=issuer, files=files, candidate=candidate, plan=plan, base=base,
                  request=request, signer=signer)


def complete(h):
    value = control.initial_journal(h.files['root.pem'])
    value.update(epoch=1, root=h.plan['root'], manifest_hash=custody.digest(h.plan),
                 history=[{'epoch': 1, 'plan_hash': custody.digest(h.plan), 'plan': h.plan}])
    return value


def test_signed_history_is_anchored_to_original_scope_and_plan_order(ceremony):
    h = ceremony
    checked = control.journal(complete(h), h.request['initial_ca'], h.request['initial_root'])
    require(checked['epoch'] == 1 and checked['manifest'] == custody.digest(h.plan))


@pytest.mark.parametrize('attack', ['proof', 'sequence', 'checkpoint', 'manifest', 'scope', 'phase', 'plan_missing', 'epoch', 'history_hash'])
def test_corrupt_or_replayed_authority_journal_is_refused(ceremony, attack):
    h = ceremony
    value = copy.deepcopy(complete(h))
    if attack == 'proof':
        value['history'][0]['plan']['proof'] = 'AAAA'
    elif attack == 'sequence':
        value['history'].append(copy.deepcopy(value['history'][0]))
    elif attack == 'checkpoint':
        value['root'] = h.request['initial_root']
    elif attack == 'manifest':
        value['manifest_hash'] = '0' * 64
    elif attack == 'scope':
        value['history'][0]['plan']['final_ca']['authority']['provisioners'][0]['claims'] = {'maxTLSCertDuration': '999h'}
    elif attack == 'phase':
        value['phase'] = 'unknown'
    elif attack == 'plan_missing':
        value['phase'] = 'migrating'
    elif attack == 'epoch':
        value['epoch'] = 2
    else:
        value['history'][0]['plan_hash'] = '0' * 64
    with pytest.raises((ValueError, KeyError)):
        control.journal(value, h.request['initial_ca'], h.request['initial_root'])


def install_files(monkeypatch, h, phase='idle', *, finished=False):
    request = copy.deepcopy(h.request)
    journal = complete(h) if finished else request['journal']
    if phase != 'idle':
        journal.update(phase=phase, plan=h.plan)
    request['journal'] = journal
    checked = control.journal(journal, request['initial_ca'], request['initial_root'])
    cfg = control.configuration_variants(h.base, checked, phase)[-1]
    pending = phase != 'idle'
    ca_config = h.plan['final_ca'] if finished or phase in {'trust_retired', 'committing'} else (
        h.plan['overlap_ca'] if phase in {'trust_staged', 'ca_activated', 'leaf_activating', 'migrating', 'quiescing_retirement'} else request['initial_ca'])
    files = {Path('/ca') / name: body.encode() for name, body in h.files.items()}
    for field in ('root', 'issuer'):
        files[Path(f'/ca/{field}-g1.pem')] = h.candidate[field].encode()
    files[Path('/ca/issuer-g1.key')] = custody.pem_key(custody.load_key(h.candidate['issuer_key']), h.files['password.txt'].encode()).encode()
    files[Path('/ca/ca.json')] = json.dumps(ca_config).encode()
    files[Path('/state/config.json')] = json.dumps(cfg).encode()
    files[Path('/state/issuer.pem')] = (h.plan['issuer'] if finished or phase in {'leaf_activating', 'migrating', 'quiescing_retirement', 'trust_retired', 'committing'} else h.files['issuer.pem']).encode()
    before = h.files['root.pem'] + h.files['issuer.pem']
    overlap = ''.join(dict.fromkeys([h.files['root.pem'], h.files['issuer.pem'], h.plan['root'], h.plan['issuer']]))
    after = h.plan['root'] + h.plan['issuer']
    trust = after if finished or phase in {'trust_retired', 'committing'} else overlap if pending else before
    files[Path('/state/root.pem')] = (h.files['root.pem'] if not pending and not finished else trust).encode()
    for root in h.base['roots']:
        files[Path(root) / 'ca.pem'] = trust.encode()
    files[Path('/managed/renewal-tls/sign-server.key')] = custody.pem_key(h.signer).encode()
    files[Path('/managed/renewal-tls/sign-server-g1.key')] = h.candidate['keys']['server-renewal-server'].encode()
    if pending:
        paths = ['/state/root.pem', *[root + '/ca.pem' for root in h.base['roots']]]
        files[Path('/state/authority-transition.json')] = json.dumps({'plan_hash': custody.digest(h.plan), 'trust': [
            {'path': str(Path(path)), 'before': h.files['root.pem'] if path == '/state/root.pem' else before, 'overlap': overlap} for path in paths]}).encode()
    files[Path('/state/state.json')] = json.dumps({'credentials': {'id': {'not_after': time.time() + 300, 'authority_epoch': 1}}}).encode()
    original_exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda p: p in files if p.as_posix().startswith(('/state/', '/managed/', '/ca/')) else original_exists(p))
    monkeypatch.setattr(control, 'read', lambda path, *args: files[Path(path)])
    seen = []
    monkeypatch.setattr(control.rekey, 'verify', lambda data: seen.append(data) or {'verified': True})
    return request, files, seen


@pytest.mark.parametrize('phase', ['idle', 'prepared', 'trust_staged', 'ca_activated', 'leaf_activating',
                                  'migrating', 'quiescing_retirement', 'trust_retired', 'committing'])
def test_every_legitimate_ceremony_phase_validates_without_resealing(ceremony, monkeypatch, phase):
    request, _, seen = install_files(monkeypatch, ceremony, phase)
    assert control.verify(request)['verified'] and len(seen) == 1


def test_completed_rotation_uses_new_live_issuer_but_keeps_retired_file_validation_separate(ceremony, monkeypatch):
    request, _, seen = install_files(monkeypatch, ceremony, finished=True)
    assert control.verify(request) == {'verified': True, 'epoch': 1, 'phase': 'idle'}
    require(seen[0]['issuers'] == ceremony.plan['issuer'])
    require(ceremony.files['issuer.pem'] in seen[0]['retired_issuers'])


@pytest.mark.parametrize('attack', ['controller', 'ca_policy', 'root', 'issuer', 'signer', 'trust', 'managed_root_only', 'ledger'])
def test_modified_public_state_is_refused_before_any_publication(ceremony, monkeypatch, attack):
    request, files, seen = install_files(monkeypatch, ceremony, 'migrating')
    if attack == 'controller':
        cfg = json.loads(files[Path('/state/config.json')])
        cfg['server_signers']['server'] = '/managed/renewal-tls/sign-server.key'
        files[Path('/state/config.json')] = json.dumps(cfg).encode()
    elif attack == 'ca_policy':
        cfg = json.loads(files[Path('/ca/ca.json')])
        cfg['authority']['disableIssuedAtCheck'] = True
        files[Path('/ca/ca.json')] = json.dumps(cfg).encode()
    elif attack == 'root':
        files[Path('/ca/root-g1.pem')] = ceremony.files['root.pem'].encode()
    elif attack == 'issuer':
        files[Path('/state/issuer.pem')] = ceremony.files['root.pem'].encode()
    elif attack == 'signer':
        files[Path('/managed/renewal-tls/sign-server-g1.key')] = custody.pem_key(ceremony.signer).encode()
    elif attack == 'trust':
        files[Path('/managed/client-tls/ca.pem')] += custody.pem_cert(ca.hierarchy()[0][1]).encode()
    elif attack == 'managed_root_only':
        files[Path('/managed/client-tls/ca.pem')] = ceremony.files['root.pem'].encode()
    else:
        ledger = json.loads(files[Path('/state/authority-transition.json')])
        ledger['trust'][0]['overlap'] = ceremony.files['root.pem']
        files[Path('/state/authority-transition.json')] = json.dumps(ledger).encode()
    with pytest.raises((ValueError, KeyError)):
        control.verify(request)
    assert not seen


def test_missing_or_foreign_volume_is_refused_before_helper_can_create_it(monkeypatch):
    value = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-authority-volumes')
    value.state = {'project': 'kmtls-012345abcdef', 'volumes': {'authority-vault': 'kmtls-012345abcdef-authority-vault'}}
    monkeypatch.setattr(runtime, 'command', lambda *args, **kw: json.dumps([{'Name': value.state['volumes']['authority-vault'], 'Labels': {'secops.runtime': 'another-project'}}]))
    with pytest.raises(runtime.RuntimeFailure, match='authority_volume_scope'):
        value.verify_owned_volumes()


def test_networked_validation_helper_cannot_mount_ca_key_material():
    value = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-authority-helper')
    with pytest.raises(runtime.RuntimeFailure, match='requires_network_none'):
        value.helper(['-c', 'pass'], network='external-network')


def test_expired_profile_cannot_be_silently_migrated_to_new_volume_graph(tmp_path):
    # The base runtime scope checker rejects the old 31-volume descriptor before Docker.
    value = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-authority-load')
    old = {'schema': 'continuous-mtls-runtime-1', 'project': 'kmtls-012345abcdef',
           'image': 'kmtls-012345abcdef-app', 'volumes': {n: 'kmtls-012345abcdef-' + n for n in RekeyRuntime.volumes}}
    path = tmp_path / 'runtime.json'
    path.write_text(json.dumps(old))
    value.descriptor = path
    with pytest.raises(ValueError, match='runtime_descriptor_scope'):
        value.load()


@pytest.mark.parametrize('attack', [None, 'id', 'image', 'foreign_volume', 'rw_ca', 'vault', 'privileged', 'capability', 'network', 'user'])
def test_pinned_online_container_must_keep_exact_scope_and_hardening(attack, monkeypatch):
    project, image = 'kmtls-012345abcdef', 'sha256:' + 'a' * 64
    expected = {'name': project + '-ca-1', 'id': 'b' * 64, 'endpoint': 'ca-a'}
    backend = object.__new__(runtime.GraphBackend)
    backend.project = project
    backend.profile = {'image': image, 'ca': {k: expected[k] for k in ('name', 'id')}, 'leaf': {'name': project + '-certificate-controller-1'}, 'ca_replicas': [expected]}
    backend.runtime = SimpleNamespace(state={'volumes': {n: project + '-' + n for n in runtime.PersistentAuthorityRuntime.volumes}}, definition=runtime.definition)
    record = {'Id': expected['id'], 'Name': '/' + expected['name'], 'Image': image,
        'Config': {'User': '10001:10001', 'Labels': {'secops.runtime': project, 'com.docker.compose.service': 'ca'}},
        'HostConfig': {'Privileged': False, 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'CapAdd': None, 'SecurityOpt': ['no-new-privileges:true']},
        'NetworkSettings': {'Networks': {project + '_ca': {}, project + '_ca-db': {}}},
        'Mounts': [{'Type': 'volume', 'Name': project + '-ca-state', 'Destination': '/ca', 'RW': False},
                   {'Type': 'volume', 'Name': project + '-authority-ca-a-db', 'Destination': '/db-tls', 'RW': False}]}
    if attack == 'id':
        record['Id'] = 'c' * 64
    elif attack == 'image':
        record['Image'] = 'sha256:' + 'c' * 64
    elif attack == 'foreign_volume':
        record['Mounts'][0]['Name'] = 'user-volume'
    elif attack == 'rw_ca':
        record['Mounts'][0]['RW'] = True
    elif attack == 'vault':
        record['Mounts'].append({'Type': 'volume', 'Name': project + '-authority-vault', 'Destination': '/vault', 'RW': True})
    elif attack == 'privileged':
        record['HostConfig']['Privileged'] = True
    elif attack == 'capability':
        record['HostConfig']['CapAdd'] = ['SYS_ADMIN']
    elif attack == 'network':
        record['NetworkSettings']['Networks']['external'] = {}
    elif attack == 'user':
        record['Config']['User'] = '0'
    monkeypatch.setattr(backend, 'command', lambda *args: json.dumps([record]))
    if attack:
        with pytest.raises(LifecycleError, match='container_changed'):
            backend.owned_container(expected)
    else:
        assert backend.owned_container(expected) == expected['name']


@pytest.mark.parametrize('reject', [False, True])
def test_shared_coordinator_always_validates_graph_before_mutating_it(tmp_path, reject):
    calls = []
    def validate():
        calls.append('validate')
        if reject:
            raise LifecycleError('synthetic_integrity_failure')
    backend = SimpleNamespace(before_authority_tick=validate, leaf=lambda *args, **kwargs: calls.append('leaf'))
    coordinator = Coordinator({'initial_root': 'public-test-root'}, tmp_path, backend)
    if reject:
        with pytest.raises(LifecycleError, match='synthetic_integrity_failure'):
            coordinator.tick()
        assert calls == ['validate'] and coordinator.state['phase'] == 'idle'
    else:
        coordinator.tick()
        assert calls == ['validate', 'leaf'] and coordinator.state['phase'] == 'quiescing'


@pytest.mark.parametrize('attack', [None, 'digest', 'architecture', 'os', 'base_layers'])
def test_tagged_postgres_digest_is_checked_using_canonical_repository_identity(tmp_path, monkeypatch, attack):
    value = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-postgres-image')
    value.directory = tmp_path
    value.state = {'project': 'kmtls-012345abcdef'}
    reference = json.loads((runtime.ROOT / assets.INPUTS[0]).read_bytes())['postgres']['image']
    canonical = 'postgres@' + reference.rsplit('@', 1)[1]
    base = {'Id': 'sha256:' + 'a' * 64, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [canonical], 'RootFS': {'Layers': ['approved-base']}}
    candidate = base | {'Id': 'sha256:' + 'b' * 64, 'RootFS': {'Layers': ['approved-base', 'local-user-layer']}}
    if attack == 'digest':
        base['RepoDigests'] = ['postgres@sha256:' + 'c' * 64]
    elif attack == 'architecture':
        base['Architecture'] = 'arm64'
    elif attack == 'os':
        base['Os'] = 'windows'
    elif attack == 'base_layers':
        candidate['RootFS']['Layers'] = ['unapproved-base']
    def command(argv, **kwargs):
        if argv[:3] == ['docker', 'image', 'inspect']:
            return json.dumps([base if '--platform' in argv else candidate])
        return ''
    monkeypatch.setattr(RekeyRuntime, 'prepare_extra_images', lambda self: None)
    monkeypatch.setattr(runtime, 'command', command)
    monkeypatch.setattr(value, 'save', lambda: None)
    if attack:
        with pytest.raises((ValueError, runtime.RuntimeFailure)):
            value.prepare_extra_images()
    else:
        value.prepare_extra_images()
        assert value.state['authority_database_image_id'] == candidate['Id']
        assert value.state['authority_database_reference'] == reference


def test_idle_scheduler_does_not_launch_validation_helpers_before_next_due(tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail('idle scheduler launched an authority operation')
    backend = SimpleNamespace(before_authority_tick=forbidden, leaf=forbidden)
    coordinator = Coordinator({'initial_root': 'public-test-root'}, tmp_path, backend)
    coordinator.state['next_due_at'] = time.time() + 300
    coordinator.tick()
    assert coordinator.state['phase'] == 'idle' and coordinator.state['epoch'] == 0


def test_embedded_acceptance_programs_parse_and_bind_real_transport_signature():
    from scripts import mtls_transport
    source = (runtime.ROOT / 'scripts/test_persistent_authority_runtime.py').read_text(encoding='utf-8')
    programs = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'execute' and len(node.args) >= 2):
            continue
        argument = node.args[1]
        if (isinstance(argument, ast.List) and len(argument.elts) >= 3
                and all(isinstance(v, ast.Constant) for v in argument.elts[:3])
                and [v.value for v in argument.elts[:2]] == ['python', '-c']):
            programs.append(argument.elts[2].value)
    assert len(programs) >= 5
    calls = []
    for program in programs:
        for node in ast.walk(ast.parse(program)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'request':
                inspect.signature(mtls_transport.request).bind(*[None for _ in node.args], **{k.arg: None for k in node.keywords})
                calls.append(node)
    assert len(calls) == 1


@pytest.mark.parametrize('attack', [None, 'changed_hash', 'extra_name'])
def test_public_hashes_are_batched_once_without_network_or_private_files(monkeypatch, attack):
    value = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-batched-public-assets')
    value.state = {'authority_image_id': 'sha256:' + 'a' * 64, 'volumes': {v: 'kmtls-012345abcdef-' + v for v in assets.PUBLIC_FILES},
                   'authority_public_sha256': {v: {n: 'a' * 64 for n in names} for v, names in assets.PUBLIC_FILES.items()}}
    if attack == 'extra_name':
        value.state['authority_public_sha256']['ca-state']['password.txt'] = 'a' * 64
    called = []
    monkeypatch.setattr(value, 'verify_owned_volumes', lambda: None)
    def command(argv, *, payload, timeout):
        called.append(argv)
        assert argv[argv.index('--network') + 1] == 'none' and '--read-only' in argv
        assert all('readonly' in arg for arg in argv if arg.startswith('type=volume,'))
        assert 'password.txt' not in payload and '.key' not in payload
        actual = copy.deepcopy(value.state['authority_public_sha256'])
        if attack == 'changed_hash':
            actual['ca-state']['database-anchor.json'] = 'b' * 64
        return json.dumps(actual)
    monkeypatch.setattr(runtime, 'command', command)
    if attack:
        with pytest.raises(runtime.RuntimeFailure):
            value.verify_authority_public_assets()
    else:
        value.verify_authority_public_assets()
    assert len(called) == (0 if attack == 'extra_name' else 1)
