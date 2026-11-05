import copy
import json
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from scripts import authority_mtls_runtime as runtime
from scripts import authority_runtime_assets as assets
from scripts import continuous_mtls_runtime as base
from scripts.certificate_controller import metadata, selected
from scripts.monitored_mtls_runtime import MonitoredRuntime
from scripts.test_authority_mtls_runtime import certificate_probe

PROJECT = 'kmtls-012345abcdef'


@pytest.fixture
def spec():
    return runtime.definition(PROJECT, 'app', 'nginx')


@pytest.mark.parametrize('name', ['ca', 'certificate-controller'])
def test_authority_services_hardened_without_host_authority(spec, name):
    service = spec['services'][name]
    assert service['user'] == '10001:10001' and service['read_only']
    assert service['cap_drop'] == ['ALL'] and service['security_opt'] == ['no-new-privileges:true']
    assert service['restart'] == 'unless-stopped' and service['pids_limit'] == 128
    assert service['mem_limit'] == service['memswap_limit'] and service['cpus'] == 1
    assert not service.get('ports') and not service.get('privileged')
    assert 'docker.sock' not in json.dumps(service) and 'network_mode' not in service
    assert all(mount.split(':')[0] in spec['volumes'] for mount in service['volumes'])


def test_control_plane_isolation_and_explicit_central_trust(spec):
    assert len(base.SERVICES) == 9 and len(MonitoredRuntime.services) == 14
    assert len(runtime.AuthorityRuntime.services) == 16 and len(spec['networks']) == 9
    assert all(value['internal'] for value in spec['networks'].values())
    assert set(spec['services']['ca']['networks']) == {'ca'}
    for name in MonitoredRuntime.services:
        assert 'ca' not in spec['services'][name].get('networks', {})
    controller = spec['services']['certificate-controller']
    sources = {mount.split(':')[0] for mount in controller['volumes']}
    assert not sources & {'ca-state', 'data', 'registry', 'operator-auth', 'collector-auth', 'collector-state', 'core-auth'}
    assert set(controller['networks']) == set(spec['networks'])
    for name in ('worker', 'watchdog'):
        assert spec['services'][name]['network_mode'] == 'none'


@pytest.mark.parametrize('name', list(assets.RELOADS))
def test_native_reload_ack_does_not_give_workload_write_access_to_tls(spec, name):
    service = spec['services'][name]
    assert name + '-tls:/service-tls:ro' in service['volumes'] if name == 'proxy' else name + '-tls:/tls:ro' in service['volumes']
    assert 'ack-' + name + ':/reload' in service['volumes']
    assert 'ack-' + name + ':/ack/' + name + ':ro' in spec['services']['certificate-controller']['volumes']
    assert service['entrypoint'][0] == ('sh' if name == 'proxy' else 'python')


@pytest.fixture(scope='module')
def private():
    class Hidden(dict):
        def __repr__(self):
            return '<ephemeral local CA material>'
    material, provisioners = assets.material()
    return Hidden(material=material, provisioners=provisioners)


def require(value):
    if not value:
        raise AssertionError('CA integration material boundary')


def test_bootstrap_authority_and_root_private_key_not_distributed(private):
    m, p = private['material'], private['provisioners']
    require('ENCRYPTED PRIVATE KEY' in m['ca-state']['issuer.key'])
    require(set(m['certificate-state']) == {'root.pem', 'issuer.pem', 'config.json'})
    require(all('root.key' not in files for files in m.values()))
    cfg = json.loads(m['certificate-state']['config.json'])
    require(len(p) == len(cfg['allowed_provisioners']) == 39)
    require(set(p) == set(cfg['allowed_provisioners']))
    require(all('key' not in entry or 'd' not in entry['key'] for entry, _ in p.values()))
    ca = json.loads(m['ca-state']['ca.json'])
    require(ca['authority']['claims']['allowRenewalAfterExpiry'] is False)
    require(len([v for v in ca['authority']['provisioners'] if v['name'].startswith('server-renewal-')]) == 11)


def test_every_mounted_leaf_is_in_inventory_and_every_server_has_native_probe(private):
    m = private['material']
    cfg = json.loads(m['certificate-state']['config.json'])
    pairs = {(cert, key) for cert, key in cfg['extra_certificates']}
    identities = set()
    issuer = x509.load_pem_x509_certificate(m['certificate-state']['issuer.pem'].encode())
    for volume in assets.MANAGED:
        for filename in m[volume]:
            if filename.endswith('.key'):
                cert = filename[:-4] + '.pem'
                require((f'/managed/{volume}/{cert}', f'/managed/{volume}/{filename}') in pairs)
                body = m[volume][cert]
                identities.add(metadata(body)['fingerprint'])
                leaf = x509.load_pem_x509_certificate(body.encode())
                require(leaf.issuer == issuer.subject)
                leaf.verify_directly_issued_by(issuer)
    require(len(identities) == 39)
    require({p['server_name'] for p in cfg['probes']} == set(assets.SERVERS))
    require(len(cfg['probes']) == 11)
    # No self-signed root or broad own-root X5C provisioner grants workload authority.
    root = x509.load_pem_x509_certificate(m['certificate-state']['root.pem'].encode())
    require(root.fingerprint(hashes.SHA256()) != issuer.fingerprint(hashes.SHA256()))
    require(all(v['type'] == 'JWK' for v in json.loads(m['ca-state']['ca.json'])['authority']['provisioners']))


@pytest.mark.parametrize('field,value', [('paused', 'yes'), ('disabled', ['other']), ('renew_before', {'core-a': True}),
                                       ('renew_before', {'core-a': 3601}), ('renew_before', {'core-a': -1})])
def test_invalid_local_controls_rejected(private, field, value):
    cfg = json.loads(private['material']['certificate-state']['config.json'])
    cfg[field] = value
    assert not assets.configuration_valid(cfg)


@pytest.mark.parametrize('value', [None, [], 'other'])
def test_non_object_controller_configuration_is_rejected(value):
    assert not assets.configuration_valid(value)


def test_configuration_seal_allows_pause_but_not_new_signers_or_managed_roots(private):
    cfg = json.loads(private['material']['certificate-state']['config.json'])
    sealed = assets.fixed_configuration(cfg)
    changed = copy.deepcopy(cfg)
    changed.update(paused=True, disabled=['a' * 64], renew_before={'collector': 1190})
    assert assets.configuration_valid(changed) and assets.fixed_configuration(changed) == sealed
    changed['server_signers'] = {'core-a': '/managed/renewal-tls/other.key'}
    assert assets.fixed_configuration(changed) != sealed


@pytest.mark.parametrize('inhibited,disabled,expired', [(False, False, True), (True, False, False), (False, True, False)])
def test_renewal_cannot_restore_expired_disabled_or_inhibited_identity(inhibited, disabled, expired):
    c = {'name': 'collector', 'generation': 1, 'not_after': 99 if expired else 200,
         'inhibited': inhibited, 'candidate': None, 'retry_at': 0}
    cfg = {'disabled': ['uid'] if disabled else [], 'renew_before': {'collector': 500}}
    assert selected(cfg, {'credentials': {'uid': c}}, 100) == []
    if expired:
        assert c['status'] == 'expired_reenrollment_required'


def test_locked_ca_inputs_and_topology_are_distinct_from_monitoring_only():
    value = runtime.AuthorityRuntime(base.ROOT / 'runtime/c02/unit-authority').release_inputs()
    other = MonitoredRuntime(base.ROOT / 'runtime/c02/unit-monitored').release_inputs()
    assert value['sha256'] != other['sha256']
    assert set(assets.INPUTS) <= set(value['payload']['files'])


def test_partial_bootstrap_is_not_silently_reapproved():
    value = runtime.AuthorityRuntime(base.ROOT / 'runtime/c02/unit-authority')
    value.state = {'authority_initialized': False}
    with pytest.raises(base.RuntimeFailure, match='authority_initialization_requires_new_approved_bootstrap'):
        value.before_start()


def test_probe_keeps_strict_sibling_asset_loader_and_removes_temporary_private_key(tmp_path, monkeypatch):
    from scripts import mtls_transport as tls
    profile = tmp_path / 'client.json'
    profile.write_text(json.dumps({'ca': 'ca.pem', 'host': 'gateway', 'port': 8443,
                                   'server_name': 'gateway', 'server_pins': ['a' * 64]}))
    for name in ('ca.pem', 'cert.pem', 'client.key'):
        (tmp_path / name).write_bytes(b'synthetic-' + name.encode())
    seen = []

    def request(path, target, payload, headers, method):
        assert isinstance(path, Path) and target == '/zero-trust/signals/inbox' and method == 'POST'
        cfg = json.loads(path.read_bytes())
        for name in ('ca', 'cert', 'key'):
            asset = Path(tls.asset(path, cfg[name]))
            assert asset.parent == path.parent and asset.exists()
            if os.name == 'posix':
                assert asset.stat().st_mode & 0o777 == 0o600
        seen.append(path)
        return 401, b'{}'

    monkeypatch.setattr(tls, 'request', request)
    assert certificate_probe(profile, tmp_path / 'cert.pem', tmp_path / 'client.key', {}) == 401
    assert len(seen) == 1 and not seen[0].parent.exists()


def test_probe_rejects_oversized_certificate_before_any_network_request(tmp_path, monkeypatch):
    from scripts import mtls_transport as tls
    profile = tmp_path / 'client.json'
    profile.write_text(json.dumps({'ca': 'ca.pem'}))
    (tmp_path / 'ca.pem').write_bytes(b'public-ca')
    (tmp_path / 'cert.pem').write_bytes(b'x' * 65537)
    (tmp_path / 'key.pem').write_bytes(b'synthetic-key')
    calls = []
    monkeypatch.setattr(tls, 'request', lambda *args, **kwargs: calls.append(True))
    with pytest.raises(ValueError, match='acceptance_probe_asset_size'):
        certificate_probe(profile, tmp_path / 'cert.pem', tmp_path / 'key.pem', {})
    assert not calls


def test_ca_creation_permission_is_consumed_once_before_exec(tmp_path):
    permit = tmp_path / 'initialize.once'
    permit.write_text('approved-new-local-ca\n')
    assets.prepare_ca_start(tmp_path)
    assert not permit.exists() and (tmp_path / 'require-existing-db').is_file()
    with pytest.raises(ValueError, match='authority_database_required'):
        assets.prepare_ca_start(tmp_path)
    assert not (tmp_path / 'db').exists()


@pytest.mark.parametrize('missing', ['MANIFEST', 'KEYREGISTRY', 'require-existing-db'])
def test_ca_missing_existing_database_metadata_cannot_create_new_database(tmp_path, missing):
    (tmp_path / 'db').mkdir()
    (tmp_path / 'db/MANIFEST').write_bytes(b'synthetic-manifest')
    (tmp_path / 'db/KEYREGISTRY').write_bytes(b'synthetic-registry')
    (tmp_path / 'require-existing-db').write_text('already-initialized')
    target = tmp_path / ('db/' + missing if missing != 'require-existing-db' else missing)
    target.unlink()
    with pytest.raises(ValueError, match='authority_database_required'):
        assets.require_existing_database(tmp_path)


def test_existing_database_never_accepts_another_first_creation_permission(tmp_path):
    (tmp_path / 'db').mkdir()
    (tmp_path / 'db/MANIFEST').write_bytes(b'synthetic-manifest')
    (tmp_path / 'db/KEYREGISTRY').write_bytes(b'synthetic-registry')
    (tmp_path / 'require-existing-db').write_text('already-initialized')
    assets.prepare_ca_start(tmp_path)
    (tmp_path / 'initialize.once').write_text('unexpected-new-approval')
    with pytest.raises(ValueError, match='authority_initialization_conflict'):
        assets.prepare_ca_start(tmp_path)
