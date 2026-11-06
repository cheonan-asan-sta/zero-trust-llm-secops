import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from scripts import authority_runtime_assets as authority
from scripts import rekey_runtime_assets as assets
from scripts.certificate_key_rotation import public_hash
from scripts.rekey_mtls_runtime import definition
from scripts.rekey_runtime_control import allowed_pairs, configuration_matches


def pair(stem, volume='prometheus-tls'):
    return {'cert': f'/managed/{volume}/{stem}.pem', 'key': f'/managed/{volume}/{stem}.key'}


@pytest.fixture
def journal():
    return {'credentials': {'id': {'name': 'prometheus', 'assets': [pair('prometheus')],
        'pending_key': {'assets': [pair('prometheus-r' + 'a' * 24)]}}}}


@pytest.mark.parametrize('stem', ['prometheus', 'prometheus-r' + 'a' * 24])
def test_only_complete_current_or_pending_pairs_are_accepted(journal, stem):
    template = 'cert: /service-tls/prometheus.pem\nkey: /service-tls/prometheus.key\nverify: true\n'
    actual = template.replace('/prometheus.', '/' + stem + '.')
    assert configuration_matches(actual, template, 'prometheus-tls', journal)


@pytest.mark.parametrize('change', ['mixed', 'arbitrary', 'unrecorded', 'foreign-role', 'path'])
def test_config_substitution_cannot_bypass_trust_or_pair_consistency(journal, change):
    template = 'cert: /service-tls/prometheus.pem\nkey: /service-tls/prometheus.key\nverify: true\n'
    actual = {'mixed': template.replace('prometheus.key', 'prometheus-r' + 'a' * 24 + '.key'),
        'arbitrary': template.replace('verify: true', 'verify: false'),
        'unrecorded': template.replace('/prometheus.', '/prometheus-r' + 'b' * 24 + '.'),
        'foreign-role': template.replace('/prometheus.', '/scrape-agent.'),
        'path': template.replace('/service-tls/', '/foreign/') }[change]
    assert not configuration_matches(actual, template, 'prometheus-tls', journal)


@pytest.mark.parametrize('bad', [pair('foreign'), pair('prometheus-rshort'),
    pair('prometheus') | {'key': '/managed/prometheus-tls/other.key'},
    pair('prometheus') | {'key': '/managed/foreign/prometheus.key'}])
def test_journal_asset_name_or_pair_mismatch_rejected(journal, bad):
    journal['credentials']['id']['assets'] = [bad]
    with pytest.raises(ValueError, match='rekey_asset_scope'):
        allowed_pairs(journal, 'prometheus', 'prometheus-tls')


def test_wrong_volume_and_missing_identity_refuse(journal):
    with pytest.raises(ValueError, match='rekey_volume_inventory'):
        allowed_pairs(journal, 'prometheus', 'operator-tls')
    with pytest.raises(ValueError, match='rekey_identity_inventory'):
        allowed_pairs(journal, 'scrape-agent', 'prometheus-tls')


@pytest.fixture(scope='module')
def private():
    class Hidden(dict):
        def __repr__(self):
            return '<ephemeral rekey material>'
    material, provisioners = assets.material()
    return Hidden(material=material, provisioners=provisioners)


def require(value):
    if not value:
        raise AssertionError('rekey material boundary')


def test_delegation_keys_are_separate_from_all_rotating_tls_keys(private):
    material = private['material']
    cfg = json.loads(material['certificate-state']['config.json'])
    require(len(cfg['allowed_provisioners']) == len(private['provisioners']) == 39)
    require(len(cfg['server_signers']) == 11)
    for name, path in cfg['server_signers'].items():
        delegated = serialization.load_pem_private_key(material['renewal-tls'][Path(path).name].encode(), None)
        tls = serialization.load_pem_private_key(material['renewal-tls']['renew-' + name + '.key'].encode(), None)
        require(public_hash(delegated.public_key()) != public_hash(tls.public_key()))
        require(all(path != key for _, key in cfg['extra_certificates']))
    require(all('root.key' not in files for files in material.values()))


@pytest.mark.parametrize('profile', ['authority', 'rekey'])
def test_reload_ack_groups_cover_real_managed_certificate_roots(private, profile):
    material = private['material'] if profile == 'rekey' else authority.material()[0]
    cfg = json.loads(material['certificate-state']['config.json'])
    for group in cfg['reload_groups']:
        require(group['root'] in cfg['roots'])
        for file in group['files']:
            require(Path(file).parent.as_posix() == group['root'])
            require(Path(file).name in material[Path(file).parent.name])


def test_bridge_probe_and_profiles_preserve_role_and_same_volume_assets(private):
    material = private['material']
    cfg = json.loads(material['certificate-state']['config.json'])
    probe = next(p for p in cfg['probes'] if p['server_name'] == 'bridge-auth')
    require(probe['profile'] in cfg['policies'])
    require(probe['profile'] == '/managed/proxy-tls/bridge-auth-probe.json')
    for relative, identity in assets.profile_identities(material).items():
        volume, filename = relative.split('/')
        document = json.loads(material[volume][filename])
        require(document['cert'] == identity + '.pem' and document['key'] == identity + '.key')
        require(all(document[field] in material[volume] for field in ('cert', 'key', 'ca')))


def test_native_services_watch_dynamic_config_and_have_read_only_tls():
    spec = definition('kmtls-012345abcdef', 'app', 'nginx')
    assert len(spec['services']) == 16 and len(spec['networks']) == 9 and len(spec['volumes']) == 31
    assert spec['services']['proxy']['entrypoint'][-1] == '/config/nginx-rekey.sh'
    for name in ('prometheus', 'alertmanager'):
        service = spec['services'][name]
        assert name + '-tls:/service-tls:ro' in service['volumes']
        assert '--resolve-tls' in service['entrypoint']
        assert '/service-tls/config.yml' in service['entrypoint'] and '/service-tls/web.yml' in service['entrypoint']
    assert all(n['internal'] for n in spec['networks'].values())
