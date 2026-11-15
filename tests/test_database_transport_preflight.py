import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from scripts import database_transport_preflight as check
from scripts import mtls_fixtures as fixtures
from scripts.certificate_controller import LifecycleError


class Private(SimpleNamespace):
    def __repr__(self):
        return '<ephemeral transport fixture in RAM>'


@pytest.fixture
def material(monkeypatch):
    root = fixtures.authority('Independent local CA database transport')
    files = {}
    pem = root[1].public_bytes(serialization.Encoding.PEM)
    for index, volume in enumerate(check.VOLUMES):
        stem, name = ('server', 'ca-db') if index == 0 else ('client', 'secops_ca')
        pair = fixtures.leaf(root, name, server=index == 0)
        files[volume] = {'root.pem': pem, stem + '.pem': pair['cert'].encode(), stem + '.key': pair['key'].encode()}

    def read(path, **kwargs):
        return files[path.parent.name][path.name]

    monkeypatch.setattr(check, 'read', read)
    return Private(root=root, files=files, digest=hashlib.sha256(pem).hexdigest(),
                   paths={name: Path('/transport') / name for name in check.VOLUMES})


def require(value):
    if not value:
        raise AssertionError('ephemeral PKI boundary failed')


def test_three_distinct_roles_and_keys_have_bounded_public_expiry_evidence(material):
    result = check.inspect_transport(material.paths, material.digest)
    require(result['verified'] and result['status'] == 'ready' and len(result['credentials']) == 3)
    require(result['automatic_renewal'] is False and 0 < result['minimum_remaining_seconds'] <= 172800)
    require('PRIVATE' not in json.dumps(result) and 'key' not in result)


def test_near_expiry_is_visible_without_silently_reissuing_or_extending_trust(material):
    result = check.inspect_transport(material.paths, material.digest,
        now=material.root[1].not_valid_after_utc - timedelta(hours=6))
    require(result['status'] == 'expires_soon' and result['minimum_remaining_seconds'] <= 21600)
    require(not result['automatic_renewal'])


@pytest.mark.parametrize('attack', ['root_pin', 'foreign_leaf', 'wrong_server_name', 'wrong_client_name',
    'server_eku', 'client_eku', 'expired', 'future', 'wrong_key', 'duplicate_client', 'truncated', 'chain',
    'expired_root', 'missing_volume', 'invalid_pin'])
def test_transport_identity_signature_expiry_and_key_attacks_are_refused(material, attack):
    m = material
    server, a, b = [m.files[name] for name in check.VOLUMES]
    now = datetime.now(UTC)
    if attack == 'root_pin':
        m.digest = '0' * 64
    elif attack == 'foreign_leaf':
        server['server.pem'] = fixtures.leaf(fixtures.authority(), 'ca-db', server=True)['cert'].encode()
    elif attack == 'wrong_server_name':
        server['server.pem'] = fixtures.leaf(m.root, 'foreign', server=True)['cert'].encode()
    elif attack == 'wrong_client_name':
        a['client.pem'] = fixtures.leaf(m.root, 'postgres')['cert'].encode()
    elif attack == 'server_eku':
        server['server.pem'] = fixtures.leaf(m.root, 'ca-db')['cert'].encode()
    elif attack == 'client_eku':
        a['client.pem'] = fixtures.leaf(m.root, 'secops_ca', server=True)['cert'].encode()
    elif attack in {'expired', 'future'}:
        pair = fixtures.leaf(m.root, 'ca-db', server=True, **{attack: True})
        server.update({'server.pem': pair['cert'].encode(), 'server.key': pair['key'].encode()})
    elif attack == 'wrong_key':
        b['client.key'] = a['client.key']
    elif attack == 'duplicate_client':
        b.update(a)
    elif attack == 'truncated':
        a['client.pem'] = b'invalid-certificate'
    elif attack == 'chain':
        server['server.pem'] += server['root.pem']
    elif attack == 'expired_root':
        now = m.root[1].not_valid_after_utc + timedelta(seconds=1)
    elif attack == 'missing_volume':
        m.paths.pop(check.VOLUMES[-1])
    else:
        m.digest = '../private-sentinel'
    with pytest.raises((LifecycleError, ValueError)):
        check.inspect_transport(m.paths, m.digest, now=now)


def test_file_reader_is_bounded_and_rejects_links_without_reading_their_target(tmp_path):
    path = tmp_path / 'input'
    path.write_bytes(b'x' * 65537)
    with pytest.raises(LifecycleError, match='file_size'):
        check.read(path)
    path.write_bytes(b'public-test-data')
    alias = tmp_path / 'alias'
    os.link(path, alias)
    with pytest.raises(LifecycleError, match='private_file_required'):
        check.read(path)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX key modes are enforced in Linux helper')
def test_private_reader_rejects_world_readable_files_and_symlinks(tmp_path):
    path = tmp_path / 'key'
    path.write_bytes(b'synthetic-not-a-private-key')
    path.chmod(0o644)
    with pytest.raises(LifecycleError, match='private_file_required'):
        check.read(path, private=True)
    path.chmod(0o600)
    assert check.read(path, private=True) == b'synthetic-not-a-private-key'
    alias = tmp_path / 'alias'
    alias.symlink_to(path)
    with pytest.raises(LifecycleError, match='regular_file_required'):
        check.read(alias, private=True)


def test_host_verifier_checks_ownership_before_only_three_readonly_transport_mounts(monkeypatch):
    from scripts import persistent_authority_runtime as runtime
    value = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-db-preflight')
    value.state = {'project': 'kmtls-012345abcdef', 'authority_image_id': 'sha256:' + 'a' * 64,
        'volumes': {n: 'kmtls-012345abcdef-' + n for n in check.VOLUMES},
        'authority_public_sha256': {'authority-db-tls': {'root.pem': 'b' * 64}}}
    calls = []
    monkeypatch.setattr(value, 'verify_owned_volumes', lambda: calls.append('owned'))

    def command(argv, **kwargs):
        assert calls == ['owned']
        calls.append('helper')
        assert argv[argv.index('--network') + 1] == 'none'
        assert argv.count('--mount') == 3 and all('readonly' in argv[i + 1] for i, x in enumerate(argv) if x == '--mount')
        assert not any('vault' in x or 'docker.sock' in x or 'authority-db-data' in x for x in argv)
        assert json.loads(kwargs['payload']) == {'expected_root_sha256': 'b' * 64}
        assert kwargs['timeout'] == 15
        return '{"verified":true}'

    monkeypatch.setattr(runtime, 'command', command)
    assert value.verify_database_transport()['verified'] and calls == ['owned', 'helper']


def test_transport_denial_blocks_database_inspection_and_startup_before_mutation(monkeypatch):
    from scripts import persistent_authority_runtime as runtime
    value = runtime.PersistentAuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-db-denial')

    def reject():
        raise runtime.RuntimeFailure('database_transport_preflight_failed')

    monkeypatch.setattr(value, 'verify_database_transport', reject)
    monkeypatch.setattr(runtime, 'command', lambda *a, **kw: pytest.fail('started DB or bypassed admission'))
    with pytest.raises(runtime.RuntimeFailure, match='database_transport_preflight_failed'):
        value.verify_authority_database()
