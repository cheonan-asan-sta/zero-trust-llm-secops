import hashlib
import json
import os

import pytest

from app.services.trusted_signals import SignalRegistryUnavailable
from scripts.f1_lab.source_registry import FrozenSignalVerifier, _RegistryBytes


@pytest.fixture
def frozen(tmp_path):
    # Empty is a valid deny-all authority snapshot, never implicit trust.
    raw = b'{"sources":[]}'
    path = tmp_path / 'sources.json'
    path.write_bytes(raw)
    return path, FrozenSignalVerifier(path, hashlib.sha256(raw).hexdigest())


def test_fixed_empty_snapshot_has_no_authority(frozen):
    _path, verifier = frozen
    assert verifier._sources() == {}
    assert verifier.configuration_binding['sha256'] == verifier.expected_sha256


@pytest.mark.parametrize('change', ['bytes', 'missing', 'oversized', 'directory'])
def test_frozen_source_changes_do_not_turn_into_a_healthy_empty_registry(frozen, change):
    path, verifier = frozen
    original = path.stat()
    if change == 'bytes':
        path.write_bytes(b'{"sources": []}')
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
    elif change == 'missing':
        path.unlink()
    elif change == 'oversized':
        path.write_bytes(b' ' * 256001)
    else:
        path.unlink()
        path.mkdir()
    with pytest.raises(SignalRegistryUnavailable):
        verifier._sources()


def test_pinned_malformed_registry_is_still_invalid(tmp_path):
    path = tmp_path / 'invalid.json'
    raw = json.dumps({'sources': [], 'private_key': 'forbidden'}).encode()
    path.write_bytes(raw)
    with pytest.raises(SignalRegistryUnavailable):
        FrozenSignalVerifier(path, hashlib.sha256(raw).hexdigest())._sources()


def test_verification_parses_the_hashed_bytes_without_reopening_mutable_path(frozen, monkeypatch):
    path, verifier = frozen
    original = _RegistryBytes.read_bytes

    def swapped(snapshot):
        path.write_bytes(b'invalid replacement')
        return original(snapshot)

    monkeypatch.setattr(_RegistryBytes, 'read_bytes', swapped)
    assert verifier._sources() == {}
    with pytest.raises(SignalRegistryUnavailable):
        verifier._sources()


@pytest.mark.parametrize('anchor', [None, '', 'a'*63, 'A'*64, 'g'*64])
def test_external_pin_must_be_an_explicit_sha256(tmp_path, anchor):
    with pytest.raises(ValueError, match='external_anchor'):
        FrozenSignalVerifier(tmp_path / 'x.json', anchor)
