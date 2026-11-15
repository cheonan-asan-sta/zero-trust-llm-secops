import base64
import hashlib
import json
import os
import sys
import tempfile
from contextlib import ExitStack
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from scripts.f1_lab import collector_provider_ha as ha
from scripts.f1_lab import collector_status_bridge as bridge
from scripts.f1_lab.collector_freshness import CollectorMonitor, atomic_capture, inspect_capture
from scripts.f1_lab.collector_status_bridge import health_report
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.systemd_credentials import CredentialSocket
from tests.test_collector_freshness import envelope, repin
from tests.test_collector_freshness import fixture as base_fixture

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='private Unix peer credential HA')


@pytest.fixture
def configured(tmp_path):
    keys, registry, _, scope, event, proof, payload, latest, now = base_fixture(tmp_path)
    standby = Ed25519PrivateKey.generate()
    authority = next(a for a in registry.authorities if a.kind == 'runtime')
    second = authority.model_copy(update={'key_id': 'proc-2', 'public_key': base64.urlsafe_b64encode(
        standby.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')})
    registry = registry.model_copy(update={'authorities': [*registry.authorities, second]})
    pin = repin(tmp_path/'trust/registry.json', registry)
    with tempfile.TemporaryDirectory(prefix='zt-ha-') as directory, ExitStack() as stack:
        root = Path(directory)
        parents = [root/name for name in ('p', 's')]
        for parent in parents:
            parent.mkdir(mode=0o700)
        paths = [p/'key.sock' for p in parents]
        profile = ha.ProviderProfile(scope=scope, registry_sha256=pin.expected_sha256,
            endpoints=[ha.ProviderEndpoint(key_id=k, socket_path=str(p), peer_uid=os.geteuid())
                       for k, p in zip(('proc-1', 'proc-2'), paths, strict=True)])
        profile_path = tmp_path/'providers.json'
        profile_path.write_bytes(canonical(profile.model_dump(mode='json'))+b'\n')
        profile_path.chmod(0o644)
        secret = lambda key: key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

        def provider(index, *, key=None, connections=10, body=None):
            selected = (keys['runtime'], standby)[index] if key is None else key
            return stack.enter_context(CredentialSocket(paths[index], lambda: secret(selected) if body is None else body,
                allowed_uid=os.geteuid(), maximum_connections=connections))

        yield SimpleNamespace(keys=keys, standby=standby, registry=registry, pin=pin, scope=scope,
            event=event, proof=proof, payload=payload, latest=latest, now=now, profile=profile,
            path=profile_path, sha=hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            provider=provider, paths=paths, secret=secret, tmp=tmp_path)


def select(f):
    return ha.select_key(f.profile, f.pin, clock=lambda: f.now)


def test_primary_then_unavailable_endpoint_selects_distinct_preapproved_key(configured):
    f = configured
    primary, standby = f.provider(0, connections=1), f.provider(1)
    loaded = ha.load_profile(f.path, f.sha, f.scope, f.pin)
    assert loaded == f.profile
    first, scope, report = select(f)
    assert scope.key_id == 'proc-1' and report['selected_provider'] == 0
    assert f.secret(first) == f.secret(f.keys['runtime'])
    primary.thread.join(timeout=2)
    assert not primary.thread.is_alive()
    second, scope, report = select(f)
    assert scope.key_id == 'proc-2' and report['selected_provider'] == 1
    assert f.secret(second) == f.secret(f.standby) and f.secret(first) != f.secret(second)
    assert standby.delivered == 1 and len(report['skipped']) == 1
    assert f.secret(second) not in json.dumps(report).encode() and report['authorization_asserted'] is False


def test_missing_primary_and_both_missing_have_bounded_explicit_behavior(configured):
    f = configured
    with pytest.raises(ha.EndpointUnavailable):
        select(f)
    f.provider(1)
    assert select(f)[1].key_id == 'proc-2'


@pytest.mark.parametrize('damage', ['wrong_key', 'short_body', 'private_parent', 'socket_file', 'socket_symlink', 'peer_uid'])
def test_invalid_primary_is_not_hidden_by_trying_standby(damage, configured):
    f = configured
    standby = f.provider(1)
    if damage == 'wrong_key':
        f.provider(0, key=Ed25519PrivateKey.generate())
    elif damage == 'short_body':
        f.provider(0, body=b'bad')
    elif damage == 'socket_file':
        f.paths[0].write_bytes(b'not socket')
    elif damage == 'socket_symlink':
        f.paths[0].symlink_to(f.paths[1])
    else:
        f.provider(0)
        if damage == 'private_parent':
            f.paths[0].parent.chmod(0o755)
        else:
            f.profile.endpoints[0].peer_uid += 1
    with pytest.raises((ValueError, OSError)):
        select(f)
    assert standby.delivered == 0


@pytest.mark.parametrize('state', ['disabled', 'expired', 'future'])
def test_only_current_preapproved_standby_can_replace_noncurrent_primary(state, configured):
    f = configured
    values = {'enabled': False} if state == 'disabled' else {
        'issued_at': f.now-timedelta(seconds=20), 'expires_at': f.now-timedelta(seconds=1)} if state == 'expired' else {
        'issued_at': f.now+timedelta(seconds=1), 'expires_at': f.now+timedelta(minutes=5)}
    authorities = [a.model_copy(update=values) if a.key_id == 'proc-1' else a for a in f.registry.authorities]
    f.pin = repin(f.pin.path, f.registry.model_copy(update={'authorities': authorities}))
    f.profile.registry_sha256 = f.pin.expected_sha256
    primary, standby = f.provider(0), f.provider(1)
    assert select(f)[1].key_id == 'proc-2'
    assert primary.delivered == 0 and standby.delivered == 1


@pytest.mark.parametrize('damage', ['file_pin', 'scope', 'registry_pin', 'unknown_key', 'wrong_source', 'duplicate_endpoint'])
def test_immutable_profile_binding_rejects_scope_and_key_substitution(damage, configured):
    f = configured
    value = f.profile.model_dump(mode='json')
    if damage == 'file_pin':
        f.sha = 'f'*64
    elif damage == 'scope':
        value['scope']['server_id'] = 'other-server'
    elif damage == 'registry_pin':
        value['registry_sha256'] = 'f'*64
    elif damage == 'unknown_key':
        value['endpoints'][1]['key_id'] = 'not-approved'
    elif damage == 'wrong_source':
        value['scope']['source_id'] = 'local-policy'
    else:
        value['endpoints'][1] = value['endpoints'][0]
    f.path.write_bytes(canonical(value)+b'\n')
    if damage != 'file_pin':
        f.sha = hashlib.sha256(f.path.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        ha.load_profile(f.path, f.sha, f.scope, f.pin)


def test_mid_selection_pin_change_cannot_return_a_key_or_try_standby(configured, monkeypatch):
    f = configured
    standby = f.provider(1)

    def changed(_endpoint):
        f.pin.path.write_bytes(b'{}')
        return f.secret(f.keys['runtime'])

    monkeypatch.setattr(ha, 'read_key', changed)
    with pytest.raises(ValueError):
        select(f)
    assert standby.delivered == 0


def secondary_capture(f, *, delay=1):
    event = f.event.model_copy(update={'observed_at': f.now+timedelta(seconds=delay), 'event_id': 'c'*64})
    proof = runtime_proof(event, f.proof.observation, f.standby, source_id=f.scope.source_id,
                           key_id='proc-2', observed_at=event.observed_at)
    return envelope(event, proof)


def test_alternate_capture_remains_opt_in_and_requires_current_exact_runtime_authority(configured):
    f = configured
    payload = secondary_capture(f)
    now = f.now+timedelta(seconds=2)
    assert inspect_capture(payload, f.scope, f.pin, now=now).state == 'unavailable'
    assert inspect_capture(payload, f.scope, f.pin, now=now, alternate_key_ids=('proc-2',)).state == 'fresh'
    assert inspect_capture(payload, f.scope, f.pin, now=now, alternate_key_ids=('other-key',)).state == 'unavailable'
    changed = [a.model_copy(update={'enabled': False}) if a.key_id == 'proc-2' else a for a in f.registry.authorities]
    pin = repin(f.pin.path, f.registry.model_copy(update={'authorities': changed}))
    assert inspect_capture(payload, f.scope, pin, now=now, alternate_key_ids=('proc-2',)).state == 'unavailable'


def test_one_persistent_monitor_fence_prevents_old_primary_replay_after_standby(configured):
    f = configured
    ledger = f.tmp/'monitor.sqlite3'
    monitor = CollectorMonitor(f.scope, f.pin, ledger, alternate_key_ids=('proc-2',))
    assert monitor.check(f.latest, now=f.now).state == 'fresh'
    payload = secondary_capture(f)
    atomic_capture(f.latest, canonical(payload))
    now = f.now+timedelta(seconds=2)
    observed = monitor.check(f.latest, now=now)
    assert observed.state == 'fresh'
    # Bridge rechecks the explicitly configured standby without changing the
    # source scope or renewing the observation/expiry times.
    # Its actual clock is unrelated to this controlled fixture timestamp, so
    # inspect its original age only through the explicit checker above.
    restarted = CollectorMonitor(f.scope, f.pin, ledger, alternate_key_ids=('proc-2',))
    atomic_capture(f.latest, canonical(f.payload))
    result = restarted.check(f.latest, now=now+timedelta(seconds=1))
    assert result.state == 'unavailable' and result.reason == 'capture_regression'


def test_bridge_rechecks_only_explicit_standby_and_preserves_original_age(configured, monkeypatch):
    f = configured
    payload = secondary_capture(f, delay=0)
    atomic_capture(f.latest, canonical(payload))
    from datetime import datetime

    result = inspect_capture(payload, f.scope, f.pin, now=f.now, alternate_key_ids=('proc-2',))
    monkeypatch.setattr(bridge, 'datetime', SimpleNamespace(now=lambda _: f.now,
                                                           fromisoformat=datetime.fromisoformat))
    with pytest.raises(ValueError):
        health_report(f.scope, result, f.latest, f.pin)
    value = health_report(f.scope, result, f.latest, f.pin, alternate_key_ids=('proc-2',))
    assert value['state'] == 'fresh' and value['observed_at'] == f.event.observed_at.isoformat()
    assert value['expires_at'] == (f.event.observed_at+timedelta(seconds=30)).isoformat()
