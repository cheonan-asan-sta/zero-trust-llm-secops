"""Independent review state cannot become a launch or an unconsumed app grant."""

import json
import os
import secrets
import shutil
import sqlite3
import sys
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag

from scripts.f1_lab import exec_bundle_backup as backup
from scripts.f1_lab import exec_bundle_snapshot as snapshot
from scripts.f1_lab import managed_exec_retention as retention
from scripts.f1_lab.exec_intent import ExecIntentJournal
from scripts.f1_lab.operation_context import canonical
from tests.test_managed_exec_retention import fixture

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='private POSIX recovery bundle')


def setup(tmp_path):
    f = fixture(tmp_path)
    for path in (f.lab.broker.path, f.lab.operations.path):
        path.chmod(0o600)
        path.parent.chmod(0o700)
    stores = {}
    for name in ('packages', 'pins', 'reviews'):
        stores[name] = tmp_path/name
        stores[name].mkdir(mode=0o700)
    manager = backup.ExecutionRecoveryBundle(f.archive_scope, f.lab.broker.joiner.registry,
                                             f.lab.broker.registry)
    journal = ExecIntentJournal(f.intents, f.lab.broker.joiner.registry, f.lab.broker.registry)
    return SimpleNamespace(f=f, manager=manager, journal=journal, key=secrets.token_bytes(32),
                           key_id='recovery-1', package=stores['packages']/'first',
                           checkpoint=stores['pins']/'first.json', review=stores['reviews']/'first')


def save(g, **kwargs):
    return g.manager.backup(g.journal, g.f.lab.broker, g.f.lab.operations,
                            [g.f.launcher.directory], kwargs.get('package', g.package),
                            kwargs.get('checkpoint', g.checkpoint), g.key, g.key_id)


def restore(g, result, **kwargs):
    return g.manager.restore(kwargs.get('package', g.package), kwargs.get('review', g.review),
                             kwargs.get('checkpoint', g.checkpoint), result['checkpoint_sha256'],
                             kwargs.get('key', g.key), kwargs.get('key_id', g.key_id))


def interrupted(g, phase):
    f = g.f
    gate = f.lab.gate(f.lab.new_request(), f.lab.new_access())
    with patch.object(retention, 'seal_completed' if phase == 'preseal' else 'fresh_file',
                      side_effect=OSError('owned process loss')), pytest.raises(OSError):
        retention.dispatch_and_retain(gate, f.launcher, f.lab.permission, f.root, f.outbox,
                                     intent_root=f.intents)
    return gate


def test_snapshot_and_review_preserve_unknown_consumed_state_after_source_loss(tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    lost = interrupted(g, 'preseal')
    g.f.execute()
    sources = {p: p.read_bytes() for p in (g.f.lab.operations.path, g.f.lab.broker.path,
                                           g.f.root/'latest.json')}
    result = save(g)
    assert result['intents'] == 3 and result['sealed'] == 2 and result['indeterminate'] == 1
    assert result['worker_artifacts'] == 1 and len(g.f.launches) == 3
    assert all(p.read_bytes() == raw for p, raw in sources.items())
    for path in (g.f.intents, g.f.launcher.directory, g.f.root, g.f.outbox):
        shutil.rmtree(path)
    for path in (g.f.lab.operations.path, g.f.lab.broker.path):
        path.unlink()
    restored = restore(g, result)
    checked = g.manager.verify_review(g.review, restored['receipt_sha256'], g.checkpoint,
                                      result['checkpoint_sha256'])
    assert checked['indeterminate'] == 1 and checked['sealed'] == 2
    assert not (g.review/'intents'/lost.request.request_id/'capture.json').exists()
    assert len(g.f.launches) == 3 and not (g.review/'latest.json').exists()
    with closing(sqlite3.connect(g.review/'broker.sqlite3')) as con:
        assert con.execute('SELECT state FROM requests WHERE id=?',
                           (lost.request.request_id,)).fetchone() == ('bound',)
    assert checked['automatic_activation_allowed'] is checked['authorization_asserted'] is False


def test_bundle_includes_only_typed_data_and_encrypts_raw_identifiers(tmp_path):
    g = setup(tmp_path)
    gate, _, _, raw = g.f.execute()
    marker = b'owned-runtime-key-not-for-backup'
    (g.f.launcher.directory/'runtime-secret.key').write_bytes(marker)
    (g.f.launcher.directory/'request.json').write_bytes(gate.token.encode())
    original = snapshot.take_snapshot(g.journal, g.f.lab.broker, g.f.lab.operations,
                                       g.f.archive_scope, [g.f.launcher.directory])
    value = json.loads(original)
    bodies = [original, snapshot.unencoded(value['app_database'], snapshot.MAX_DB),
              snapshot.unencoded(value['broker_database'], snapshot.MAX_DB)]
    for record in value['runs']:
        bodies.extend(snapshot.unencoded(record[key], 2*1024**2)
                      for key in ('intent', 'capture', 'worker') if record[key] is not None)
    assert all(gate.token.encode() not in body and gate.access.grant_token.encode() not in body
               and marker not in body for body in bodies)
    result = save(g)
    assert {p.name for p in g.package.iterdir()} == {'manifest.json', 'payload.aesgcm'}
    public = b''.join(p.read_bytes() for p in g.package.iterdir())+g.checkpoint.read_bytes()
    assert b'fixture-person' not in public and raw not in public
    assert gate.token.encode() not in public and gate.access.grant_token.encode() not in public
    restore(g, result)
    files = [p.relative_to(g.review).as_posix() for p in g.review.rglob('*') if p.is_file()]
    assert all(not any(v in p for v in ('key', 'request.json', 'argv', 'token')) for p in files)
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in g.review.rglob('*') if p.is_file())


@pytest.mark.parametrize('phase', ['preseal', 'preoutbox'])
def test_snapshot_does_not_upgrade_an_unsealed_or_unpublished_request(phase, tmp_path):
    g = setup(tmp_path)
    interrupted(g, phase)
    result = save(g)
    restored = restore(g, result)
    assert restored['indeterminate'] == (phase == 'preseal')
    assert restored['sealed'] == (phase == 'preoutbox')
    assert not list(g.f.outbox.glob('*.json')) and not (g.review/'latest.json').exists()
    assert len(g.f.launches) == 1


def test_in_flight_execution_is_refused_before_creating_backup_or_pin(tmp_path):
    g = setup(tmp_path)
    request = g.f.lab.new_request()
    with g.f.lab.broker.connect() as con:
        con.execute("UPDATE requests SET state='launching' WHERE id=?", (request.request_id,))
    with pytest.raises(ValueError, match='exec_bundle_execution_in_flight'):
        save(g)
    assert not g.package.exists() and not g.checkpoint.exists() and not g.f.launches


def test_snapshot_waits_for_actual_other_process_broker_transaction_then_refuses_launching(tmp_path):
    g = setup(tmp_path)
    request = g.f.lab.new_request()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        code = 71
        try:
            with g.f.lab.broker.connect() as con:
                con.execute('BEGIN IMMEDIATE')
                con.execute("UPDATE requests SET state='launching' WHERE id=?", (request.request_id,))
                os.write(write_fd, b'1')
                time.sleep(0.25)
            code = 0
        finally:
            os._exit(code)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 1) == b'1'
        with pytest.raises(ValueError, match='exec_bundle_execution_in_flight'):
            save(g)
    finally:
        os.close(read_fd)
        waited, status = os.waitpid(child, 0)
    assert waited == child and os.waitstatus_to_exitcode(status) == 0
    assert not g.package.exists() and not g.checkpoint.exists()


@pytest.mark.parametrize('damage', ['ciphertext', 'manifest', 'wrong_key', 'key_id', 'checkpoint', 'extra_file'])
def test_modified_or_unpinned_package_never_creates_review(damage, tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    result = save(g)
    kwargs = {}
    if damage == 'ciphertext':
        p = g.package/'payload.aesgcm'
        raw = p.read_bytes()
        p.write_bytes(bytes([raw[0] ^ 1])+raw[1:])
    elif damage == 'manifest':
        p = g.package/'manifest.json'
        value = json.loads(p.read_bytes())
        value['created_at'] = datetime.now(UTC).isoformat()
        p.write_bytes(canonical(value))
    elif damage == 'wrong_key':
        kwargs['key'] = secrets.token_bytes(32)
    elif damage == 'key_id':
        kwargs['key_id'] = 'another-key'
    elif damage == 'checkpoint':
        g.checkpoint.write_bytes(b'{}')
    else:
        (g.package/'secret-extra.key').write_bytes(b'not allowed')
    with pytest.raises((ValueError, OSError, InvalidTag)):
        restore(g, result, **kwargs)
    assert not g.review.exists()


def test_current_external_pin_rejects_an_older_authentic_package(tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    save(g)
    g.f.execute()
    second_package, second_pin = g.package.parent/'second', g.checkpoint.parent/'second.json'
    current = save(g, package=second_package, checkpoint=second_pin)
    with pytest.raises(ValueError, match='pin_mismatch'):
        restore(g, current, checkpoint=second_pin)
    restored = restore(g, current, package=second_package, checkpoint=second_pin)
    assert restored['intents'] == 2


@pytest.mark.parametrize('kind', ['capture', 'intent', 'app_db', 'broker_db', 'inventory', 'unknown_file', 'link'])
def test_review_recheck_rejects_missing_changed_or_linked_originals(kind, tmp_path):
    g = setup(tmp_path)
    gate, _, _, _ = g.f.execute()
    result = save(g)
    restored = restore(g, result)
    path = {'capture': g.review/'intents'/gate.request.request_id/'capture.json',
            'intent': g.review/'intents'/gate.request.request_id/'intent.json',
            'app_db': g.review/'app.sqlite3', 'broker_db': g.review/'broker.sqlite3',
            'inventory': g.review/'inventory.json', 'unknown_file': g.review/'unknown.json',
            'link': g.review/'app.sqlite3'}[kind]
    if kind == 'link':
        target = tmp_path/'owned-link-original'
        target.write_bytes(path.read_bytes())
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)
    else:
        path.write_bytes(b'{}')
    with pytest.raises((ValueError, OSError)):
        g.manager.verify_review(g.review, restored['receipt_sha256'], g.checkpoint,
                                result['checkpoint_sha256'])


@pytest.mark.parametrize('field', ['signature', 'caller_pin', 'policy_sha256', 'scope', 'created_at', 'runs'])
def test_snapshot_contract_and_current_trust_are_rechecked(field, tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    raw = snapshot.take_snapshot(g.journal, g.f.lab.broker, g.f.lab.operations,
                                  g.f.archive_scope, [g.f.launcher.directory])
    value = json.loads(raw)
    if field == 'signature':
        record = value['runs'][0]
        intent = json.loads(snapshot.unencoded(record['intent'], 2*1024**2))
        intent['signature'] = 'B'*86
        record['intent'] = snapshot.encoded(canonical(intent))
    elif field == 'caller_pin' or field == 'policy_sha256':
        value[field] = 'f'*64
    elif field == 'scope':
        value[field]['unit'] = 'other.service'
    elif field == 'created_at':
        value[field] = (datetime.now(UTC)+timedelta(days=1)).isoformat()
    else:
        value[field].append(value[field][0])
    from cryptography.exceptions import InvalidSignature

    with pytest.raises((ValueError, InvalidSignature)):
        snapshot.validate_snapshot(canonical(value), g.f.archive_scope,
                                    g.f.lab.broker.joiner.registry, g.f.lab.broker.registry)


@pytest.mark.parametrize('kind', ['worker_allowlist', 'private_permissions', 'extra_intent_file', 'body_capacity',
                                 'database_schema', 'other_unit'])
def test_snapshot_refuses_unconfigured_or_unsafe_sources(kind, tmp_path, monkeypatch):
    g = setup(tmp_path)
    gate, _, _, _ = g.f.execute()
    if kind == 'worker_allowlist':
        other = tmp_path/'another-worker'
        other.mkdir(mode=0o700)
        g.f.launcher.directory = other
    elif kind == 'private_permissions':
        g.f.lab.operations.path.chmod(0o644)
    elif kind == 'extra_intent_file':
        (g.f.intents/gate.request.request_id/'secret.key').write_bytes(b'refuse')
    elif kind == 'body_capacity':
        monkeypatch.setattr(snapshot, 'MAX_BODY', 100)
    elif kind == 'database_schema':
        with g.f.lab.broker.connect() as con:
            con.execute('CREATE TABLE surprise (value TEXT)')
    else:
        with g.f.lab.broker.connect() as con:
            con.execute('UPDATE requests SET scope=?', ('f'*64,))
    with pytest.raises((ValueError, OSError, RuntimeError)):
        save(g)
    assert not g.package.exists() and not g.checkpoint.exists() and len(g.f.launches) == 1


def test_restored_intent_and_databases_cannot_override_current_registry(tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    result = save(g)
    g.f.lab.broker.registry.path.write_bytes(b'{}')
    with pytest.raises(ValueError):
        restore(g, result)
    assert not g.review.exists()


def test_backup_and_restore_refuse_existing_destinations(tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    result = save(g)
    before = (g.package/'payload.aesgcm').read_bytes()
    with pytest.raises(FileExistsError):
        save(g)
    first = restore(g, result)
    with pytest.raises(FileExistsError):
        restore(g, result)
    assert before == (g.package/'payload.aesgcm').read_bytes()
    assert g.manager.verify_review(g.review, first['receipt_sha256'], g.checkpoint,
                                   result['checkpoint_sha256'])['completed']


def test_wal_databases_restore_a_consistent_logical_snapshot_without_copying_sidecars(tmp_path):
    g = setup(tmp_path)
    g.f.execute()
    for path in (g.f.lab.operations.path, g.f.lab.broker.path):
        with closing(sqlite3.connect(path)) as con:
            assert con.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
    g.f.execute()
    saved = save(g)
    for path in (g.f.lab.operations.path, g.f.lab.broker.path):
        with closing(sqlite3.connect(path)) as con:
            assert con.execute('PRAGMA journal_mode').fetchone() == ('wal',)
    restored = restore(g, saved)
    assert restored['sealed'] == 2 and restored['indeterminate'] == 0
    assert g.manager.verify_review(g.review, restored['receipt_sha256'], g.checkpoint,
                                   saved['checkpoint_sha256'])['completed']
    assert not list(g.review.rglob('*-wal')) and not list(g.review.rglob('*-shm'))
