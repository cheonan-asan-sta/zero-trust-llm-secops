"""Durable upstream feed, ordered HTTP receipts, restart and least privilege."""

import json
import os
import re
import sqlite3
from datetime import timedelta

import pytest

from scripts import behavior_execution_collector as module
from scripts import execution_mtls_runtime as runtime
from scripts.continuous_mtls_assets import assets
from scripts.mtls_transport import ROUTES
from tests import test_behavior_execution_collector as existing


@pytest.fixture
def lab(tmp_path, monkeypatch):
    return existing.lab.__wrapped__(tmp_path, monkeypatch)


def feed(tmp_path, record):
    directory = tmp_path / 'feed'
    directory.mkdir(mode=0o700)
    path = directory / '0001.json'
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    return directory, path


def bundle(lab):
    capture = next(entry['payload']['capture'] for entry in lab.runtime.store.read(lab.runtime.tenant)
                   if entry['kind'] == 'capture' and entry['record_id'] == lab.record['capture_id'])
    return {'capture': capture, 'execution': lab.record}


def context_transport(lab, calls):
    def send(base_url, endpoint, payload, **options):
        calls.append(endpoint)
        response = lab.client.post(endpoint, json=payload)
        return response.status_code, response.json()
    return send


def test_feed_atomic_enqueue_mark_and_restart_without_resigning_old_input(lab, tmp_path):
    directory, path = feed(tmp_path, lab.record)
    first = lab.collector()
    assert first.capture_one(directory)['duplicate'] is False
    before = existing.stored(lab)[0]['envelope']
    lab.clock.now += timedelta(minutes=6)
    restarted = lab.collector()
    assert restarted.capture_one(directory) == {'state': 'idle'}
    assert restarted.enqueue(lab.record)['duplicate'] is True
    assert existing.stored(lab)[0]['envelope'] == before
    assert path.exists()


def test_input_mark_rolls_back_with_enqueue_crash(lab, tmp_path, monkeypatch):
    directory, _ = feed(tmp_path, lab.record)
    collector = lab.collector()
    original = module.sign_record

    def crash(*args, **kwargs):
        raise OSError('simulated disk interruption')

    monkeypatch.setattr(module, 'sign_record', crash)
    with pytest.raises(OSError):
        collector.capture_one(directory)
    with sqlite3.connect(collector.database) as connection:
        assert connection.execute('SELECT COUNT(*) FROM input_files').fetchone()[0] == 0
    monkeypatch.setattr(module, 'sign_record', original)
    assert lab.collector().capture_one(directory)['state'] == 'pending'


def test_input_replacement_rejected_while_old_durable_delivery_continues(lab, tmp_path):
    directory, path = feed(tmp_path, lab.record)
    collector = lab.collector()
    collector.capture_one(directory)
    path.write_text(json.dumps(lab.record | {'actor': None}))
    result = collector.tick(directory)
    assert result['input']['state'] == 'input_error'
    assert result['delivery']['state'] == 'acknowledged'
    assert lab.sent[0]['actor'] == lab.record['actor']


@pytest.mark.parametrize('contents', ['{incomplete JSON', '[' * 2000 + '0' + ']' * 2000])
def test_malformed_new_file_does_not_starve_later_valid_input(lab, tmp_path, contents):
    directory, bad = feed(tmp_path, lab.record)
    bad.write_text(contents)
    good = directory / '0002.json'
    good.write_text(json.dumps(lab.record))
    good.chmod(0o600)
    collector = lab.collector()
    result = collector.tick(directory)
    assert result['input']['invalid_files_skipped'] == 1
    assert result['delivery']['state'] == 'acknowledged'
    assert bad.read_text() == contents
    with sqlite3.connect(collector.database) as connection:
        assert connection.execute('SELECT name FROM input_files').fetchall() == [('0002.json',)]


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'public'])
def test_feed_rejects_unprotected_or_blocking_files(lab, tmp_path, kind):
    directory, path = feed(tmp_path, lab.record)
    if kind == 'symlink':
        target = tmp_path / 'private.json'
        path.rename(target)
        path.symlink_to(target)
    elif kind == 'fifo':
        path.unlink()
        os.mkfifo(path, 0o600)
    else:
        path.chmod(0o644)
    assert lab.collector().tick(directory)['input']['state'] == 'input_error'
    assert lab.sent == []


def test_bundle_capture_execution_evaluation_order_and_lost_reply_restart(lab, tmp_path):
    directory, _ = feed(tmp_path, bundle(lab))
    calls = []
    real = context_transport(lab, calls)
    lose = [True]

    def lost(base_url, endpoint, payload, **options):
        result = real(base_url, endpoint, payload, **options)
        if lose[0] and endpoint.endswith('/captures'):
            lose[0] = False
            raise OSError('lost capture receipt')
        return result

    first = lab.collector(context_transport=lost)
    assert first.tick(directory)['delivery']['state'] == 'pending'
    assert lab.sent == []
    before = existing.stored(lab)[0]['envelope']
    lab.clock.now += timedelta(seconds=3)
    result = lab.collector(context_transport=real).tick(directory)
    assert result['delivery']['state'] == 'acknowledged'
    assert result['evaluation']['state'] == 'acknowledged'
    assert calls == ['/detections/context/captures', '/detections/context/captures', '/detections/context/evaluate']
    assert existing.stored(lab)[0]['envelope'] == before
    assert lab.collector(context_transport=real).tick(directory)['evaluation']['state'] == 'idle'


@pytest.mark.parametrize('status', [401, 403, 409, 422, 503])
def test_failed_capture_never_delivers_execution_or_evaluates(lab, tmp_path, status):
    directory, _ = feed(tmp_path, bundle(lab))
    calls = []

    def rejected(base_url, endpoint, payload, **options):
        calls.append(endpoint)
        return status, {}

    result = lab.collector(context_transport=rejected).tick(directory)
    assert result['delivery']['state'] == ('pending' if status == 503 else 'rejected')
    assert result['evaluation']['state'] == 'idle'
    assert calls == ['/detections/context/captures'] and lab.sent == []


def test_mismatched_bundle_cannot_commit_input_mark_or_record(lab, tmp_path):
    value = bundle(lab)
    value['execution'] = value['execution'] | {'capture_input_sha256': '0' * 64}
    directory, _ = feed(tmp_path, value)
    collector = lab.collector()
    assert collector.tick(directory)['input']['state'] == 'input_error'
    assert collector.status()['records'] == 0


def test_evaluation_lost_reply_retries_without_duplicate_approval_use(lab, tmp_path):
    directory, _ = feed(tmp_path, bundle(lab))
    real = context_transport(lab, [])

    def lost(base_url, endpoint, payload, **options):
        result = real(base_url, endpoint, payload, **options)
        if endpoint.endswith('/evaluate'):
            raise OSError('lost evaluation receipt')
        return result

    first = lab.collector(context_transport=lost)
    assert first.tick(directory)['evaluation']['state'] == 'pending'
    before = len([entry for entry in lab.runtime.store.read(lab.runtime.tenant) if entry['kind'] == 'evaluation'])
    lab.clock.now += timedelta(seconds=3)
    assert lab.collector(context_transport=real).tick(directory)['evaluation']['state'] == 'acknowledged'
    assert len([entry for entry in lab.runtime.store.read(lab.runtime.tenant) if entry['kind'] == 'evaluation']) == before


def test_runtime_keeps_observer_credentials_and_input_separate():
    spec = runtime.definition('kmtls-' + 'a' * 12, 'app', 'nginx')
    observer = spec['services']['execution-observer']
    assert observer['restart'] == 'unless-stopped' and observer['read_only']
    assert observer['networks'] == {'core': {}}
    assert 'execution-input:/observer/input' in observer['volumes']
    assert all('operator-auth' not in mount and 'reviewer' not in mount for mount in observer['volumes'])
    material = runtime.add_material(assets())
    account = next(row for row in json.loads(material['core-auth']['accounts.json'])['accounts']
                   if row['subject'] == 'runtime-execution-observer')
    assert account['roles'] == ['analyst']
    assert 'behavior-private.pem' in material['operator-auth']
    assert 'behavior-private.pem' not in material['execution-state']
    registry = json.loads(material['execution-state']['sources.json'])
    assert 'behavior_scopes' not in registry['sources'][0]
    for restored in (False, True):
        graph = runtime.recoverable_definition('kmtls-' + 'a' * 12, 'app', 'nginx', restored=restored)
        assert len(graph['services']) == 10 and len(graph['volumes']) == 28
        entry = graph['services']['execution-observer']
        assert entry['entrypoint'][-1] == ('approved' if restored else 'original')
        assert 'recovery-public:/admission:ro' in entry['volumes']
        assert all('context-auth' not in mount for service in graph['services'].values()
                   for mount in service['volumes'])


@pytest.mark.parametrize('field,value', [('capture_id', 'other'), ('input_digest', '0' * 64), ('duplicate', 1)])
def test_invalid_capture_receipt_blocks_execution(lab, tmp_path, field, value):
    directory, _ = feed(tmp_path, bundle(lab))
    real = context_transport(lab, [])

    def forged(base_url, endpoint, payload, **options):
        status, receipt = real(base_url, endpoint, payload, **options)
        return status, receipt | {field: value}

    result = lab.collector(context_transport=forged).tick(directory)
    assert result['delivery']['state'] == 'pending' and lab.sent == []


@pytest.mark.parametrize('field,value', [('capture_id', 'other'), ('enforcement_eligible', True), ('verdict', 'allow')])
def test_invalid_evaluation_receipt_is_not_persisted_as_success(lab, tmp_path, field, value):
    directory, _ = feed(tmp_path, bundle(lab))
    real = context_transport(lab, [])

    def forged(base_url, endpoint, payload, **options):
        status, receipt = real(base_url, endpoint, payload, **options)
        return status, receipt | {field: value} if endpoint.endswith('/evaluate') else receipt

    collector = lab.collector(context_transport=forged)
    result = collector.tick(directory)
    assert result['delivery']['state'] == 'acknowledged' and result['evaluation']['state'] == 'pending'
    assert collector.status()['evaluations']['acknowledged'] == 0


def test_bundle_tenant_mismatch_fails_before_queue_commit(lab, tmp_path):
    value = bundle(lab)
    value['capture']['tenant_id'] = 'tenant-other'
    directory, _ = feed(tmp_path, value)
    collector = lab.collector()
    assert collector.tick(directory)['input']['state'] == 'input_error'
    assert collector.status()['records'] == 0


@pytest.mark.parametrize('path,allowed', [
    ('/detections/context/captures', True), ('/detections/context/execution-evidence', True),
    ('/detections/context/evaluate', True), ('/detections/context/baselines', False),
    ('/detections/context/approvals', False), ('/zero-trust/protected-access', False),
    ('/response/requests', False), ('/detections/context/evaluate?admin=true', False),
])
def test_observer_route_cannot_mint_approve_or_execute(path, allowed):
    assert any(method == 'POST' and re.fullmatch(pattern, path)
               for method, pattern in ROUTES['execution-observer']) is allowed
