"""Backup integrity cannot erase unknown state or renew original recovery age."""

import copy
import json
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from scripts.f1_lab import exec_bundle_snapshot as snapshot
from scripts.f1_lab import exec_bundle_status as status
from scripts.f1_lab.capture_archive import ArchiveScope
from tests.test_exec_bundle_backup import interrupted, restore, save, setup

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='private POSIX typed bundle status')


def fixture(tmp_path):
    g = setup(tmp_path)
    interrupted(g, 'preseal')
    g.f.execute()
    saved = save(g)
    recovered = restore(g, saved)

    def inspect():
        return status.inspect(g.f.archive_scope, g.package, g.checkpoint, saved['checkpoint_sha256'],
                               g.review, recovered['receipt_sha256'], g.f.lab.broker.joiner.registry,
                               g.f.lab.broker.registry)

    return SimpleNamespace(g=g, inspect=inspect, saved=saved, recovered=recovered)


def profile(scope, path):
    return {'schema': 'zt-exec-bundle-metrics-profile-1', 'scope_sha256': status.scope_hash(scope),
            'status_file': str(path), 'max_snapshot_age_seconds': 60, 'max_restore_age_seconds': 60}


def test_keyless_package_and_review_recheck_retains_unknown_and_original_dates(tmp_path):
    f = fixture(tmp_path)
    first = f.inspect()
    second = f.inspect()
    assert first['state'] == second['state'] == 'verified'
    assert first['values'] == second['values']
    assert first['values']['intents'] == 2 and first['values']['sealed'] == 1
    assert first['values']['indeterminate'] == 1 and len(f.g.f.launches) == 2
    assert second['automatic_activation_allowed'] is second['authorization_asserted'] is False
    assert not any(text in json.dumps(second) for text in ('fixture-person', 'request_id', 'worker_directory', 'token'))


@pytest.mark.parametrize('kind', ['payload', 'manifest', 'checkpoint', 'app', 'broker', 'inventory', 'seal', 'current_pin'])
def test_package_or_review_damage_cannot_report_verified_or_zero_counts(kind, tmp_path):
    f = fixture(tmp_path)
    if kind == 'payload':
        path = f.g.package/'payload.aesgcm'
    elif kind == 'manifest':
        path = f.g.package/'manifest.json'
    elif kind == 'checkpoint':
        path = f.g.checkpoint
    elif kind in {'app', 'broker'}:
        path = f.g.review/(kind+'.sqlite3')
    elif kind == 'inventory':
        path = f.g.review/'inventory.json'
    elif kind == 'seal':
        path = next((f.g.review/'intents').glob('*/capture.json'))
    else:
        path = f.g.f.lab.broker.registry.path
    path.write_bytes(b'{}')
    with pytest.raises((ValueError, OSError)):
        f.inspect()
    value = status.report(f.g.f.archive_scope)
    assert value['state'] == 'unavailable' and value['values'] == {}
    assert len(f.g.f.launches) == 2


def test_actual_ciphertext_repair_preserves_snapshot_backup_restore_times_and_unknown(tmp_path):
    f = fixture(tmp_path)
    original = f.inspect()
    payload = f.g.package/'payload.aesgcm'
    raw = payload.read_bytes()
    payload.write_bytes(bytes([raw[0] ^ 1])+raw[1:])
    with pytest.raises(ValueError):
        f.inspect()
    payload.write_bytes(raw)
    repaired = f.inspect()
    assert repaired['values'] == original['values'] and repaired['values']['indeterminate'] == 1


@pytest.mark.parametrize('damage', ['unknown_field', 'activation', 'auth', 'execute', 'wrong_scope',
                                  'counter_bool', 'count_invariant', 'worker_count', 'future_origin'])
def test_public_status_schema_rejects_misleading_counts_or_authorization_claims(damage, tmp_path):
    f = fixture(tmp_path)
    value = f.inspect()
    if damage == 'unknown_field':
        value['token'] = 'not-public'
    elif damage in {'activation', 'auth', 'execute'}:
        value[{'activation': 'automatic_activation_allowed', 'auth': 'authorization_asserted',
               'execute': 'automatic_execution_allowed'}[damage]] = True
    elif damage == 'wrong_scope':
        value['scope_sha256'] = 'f'*64
    elif damage == 'counter_bool':
        value['values']['intents'] = True
    elif damage == 'count_invariant':
        value['values']['indeterminate'] = 0
    elif damage == 'worker_count':
        value['values']['worker_artifacts'] = 3
    else:
        value['values']['snapshot_at'] = (datetime.now(UTC)+timedelta(days=1)).isoformat()
    with pytest.raises(ValueError):
        status.validate(value, status.scope_hash(f.g.f.archive_scope))


@pytest.mark.parametrize('age', [-1, 60, 61])
def test_future_or_expired_public_report_never_exports_cached_counts(age, tmp_path):
    f = fixture(tmp_path)
    value = f.inspect()
    path = tmp_path/'status.json'
    status.publish(path, value)
    now = datetime.fromisoformat(value['checked_at'])+timedelta(seconds=age)
    body = status.metrics(profile(f.g.f.archive_scope, path), now=now)
    assert 'secops_exec_bundle_status_success 0' in body
    assert not any('secops_exec_bundle_'+key+' ' in body for key in status.COUNTERS)


def test_repeated_integrity_check_never_renews_snapshot_or_restore_age(tmp_path):
    f = fixture(tmp_path)
    value = f.inspect()
    path = tmp_path/'status.json'
    later = datetime.fromisoformat(value['checked_at'])+timedelta(seconds=120)
    checked = status.report(f.g.f.archive_scope, value['values'], now=later)
    status.publish(path, checked)
    body = status.metrics(profile(f.g.f.archive_scope, path), now=later)
    assert 'secops_exec_bundle_status_success 1' in body
    assert 'secops_exec_bundle_recovery_recent 0' in body
    assert 'secops_exec_bundle_indeterminate_retained 1' in body
    assert checked['values'] == value['values']


@pytest.mark.parametrize('damage', ['schema', 'scope', 'relative_path', 'negative_age', 'boolean_age', 'extra'])
def test_optional_metrics_profile_requires_exact_bounded_policy(damage, tmp_path):
    scope = ArchiveScope(tenant_id='local-lab', server_id='shared-lab', unit='fixture.service', source_id='local-proc')
    value = profile(scope, tmp_path/'status.json')
    path = tmp_path/'profile.json'
    path.write_text(json.dumps(value))
    path.chmod(0o644)
    assert status.load_profile(path) == value
    if damage == 'schema':
        value['schema'] = 'different'
    elif damage == 'scope':
        value['scope_sha256'] = 'unknown'
    elif damage == 'relative_path':
        value['status_file'] = 'relative.json'
    elif damage == 'negative_age':
        value['max_restore_age_seconds'] = -1
    elif damage == 'boolean_age':
        value['max_restore_age_seconds'] = True
    else:
        value['extra'] = 1
    path.write_text(json.dumps(value))
    path.chmod(0o644)
    with pytest.raises(ValueError):
        status.load_profile(path)


def test_publisher_rejects_clock_regression_and_evidence_directory_overlap(tmp_path):
    f = fixture(tmp_path)
    value = f.inspect()
    path = tmp_path/'status.json'
    status.publish(path, value)
    previous = copy.deepcopy(value)
    previous['checked_at'] = (datetime.fromisoformat(value['checked_at'])-timedelta(seconds=1)).isoformat()
    # It may already precede restored_at; either chronology or publication
    # monotonicity must reject it, without replacing the valid status.
    with pytest.raises(ValueError):
        status.publish(path, previous)
    assert json.loads(path.read_bytes()) == value
    from scripts.f1_lab.backup_recovery_status import public_destination

    with pytest.raises(ValueError):
        public_destination(f.g.review/'public.json', f.g.package, f.g.review, f.g.checkpoint)


def test_current_pin_expiry_during_reconstruction_cannot_be_hidden_by_start_time(tmp_path, monkeypatch):
    f = fixture(tmp_path)
    raw = snapshot.take_snapshot(f.g.journal, f.g.f.lab.broker, f.g.f.lab.operations,
                                  f.g.f.archive_scope, [f.g.f.launcher.directory])
    start = datetime.now(UTC)
    ticks = iter([start, start+timedelta(hours=2)])
    clock = SimpleNamespace(now=lambda _zone: next(ticks), fromisoformat=datetime.fromisoformat)
    monkeypatch.setattr(snapshot, 'datetime', clock)
    with pytest.raises(ValueError):
        snapshot.validate_snapshot(raw, f.g.f.archive_scope, f.g.f.lab.broker.joiner.registry,
                                     f.g.f.lab.broker.registry)
