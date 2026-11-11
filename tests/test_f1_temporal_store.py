import base64
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models import SecurityEvent
from app.security import Principal, Role
from app.services.detection_benchmark import DetectionBenchmark
from app.services.trusted_signals import SignalVerifier, canonical_signal
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.approvals import (
    ApprovalContext,
    ApprovalVerifier,
    Authority,
    event_digest,
    sign,
)
from scripts.f1_lab.detector import RULE_IDS, ShadowDetector
from scripts.f1_lab.temporal import TemporalStore, TemporalUnavailable


@pytest.fixture
def lab(tmp_path):
    now = datetime.now(UTC)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    registry = {'sources': [{'source_id': 'events', 'tenant_id': 'tenant-a',
        'user_ids': ['user-a', 'user-b'], 'device_ids': ['device-a', 'device-b'], 'roles': ['employee'],
        'keys': [{'key_id': 'key-a', 'public_key_pem': public, 'not_before': (now-timedelta(hours=1)).isoformat(),
                  'not_after': (now+timedelta(days=1)).isoformat()}]}]}
    path = tmp_path / 'registry.json'

    def publish():
        path.write_text(json.dumps(registry), encoding='utf8')

    publish()
    principal = Principal('operator', 'tenant-a', frozenset({Role.ANALYST}), 'api_key')
    sources = frozenset({('tenant-a', 'events', 'key-a')})
    store = TemporalStore(tmp_path / 'events.sqlite3', tmp_path / 'control', SignalVerifier(path), sources)
    store.initialize()
    original = DetectionBenchmark().cases[0].event.analysis_payload()

    def signal(ident='event-a', seconds=0, *, session='session-a', issued=None, **changes):
        raw = json.loads(json.dumps(original))
        raw.update(event_id=ident, timestamp=(now+timedelta(seconds=seconds)).isoformat())
        raw['user'].update(user_id='user-a', role='employee')
        raw['device'].update(device_id='device-a', managed=True, security_posture='healthy')
        raw['resource'].update(resource_id='resource-a', required_role='employee')
        for field, value in changes.items():
            parts = field.split('.')
            target = raw
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
        at = now+timedelta(seconds=seconds) if issued is None else issued
        message = SignedSessionSignal(tenant_id='tenant-a', source_id='events', key_id='key-a',
            issued_at=at, expires_at=at+timedelta(seconds=90), expected_version=0,
            session_id=session, event=SecurityEvent.model_validate(raw), signature='A'*86)
        signature = base64.urlsafe_b64encode(key.sign(canonical_signal(message))).decode().rstrip('=')
        return message.model_copy(update={'signature': signature})

    return SimpleNamespace(root=tmp_path, now=now, store=store, principal=principal, signal=signal,
                           registry=registry, publish=publish, registry_path=path, sources=sources)


def at(lab, seconds):
    return lab.now+timedelta(seconds=seconds)


def test_distinct_events_aggregate_deltas_and_exact_retries_do_not_add_counts(lab):
    first = lab.signal()
    result = lab.store.observe(first, lab.principal, now=lab.now)
    assert result['event_count'] == result['failed_login_events'] == 1
    repeated = lab.store.observe(first, lab.principal, now=lab.now)
    assert repeated['duplicate'] and repeated['event_count'] == repeated['failed_login_events'] == 1
    result = lab.store.observe(lab.signal('event-b', 1), lab.principal, now=at(lab, 1))
    # failed_attempts was a cumulative field in each input; it must not be summed.
    assert result['failed_login_events'] == 2
    assert result['complete'] and not result['collection_completeness_proven']


def test_restart_preserves_window_and_session_scope(lab):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    restarted = TemporalStore(lab.store.database, lab.store.control, SignalVerifier(lab.registry_path), lab.sources)
    assert restarted.summary('session-a', lab.principal, now=lab.now)['event_count'] == 1
    other = lab.signal('other', 1, session='session-b')
    assert restarted.observe(other, lab.principal, now=at(lab, 1))['event_count'] == 1
    assert restarted.summary('session-a', lab.principal, now=at(lab, 1))['event_count'] == 1


def test_window_expiry_is_missing_evidence_not_a_positive_safety_claim(lab):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    result = lab.store.summary('session-a', lab.principal, now=at(lab, 600))
    assert result['event_count'] == 0 and not result['complete']
    assert not result['collection_completeness_proven']


def test_low_rate_downloads_accumulate_without_double_counting(lab):
    for index in range(5):
        message = lab.signal('download-'+str(index), index*120, action='DOWNLOAD',
                             **{'resource.sensitivity': 'critical', 'behavior.download_volume_mb': 110,
                                'auth_context.authentication_result': 'success', 'auth_context.failed_attempts': 0})
        result = lab.store.observe(message, lab.principal, now=at(lab, index*120))
    assert result['sensitive_download_mb'] == 550 and result['event_count'] == 5


def test_signed_window_catches_low_rate_authentication_missed_by_single_event(lab):
    detector = ShadowDetector(temporal_store=lab.store)
    for index in range(3):
        message = lab.signal('attempt-'+str(index), index*30, **{'auth_context.failed_attempts': 1})
        assert not ShadowDetector().evaluate(message.event, 'tenant-a')['detected']
        result = detector.evaluate_signed(message, lab.principal, now=at(lab, index*30))
        assert result['detected'] == (index == 2)
    assert 'REPEATED_SIGNED_FAILED_LOGIN_EVENTS' in result['reason_codes']
    assert result['access_grants'] == result['session_changes'] == 0


def test_signed_window_catches_low_and_slow_bytes_without_changing_independent_benchmark(lab):
    detector = ShadowDetector(temporal_store=lab.store)
    for index in range(5):
        message = lab.signal('transfer-'+str(index), index*120, action='DOWNLOAD',
            **{'resource.sensitivity': 'critical', 'behavior.download_volume_mb': 110,
               'auth_context.authentication_result': 'success', 'auth_context.failed_attempts': 0})
        assert not ShadowDetector().evaluate(message.event, 'tenant-a')['detected']
        result = detector.evaluate_signed(message, lab.principal, now=at(lab, index*120))
        assert result['detected'] == (index == 4)
    assert RULE_IDS['exfiltration'] in result['predicted_rule_ids']
    assert result['temporal_evidence']['sensitive_download_mb'] == 550


def test_small_legitimate_transfers_remain_below_window_threshold(lab):
    detector = ShadowDetector(temporal_store=lab.store)
    for index in range(5):
        message = lab.signal('small-'+str(index), index*100, action='DOWNLOAD',
            **{'resource.sensitivity': 'critical', 'behavior.download_volume_mb': 60,
               'auth_context.authentication_result': 'success', 'auth_context.failed_attempts': 0})
        result = detector.evaluate_signed(message, lab.principal, now=at(lab, index*100))
        assert not result['detected']


def test_signed_history_is_not_cleared_by_a_later_healthy_snapshot(lab):
    detector = ShadowDetector(temporal_store=lab.store)
    first = lab.signal('bad', **{'device.security_posture': 'compromised'})
    detector.evaluate_signed(first, lab.principal, now=lab.now)
    healthy = lab.signal('healthy', 1, **{'auth_context.authentication_result': 'success',
                                        'auth_context.failed_attempts': 0})
    result = detector.evaluate_signed(healthy, lab.principal, now=at(lab, 1))
    assert 'RECENT_COMPROMISED_DEVICE' in result['reason_codes']
    assert result['session_changes'] == 0


def test_event_approval_does_not_approve_prior_events_in_a_window(lab):
    for index in range(2):
        lab.store.observe(lab.signal('prior-'+str(index), index*10, **{'auth_context.failed_attempts': 1}),
                          lab.principal, now=at(lab, index*10))
    message = lab.signal('latest', 20)
    event = message.event
    key = Ed25519PrivateKey.generate()
    now = at(lab, 20)
    context = ApprovalContext(approval_id='approval-'+'a'*32, tenant_id='tenant-a', issuer_id='business', key_id='business-key',
        event_sha256=event_digest(event), user_id=event.user.user_id, device_id=event.device.device_id,
        resource_id=event.resource.resource_id, action=event.action, permitted_deviations=['authentication_failure'],
        maximum_download_mb=0, issued_at=now, expires_at=now+timedelta(seconds=60))
    authority = Authority('tenant-a', 'business', 'business-key', key.public_key(),
        frozenset({'authentication_failure'}), frozenset({event.user.user_id}), frozenset({event.device.device_id}),
        frozenset({event.resource.resource_id}), frozenset({event.action}),
        now-timedelta(minutes=1), now+timedelta(hours=1))
    detector = ShadowDetector(temporal_store=lab.store, approval_verifier=ApprovalVerifier((authority,)))
    result = detector.evaluate_signed(message, lab.principal, approval=sign(context, key), now=now)
    assert result['signed_context_status'] == 'verified'
    assert 'REPEATED_AUTHENTICATION_FAILURE' in result['context_only_suppressed_signals']
    assert 'REPEATED_SIGNED_FAILED_LOGIN_EVENTS' in result['reason_codes'] and result['detected']


def test_observation_key_cannot_also_be_the_business_approval_authority(lab):
    message = lab.signal()
    public = serialization.load_pem_public_key(lab.registry['sources'][0]['keys'][0]['public_key_pem'].encode())
    event = message.event
    authority = Authority('tenant-a', 'business', 'shared-key', public,
        frozenset({'authentication_failure'}), frozenset({event.user.user_id}), frozenset({event.device.device_id}),
        frozenset({event.resource.resource_id}), frozenset({event.action}),
        lab.now-timedelta(minutes=1), lab.now+timedelta(hours=1))
    detector = ShadowDetector(temporal_store=lab.store, approval_verifier=ApprovalVerifier((authority,)))
    with pytest.raises(ValueError, match='keys_must_be_distinct'):
        detector.evaluate_signed(message, lab.principal, now=lab.now)
    with pytest.raises(TemporalUnavailable, match='session_unavailable'):
        lab.store.summary('session-a', lab.principal, now=lab.now)


def test_parallel_exact_retries_commit_one_event_with_one_receipt(lab):
    message = lab.signal()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: lab.store.observe(message, lab.principal, now=lab.now), range(8)))
    assert sum(not r['duplicate'] for r in results) == 1
    assert all(r['event_count'] == 1 for r in results)
    assert lab.store.summary('session-a', lab.principal, now=lab.now)['failed_login_events'] == 1


def test_fresh_out_of_order_observation_is_kept_but_future_and_clock_rollback_are_rejected(lab):
    lab.store.observe(lab.signal('later', 10), lab.principal, now=at(lab, 10))
    older = lab.signal('older', 5, issued=at(lab, 11))
    assert lab.store.observe(older, lab.principal, now=at(lab, 11))['event_count'] == 2
    with pytest.raises(TemporalUnavailable, match='clock_rollback'):
        lab.store.summary('session-a', lab.principal, now=at(lab, 9))
    with pytest.raises(TemporalUnavailable):
        lab.store.observe(lab.signal('future', 20), lab.principal, now=at(lab, 12))


@pytest.mark.parametrize('change', ['event', 'user', 'device', 'owner', 'tenant', 'signature'])
def test_changed_identity_cross_subject_or_bad_signature_cannot_extend_a_session(lab, change):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    principal = lab.principal
    if change == 'event':
        message = lab.signal('event-a', 1)
    elif change in {'user', 'device'}:
        message = lab.signal('new', 1, **{change+'.'+change+'_id': change+'-b'})
    elif change in {'owner', 'tenant'}:
        principal = Principal('other' if change == 'owner' else 'operator',
                              'tenant-b' if change == 'tenant' else 'tenant-a',
                              frozenset({Role.ADMIN}), 'api_key')
        message = lab.signal('new', 1)
    else:
        message = lab.signal('new', 1).model_copy(update={'signature': 'B'*86})
    with pytest.raises(TemporalUnavailable):
        lab.store.observe(message, principal, now=at(lab, 1))
    assert lab.store.summary('session-a', lab.principal, now=at(lab, 1))['event_count'] == 1


def test_role_tenant_and_disabled_auth_cannot_read_private_window(lab):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    principals = [Principal('operator', 'tenant-b', frozenset({Role.ADMIN}), 'api_key'),
                  Principal('someone-else', 'tenant-a', frozenset({Role.ADMIN}), 'api_key'),
                  Principal('operator', 'tenant-a', frozenset({Role.VIEWER}), 'api_key'),
                  Principal('operator', 'tenant-a', frozenset({Role.ADMIN}), 'disabled')]
    for principal in principals:
        with pytest.raises(TemporalUnavailable):
            lab.store.summary('session-a', principal, now=lab.now)


def test_revocation_and_registry_failure_do_not_turn_old_records_into_healthy_zeros(lab):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    lab.registry['sources'][0]['keys'][0]['enabled'] = False
    lab.publish()
    result = lab.store.summary('session-a', lab.principal, now=lab.now)
    assert result['authority_excluded_events'] == 1 and not result['complete']
    lab.registry_path.write_bytes(b'broken')
    with pytest.raises(TemporalUnavailable, match='authority_unavailable'):
        lab.store.summary('session-a', lab.principal, now=lab.now)


def test_snapshot_source_or_key_activated_after_issue_cannot_claim_event_deltas(lab):
    wrong = TemporalStore(lab.root / 'other.db', lab.root / 'other-control', SignalVerifier(lab.registry_path),
                          {('tenant-a', 'snapshot-source', 'key-a')})
    wrong.initialize()
    with pytest.raises(TemporalUnavailable, match='not_event_producer'):
        wrong.observe(lab.signal(), lab.principal, now=lab.now)
    lab.registry['sources'][0]['keys'][0]['not_before'] = at(lab, -5).isoformat()
    lab.publish()
    with pytest.raises(TemporalUnavailable, match='issued_before_activation'):
        lab.store.observe(lab.signal('backdated', -10), lab.principal, now=lab.now)


@pytest.mark.parametrize('damage', ['rewrite', 'truncate', 'witness', 'rollback'])
def test_journal_and_independent_witness_detect_tampering_or_old_database(lab, damage):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    old = lab.root / 'old.db'
    shutil.copyfile(lab.store.database, old)
    lab.store.observe(lab.signal('second', 1), lab.principal, now=at(lab, 1))
    if damage == 'witness':
        path = lab.store.control / 'witness.json'
        data = json.loads(path.read_bytes())
        data['state']['current']['seq'] = 1
        path.write_text(json.dumps(data))
    elif damage == 'rollback':
        shutil.copyfile(old, lab.store.database)
    else:
        with sqlite3.connect(lab.store.database) as db:
            if damage == 'rewrite':
                db.execute("UPDATE signed_events SET body='{}' WHERE seq=1")
            else:
                db.execute('DELETE FROM signed_events WHERE seq=2')
    with pytest.raises(TemporalUnavailable):
        lab.store.summary('session-a', lab.principal, now=at(lab, 1))


def test_capacity_and_configuration_cannot_silently_discard_history(lab):
    small = TemporalStore(lab.root / 'small.db', lab.root / 'small-control', SignalVerifier(lab.registry_path),
                          lab.sources, capacity=1)
    small.initialize()
    small.observe(lab.signal(), lab.principal, now=lab.now)
    with pytest.raises(TemporalUnavailable, match='capacity'):
        small.observe(lab.signal('second', 1), lab.principal, now=at(lab, 1))
    changed = TemporalStore(small.database, small.control, SignalVerifier(lab.registry_path), lab.sources, capacity=2)
    with pytest.raises(TemporalUnavailable, match='witness_head'):
        changed.summary('session-a', lab.principal, now=lab.now)


@pytest.mark.parametrize('point', ['after_prepare', 'before_db_commit', 'after_db_commit', 'after_publish'])
def test_actual_process_exit_recovers_same_record_at_four_durable_boundaries(lab, point):
    message = lab.signal()
    payload = lab.root / 'signed-input.json'
    payload.write_text(message.model_dump_json(), encoding='utf8')
    program = """import os,sys
from pathlib import Path
from datetime import datetime
from app.security import Principal,Role
from app.services.trusted_signals import SignalVerifier
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.temporal import TemporalStore
root=Path(sys.argv[1])
s=TemporalStore(root/'events.sqlite3',root/'control',SignalVerifier(root/'registry.json'),{('tenant-a','events','key-a')})
def fault(name):
    if name==sys.argv[2]: os._exit(73)
s._phase=fault
s.observe(SignedSessionSignal.model_validate_json((root/'signed-input.json').read_bytes()),
    Principal('operator','tenant-a',frozenset({Role.ANALYST}),'api_key'),now=datetime.fromisoformat(sys.argv[3]))
"""
    result = subprocess.run([sys.executable, '-c', program, str(lab.root), point, lab.now.isoformat()],
                            capture_output=True, env=os.environ.copy(), timeout=30, check=False)
    assert result.returncode == 73
    resumed = lab.store.observe(message, lab.principal, now=lab.now)
    assert resumed['event_count'] == resumed['failed_login_events'] == 1
    assert resumed['duplicate'] == (point in {'after_db_commit', 'after_publish'})
    witness = json.loads((lab.store.control / 'witness.json').read_bytes())
    assert witness['state']['pending'] is None and witness['state']['current']['seq'] == 1
