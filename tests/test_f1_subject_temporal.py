import base64
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
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
from scripts.f1_lab.detector import ShadowDetector
from scripts.f1_lab.resource_policy import PinnedResourcePolicies
from scripts.f1_lab.subject_temporal import (
    PinnedSubjectApprovalVerifier,
    SubjectApprovalVerifier,
    SubjectShadowDetector,
    SubjectTemporalStore,
)
from scripts.f1_lab.temporal import TemporalStore, TemporalUnavailable


@pytest.fixture
def lab(tmp_path):
    now = datetime.now(UTC)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    registry = {'sources': [{'source_id': 'events', 'tenant_id': tenant,
        'user_ids': ['user-a', 'user-b'], 'device_ids': ['device-a', 'device-b'], 'roles': ['employee'],
        'keys': [{'key_id': 'key-a', 'public_key_pem': public, 'not_before': (now-timedelta(hours=1)).isoformat(),
                  'not_after': (now+timedelta(days=1)).isoformat()}]} for tenant in ('tenant-a', 'tenant-b')]}
    path = tmp_path/'sources.json'
    def publish():
        path.write_text(json.dumps(registry), encoding='utf8')
    publish()
    principal = Principal('operator', 'tenant-a', frozenset({Role.ANALYST}), 'api_key')
    sources = {('tenant-a', 'events', 'key-a'), ('tenant-b', 'events', 'key-a')}
    store = SubjectTemporalStore(tmp_path/'events.db', tmp_path/'control', SignalVerifier(path), sources)
    store.initialize()
    original = DetectionBenchmark().cases[0].event.analysis_payload()
    def signal(ident='event-a', seconds=0, *, session='session-a', tenant='tenant-a', **changes):
        raw = json.loads(json.dumps(original))
        raw.update(event_id=ident, timestamp=(now+timedelta(seconds=seconds)).isoformat(), action='READ')
        raw['user'].update(user_id='user-a', role='employee', active=True)
        raw['device'].update(device_id='device-a', managed=True, security_posture='healthy')
        raw['resource'].update(resource_id='resource-a', required_role='employee', sensitivity='high')
        raw['auth_context'].update(authentication_result='success', failed_attempts=0, mfa='success')
        raw['network'].update(access_method='office', location_anomaly=False)
        raw['behavior'].update(download_volume_mb=0, distinct_resources_10m=1, unusual_time=False,
                               new_device=False, request_rate='normal')
        for field, value in changes.items():
            parts, target = field.split('.'), raw
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
        at = now+timedelta(seconds=seconds)
        message = SignedSessionSignal(tenant_id=tenant, source_id='events', key_id='key-a', issued_at=at,
            expires_at=at+timedelta(seconds=90), expected_version=0, session_id=session,
            event=SecurityEvent.model_validate(raw), signature='A'*86)
        return message.model_copy(update={'signature': base64.urlsafe_b64encode(key.sign(canonical_signal(message))).decode().rstrip('=')})
    return SimpleNamespace(root=tmp_path, now=now, key=key, store=store, principal=principal, signal=signal,
        registry=registry, publish=publish, registry_path=path, sources=sources)


def at(lab, seconds):
    return lab.now+timedelta(seconds=seconds)


def export(lab, count=3):
    messages = []
    for index in range(count):
        message = lab.signal('download-'+str(index), index, session='session-'+str(index), action='DOWNLOAD',
            **{'device.device_id': 'device-b' if index == 0 else 'device-a',
               'resource.resource_id': 'resource-'+str(index), 'behavior.download_volume_mb': 200})
        lab.store.observe(message, lab.principal, now=at(lab, index))
        messages.append(message)
    return messages


def approval(lab, message, *, devices=('device-a', 'device-b'), resources=None, maximum=600, evidence=None):
    key = Ed25519PrivateKey.generate()
    context = ApprovalContext(approval_id='approval-'+'d'*32, tenant_id='tenant-a', issuer_id='business', key_id='key',
        event_sha256=event_digest(message.event), user_id='user-a', device_id=message.event.device.device_id,
        resource_id=message.event.resource.resource_id, action=message.event.action, permitted_deviations=['bulk_export'],
        maximum_download_mb=maximum, issued_at=message.issued_at, expires_at=message.issued_at+timedelta(seconds=60),
        window_evidence_sha256=evidence)
    authority = Authority('tenant-a', 'business', 'key', key.public_key(), frozenset({'bulk_export'}),
        frozenset({'user-a'}), frozenset(devices), frozenset(resources or {'resource-0', 'resource-1', 'resource-2'}),
        frozenset({'DOWNLOAD'}), at(lab, -60), at(lab, 3600))
    return key, context, authority


def test_session_hopping_does_not_reset_subject_failed_login_count(lab):
    detector = SubjectShadowDetector(temporal_store=lab.store)
    for index in range(3):
        result = detector.evaluate_signed(lab.signal('failed-'+str(index), index, session='session-'+str(index),
            action='LOGIN', **{'auth_context.authentication_result': 'failure', 'auth_context.failed_attempts': 1}),
            lab.principal, now=at(lab, index))
        assert result['detected'] == (index == 2)
    assert result['temporal_evidence']['failed_login_events'] == 3
    assert 'REPEATED_SIGNED_FAILED_LOGIN_EVENTS' in result['reason_codes']
    assert not result['temporal_evidence']['complete'] and result['temporal_evidence']['subject_evidence_complete']


def test_split_exports_across_sessions_and_devices_are_real_deltas(lab):
    message = export(lab)[-1]
    result = SubjectShadowDetector(temporal_store=lab.store).evaluate_signed(message, lab.principal, now=at(lab, 2))
    window = result['temporal_evidence']
    assert window['sensitive_download_mb'] == 600 and window['event_count'] == 3 and window['duplicate']
    assert window['device_ids'] == ['device-a', 'device-b']
    assert 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' in result['reason_codes']
    assert result['access_grants'] == result['session_changes'] == result['external_calls'] == 0


def test_resource_fanout_uses_distinct_resources_across_sessions(lab):
    detector = SubjectShadowDetector(temporal_store=lab.store)
    for index in range(8):
        result = detector.evaluate_signed(lab.signal('read-'+str(index), index, session='session-'+str(index),
            **{'resource.resource_id': 'resource-'+str(index)}), lab.principal, now=at(lab, index))
        assert result['detected'] == (index == 7)
    assert result['temporal_evidence']['distinct_resources'] == 8


@pytest.mark.parametrize('foreign', ['tenant', 'operator', 'user'])
def test_activity_does_not_cross_its_tenant_analyst_user_scope(lab, foreign):
    principal, kwargs = lab.principal, {}
    if foreign == 'tenant':
        principal = replace(principal, tenant_id='tenant-b')
        kwargs['tenant'] = 'tenant-b'
    elif foreign == 'operator':
        principal = replace(principal, subject='other-operator')
    else:
        kwargs['user.user_id'] = 'user-b'
    lab.store.observe(lab.signal('private-event', session='private-session', action='DOWNLOAD',
        **{'resource.resource_id': 'private-resource', 'behavior.download_volume_mb': 900, **kwargs}), principal, now=lab.now)
    result = SubjectShadowDetector(temporal_store=lab.store).evaluate_signed(lab.signal('current', 1), lab.principal, now=at(lab, 1))
    assert not result['detected'] and result['temporal_evidence']['event_count'] == 1
    assert all(value not in json.dumps(result) for value in ('private-event', 'private-session', 'private-resource', 'other-operator'))


@pytest.mark.parametrize('scope', ['device', 'resource', 'quota', 'event-only'])
def test_partial_authority_or_event_only_approval_cannot_suppress_wider_export(lab, scope):
    message = export(lab)[-1]
    window = lab.store.summary(message.session_id, lab.principal, now=at(lab, 2))
    args = {'evidence': window['evidence_sha256']}
    if scope == 'device':
        args['devices'] = ('device-a',)
    elif scope == 'resource':
        args['resources'] = {'resource-2'}
    elif scope == 'quota':
        args['maximum'] = 200
    else:
        args['evidence'] = None
    key, context, authority = approval(lab, message, **args)
    result = SubjectShadowDetector(temporal_store=lab.store, approval_verifier=SubjectApprovalVerifier((authority,))).evaluate_signed(
        message, lab.principal, approval=sign(context, key), now=at(lab, 2))
    assert result['signed_context_status'] == 'verified'
    assert result['signed_window_context_status'] == ('absent' if scope == 'event-only' else 'rejected')
    assert 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' in result['reason_codes']


def test_full_device_resource_and_exact_fact_set_approval_covers_only_the_observed_job(lab):
    message = export(lab)[-1]
    window = lab.store.summary(message.session_id, lab.principal, now=at(lab, 2))
    key, context, authority = approval(lab, message, evidence=window['evidence_sha256'])
    detector = SubjectShadowDetector(temporal_store=lab.store, approval_verifier=SubjectApprovalVerifier((authority,)))
    result = detector.evaluate_signed(message, lab.principal, approval=sign(context, key), now=at(lab, 2))
    assert not result['detected'] and result['signed_window_context_status'] == 'verified'
    lab.store.observe(lab.signal('new-fact', 3, session='new-session'), lab.principal, now=at(lab, 3))
    result = detector.evaluate_signed(message, lab.principal, approval=sign(context, key), now=at(lab, 3))
    assert result['signed_window_context_status'] == 'rejected' and result['detected']


def test_legacy_detector_and_legacy_verifier_fail_closed_on_subject_summary(lab):
    message = export(lab)[-1]
    window = lab.store.summary(message.session_id, lab.principal, now=at(lab, 2))
    key, context, authority = approval(lab, message, devices=('device-a',), evidence=window['evidence_sha256'])
    result = ShadowDetector(temporal_store=lab.store, approval_verifier=ApprovalVerifier((authority,))).evaluate_signed(
        message, lab.principal, approval=sign(context, key), now=at(lab, 2))
    assert result['signed_window_context_status'] == 'rejected'
    assert 'TEMPORAL_AUTHORITY_OR_EVIDENCE_INCOMPLETE' in result['reason_codes']
    assert 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' in result['reason_codes']


def test_subject_detector_rejects_legacy_store_verifier_and_raw_event_path(lab):
    legacy = TemporalStore(lab.root/'unused.db', lab.root/'unused-control', lab.store.verifier, lab.sources)
    with pytest.raises(TypeError, match='subject_temporal_store_required'):
        SubjectShadowDetector(temporal_store=legacy)
    with pytest.raises(TypeError, match='subject_approval_verifier_required'):
        SubjectShadowDetector(temporal_store=lab.store, approval_verifier=ApprovalVerifier(()))
    with pytest.raises(ValueError, match='authenticated_received_events'):
        SubjectShadowDetector(temporal_store=lab.store).evaluate(lab.signal().event, 'tenant-a')


def test_reopening_with_base_scope_cannot_silently_reinterpret_the_same_journal(lab):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    base = TemporalStore(lab.store.database, lab.store.control, lab.store.verifier, lab.sources)
    with pytest.raises(TemporalUnavailable, match='witness_head'):
        base.summary('session-a', lab.principal, now=lab.now)
    reopened = SubjectTemporalStore(lab.store.database, lab.store.control, lab.store.verifier, lab.sources)
    assert reopened.summary('session-a', lab.principal, now=lab.now)['event_count'] == 1


def test_subject_window_expires_and_read_clock_cannot_rewind_after_restart(lab):
    export(lab)
    assert lab.store.summary('session-2', lab.principal, now=at(lab, 599))['event_count'] == 3
    result = lab.store.summary('session-2', lab.principal, now=at(lab, 602))
    assert result['event_count'] == 0 and not result['subject_evidence_complete']
    reopened = SubjectTemporalStore(lab.store.database, lab.store.control, lab.store.verifier, lab.sources)
    with pytest.raises(TemporalUnavailable, match='clock_rollback'):
        reopened.summary('session-2', lab.principal, now=at(lab, 601))


def test_changed_source_authority_cannot_turn_prior_subject_history_into_healthy_evidence(lab):
    export(lab)
    lab.registry['sources'][0]['device_ids'].append('device-c')
    lab.publish()
    result = lab.store.summary('session-2', lab.principal, now=at(lab, 3))
    assert not result['subject_evidence_complete'] and result['authority_excluded_events'] == 3
    assert result['event_count'] == 0 and not result['collection_completeness_proven']


def test_other_operator_adverse_state_on_a_subject_device_is_derived_without_raw_ids(lab):
    export(lab)
    other = replace(lab.principal, subject='private-operator')
    lab.store.observe(lab.signal('private-event', 3, session='private-session', **{
        'user.user_id': 'user-b', 'device.device_id': 'device-b', 'device.security_posture': 'compromised',
        'resource.resource_id': 'private-resource'}), other, now=at(lab, 3))
    result = SubjectShadowDetector(temporal_store=lab.store).evaluate_signed(lab.signal('current', 4), lab.principal, now=at(lab, 4))
    assert 'RECENT_COMPROMISED_DEVICE' in result['reason_codes']
    assert result['temporal_evidence']['event_count'] == 4
    assert all(value not in json.dumps(result) for value in ('private-event', 'private-session', 'private-resource', 'private-operator'))


def test_policy_is_read_once_and_policy_loss_keeps_subject_download_deltas(lab, monkeypatch):
    body = {'schema_version': 'f1-resource-policies-1', 'version': 1,
        'issued_at': at(lab, -60).isoformat(), 'expires_at': at(lab, 3600).isoformat(),
        'resources': [{'tenant_id': 'tenant-a', 'resource_id': 'resource-'+str(i), 'sensitivity': 'critical',
            'permissions': [{'action': 'DOWNLOAD', 'roles': ['employee']}]} for i in range(3)]}
    path = lab.root/'policies.json'
    path.write_bytes(json.dumps(body).encode())
    policy = PinnedResourcePolicies(path, hashlib.sha256(path.read_bytes()).hexdigest(), minimum_version=1)
    lab.store = SubjectTemporalStore(lab.root/'policies.db', lab.root/'policy-control', lab.store.verifier,
                                     lab.sources, resource_policies=policy)
    lab.store.initialize()
    export(lab)
    calls, original = [], policy.snapshot
    def counted(**kwargs):
        calls.append(1)
        return original(**kwargs)
    monkeypatch.setattr(policy, 'snapshot', counted)
    assert lab.store.summary('session-2', lab.principal, now=at(lab, 2))['sensitive_download_mb'] == 600
    assert len(calls) == 1
    path.write_bytes(b'changed')
    result = lab.store.summary('session-2', lab.principal, now=at(lab, 3))
    assert result['sensitive_download_mb'] == 600 and result['resource_policy_unavailable_events'] == 3
    assert not result['subject_evidence_complete']


def test_pinned_subject_registry_refreshes_revocation_and_keeps_wider_device_scope(lab):
    message = export(lab)[-1]
    window = lab.store.summary(message.session_id, lab.principal, now=at(lab, 2))
    key, context, authority = approval(lab, message, evidence=window['evidence_sha256'])
    row = {'tenant_id': authority.tenant_id, 'issuer_id': authority.issuer_id, 'key_id': authority.key_id,
        'public_key_pem': authority.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        'allowed_deviations': sorted(authority.allowed_deviations), 'user_ids': sorted(authority.user_ids),
        'device_ids': sorted(authority.device_ids), 'resource_ids': sorted(authority.resource_ids), 'actions': sorted(authority.actions),
        'key_not_before': authority.key_not_before.isoformat(), 'key_not_after': authority.key_not_after.isoformat()}
    path = lab.root/'approvals.json'
    raw = json.dumps({'schema_version': 'zt-business-authorities-1', 'version': 1, 'authorities': [row]}).encode()
    path.write_bytes(raw)
    verifier = PinnedSubjectApprovalVerifier(path, hashlib.sha256(raw).hexdigest(), minimum_version=1)
    detector = SubjectShadowDetector(temporal_store=lab.store, approval_verifier=verifier)
    assert not detector.evaluate_signed(message, lab.principal, approval=sign(context, key), now=at(lab, 2))['detected']
    # External pin makes a changed registry unavailable, never a cached allow.
    path.write_bytes(b'changed')
    with pytest.raises(ValueError, match='registry_unavailable'):
        detector.evaluate_signed(message, lab.principal, approval=sign(context, key), now=at(lab, 3))


@pytest.mark.parametrize('danger,reason', [
    ({'user.active': False}, 'RECENT_INACTIVE_IDENTITY'),
    ({'device.security_posture': 'at_risk'}, 'RECENT_AT_RISK_DEVICE'),
    ({'device.security_posture': 'compromised'}, 'RECENT_COMPROMISED_DEVICE'),
    ({'auth_context.mfa': 'failed', 'auth_context.authentication_result': 'failure',
      'auth_context.failed_attempts': 1}, 'RECENT_REJECTED_MFA'),
])
def test_subject_window_approval_never_suppresses_received_hard_danger(lab, danger, reason):
    lab.store.observe(lab.signal('danger', session='danger-session', **danger), lab.principal, now=lab.now)
    message = lab.signal('job', 1, session='job-session', action='DOWNLOAD', **{'behavior.download_volume_mb': 600})
    window = lab.store.observe(message, lab.principal, now=at(lab, 1))
    key, context, authority = approval(lab, message, resources={'resource-a'}, evidence=window['evidence_sha256'])
    authority = replace(authority, actions=frozenset({'READ', 'DOWNLOAD'}))
    result = SubjectShadowDetector(temporal_store=lab.store, approval_verifier=SubjectApprovalVerifier((authority,))).evaluate_signed(
        message, lab.principal, approval=sign(context, key), now=at(lab, 1))
    assert result['signed_window_context_status'] == 'verified'
    assert result['detected'] and reason in result['reason_codes']
    assert 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' not in result['reason_codes']


def test_valid_all_action_approval_cannot_override_a_resource_owner_deny(lab):
    body = {'schema_version': 'f1-resource-policies-1', 'version': 1,
        'issued_at': at(lab, -60).isoformat(), 'expires_at': at(lab, 3600).isoformat(),
        'resources': [{'tenant_id': 'tenant-a', 'resource_id': 'resource-a', 'sensitivity': 'critical',
            'permissions': [{'action': 'DOWNLOAD', 'roles': ['employee']}, {'action': 'ADMIN', 'roles': ['administrator']}]}]}
    path = lab.root/'deny-policy.json'
    path.write_bytes(json.dumps(body).encode())
    policy = PinnedResourcePolicies(path, hashlib.sha256(path.read_bytes()).hexdigest(), minimum_version=1)
    store = SubjectTemporalStore(lab.root/'deny.db', lab.root/'deny-control', lab.store.verifier,
                                 lab.sources, resource_policies=policy)
    store.initialize()
    store.observe(lab.signal('denied', session='denied-session', action='ADMIN'), lab.principal, now=lab.now)
    message = lab.signal('job', 1, session='job-session', action='DOWNLOAD', **{'behavior.download_volume_mb': 600})
    window = store.observe(message, lab.principal, now=at(lab, 1))
    key, context, authority = approval(lab, message, resources={'resource-a'}, evidence=window['evidence_sha256'])
    authority = replace(authority, actions=frozenset({'DOWNLOAD', 'ADMIN'}))
    result = SubjectShadowDetector(temporal_store=store, approval_verifier=SubjectApprovalVerifier((authority,))).evaluate_signed(
        message, lab.principal, approval=sign(context, key), now=at(lab, 1))
    assert result['signed_window_context_status'] == 'verified'
    assert 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' not in result['reason_codes']
    assert 'RECENT_RESOURCE_POLICY_DENIED' in result['reason_codes']


def test_same_tenant_event_identity_cannot_move_to_another_session_or_be_counted_twice(lab):
    original = lab.signal('unique', session='first-session', action='DOWNLOAD', **{'behavior.download_volume_mb': 200})
    first = lab.store.observe(original, lab.principal, now=lab.now)
    repeated = lab.store.observe(original, lab.principal, now=lab.now)
    assert first['event_count'] == repeated['event_count'] == 1 and repeated['duplicate']
    with pytest.raises(TemporalUnavailable, match='event_identity_conflict'):
        lab.store.observe(lab.signal('unique', session='new-session', action='DOWNLOAD',
            **{'behavior.download_volume_mb': 200}), lab.principal, now=lab.now)


@pytest.mark.parametrize('changed', ['user.user_id', 'device.device_id'])
def test_broader_activity_scope_does_not_relax_single_session_binding(lab, changed):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    with pytest.raises(TemporalUnavailable, match='session_binding'):
        lab.store.observe(lab.signal('changed', 1, **{changed: 'user-b' if changed.startswith('user') else 'device-b'}),
                          lab.principal, now=at(lab, 1))


def test_unrelated_subject_journal_growth_does_not_invalidate_an_exact_owned_fact_set(lab):
    message = export(lab)[-1]
    window = lab.store.summary(message.session_id, lab.principal, now=at(lab, 2))
    key, context, authority = approval(lab, message, evidence=window['evidence_sha256'])
    lab.store.observe(lab.signal('other-user-event', 3, session='other-user-session', **{
        'user.user_id': 'user-b', 'device.device_id': 'device-b'}), lab.principal, now=at(lab, 3))
    result = SubjectShadowDetector(temporal_store=lab.store, approval_verifier=SubjectApprovalVerifier((authority,))).evaluate_signed(
        message, lab.principal, approval=sign(context, key), now=at(lab, 3))
    assert not result['detected'] and result['signed_window_context_status'] == 'verified'
    assert result['temporal_evidence']['evidence_sha256'] == window['evidence_sha256']
    assert result['temporal_evidence']['journal_head_sha256'] != window['journal_head_sha256']


def test_current_approval_revocation_stops_suppressing_a_subject_export(lab):
    message = export(lab)[-1]
    window = lab.store.summary(message.session_id, lab.principal, now=at(lab, 2))
    key, context, authority = approval(lab, message, evidence=window['evidence_sha256'])
    verifier = SubjectApprovalVerifier((authority,), revoked_approval_ids={context.approval_id})
    result = SubjectShadowDetector(temporal_store=lab.store, approval_verifier=verifier).evaluate_signed(
        message, lab.principal, approval=sign(context, key), now=at(lab, 2))
    assert result['detected'] and result['signed_context_status'] == 'rejected'
    assert result['context_error'] == 'approval_revoked'


@pytest.mark.parametrize('point', ['after_prepare', 'before_db_commit', 'after_db_commit', 'after_publish'])
def test_subject_scope_survives_actual_worker_exit_and_exact_retry(lab, point):
    export(lab, count=2)
    message = lab.signal('third-download', 2, session='third-session', action='DOWNLOAD',
                         **{'behavior.download_volume_mb': 200})
    (lab.root/'input.json').write_text(message.model_dump_json(), encoding='utf8')
    program = """import os,sys
from datetime import datetime
from pathlib import Path
from app.security import Principal,Role
from app.services.trusted_signals import SignalVerifier
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.subject_temporal import SubjectTemporalStore
root=Path(sys.argv[1])
store=SubjectTemporalStore(root/'events.db',root/'control',SignalVerifier(root/'sources.json'),
    {('tenant-a','events','key-a'),('tenant-b','events','key-a')})
def fault(name):
    if name==sys.argv[2]: os._exit(73)
store._phase=fault
store.observe(SignedSessionSignal.model_validate_json((root/'input.json').read_bytes()),
    Principal('operator','tenant-a',frozenset({Role.ANALYST}),'api_key'),now=datetime.fromisoformat(sys.argv[3]))
"""
    process = subprocess.run([sys.executable, '-c', program, str(lab.root), point, at(lab, 2).isoformat()],
                             capture_output=True, env=os.environ.copy(), timeout=30, check=False)
    assert process.returncode == 73
    result = SubjectShadowDetector(temporal_store=lab.store).evaluate_signed(message, lab.principal, now=at(lab, 2))
    window = result['temporal_evidence']
    assert window['event_count'] == 3 and window['sensitive_download_mb'] == 600
    assert window['duplicate'] == (point in {'after_db_commit', 'after_publish'})
    assert 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD' in result['reason_codes']
    witness = json.loads((lab.store.control/'witness.json').read_bytes())
    assert witness['state']['pending'] is None and witness['state']['current']['seq'] == 3


def test_concurrent_different_session_deltas_and_exact_retries_have_one_global_count(lab):
    messages = [lab.signal('parallel-'+str(index), session='session-'+str(index), action='DOWNLOAD',
                          **{'behavior.download_volume_mb': 100}) for index in range(6)]
    def receive(message):
        return lab.store.observe(message, lab.principal, now=lab.now)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(receive, messages*2))
    assert sum(not result['duplicate'] for result in results) == 6
    summary = lab.store.summary('session-0', lab.principal, now=lab.now)
    assert summary['event_count'] == 6 and summary['sensitive_download_mb'] == 600


@pytest.mark.parametrize('change', ['operator', 'tenant', 'viewer', 'disabled'])
def test_broader_window_is_not_readable_by_an_unauthorized_principal(lab, change):
    lab.store.observe(lab.signal(), lab.principal, now=lab.now)
    changes = {'operator': {'subject': 'other-operator'}, 'tenant': {'tenant_id': 'tenant-b'},
               'viewer': {'roles': frozenset({Role.VIEWER})}, 'disabled': {'auth_method': 'disabled'}}
    principal = replace(lab.principal, **changes[change])
    with pytest.raises(TemporalUnavailable):
        lab.store.summary('session-a', principal, now=lab.now)


def test_no_new_event_is_accepted_when_the_subject_journal_reaches_its_declared_capacity(lab):
    store = SubjectTemporalStore(lab.root/'bounded.db', lab.root/'bounded-control', lab.store.verifier,
                                 lab.sources, capacity=1)
    store.initialize()
    store.observe(lab.signal(), lab.principal, now=lab.now)
    with pytest.raises(TemporalUnavailable, match='capacity'):
        store.observe(lab.signal('other', 1, session='other-session'), lab.principal, now=at(lab, 1))
    assert store.summary('session-a', lab.principal, now=at(lab, 1))['event_count'] == 1
