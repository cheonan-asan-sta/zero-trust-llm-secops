import base64
import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts import collect_pam_journal as collector
from scripts.f1_lab import pam_journal as pam
from scripts.f1_lab.collector_freshness import CollectorScope, runtime_authority
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry, ServiceProof
from scripts.run_shared_execution_controls import setup
from tests.test_shared_execution_evidence import bundle


@pytest.fixture
def configured(tmp_path):
    keys, registry, _ = setup(tmp_path/'trust')
    auth_key = Ed25519PrivateKey.generate()
    public = base64.urlsafe_b64encode(auth_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')
    selected = registry.authorities[0].model_copy(update={'kind': 'authentication', 'mode': 'systemd',
        'source_id': 'local-auth-journal', 'key_id': 'auth-1', 'public_key': public})
    registry = registry.model_copy(update={'authorities': [*registry.authorities, selected]})
    path = tmp_path/'trust/registry.json'
    path.write_bytes(canonical(registry.model_dump(mode='json')))
    pinned = PinnedServiceRegistry(path, hashlib.sha256(path.read_bytes()).hexdigest())
    scope = CollectorScope(tenant_id='local-lab', server_id='shared-lab', unit='shared-fixture.service',
                           source_id='local-auth-journal', key_id='auth-1')
    now = datetime.now(UTC)
    return SimpleNamespace(key=auth_key, keys=keys, registry=registry, pinned=pinned, scope=scope,
        now=now, boot='1'*32, invocation='2'*32, path=path)


def row(f, index=1, *, close=False, **updates):
    result = {'MESSAGE': ('pam_unix(sudo:session): session closed for user root' if close else
        'pam_unix(sudo:session): session opened for user root(uid=0) by (uid=0)'),
        '_PID': '42', '_UID': '0', '_GID': '0', '_EXE': '/usr/bin/sudo', '_COMM': 'sudo',
        '_TRANSPORT': 'syslog', '_BOOT_ID': f.boot, '_SYSTEMD_UNIT': f.scope.unit,
        '_SYSTEMD_INVOCATION_ID': f.invocation, '__CURSOR': 's=fixture;i='+str(index),
        '__REALTIME_TIMESTAMP': str(pam.micros(f.now)-2000000+index*100000),
        '__MONOTONIC_TIMESTAMP': str(1000000+index*100000)}
    result.update(updates)
    return canonical(result)


def build(f, rows=None, **kwargs):
    args = {'boot': f.boot, 'invocation': f.invocation, 'window_start_us': pam.micros(f.now)-5000000,
            'window_end_us': pam.micros(f.now), 'now': f.now}
    args.update(kwargs)
    return pam.build([row(f), row(f, 2, close=True)] if rows is None else rows,
                     f.scope, f.pinned, f.key, **args)


def verify(f, capture, **kwargs):
    args = {'boot': f.boot, 'invocation': f.invocation, 'now': f.now}
    args.update(kwargs)
    return pam.verify(capture, f.scope, f.pinned, **args)


def test_valid_capture_keeps_original_times_reported_pid_and_unknown_human_without_pairing(configured):
    f = configured
    capture = build(f)
    assert verify(f, capture) == capture
    assert len(capture.records) == 2 and capture.journal_rows_seen == 2
    assert capture.records[0].reported_process_id == capture.records[1].reported_process_id == 42
    assert capture.records[0].audit_login_uid is capture.records[0].audit_session_id is None
    assert capture.records[0].reported_opener_account_sha256 is None
    assert capture.records[0].reported_target_uid == 0
    assert capture.records[1].reported_opener_uid is None
    assert not capture.human_authenticated and not capture.process_lifetime_identity_verified
    assert not capture.authorization_asserted and not capture.automatic_enforcement_allowed
    assert capture.records[0].recorded_at_us < capture.records[1].recorded_at_us < pam.micros(f.now)
    with pytest.raises(ValueError):
        ServiceProof.model_validate(capture.model_dump(mode='json'))


def test_legacy_pam_and_unset_kernel_audit_values_stay_explicitly_unknown(configured):
    f = configured
    capture = build(f, [row(f, MESSAGE='pam_unix(sudo:session): session opened for user root by (uid=0)',
                            _AUDIT_LOGINUID='4294967295', _AUDIT_SESSION='4294967295')])
    assert capture.records[0].reported_target_uid is None
    assert capture.records[0].audit_login_uid is capture.records[0].audit_session_id is None
    assert verify(f, capture)


@pytest.mark.parametrize('field,value', [('_TRANSPORT', 'stdout'), ('_COMM', 'logger'),
    ('_EXE', '/tmp/sudo'), ('_EXE', None), ('_SYSTEMD_UNIT', 'other.service'),
    ('_SYSTEMD_INVOCATION_ID', '3'*32), ('_BOOT_ID', '4'*32)])
def test_syslog_tag_or_claimed_pid_never_replaces_actual_journal_origin(configured, field, value):
    f = configured
    capture = build(f, [row(f, **{field: value, 'SYSLOG_IDENTIFIER': 'sudo', 'SYSLOG_PID': '42'})])
    assert not capture.records and capture.rejections.untrusted_pam == 1
    assert verify(f, capture) and not capture.human_authenticated


@pytest.mark.parametrize('field,value', [('_PID', None), ('_PID', '0'), ('_PID', True),
    ('_UID', '4294967295'), ('_GID', -1), ('_AUDIT_LOGINUID', 'invalid'),
    ('__MONOTONIC_TIMESTAMP', '0'), ('MESSAGE', 'pam_unix(sudo:session): incomplete'),
    ('MESSAGE', 'pam_unix(sudo:session): session opened for user root(uid=getpwnam error) by (uid=0)')])
def test_incomplete_metadata_is_counted_unavailable_and_never_becomes_normal_or_authenticated(configured, field, value):
    f = configured
    capture = build(f, [row(f, **{field: value})])
    assert not capture.records and capture.rejections.unavailable_pam == 1
    assert capture.journal_rows_seen == 1 and not capture.authorization_asserted


def test_raw_messages_arguments_and_reported_account_plaintext_are_not_in_capture(configured):
    f = configured
    message = 'pam_unix(sudo:session): session opened for user private-user by private-caller(uid=1000)'
    capture = build(f, [row(f, MESSAGE=message, _CMDLINE='DO_NOT_PERSIST_ARGUMENT_CANARY')])
    raw = canonical(capture.model_dump(mode='json'))
    for value in (message.encode(), b'private-user', b'private-caller', b'DO_NOT_PERSIST_ARGUMENT_CANARY'):
        assert value not in raw
    assert capture.records[0].reported_opener_uid == 1000


@pytest.mark.parametrize('flag', ['human_authenticated', 'authorization_asserted',
    'automatic_enforcement_allowed', 'process_lifetime_identity_verified'])
@pytest.mark.parametrize('value', [True, 0, 'false'])
def test_fixed_false_flags_reject_coercion_and_authority_invention(configured, flag, value):
    f = configured
    payload = build(f).model_dump(mode='json')
    payload[flag] = value
    with pytest.raises(ValueError):
        pam.PamCapture.model_validate(payload)


@pytest.mark.parametrize('mutation', ['duplicate_cursor', 'backward_time', 'backward_monotonic',
                                    'future_record', 'outside_window', 'over_limit'])
def test_population_time_and_cursor_ambiguity_never_creates_a_partial_valid_capture(configured, mutation):
    f = configured
    records = [row(f), row(f, 2, close=True)]
    if mutation == 'duplicate_cursor':
        records[1] = row(f, 1, close=True)
    elif mutation == 'backward_time':
        records[1] = row(f, 2, close=True, __REALTIME_TIMESTAMP=str(pam.micros(f.now)-3000000))
    elif mutation == 'backward_monotonic':
        records[1] = row(f, 2, close=True, __MONOTONIC_TIMESTAMP='1')
    elif mutation == 'future_record':
        records[1] = row(f, 2, close=True, __REALTIME_TIMESTAMP=str(pam.micros(f.now)+1))
    elif mutation == 'outside_window':
        records[1] = row(f, 2, close=True, __REALTIME_TIMESTAMP=str(pam.micros(f.now)-6000000))
    else:
        records = [row(f, i) for i in range(1, 1002)]
    with pytest.raises(ValueError):
        build(f, records)


def test_duplicate_json_keys_and_partial_json_are_rejected(configured):
    f = configured
    for raw in (b'{"MESSAGE":"x","MESSAGE":"y"}', b'{"MESSAGE":'):
        with pytest.raises(ValueError):
            build(f, [raw])


def test_runtime_or_authorization_key_cannot_issue_authentication_capture(configured):
    f = configured
    for kind in ('runtime', 'authorization'):
        with pytest.raises(ValueError):
            pam.build([row(f)], f.scope, f.pinned, f.keys[kind], boot=f.boot, invocation=f.invocation,
                window_start_us=pam.micros(f.now)-5000000, window_end_us=pam.micros(f.now), now=f.now)
    with pytest.raises(ValueError):
        runtime_authority(f.pinned.current(f.now), f.scope, f.now)


def test_authentication_key_cannot_forge_existing_runtime_or_policy_proof(tmp_path):
    keys, registry, pinned, event, proofs, joiner, now = bundle(tmp_path)
    registry = registry.model_copy(update={'authorities': [
        a.model_copy(update={'kind': 'authentication'}) if a.kind == 'runtime' else a
        for a in registry.authorities]})
    pinned.path.write_bytes(canonical(registry.model_dump(mode='json')))
    pin = PinnedServiceRegistry(pinned.path, hashlib.sha256(pinned.path.read_bytes()).hexdigest())
    joiner.registry = pin
    forged = runtime_proof(event, proofs[0].observation, keys['runtime'],
        source_id='local-proc', key_id='proc-1', observed_at=now)
    assert joiner.check(event, [forged, proofs[1]], now=now).state == 'unavailable'


@pytest.mark.parametrize('mutation', ['tampered_record', 'wrong_scope', 'wrong_boot', 'wrong_invocation',
                                    'expired', 'changed_pin', 'numeric_time'])
def test_current_trust_signature_scope_and_expiry_are_required(configured, mutation):
    f = configured
    capture = build(f)
    kwargs = {}
    if mutation == 'tampered_record':
        capture.records[0].sender_uid = 123
    elif mutation == 'wrong_scope':
        capture.scope.server_id = 'other'
        f.scope = f.scope.model_copy(update={'server_id': 'shared-lab'})
    elif mutation == 'wrong_boot':
        kwargs['boot'] = '3'*32
    elif mutation == 'wrong_invocation':
        kwargs['invocation'] = '3'*32
    elif mutation == 'expired':
        kwargs['now'] = f.now+timedelta(seconds=60)
    elif mutation == 'changed_pin':
        f.path.write_bytes(f.path.read_bytes()+b' ')
    else:
        capture = capture.model_copy(update={'issued_at': 1})
    with pytest.raises(ValueError):
        verify(f, capture, **kwargs)


def test_registry_changed_while_reading_cannot_be_sealed(configured):
    f = configured

    def records():
        yield row(f)
        f.path.write_bytes(f.path.read_bytes()+b' ')

    with pytest.raises(ValueError):
        build(f, records())


def test_collection_rechecks_invocation_and_fails_before_source_read_for_wrong_key(configured, monkeypatch):
    f = configured
    reads = []
    states = iter([(f.boot, f.invocation), (f.boot, '3'*32)])
    monkeypatch.setattr(collector, 'unit_invocation', lambda _: next(states))
    monkeypatch.setattr(collector, 'journal_rows', lambda *_: reads.append(True) or [row(f)])
    with pytest.raises(ValueError):
        collector.collect(f.scope, f.pinned, f.key, clock=lambda: f.now)
    assert reads == [True]
    reads.clear()
    with pytest.raises(ValueError):
        collector.collect(f.scope, f.pinned, f.keys['runtime'], clock=lambda: f.now)
    assert reads == []


def test_real_clock_verification_rechecks_expiry_after_signature_work(configured, monkeypatch):
    f = configured
    capture = build(f)
    sequence = iter([f.now, f.now+timedelta(seconds=61)])

    monkeypatch.setattr(pam, 'now_utc', lambda: next(sequence))
    with pytest.raises(ValueError):
        pam.verify(capture, f.scope, f.pinned, boot=f.boot, invocation=f.invocation)
