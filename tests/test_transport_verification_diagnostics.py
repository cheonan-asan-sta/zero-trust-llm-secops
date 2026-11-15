import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts import transport_verification as v
from scripts.certificate_controller import LifecycleError
from scripts.test_transport_process_recovery import public_failure

IMAGE = 'sha256:' + 'a' * 64
GOOD = {'verified': True, 'epoch': 2, 'pending': False,
        'transport': {'schema': 'database-transport-preflight-1', 'verified': True}}


def call(monkeypatch, raw=None, code=0, **changes):
    def run(argv, **kwargs):
        assert argv[:2] == ['docker', 'run']
        assert '--name' in argv and '--label' in argv
        assert kwargs['timeout'] == 20 and kwargs['input'] == 'private-input-canary'
        return SimpleNamespace(returncode=code, stdout=raw if raw is not None else json.dumps(GOOD),
                               stderr='secret-stderr-canary')
    monkeypatch.setattr(v.subprocess, 'run', run)
    return v.verify(['docker', 'run', '--rm'], payload='private-input-canary',
                    epoch=2, pending=False, partial=False, image=IMAGE, **changes)


def test_valid_verification_receipt(monkeypatch):
    assert call(monkeypatch) == GOOD


@pytest.mark.parametrize('raw', ['{}', '[]', 'null', '{bad', '{"verified":true,"verified":true}',
    json.dumps(GOOD | {'epoch': True}), json.dumps(GOOD | {'epoch': 1}),
    json.dumps(GOOD | {'pending': 0}), json.dumps(GOOD | {'pending': True}),
    json.dumps(GOOD | {'verified': 1}), json.dumps(GOOD | {'transport': None}),
    json.dumps(GOOD | {'transport': {'verified': True}}),
    json.dumps(GOOD | {'transport': {'schema': 'database-transport-preflight-1', 'verified': 1}}),
    json.dumps(GOOD | {'unexpected': 'secret-canary'}), 'x' * 32769], ids=lambda raw: hashlib.sha256(raw.encode()).hexdigest()[:12])
def test_bad_success_receipts_fail_closed_without_echo(monkeypatch, raw):
    with pytest.raises(v.VerificationFailure) as caught:
        call(monkeypatch, raw)
    detail = public_failure(caught.value)
    assert detail['transport_verification']['reason'] == 'invalid_receipt'
    assert 'canary' not in json.dumps(detail) and 'stderr' not in json.dumps(detail)


@pytest.mark.parametrize('code', [1, 125, 137])
def test_child_failure_preserves_exit_without_claiming_oom(monkeypatch, code):
    with pytest.raises(v.VerificationFailure) as caught:
        call(monkeypatch, json.dumps({'verified': False, 'reason': 'transport_published_file_changed'}), code)
    d = caught.value.diagnostic
    assert d['cli_exit_code'] == code and d['child_reason'] == 'transport_published_file_changed'
    assert d['oom_killed'] is None and d['container_state_available'] is False


def test_exit_failure_cannot_be_overridden_by_success_json(monkeypatch):
    with pytest.raises(v.VerificationFailure, match='preflight_failed'):
        call(monkeypatch, code=1)


def test_untrusted_child_reason_is_not_reflected(monkeypatch):
    with pytest.raises(v.VerificationFailure) as caught:
        call(monkeypatch, '{"verified":false,"reason":"key-secret-canary"}', 1)
    assert caught.value.diagnostic['child_reason'] is None


@pytest.mark.parametrize('reason', [[], {}, 1, True, None])
def test_invalid_child_reason_types_remain_fixed_failure(monkeypatch, reason):
    with pytest.raises(v.VerificationFailure) as caught:
        call(monkeypatch, json.dumps({'verified': False, 'reason': reason}), 1)
    assert caught.value.diagnostic['child_reason'] is None


@pytest.mark.parametrize('error,expected', [
    (LifecycleError('transport_published_file_changed'), 'transport_published_file_changed'),
    (OSError('key-secret-canary'), 'transport_filesystem_failure'),
    (ValueError('key-secret-canary'), 'transport_invalid_input'),
    (RuntimeError('key-secret-canary'), 'transport_crypto_failure'),
])
def test_child_error_allowlist(error, expected):
    assert v.child_reason(error) == expected


@pytest.mark.parametrize('cleanup', [True, False])
def test_timeout_never_retries_and_reports_owned_cleanup(monkeypatch, cleanup):
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        raise subprocess.TimeoutExpired(argv, 20, output='key-secret-canary')
    monkeypatch.setattr(v.subprocess, 'run', run)
    monkeypatch.setattr(v, 'timeout_cleanup', lambda *args: cleanup)
    with pytest.raises(v.VerificationFailure) as caught:
        v.verify(['docker', 'run', '--rm'], payload='secret', epoch=0, pending=False, partial=False, image=IMAGE)
    assert len(calls) == 1 and caught.value.diagnostic['owned_helper_cleanup_confirmed'] is cleanup
    assert 'canary' not in json.dumps(public_failure(caught.value))


@pytest.mark.parametrize('change', ['name', 'image', 'token', 'user', 'network', 'readonly', 'caps', 'mount'])
def test_timeout_cleanup_never_removes_foreign_or_writable_helper(monkeypatch, change):
    value = {'Id': 'owned-id', 'Name': '/owned', 'Image': IMAGE,
        'Config': {'Labels': {'secops.transport.verify': 'token'}, 'User': '10001:10001'},
        'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL']},
        'Mounts': [{'RW': False}]}
    if change == 'name': value['Name'] = '/foreign'
    if change == 'image': value['Image'] = 'foreign'
    if change == 'token': value['Config']['Labels']['secops.transport.verify'] = 'foreign'
    if change == 'user': value['Config']['User'] = '0'
    if change == 'network': value['HostConfig']['NetworkMode'] = 'host'
    if change == 'readonly': value['HostConfig']['ReadonlyRootfs'] = False
    if change == 'caps': value['HostConfig']['CapDrop'] = []
    if change == 'mount': value['Mounts'] = [{'RW': True}]
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps([value]))
    monkeypatch.setattr(v.subprocess, 'run', run)
    assert v.timeout_cleanup('owned', 'token', IMAGE) is False
    assert calls == [['docker', 'inspect', 'owned']]


def test_daemon_query_failure_is_not_confirmed_cleanup(monkeypatch):
    monkeypatch.setattr(v.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=1, stdout=''))
    assert v.timeout_cleanup('owned', 'token', IMAGE) is False


def test_partial_stopped_receipt_requires_null_transport(monkeypatch):
    receipt = GOOD | {'pending': True, 'transport': None}
    monkeypatch.setattr(v.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(receipt)))
    assert v.verify(['docker', 'run', '--rm'], payload='{}', epoch=2, pending=True, partial=True, image=IMAGE) == receipt
    receipt['transport'] = GOOD['transport']
    with pytest.raises(v.VerificationFailure):
        v.verify(['docker', 'run', '--rm'], payload='{}', epoch=2, pending=True, partial=True, image=IMAGE)


def test_timeout_cleanup_removes_only_inspected_owned_id(monkeypatch):
    value = {'Id': 'owned-id', 'Name': '/owned', 'Image': IMAGE,
        'Config': {'Labels': {'secops.transport.verify': 'token'}, 'User': '10001:10001'},
        'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL']},
        'Mounts': [{'RW': False}]}
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps([value]) if argv[1] == 'inspect' else '')
    monkeypatch.setattr(v.subprocess, 'run', run)
    assert v.timeout_cleanup('owned', 'token', IMAGE) is True
    assert calls[-1] == ['docker', 'rm', '--force', 'owned-id']


def test_admission_preserves_existing_public_denial_and_typed_diagnostics(monkeypatch):
    from scripts.database_transport_runtime import TransportRuntime
    from scripts.persistent_authority_runtime import PersistentAuthorityRuntime
    monkeypatch.setattr(PersistentAuthorityRuntime, 'verify_authority_public_assets', lambda _: None)
    runtime = object.__new__(TransportRuntime)
    error = v.VerificationFailure('child_failed', exit_code=1, child='database_transport_private_file_required')
    def fail(operation):
        assert operation == 'verify'
        raise error
    monkeypatch.setattr(runtime, 'transport_job', fail)
    with pytest.raises(v.VerificationFailure) as caught:
        runtime.verify_authority_public_assets()
    assert caught.value is error and str(error) == 'database_transport_preflight_failed'
    assert public_failure(error)['transport_verification']['child_reason'] == 'database_transport_private_file_required'
