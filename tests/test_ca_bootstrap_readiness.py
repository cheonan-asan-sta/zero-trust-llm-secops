"""CA readiness ordering and paired controls that cannot hide replay DB loss."""

import json
import ssl
import subprocess
from types import SimpleNamespace

import jwt
import pytest

from scripts import authority_mtls_runtime as runtime
from scripts import authority_runtime_assets as assets
from scripts import test_authority_mtls_runtime as acceptance


@pytest.mark.parametrize('status,body,date,healthy', [
    (200, b'{"status":"ok"}', 'Fri, 06 Nov 2026 00:00:00 GMT', True),
    (503, b'{"status":"ok"}', 'Fri, 06 Nov 2026 00:00:00 GMT', False),
    (200, b'{"status":"starting"}', 'Fri, 06 Nov 2026 00:00:00 GMT', False),
    (200, b'{"status":"ok","extra":true}', 'Fri, 06 Nov 2026 00:00:00 GMT', False),
    (200, b'x' * 1025, 'Fri, 06 Nov 2026 00:00:00 GMT', False),
    (200, b'not-json', 'Fri, 06 Nov 2026 00:00:00 GMT', False),
    (200, b'{"status":"ok"}', '', False),
    (200, b'{"status":"ok"}', 'Fri, 06 Nov 2026 00:00:00', False),
    (200, b'{"status":"ok"}', 'Fri, 06 Nov 2026 09:00:00 +0900', False),
    (200, b'{"status":"ok"}', 'Thu, 05 Nov 2026 23:59:54 GMT', False),
    (200, b'{"status":"ok"}', 'Fri, 06 Nov 2026 00:00:06 GMT', False),
])
def test_tls_health_is_bounded_and_requires_ca_clock(monkeypatch, status, body, date, healthy):
    context = SimpleNamespace(minimum_version=None)
    seen = []

    def root_context(*, cafile):
        assert cafile == '/ca/root.pem'
        return context

    class Connection:
        def __init__(self, host, port, **options):
            assert (host, port) == ('ca', 9000)
            assert options == {'context': context, 'timeout': 2}

        def request(self, method, path):
            assert (method, path) == ('GET', '/health')

        def getresponse(self):
            def read(limit):
                assert limit == 1025
                return body
            return SimpleNamespace(status=status, read=read, getheader=lambda name: date)

        def close(self):
            seen.append('closed')

    monkeypatch.setattr(assets.ssl, 'create_default_context', root_context)
    monkeypatch.setattr(assets.http.client, 'HTTPSConnection', Connection)
    monkeypatch.setattr(assets.time, 'time', lambda: 1793923200)
    result = assets.ca_health()
    assert result == ({'healthy': True, 'server_time': 1793923200} if healthy else {'healthy': False})
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2 and seen == ['closed']


def test_tls_verification_failure_never_becomes_readiness(monkeypatch):
    def fail(**options):
        raise ssl.SSLCertVerificationError('synthetic-private-detail')
    monkeypatch.setattr(assets.ssl, 'create_default_context', fail)
    assert assets.ca_health() == {'healthy': False}


@pytest.mark.parametrize('unavailable', [False, True])
@pytest.mark.parametrize('transient', [runtime.RuntimeFailure('transient'),
                                     subprocess.TimeoutExpired(['synthetic-health'], 5)])
def test_grants_only_created_after_authenticated_readiness(monkeypatch, unavailable, transient):
    value = runtime.AuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-ca-readiness')
    value.state = {}
    value._bootstrap_provisioners = {'collector-clientAuth': ('entry', 'synthetic-key')}
    events = []
    inventory = {'uid': {'name': 'collector', 'purpose': 'clientAuth', 'csr': 'synthetic-csr'}}
    answers = iter([transient, {'healthy': False}, {'healthy': True, 'server_time': 123}])

    def health():
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def wait(predicate, *, timeout):
        events.append(('wait', timeout))
        if timeout == 30:
            assert not predicate() and not predicate()
            assert not any(e[0] == 'grant' for e in events)
            if unavailable:
                raise runtime.RuntimeFailure('runtime_wait_timeout')
        assert predicate()

    def grant(entry, key, csr, *, seconds, now):
        assert (entry, key, csr, seconds, now) == ('entry', 'synthetic-key', 'synthetic-csr', 300, 123)
        events.append(('grant', now))
        return 'synthetic-grant'

    monkeypatch.setattr(value, 'compose', lambda *args, **kwargs: events.append(('compose', args)))
    monkeypatch.setattr(value, 'helper', lambda *args: json.dumps(inventory))
    monkeypatch.setattr(value, 'authority_health', health)
    monkeypatch.setattr(value, 'wait', wait)
    monkeypatch.setattr(value, 'save', lambda: None)
    monkeypatch.setattr(value, 'write_volume', lambda label, files: events.append(('write', label)))
    monkeypatch.setattr(value, 'controller_status', lambda: {'phase': None, 'credentials': {'uid': {'generation': 1}}})
    monkeypatch.setattr(runtime.authority, 'bootstrap_token', grant)
    if unavailable:
        with pytest.raises(runtime.RuntimeFailure, match='^authority_health_unavailable$'):
            value.before_start()
        assert not any(e[0] in {'grant', 'write'} for e in events)
        assert len([e for e in events if e[0] == 'compose']) == 1
        assert value._bootstrap_provisioners and not value.state.get('authority_initialized')
    else:
        value.before_start()
        assert value.state == {'authority_bootstrap_time': 123, 'authority_initialized': True}
        assert not value._bootstrap_provisioners
        assert events[-2:] == [('compose', ('up', '--detach', 'certificate-controller')), ('wait', 180)]


def test_initialized_resume_does_not_mint_or_reapprove(monkeypatch):
    value = runtime.AuthorityRuntime(runtime.ROOT / 'runtime/c02/unit-ca-readiness')
    value.state = {'authority_initialized': True}
    def forbidden(*args, **kwargs):
        pytest.fail('initialized resume entered bootstrap')
    for name in ('compose', 'helper', 'authority_health', 'write_volume'):
        monkeypatch.setattr(value, name, forbidden)
    value.before_start()


@pytest.mark.parametrize('lost_db', [False, True])
def test_current_iat_replay_control_detects_lost_database(monkeypatch, lost_db):
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    claims = {'jti': 'used-nonce', 'iat': 1, 'nbf': 1, 'exp': 2, 'sha': 'same-csr-binding'}
    checks = acceptance.AuthorityChecks(runtime.ROOT / 'runtime/c02/unit-ca-replay')
    checks.runtime = SimpleNamespace(
        _consumed_grant={'csr': 'synthetic-csr', 'ott': jwt.encode(claims, key, algorithm='ES256')},
        _acceptance_signer=({'key': {'kid': 'test-only'}}, key),
        authority_health=lambda: {'healthy': True, 'server_time': 100})
    seen = []

    def rpc(operation, *, path, payload):
        assert operation == 'ca_post' and path == '/1.0/sign' and payload['csr'] == 'synthetic-csr'
        decoded = jwt.decode(payload['ott'], key.public_key(), algorithms=['ES256'], options={'verify_exp': False})
        assert (decoded['iat'], decoded['nbf'], decoded['exp']) == (100, 98, 160)
        assert decoded['sha'] == 'same-csr-binding'
        seen.append(decoded)
        return {'status': 201 if lost_db or decoded['jti'] != 'used-nonce' else 401}

    monkeypatch.setattr(checks, 'rpc', rpc)
    if lost_db:
        with pytest.raises(runtime.RuntimeFailure, match='authority_bootstrap_replay_accepted'):
            checks.replay_denied()
    else:
        assert checks.replay_denied() == 401
    assert len(seen) == 2
    assert {k: v for k, v in seen[0].items() if k != 'jti'} == {k: v for k, v in seen[1].items() if k != 'jti'}


def test_ca_issued_at_policy_stays_enabled():
    material, _ = assets.material()
    cfg = json.loads(material['ca-state']['ca.json'])
    if cfg['authority'].get('disableIssuedAtCheck'):
        raise AssertionError('CA issued-at validation disabled')
