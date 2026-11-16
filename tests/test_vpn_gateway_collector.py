"""Real loopback mTLS collection plus independently signed *fixture* policies."""

import hashlib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.vpn_gateway_collector import collect_connection
from scripts.f1_lab.vpn_risk_retention import RiskRetention
from scripts.f1_lab.vpn_signal_controls import VPNControls, arguments, sha
from scripts.f1_lab.vpn_verified_signals import VerifiedVPNRisk
from scripts.mtls_fixtures import authority, leaf

CLAIMS = {'tenant_id': 'vpn-lab', 'gateway_id': 'gateway-local', 'session_id': 'vpn-session',
              'session_version': 0, 'user_id': 'vpn-user', 'device_id': 'vpn-device', 'resource_id': 'vpn-resource'}


def connected(tmp_path, callback, *, verify=True, with_certificate=True,
              tls13=False, tickets=False, renegotiation=False):
    ca = authority()
    ca_text = ca[1].public_bytes(Encoding.PEM).decode()
    server_leaf, client_leaf = leaf(ca, 'gateway', server=True), leaf(ca, 'vpn-device')
    contexts = []
    for name, material, purpose in [('server', server_leaf, ssl.Purpose.CLIENT_AUTH),
                                     ('client', client_leaf, ssl.Purpose.SERVER_AUTH)]:
        context = ssl.create_default_context(purpose, cadata=ca_text)
        context.minimum_version = ssl.TLSVersion.TLSv1_3 if tls13 else ssl.TLSVersion.TLSv1_2
        context.maximum_version = context.minimum_version
        if not tickets:
            context.options |= ssl.OP_NO_TICKET
        if not renegotiation:
            context.options |= ssl.OP_NO_RENEGOTIATION
        context.verify_mode = ssl.CERT_REQUIRED if (verify or name == 'client') else ssl.CERT_NONE
        cert, key = tmp_path/(name+'.crt'), tmp_path/(name+'.key')
        cert.write_text(material['cert'], encoding='ascii')
        key.write_text(material['key'], encoding='ascii')
        key.chmod(0o600)
        if name == 'server' or with_certificate:
            context.load_cert_chain(cert, key)
        contexts.append(context)
    try:
        with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as pool:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(5)

            def server():
                sock, _ = listener.accept()
                with sock:
                    sock.settimeout(5)
                    with contexts[0].wrap_socket(sock, server_side=True) as tls:
                        result = callback(tls)
                        tls.sendall(b'x')
                        return result

            future = pool.submit(server)
            try:
                with (socket.create_connection(listener.getsockname(), timeout=5) as sock,
                      contexts[1].wrap_socket(sock, server_hostname='gateway') as tls):
                    tls.recv(1)
            except ssl.SSLError:
                # Propagate the server's actual handshake/collector rejection.
                pass
            return future.result(timeout=5), client_leaf
    finally:
        for name in ('server', 'client'):
            (tmp_path/(name+'.key')).unlink(missing_ok=True)


def test_actual_tls_peer_certificate_channel_and_time_are_collected(tmp_path):
    observed, client = connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS))
    request = observed.connection
    assert request.client_certificate_sha256 == client['fingerprint']
    assert request.peer_ip.exploded == '127.0.0.1' and request.peer_port != 1194
    assert len(request.tls_channel_sha256) == 64 and request.tls_channel_sha256 != 'd'*64
    assert hashlib.sha256(observed.raw_line.encode()).hexdigest() == request.raw_line_sha256
    assert '127.0.0.1:'+str(request.peer_port) in observed.raw_line
    assert not list(tmp_path.glob('*.key'))


@pytest.mark.parametrize('changes,expected', [({}, 'approved'), ({'device': 'compromised'}, 'adverse'),
    ({'mfa': 'failed'}, 'adverse'), ({'role': 'admin'}, 'unavailable'), ({'approval': False}, 'unavailable')])
def test_real_tls_facts_flow_through_existing_identity_device_permission_verifiers(tmp_path, changes, expected):
    observed, _ = connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS))
    baseline = RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.),
        SimpleNamespace(profile=PROFILE, probability=lambda _: .98)))
    c = VPNControls(tmp_path/'control', baseline, now=observed.connection.observed_at)
    c.enrollment_registry['bindings'][0]['client_certificate_sha256'] = observed.connection.client_certificate_sha256
    c.write()
    c.enrollments.expected_sha256 = sha(c.directory/'enrollments.json')
    row = c.build(gateway_observation=observed, **changes)
    result = VerifiedVPNRisk(baseline, c.bridge).decide(**arguments(row))
    assert result.evidence_state == expected
    assert result.alert is (expected != 'approved')
    assert not result.automatic_enforcement_allowed


@pytest.mark.parametrize('mode', ['unenrolled', 'revoked', 'wrong_device', 'expired_policy', 'policy_changed'])
def test_actual_tls_alone_cannot_supply_device_or_permission_authority(tmp_path, mode):
    observed, _ = connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS))
    baseline = RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.),
        SimpleNamespace(profile=PROFILE, probability=lambda _: .98)))
    c = VPNControls(tmp_path/'control', baseline, now=observed.connection.observed_at)
    binding = c.enrollment_registry['bindings'][0]
    if mode != 'unenrolled':
        binding['client_certificate_sha256'] = observed.connection.client_certificate_sha256
    if mode == 'revoked':
        binding['enabled'] = False
    if mode == 'wrong_device':
        binding['device_id'] = 'another-device'
    c.write()
    c.enrollments.expected_sha256 = sha(c.directory/'enrollments.json')
    row = c.build(gateway_observation=observed)
    if mode == 'expired_policy':
        c.policy['expires_at'] = observed.connection.observed_at.isoformat()
        c.write()
        c.policies.expected_sha256 = sha(c.directory/'policies.json')
    if mode == 'policy_changed':
        (c.directory/'policies.json').write_bytes(b'{}')
    result = VerifiedVPNRisk(baseline, c.bridge).decide(**arguments(row))
    assert result.alert and result.evidence_state == 'unavailable'


def test_optional_or_absent_peer_authentication_is_not_evidence(tmp_path):
    with pytest.raises(ValueError, match='vpn_verified_tls_server'):
        connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS), verify=False)
    with pytest.raises(ssl.SSLError):
        connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS), with_certificate=False)


def test_submitted_socket_like_objects_and_naive_time_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        collect_connection(SimpleNamespace(server_side=True), **CLAIMS)
    with pytest.raises(ValueError, match='vpn_gateway_time'):
        connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS, now=datetime.now(UTC).replace(tzinfo=None)))


def test_new_tls_connection_cannot_reuse_previously_bound_signal_bundle(tmp_path):
    first = tmp_path/'first'
    second = tmp_path/'second'
    first.mkdir()
    second.mkdir()
    one, _ = connected(first, lambda tls: collect_connection(tls, **CLAIMS))
    two, _ = connected(second, lambda tls: collect_connection(tls, **CLAIMS))
    assert one.connection.tls_channel_sha256 != two.connection.tls_channel_sha256
    baseline = RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.),
        SimpleNamespace(profile=PROFILE, probability=lambda _: .98)))
    c = VPNControls(tmp_path/'control', baseline, now=one.connection.observed_at)
    c.enrollment_registry['bindings'][0]['client_certificate_sha256'] = one.connection.client_certificate_sha256
    c.write()
    c.enrollments.expected_sha256 = sha(c.directory/'enrollments.json')
    row = c.build(gateway_observation=one)
    challenge = c.bridge.issue(two.connection, row['principal'], now=two.connection.observed_at)
    result = c.bridge.check(challenge.nonce, row['evidence'], two.raw_line, row['principal'],
                            now=two.connection.observed_at)
    assert result.state == 'unavailable'


@pytest.mark.parametrize('options', [{'tls13': True}, {'tickets': True}, {'renegotiation': True}])
def test_unsupported_or_ambiguous_channel_binding_is_rejected(tmp_path, options):
    with pytest.raises(ValueError, match='vpn_channel_binding_protocol'):
        connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS), **options)
