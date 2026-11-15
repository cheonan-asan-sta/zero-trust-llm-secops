import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts import rekey_runtime_control as control
from scripts.certificate_controller import metadata


def fixture(tmp_path, monkeypatch, *, future=False):
    now = datetime.now(UTC)
    issuer_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'issuer')])
    issuer = (x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
        .public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(issuer_key, hashes.SHA256()))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'collector')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name).public_key(key.public_key()).serial_number(2)
        .not_valid_before(now + timedelta(minutes=1) if future else now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(minutes=2) if future else now - timedelta(minutes=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('collector')]), False).sign(issuer_key, hashes.SHA256()))
    body = cert.public_bytes(serialization.Encoding.PEM).decode()
    certificate, private, policy = tmp_path / 'collector.pem', tmp_path / 'collector.key', tmp_path / 'policy.json'
    certificate.write_text(body)
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)
    if os.name == 'nt':
        # Windows lacks these POSIX mode bits; Linux runs the real mode check.
        monkeypatch.setattr(control.stat, 'S_IMODE', lambda value: 0o600)
    policy.write_text('{"peers":{}}')
    credential = metadata(body) | {'status': 'disabled', 'bindings': [{'path': str(policy)}], 'candidate': None}
    return {'cert': str(certificate), 'key': str(private)}, issuer, {'credentials': {'id': credential}}, policy


def test_expired_disabled_client_with_no_remaining_pin_is_an_integrity_archive(tmp_path, monkeypatch):
    pair, issuer, state, _ = fixture(tmp_path, monkeypatch)
    control.verify_pair(pair, 'collector', issuer, state, ['collector-clientAuth'], disabled=['id'])


@pytest.mark.parametrize('fault', ['active', 'future', 'wrong-key', 'wrong-issuer', 'fingerprint', 'pin-present',
    'status', 'candidate', 'pending-key', 'no-bindings', 'server', 'permissions'])
def test_archive_exception_never_relaxes_active_expiry_trust_key_or_pin_checks(tmp_path, monkeypatch, fault):
    pair, issuer, state, policy = fixture(tmp_path, monkeypatch, future=fault == 'future')
    c, disabled = state['credentials']['id'], ['id']
    if fault == 'active':
        disabled = []
    elif fault == 'wrong-key':
        from pathlib import Path
        Path(pair['key']).write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    elif fault == 'wrong-issuer':
        issuer = x509.load_pem_x509_certificate(__import__('pathlib').Path(pair['cert']).read_bytes())
    elif fault == 'fingerprint':
        c['fingerprint'] = '0' * 64
    elif fault == 'pin-present':
        policy.write_text(json.dumps({'peers': {c['fingerprint']: 'collector'}}))
    elif fault == 'status':
        c['status'] = 'active'
    elif fault in {'candidate', 'pending-key'}:
        c['candidate' if fault == 'candidate' else 'pending_key'] = 'pending'
    elif fault == 'no-bindings':
        c['bindings'] = []
    elif fault == 'server':
        c['purpose'] = 'serverAuth'
    elif fault == 'permissions':
        monkeypatch.setattr(control.stat, 'S_IMODE', lambda value: 0o644)
    with pytest.raises(ValueError):
        control.verify_pair(pair, 'collector', issuer, state, ['collector-clientAuth'], disabled=disabled)
