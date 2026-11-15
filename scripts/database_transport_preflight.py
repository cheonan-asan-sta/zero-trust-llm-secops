"""Offline DB transport PKI admission; public results, no private material output."""

import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.certificate_controller import LifecycleError

VOLUMES = ('authority-db-tls', 'authority-ca-a-db', 'authority-ca-b-db')


def read(path, *, private=False):
    # fstat after O_NOFOLLOW avoids symlink/FIFO replacement between checks.
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    if path.is_symlink():
        raise LifecycleError('database_transport_regular_file_required')
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        detail = os.fstat(stream.fileno())
        if (not stat.S_ISREG(detail.st_mode) or detail.st_nlink != 1
                or private and (stat.S_IMODE(detail.st_mode) & 0o077
                                or hasattr(os, 'geteuid') and detail.st_uid != os.geteuid())):
            raise LifecycleError('database_transport_private_file_required')
        body = stream.read(65537)
    if not 0 < len(body) <= 65536:
        raise LifecycleError('database_transport_file_size')
    return body


def public_key(value):
    return value.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def certificate(body, now, *, ca=False):
    if body.count(b'-----BEGIN CERTIFICATE-----') != 1:
        raise LifecycleError('database_transport_single_certificate_required')
    value = x509.load_pem_x509_certificate(body)
    constraints = value.extensions.get_extension_for_class(x509.BasicConstraints).value
    usage = value.extensions.get_extension_for_class(x509.KeyUsage).value
    key = value.public_key()
    if (not value.not_valid_before_utc <= now < value.not_valid_after_utc
            or constraints.ca != ca or constraints.path_length != (0 if ca else None)
            or usage.key_cert_sign != ca or usage.crl_sign != ca or not usage.digital_signature
            or not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1)
            or not isinstance(value.signature_hash_algorithm, hashes.SHA256)):
        raise LifecycleError('database_transport_certificate_invalid')
    return value


def inspect_transport(roots, expected_root_sha256, *, now=None):
    now = now or datetime.now(UTC)
    if (set(roots) != set(VOLUMES) or not isinstance(expected_root_sha256, str)
            or not re.fullmatch('[a-f0-9]{64}', expected_root_sha256)):
        raise LifecycleError('database_transport_scope')
    observations, keys, serials, expiries = {}, set(), set(), []
    for index, volume in enumerate(VOLUMES):
        directory = Path(roots[volume])
        root_body = read(directory / 'root.pem')
        if hashlib.sha256(root_body.replace(b'\r\n', b'\n')).hexdigest() != expected_root_sha256:
            raise LifecycleError('database_transport_root_changed')
        root = certificate(root_body, now, ca=True)
        root.verify_directly_issued_by(root)
        server = index == 0
        stem, name = ('server', 'ca-db') if server else ('client', 'secops_ca')
        cert = certificate(read(directory / (stem + '.pem')), now)
        cert.verify_directly_issued_by(root)
        key = serialization.load_pem_private_key(read(directory / (stem + '.key'), private=True), password=None)
        encoded = public_key(cert.public_key())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if (not isinstance(key, ec.EllipticCurvePrivateKey) or public_key(key.public_key()) != encoded
                or cert.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
                or list(sans) != [x509.DNSName(name)]
                or list(eku) != [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
                or encoded in keys or cert.serial_number in serials):
            raise LifecycleError('database_transport_identity_or_key_invalid')
        keys.add(encoded)
        serials.add(cert.serial_number)
        remaining = int((min(root.not_valid_after_utc, cert.not_valid_after_utc) - now).total_seconds())
        expiries.append(remaining)
        observations[volume] = {'identity': name, 'purpose': 'server' if server else 'client',
            'fingerprint': cert.fingerprint(hashes.SHA256()).hex(), 'remaining_seconds': remaining,
            'certificate_expires_at': cert.not_valid_after_utc.isoformat(),
            'root_expires_at': root.not_valid_after_utc.isoformat(), 'private_permissions_verified': True}
    return {'schema': 'database-transport-preflight-1', 'verified': True,
            'status': 'expires_soon' if min(expiries) <= 86400 else 'ready',
            'minimum_remaining_seconds': min(expiries), 'credentials': observations,
            'automatic_renewal': False}


def main():
    try:
        raw = sys.stdin.buffer.read(257)
        if len(raw) > 256:
            raise ValueError('size')
        request = json.loads(raw)
        if set(request) != {'expected_root_sha256'}:
            raise ValueError('scope')
        result = inspect_transport({name: Path('/transport') / name for name in VOLUMES}, request['expected_root_sha256'])
    except (OSError, ValueError, TypeError, KeyError, InvalidSignature, UnsupportedAlgorithm,
            x509.ExtensionNotFound, x509.DuplicateExtension, LifecycleError):
        print(json.dumps({'verified': False, 'reason': 'database_transport_preflight_failed'}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
