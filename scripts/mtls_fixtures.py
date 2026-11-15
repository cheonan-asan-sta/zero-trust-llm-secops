"""Ephemeral local PKI. Private material is returned in RAM, never saved on host."""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def material(key, cert):
    return {"key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode(),
            "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "fingerprint": cert.fingerprint(hashes.SHA256()).hex()}


def authority(name="I2 ephemeral local CA"):
    key, now = ec.generate_private_key(ec.SECP256R1()), datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256()))
    return key, cert


def leaf(ca, name, *, server=False, expired=False, future=False):
    key, now = ec.generate_private_key(ec.SECP256R1()), datetime.now(UTC)
    start = now + timedelta(days=1) if future else now - timedelta(minutes=10)
    end = now + timedelta(days=2)
    if expired:
        start, end = now - timedelta(days=2), now - timedelta(days=1)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca[1].subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca[0].public_key()), False)
        .sign(ca[0], hashes.SHA256()))
    return material(key, cert)


def fixtures():
    ca, stranger = authority(), authority("I2 untrusted CA")
    leaves = {"server": leaf(ca, "gateway", server=True), "server-next": leaf(ca, "gateway", server=True),
        "bridge": leaf(ca, "pep-bridge"), "bridge-next": leaf(ca, "pep-bridge"), "collector": leaf(ca, "collector"),
        "unknown": leaf(ca, "pep-bridge"), "foreign": leaf(stranger, "pep-bridge"),
        "expired": leaf(ca, "pep-bridge", expired=True), "future": leaf(ca, "pep-bridge", future=True),
        "wrong-eku": leaf(ca, "pep-bridge", server=True),
        "server-expired": leaf(ca, "gateway", server=True, expired=True),
        "server-future": leaf(ca, "gateway", server=True, future=True),
        "server-wrong-name": leaf(ca, "different.local", server=True),
        "server-wrong-eku": leaf(ca, "gateway")}
    return ca[1].public_bytes(serialization.Encoding.PEM).decode(), leaves
