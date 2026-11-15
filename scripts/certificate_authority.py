"""Ephemeral local step-ca bootstrap; signing/provisioner keys never go to host files."""

import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def hierarchy():
    now = datetime.now(UTC)
    root_key, issuer_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
    def certificate(key, name, signer, issuer, depth):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=depth), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .sign(signer, hashes.SHA256()))
    root = certificate(root_key, "C04 offline ephemeral root", root_key, None, 1)
    issuer = certificate(issuer_key, "C04 online issuing intermediate", root_key, root.subject, 0)
    return (root_key, root), (issuer_key, issuer)


def public_jwk(key):
    numbers = key.public_numbers()
    public = {"crv": "P-256", "kty": "EC", "x": b64(numbers.x.to_bytes(32, "big")),
              "y": b64(numbers.y.to_bytes(32, "big"))}
    kid = b64(hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).digest())
    public.update(kid=kid, alg="ES256", use="sig")
    return public


def provisioner(name, purpose):
    if purpose not in {"clientAuth", "serverAuth"}:
        raise ValueError("certificate_purpose")
    key = ec.generate_private_key(ec.SECP256R1())
    public = public_jwk(key.public_key())
    template = {"subject": {"commonName": name}, "sans": [{"type": "dns", "value": name}],
        "keyUsage": ["digitalSignature"], "extKeyUsage": [purpose],
        "basicConstraints": {"isCA": False}}
    config = {"type": "JWK", "name": name + "-" + purpose, "key": public,
        "options": {"x509": {"template": json.dumps(template)}}}
    return config, key


def server_renewal_provisioner(name, public_key):
    # A registered, control-plane-only key, never an own-root X5C provisioner.
    # A normal CA-issued client certificate confers no management capability.
    template = {"subject": {"commonName": name}, "sans": [{"type": "dns", "value": name}],
        "keyUsage": ["digitalSignature"], "extKeyUsage": ["serverAuth"], "basicConstraints": {"isCA": False}}
    return {"type": "JWK", "name": "server-renewal-" + name, "key": public_jwk(public_key),
        "claims": {"disableRenewal": True}, "options": {"x509": {"template": json.dumps(template)}}}


def server_renewal_token(name, certificate_chain, key, csr):
    now = int(datetime.now(UTC).timestamp())
    certificates = x509.load_pem_x509_certificates(certificate_chain.encode())
    expected = public_jwk(certificates[0].public_key())
    if expected != public_jwk(key.public_key()):
        raise ValueError("renewal_signer_key_mismatch")
    request = x509.load_pem_x509_csr(csr.encode())
    return jwt.encode({"iss": "server-renewal-" + name, "sub": name, "sans": [name],
        "aud": "https://ca:9000/1.0/sign", "iat": now, "nbf": now - 2, "exp": now + 60,
        "cnf": {"x5rt#S256": b64(hashlib.sha256(request.public_bytes(serialization.Encoding.DER)).digest())},
        "jti": secrets.token_hex(24)}, key, algorithm="ES256", headers={"kid": expected["kid"]})


def bootstrap_token(config, key, csr, *, audience="https://ca:9000/1.0/sign", seconds=120, now=None):
    now = int(datetime.now(UTC).timestamp()) if now is None else now
    request = x509.load_pem_x509_csr(csr.encode())
    name = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    payload = {"iss": config["name"], "sub": name, "aud": audience, "iat": now, "nbf": now - 2,
        "exp": now + seconds, "jti": secrets.token_hex(24), "sans": [name],
        "cnf": {"x5rt#S256": b64(hashlib.sha256(request.public_bytes(serialization.Encoding.DER)).digest())}}
    return jwt.encode(payload, key, algorithm="ES256", headers={"kid": config["key"]["kid"]})


def ca_files(root, issuer, provisioners):
    password = secrets.token_urlsafe(40)
    config = {"root": "/ca/root.pem", "crt": "/ca/issuer.pem", "key": "/ca/issuer.key",
        "address": ":9000", "dnsNames": ["ca"], "logger": {"format": "json"},
        "db": {"type": "badgerv2", "dataSource": "/ca/db"},
        "authority": {"backdate": "0s", "provisioners": provisioners, "claims": {
            "minTLSCertDuration": "5s", "maxTLSCertDuration": "24h", "defaultTLSCertDuration": "20m",
            "disableRenewal": False, "allowRenewalAfterExpiry": False, "enableSSHCA": False}}}
    return {"root.pem": root[1].public_bytes(serialization.Encoding.PEM).decode(),
        "issuer.pem": issuer[1].public_bytes(serialization.Encoding.PEM).decode(),
        "issuer.key": issuer[0].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode())).decode(),
        "password.txt": password, "ca.json": json.dumps(config)}
