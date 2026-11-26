"""Real transport: TLS/mTLS validation and redirect credential containment."""

import ipaddress
import json
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.audit_review_client import AuditReviewClient, ReviewClientError


@pytest.fixture
def certificates(tmp_path):
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned operator client test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result = {"ca": str(ca_path)}
    for purpose in ("server", "client", "wrong-host"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, purpose)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH
                        if purpose == "client"
                        else ExtendedKeyUsageOID.SERVER_AUTH
                    ]
                ),
                critical=False,
            )
        )
        if purpose != "client":
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.IPAddress(
                            ipaddress.ip_address(
                                "127.0.0.2" if purpose == "wrong-host" else "127.0.0.1"
                            )
                        )
                    ]
                ),
                critical=False,
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        cert_path, key_path = tmp_path / (purpose + ".pem"), tmp_path / (purpose + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        result[purpose] = (str(cert_path), str(key_path))
    return result


@contextmanager
def server(context=None, *, redirect=None, tls=False):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.requests.append((self.path, self.headers.get("X-API-Key")))
            if redirect:
                self.send_response(302)
                self.send_header("Location", redirect)
                self.end_headers()
                return
            body = json.dumps(
                {"subject": "operator", "tenant_id": "local", "auth_method": "api_key"}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    instance.requests = []
    if tls:
        instance.socket = context.wrap_socket(instance.socket, server_side=True)
    worker = threading.Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    try:
        yield instance, ("https" if tls else "http") + f"://127.0.0.1:{instance.server_port}"
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def tls_context(certificates, *, require_client=False, wrong_host=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificates["wrong-host" if wrong_host else "server"])
    if require_client:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=certificates["ca"])
    return context


def test_verified_ca_and_hostname_deliver_only_to_owned_tls_server(certificates):
    with server(tls_context(certificates), tls=True) as (host, url):
        client = AuditReviewClient(url, "owned-placeholder", ca_file=certificates["ca"])
        assert client._identity()["subject"] == "operator"
        assert host.requests == [("/auth/me", "owned-placeholder")]


@pytest.mark.parametrize("reason", ["untrusted-ca", "wrong-host", "missing-client-cert"])
def test_failed_tls_validation_sends_no_application_credential(certificates, reason):
    context = tls_context(
        certificates,
        require_client=reason == "missing-client-cert",
        wrong_host=reason == "wrong-host",
    )
    with server(context, tls=True) as (host, url):
        client = AuditReviewClient(
            url, "must-not-arrive", ca_file=certificates["ca"] if reason != "untrusted-ca" else None
        )
        with pytest.raises(ReviewClientError, match="HTTP/TLS"):
            client._identity()
        assert host.requests == []


def test_mutual_tls_uses_explicit_client_certificate(certificates):
    with server(tls_context(certificates, require_client=True), tls=True) as (host, url):
        cert, key = certificates["client"]
        client = AuditReviewClient(
            url, "owned-placeholder", ca_file=certificates["ca"], cert_file=cert, key_file=key
        )
        assert client._identity()["tenant_id"] == "local"
        assert len(host.requests) == 1


def test_redirect_never_forwards_credentials_to_another_origin():
    with (
        server() as (other, destination),
        server(redirect=destination + "/stolen") as (origin, url),
    ):
        client = AuditReviewClient(url, "keep-at-explicit-origin")
        with pytest.raises(ReviewClientError, match="HTTP 302"):
            client._identity()
        assert len(origin.requests) == 1
        assert other.requests == []
