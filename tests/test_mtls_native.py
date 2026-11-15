"""Native transport scope and per-request revocation; private PKI stays in RAM.

These are guard/unit tests. Real native TLS, NGINX and Go client verification
are exercised separately by scripts.test_all_hops_mtls in Docker.
"""

import asyncio
import json
import ssl
from email.message import Message
from urllib.parse import quote

import pytest

from scripts import mtls_native as native
from scripts import signal_metrics_exporter as exporter
from scripts.mtls_fixtures import authority, leaf


@pytest.fixture
def certs():
    ca = authority()
    return {"valid": leaf(ca, "core-operator"), "unknown": leaf(ca, "core-operator"),
        "expired": leaf(ca, "core-operator", expired=True), "future": leaf(ca, "core-operator", future=True),
        "server": leaf(ca, "core-operator", server=True)}


def run_guard(path, cert, *, target=b"/zero-trust/protected-access", method="POST", query=b"", headers=()):
    called, sent = [], []
    async def app(scope, receive, send):
        called.append(True)
    async def send(message):
        sent.append(message)
    scope = {"type": "http", "raw_path": target, "method": method, "query_string": query, "headers": headers}
    der = ssl.PEM_cert_to_DER_cert(cert["cert"]) if cert else None
    asyncio.run(native.guard_asgi(app, path, der, scope, None, send))
    return called, sent


def registry(tmp_path, cert):
    path = tmp_path / "public-policy.json"
    path.write_text(json.dumps({"peers": {cert["fingerprint"]: "core-operator"}}))
    return path


@pytest.mark.parametrize("label", ["unknown", "expired", "future", "server"])
def test_native_guard_cannot_be_bypassed_by_trusted_ca_or_expired_peer(tmp_path, certs, label):
    # Register even the invalid leaf to prove pin matching cannot bypass validity/EKU.
    registered = certs[label] if label != "unknown" else certs["valid"]
    called, sent = run_guard(registry(tmp_path, registered), certs[label])
    assert not called and sent[0]["status"] == 403


@pytest.mark.parametrize("target,method,query", [
    (b"//zero-trust/protected-access", "POST", b""), (b"/zero-trust/%70rotected-access", "POST", b""),
    (b"/zero-trust/protected-access", "POST", b"scope=admin"), (b"/zero-trust/protected-access", "GET", b""),
    (b"/zero-trust/sessions/evaluate", "POST", b"")])
def test_native_asgi_checks_wire_path_and_method(tmp_path, certs, target, method, query):
    called, sent = run_guard(registry(tmp_path, certs["valid"]), certs["valid"], target=target, method=method, query=query)
    assert not called and sent[0]["status"] == 403


def test_native_asgi_rechecks_retired_identity_on_existing_tls_peer(tmp_path, certs):
    path = registry(tmp_path, certs["valid"])
    assert run_guard(path, certs["valid"])[0]
    path.write_text(json.dumps({"peers": {certs["unknown"]["fingerprint"]: "core-operator"}}))
    called, sent = run_guard(path, certs["valid"])
    assert not called and sent[0]["status"] == 403


def test_native_asgi_cannot_trust_forwarded_headers_without_real_tls_peer(tmp_path, certs):
    called, sent = run_guard(registry(tmp_path, certs["valid"]), None,
        headers=[(b"x-ssl-client-cert", certs["valid"]["cert"].encode()), (b"x-service-identity", b"core-operator")])
    assert not called and sent[0]["status"] == 403


@pytest.mark.parametrize("label", ["unknown", "expired", "future", "server"])
def test_forwarded_frontend_identity_needs_registered_valid_client_certificate(tmp_path, certs, label):
    path = tmp_path / "public-front.json"
    registered = certs[label] if label != "unknown" else certs["valid"]
    path.write_text(json.dumps({"forwarded_peers": [registered["fingerprint"]]}))
    headers = Message()
    headers["X-Verified-Client-Cert"] = quote(certs[label]["cert"])
    with pytest.raises(ValueError):
        native.forwarded_client(headers, path)


def test_forwarded_frontend_duplicate_certificate_header_is_rejected(tmp_path, certs):
    path = tmp_path / "public-front.json"
    path.write_text(json.dumps({"forwarded_peers": [certs["valid"]["fingerprint"]]}))
    headers = Message()
    headers["X-Verified-Client-Cert"] = quote(certs["valid"]["cert"])
    native.forwarded_client(headers, path)
    headers["X-Verified-Client-Cert"] = quote(certs["valid"]["cert"])
    with pytest.raises(ValueError):
        native.forwarded_client(headers, path)


def test_exporter_tls_failure_never_falls_back_or_exposes_stale_metrics(monkeypatch, tmp_path):
    from scripts import mtls_transport as transport
    path = tmp_path / "public-client.json"
    path.write_text(json.dumps({"host": "reader", "port": 8000}))
    def denied(*args, **kwargs):
        raise ssl.SSLError("test-only")
    monkeypatch.setattr(transport, "request", denied)
    monkeypatch.setattr(exporter, "build_opener", lambda *args: pytest.fail("HTTP fallback"))
    result = exporter.metrics("https://reader:8000/zero-trust/signals/inbox", "private-stub",
        lambda u, k: exporter.fetch_summary(u, k, tls_profile=path))
    assert "secops_signal_collection_success 0" in result and "records" not in result


@pytest.mark.parametrize("url", ["http://reader:8000/zero-trust/signals/inbox", "https://other:8000/zero-trust/signals/inbox"])
def test_exporter_tls_cannot_be_redirected_to_other_endpoint(tmp_path, url):
    path = tmp_path / "public-client.json"
    path.write_text(json.dumps({"host": "reader", "port": 8000}))
    with pytest.raises(ValueError):
        exporter.fetch_summary(url, "private-stub", tls_profile=path)
