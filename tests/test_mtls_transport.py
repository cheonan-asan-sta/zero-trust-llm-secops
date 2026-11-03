"""Policy/credential ordering boundaries on Windows/Linux; real TLS in I2 Docker lab.

These unit sockets stub the TLS peer only. No private key files are written here.
"""

import hashlib
import json
import threading
from collections import Counter
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

import pytest

from scripts import mtls_transport as tls
from scripts import pep_lab as pep

PEER = b"unit-peer-der-stub"
PIN = hashlib.sha256(PEER).hexdigest()


class PeerSocket:
    def __init__(self, raw):
        self.raw = raw

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def getpeercert(self, binary_form=False):
        assert binary_form
        return PEER


@contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.fixture
def boundary(tmp_path):
    calls = []
    class Backend(pep.QuietHandler):
        def do_POST(self):
            calls.append({"headers": dict(self.headers), "body": self.rfile.read(int(self.headers["Content-Length"]))})
            self.reply(401 if self.headers["X-API-Key"] == "bad" else 200, b'{}')
    class UnitGateway(ThreadingHTTPServer):
        def get_request(self):
            raw, address = super().get_request()
            return PeerSocket(raw), address

        def count(self, label):
            self.counts[label] += 1
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"peers": {PIN: "pep-bridge"}}))
    with serving(ThreadingHTTPServer(("127.0.0.1", 0), Backend)) as backend:
        gateway = UnitGateway(("127.0.0.1", 0), tls.GatewayHandler)
        gateway.path, gateway.backend, gateway.backend_port = path, "127.0.0.1", backend.server_port
        gateway.counts = Counter()
        with serving(gateway):
            yield gateway, calls, path


def send(gateway, **changes):
    return pep.probe({"port": gateway.server_port, "method": "POST", "path": "/zero-trust/protected-access",
        "headers": [["X-API-Key", "valid"]], "payload": {"grant_token": "unit-value"}, **changes})


@pytest.mark.parametrize("target", ["/", "/health/live", "/zero-trust/sessions/evaluate",
    "/zero-trust/protected-access?admin=1", "/zero-trust/%70rotected-access",
    "//zero-trust/protected-access", "/zero-trust/sessions/abc/revoke"])
def test_registered_bridge_cannot_change_service_scope(boundary, target):
    gateway, calls, _ = boundary
    assert send(gateway, path=target)["status"] == 403
    assert not calls


@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"])
def test_service_scope_preserves_method(boundary, method):
    gateway, calls, _ = boundary
    assert send(gateway, method=method)["status"] == 403
    assert not calls


def test_peer_pin_retirement_and_repair_cannot_be_overridden_by_headers(boundary):
    gateway, calls, path = boundary
    assert send(gateway)["status"] == 200
    path.write_text(json.dumps({"peers": {"1" * 64: "pep-bridge"}}))
    assert send(gateway, headers=[["X-API-Key", "valid"], ["X-Service-Identity", "pep-bridge"],
                                  ["X-User", "administrator"]])["status"] == 403
    assert len(calls) == 1
    path.write_text("{")
    assert send(gateway)["status"] in {0, 503}
    path.write_text(json.dumps({"peers": {"1" * 64: "pep-bridge"}}))
    assert send(gateway)["status"] == 403
    assert len(calls) == 1


def test_mtls_does_not_replace_application_auth_and_no_identity_headers_are_forwarded(boundary):
    gateway, calls, _ = boundary
    assert send(gateway, headers=[["X-API-Key", "bad"], ["X-Tenant", "other"], ["Authorization", "Bearer fake"]])["status"] == 401
    assert len(calls) == 1
    assert "X-Tenant" not in calls[0]["headers"] and "Authorization" not in calls[0]["headers"]


def test_duplicate_credentials_are_not_forwarded(boundary):
    gateway, calls, _ = boundary
    assert send(gateway, headers=[["X-API-Key", "valid"], ["X-API-Key", "other"]])["status"] in {0, 400}
    assert not calls


@pytest.mark.parametrize("bad", ["../key.pem", "/private.pem", "nested/key.pem", "key.json"])
def test_profile_cannot_load_keys_outside_mount(tmp_path, bad):
    with pytest.raises(ValueError):
        tls.asset(tmp_path / "profile.json", bad)


@pytest.mark.parametrize("peers", [{}, {"x": "pep-bridge"}, {PIN: "administrator"}, [PIN]])
def test_invalid_peer_registry_fails_closed(tmp_path, peers):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"peers": peers}))
    with pytest.raises(ValueError):
        tls.server_policy(path)


def test_server_pin_checked_before_http_credentials(monkeypatch, tmp_path):
    class Socket:
        closed = False
        def getpeercert(self, binary_form=False):
            return PEER
        def close(self):
            self.closed = True
    class Context:
        options = verify_flags = 0
        def set_alpn_protocols(self, protocols):
            pass
        def wrap_socket(self, raw, server_hostname):
            return raw
    socket = Socket()
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda **kwargs: Context())
    monkeypatch.setattr(tls.socket, "create_connection", lambda *args: socket)
    monkeypatch.setattr(tls.PinnedConnection, "request", lambda *args, **kwargs: pytest.fail("Credentials written before peer pin verification"))
    path = tmp_path / "profile.json"
    (tmp_path / "ca.pem").write_text("public stub")
    path.write_text(json.dumps({"host": "gateway", "port": 8443, "server_name": "gateway", "ca": "ca.pem",
                                "cert": None, "server_pins": ["0" * 64]}))
    with pytest.raises(tls.ssl.SSLError):
        tls.request(path, "/zero-trust/protected-access", {}, {"X-API-Key": "private-stub"})
    assert socket.closed


def test_pep_missing_tls_profile_never_falls_back_to_http(monkeypatch, tmp_path):
    def never(*args):
        pytest.fail("TLS failure must not fall back to HTTP")
    monkeypatch.setattr(pep, "upstream", never)
    tickets = pep.Handoffs()
    handler = pep.authorization_handler("http://core", tickets, tmp_path / "missing.json")
    with serving(ThreadingHTTPServer(("127.0.0.1", 0), handler)) as gateway:
        response = pep.probe({"port": gateway.server_port, "path": "/documents", "headers": [
            ["X-API-Key", "k" * 43], ["X-Session-ID", "session-one"], ["X-Grant-Token", "g" * 43]]})
        assert response["status"] == 503
        assert not tickets.entries
