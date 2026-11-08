"""Local I2 service boundary: verified TLS, leaf pins and per-request service scope.

No CA service, application role substitution, retries, redirects or HTTP fallback.
"""

import argparse
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import sys
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROUTES = {
    "pep-bridge": [("POST", r"/zero-trust/protected-access")],
    "collector": [("POST", r"/zero-trust/signals/(?:evaluate|inbox)")],
    "api-gateway": [("POST", r"/zero-trust/(?:protected-access|signals/(?:evaluate|inbox))")],
    "core-operator": [("GET", r"/(?:health/live|zero-trust/(?:signals/inbox(?:/[A-Za-z0-9._-]+)?|sessions(?:/[A-Za-z0-9._-]+)?))"),
                      ("POST", r"/zero-trust/(?:signals/(?:evaluate|inbox)|protected-access|sessions/[A-Za-z0-9._-]+/revoke)")],
    "proxy-auth": [("GET", r"/_authorize")],
    "bridge-probe": [("GET", r"/(?:documents|_authorize)")],
    "proxy-resource": [("GET", r"/documents")],
    "resource-consumer": [("POST", r"/consume")],
    "resource-auditor": [("GET", r"/_stats")],
    "transport-auditor": [("GET", r"/_transport/stats")],
    "metrics-reader": [("GET", r"/zero-trust/signals/inbox")],
    "scrape-agent": [("GET", r"/metrics")],
    "alert-manager": [("POST", r"/events")],
    "sink-auditor": [("GET", r"/events")],
}


def profile(path):
    if path.stat().st_size > 32768:
        raise ValueError("tls_profile_size")
    data = json.loads(path.read_bytes())
    if not isinstance(data, dict):
        raise TypeError("tls_profile_shape")
    return data


def asset(path, name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+\.(?:pem|key)", name):
        raise ValueError("tls_asset_name")
    target = (path.parent / name).resolve()
    if not target.is_relative_to(path.parent.resolve()) or target.stat().st_size > 65536:
        raise ValueError("tls_asset_scope")
    return str(target)


def pins(values):
    if not isinstance(values, (dict, list)) or not 1 <= len(values) <= 16 or any(
            not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v) for v in values):
        raise ValueError("tls_pins")
    return values


def server_policy(path):
    data = profile(path)
    if not isinstance(data["peers"], dict) or any(v not in ROUTES for v in pins(data["peers"]).values()):
        raise ValueError("tls_peer_identity")
    return data


def server_context(path):
    data = server_policy(path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_TICKET
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.load_verify_locations(cafile=asset(path, data["ca"]))
    context.load_cert_chain(asset(path, data["cert"]), asset(path, data["key"]))
    context.set_alpn_protocols(["http/1.1"])
    return context


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, path):
        data = profile(path)
        if (not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", data["host"])
                or type(data["port"]) is not int or not 1 <= data["port"] <= 65535
                or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", data["server_name"])):
            raise ValueError("tls_endpoint")
        super().__init__(data["host"], data["port"], timeout=2)
        self.server_name, self.expected = data["server_name"], pins(data["server_pins"])
        self.context = ssl.create_default_context(cafile=asset(path, data["ca"]))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.verify_flags |= ssl.VERIFY_X509_STRICT
        self.context.options |= ssl.OP_NO_TICKET
        self.context.set_alpn_protocols(["http/1.1"])
        if data.get("cert") is not None:
            self.context.load_cert_chain(asset(path, data["cert"]), asset(path, data["key"]))

    def connect(self):
        raw = socket.create_connection((self.host, self.port), self.timeout)
        try:
            self.sock = self.context.wrap_socket(raw, server_hostname=self.server_name)
            actual = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
            if not any(hmac.compare_digest(actual, expected) for expected in self.expected):
                raise ssl.SSLError("server_pin_rejected")
        except (OSError, ValueError):
            raw.close()
            if self.sock:
                self.sock.close()
                self.sock = None
            raise


def request(path, target, payload, headers, method="POST", observed=None):
    connection = PinnedConnection(path)  # Fresh context/profile: no stale identity or pin cache.
    try:
        connection.connect()  # Verify chain, hostname AND pin before writing credentials/body.
        if observed is not None:
            observed.update(tls_version=connection.sock.version(), cipher=connection.sock.cipher()[0])
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode() if payload is not None else None
        connection.request(method, target, body=data, headers={"Content-Type": "application/json", **headers})
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("tls_response_size")
        return response.status, body
    finally:
        connection.close()


class Quiet(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body=b"{}"):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Gateway(ThreadingHTTPServer):
    daemon_threads = True
    # A TLS handshake occupies accept() briefly. Keep a bounded pending queue
    # above the eight-client local workload instead of TCPServer's default 5.
    # NativeServer inherits this value; authentication and timeouts are unchanged.
    request_queue_size = 32

    def __init__(self, address, path, backend="core", backend_port=8000, backend_profile=None, secure_stats=False):
        self.path, self.backend, self.backend_port = path, backend, backend_port
        self.backend_profile, self.secure_stats = backend_profile, secure_stats
        self.counts, self.count_lock = Counter(), threading.Lock()
        server_context(path)  # Refuse an invalid initial configuration.
        super().__init__(address, GatewayHandler)

    def count(self, label):
        with self.count_lock:
            self.counts[label] += 1

    def get_request(self):
        raw, address = self.socket.accept()
        raw.settimeout(3)
        try:
            return server_context(self.path).wrap_socket(raw, server_side=True), address
        except (OSError, ValueError, KeyError, TypeError):
            self.count("handshake_or_config_denied")
            raw.close()
            raise OSError("tls_connection_rejected") from None

    def handle_error(self, request, client_address):
        self.count("connection_closed")  # Expected TLS rejections must not dump request context.


class GatewayHandler(Quiet):
    def handle_request(self):
        self.server.count("http_requests")
        try:
            identity = server_policy(self.server.path)["peers"].get(
                hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest())
            if getattr(self.server, "secure_stats", False) and self.command == "GET" and self.path == "/_transport/stats":
                if identity != "transport-auditor":
                    return self.reply(403)
                with self.server.count_lock:
                    snapshot = dict(self.server.counts)
                    snapshot["http_requests"] -= 1  # Management reads do not contaminate data-plane assertions.
                    self.server.counts["http_requests"] -= 1
                return self.reply(200, json.dumps(snapshot).encode())
            lengths = self.headers.get_all("Content-Length", [])
            keys = self.headers.get_all("X-API-Key", [])
            if (self.headers.get_all("Transfer-Encoding") or len(lengths) != 1
                    or not re.fullmatch(r"[0-9]{1,5}", lengths[0]) or int(lengths[0]) > 65536
                    or len(keys) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", keys[0])):
                return self.reply(400)
            body = self.rfile.read(int(lengths[0]))
            if len(body) != int(lengths[0]):
                return self.reply(400)
            if identity is None:
                self.server.count("identity_denied")
                return self.reply(403)
            # BaseHTTPRequestHandler normalizes a leading //; scope checks use the wire target.
            target = self.requestline.split()[1]
            if not any(self.command == method and re.fullmatch(pattern, target)
                       for method, pattern in ROUTES[identity]):
                self.server.count("scope_denied")
                return self.reply(403)
            backend_profile = getattr(self.server, "backend_profile", None)
            connection = (PinnedConnection(backend_profile) if backend_profile
                          else http.client.HTTPConnection(self.server.backend, self.server.backend_port, timeout=1))
            try:
                if backend_profile:
                    connection.connect()  # Authenticate the native core before transmitting the API key.
                self.server.count("forwarded")
                connection.request(self.command, target, body, {"Content-Type": "application/json", "X-API-Key": keys[0]})
                response = connection.getresponse()
                result = response.read(65537)
                if len(result) > 65536:
                    raise ValueError("backend_size")
                return self.reply(response.status, result)
            finally:
                connection.close()
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            self.server.count("request_failed")
            return self.reply(503)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = handle_request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["serve", "probe"])
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--backend-profile", type=Path)
    parser.add_argument("--secure-stats", action="store_true")
    parser.add_argument("--stats-profile", type=Path)
    args = parser.parse_args()
    if args.mode == "probe":
        data = json.load(sys.stdin)
        observed = {}
        try:
            status, body = request(args.profile, data["path"], data.get("payload"),
                                   dict(data.get("headers", [])), data.get("method", "POST"), observed)
            result = {"status": status, "body_sha256": hashlib.sha256(body).hexdigest(), **observed}
            parsed = json.loads(body)
            reason = parsed.get("reason_code") if isinstance(parsed, dict) else None
            if isinstance(reason, str) and re.fullmatch(r"[A-Z_]{1,64}", reason):
                result["reason_code"] = reason
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            result = {"status": 0, "body_sha256": None}
        print(json.dumps(result))
        return
    gateway = Gateway(("0.0.0.0", 8443), args.profile, backend_profile=args.backend_profile, secure_stats=args.secure_stats)
    if args.secure_stats and not args.stats_profile:
        gateway.serve_forever()
        return

    class Stats(Quiet):
        def do_GET(self):
            with gateway.count_lock:
                self.reply(200, json.dumps(dict(gateway.counts)).encode())
    if args.stats_profile:
        from scripts.mtls_native import NativeServer
        stats = NativeServer(("0.0.0.0", 8444), args.stats_profile, Stats)
    else:
        stats = ThreadingHTTPServer(("127.0.0.1", 8444), Stats)
    threading.Thread(target=stats.serve_forever, daemon=True).start()
    gateway.serve_forever()


if __name__ == "__main__":
    main()
