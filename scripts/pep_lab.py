"""C02 local HTTP PEP bridge, one-use resource handoff and Docker-exec probe.

This is an isolated lab adapter, not a production identity or policy service.
The existing core atomically consumes the grant; failed forwarding never refunds it.
"""

import argparse
import hashlib
import hmac
import http.client
import json
import re
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, build_opener

from scripts.signal_metrics_exporter import NoRedirect, ProxyHandler

DOCUMENT = b'C02 protected fixture: independently served after one-use authorization.\n'
DOCUMENT_HASH = hashlib.sha256(DOCUMENT).hexdigest()
PATH = "/documents"


def single(headers, name, pattern):
    values = headers.get_all(name, [])
    if len(values) != 1 or not re.fullmatch(pattern, values[0]):
        raise ValueError("invalid_header")
    return values[0]


class Handoffs:
    """Bounded, hashed, monotonic, atomic one-use capabilities; never persisted."""

    def __init__(self, *, clock=time.monotonic, ttl=3, capacity=1024):
        self.clock, self.ttl, self.capacity = clock, ttl, capacity
        self.entries, self.lock = {}, threading.Lock()

    def issue(self, session, version):
        with self.lock:
            now = self.clock()
            self.entries = {k: v for k, v in self.entries.items() if v[0] > now}
            if len(self.entries) >= self.capacity:
                raise ValueError("handoff_capacity")
            token = secrets.token_urlsafe(32)
            self.entries[hashlib.sha256(token.encode()).hexdigest()] = (
                now + self.ttl, "GET", PATH, session, version)
            return token

    def consume(self, token, method, path):
        with self.lock:
            entry = self.entries.pop(hashlib.sha256(token.encode()).hexdigest(), None)
            return bool(entry and entry[0] > self.clock() and entry[1:3] == (method, path))


def strict_allow(status, body):
    """Unexpected shape/status never creates a capability, even for truthy values."""
    if status != 200:
        return None
    decision = json.loads(body)
    if (not isinstance(decision, dict) or decision.get("allowed") is not True
            or decision.get("reason_code") != "ACCESS_GRANTED"
            or type(decision.get("session_version")) is not int
            or decision["session_version"] < 1
            or decision.get("enforcement_mode") != "local_simulation"):
        raise ValueError("invalid_core_allow")
    return decision["session_version"]


def upstream(url, payload, headers):
    request = Request(url, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json", **headers})
    try:
        response = build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=1)
    except HTTPError as exc:
        response = exc
    with response:
        raw = response.read(16385)
        if len(raw) > 16384:
            raise ValueError("core_response_size")
        return response.code, raw


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log credentials, grants or capabilities.

    def reply(self, code, body=b"", headers=None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.reply(405)

    do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_HEAD


def authorization_handler(core, tickets, tls_profile=None):
    class Authorize(QuietHandler):
        def do_GET(self):
            try:
                target = self.path
                if target == "/_authorize":
                    target = single(self.headers, "X-C02-Target", r"/documents")
                if target != PATH:
                    return self.reply(403)
                key = single(self.headers, "X-API-Key", r"[A-Za-z0-9_-]{32,128}")
                session = single(self.headers, "X-Session-ID", r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
                grant = single(self.headers, "X-Grant-Token", r"[A-Za-z0-9_-]{32,128}")
            except ValueError:
                return self.reply(403)
            try:
                payload = {
                    "session_id": session, "grant_token": grant,
                    "resource_id": "zt-demo-documents", "action": "READ"}
                if tls_profile is None:
                    status, body = upstream(core + "/zero-trust/protected-access", payload, {"X-API-Key": key})
                else:
                    from scripts.mtls_transport import request
                    status, body = request(tls_profile, "/zero-trust/protected-access", payload, {"X-API-Key": key})
                version = strict_allow(status, body)
                if version is None:
                    return self.reply(403 if status in {401, 403, 404, 422} else 503)
                token = tickets.issue(session, version)
                return self.reply(200, headers={"X-PEP-Handoff": token})
            except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
                return self.reply(503)

        def do_POST(self):
            self.reply(405)
    return Authorize


def consume_handler(secret, tickets):
    class Consume(QuietHandler):
        def do_POST(self):
            try:
                auth = single(self.headers, "Authorization", r"Bearer [A-Za-z0-9_-]{43}")
                length = int(single(self.headers, "Content-Length", r"[0-9]{1,4}"))
                if length > 1024:
                    return self.reply(403)
                raw = self.rfile.read(length)
                if self.path != "/consume" or not hmac.compare_digest(auth, "Bearer " + secret):
                    return self.reply(403)
                data = json.loads(raw)
                token = data["token"]
                if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
                    return self.reply(403)
                allowed = tickets.consume(token, data["method"], data["path"])
                self.reply(200 if allowed else 403)
            except (ValueError, KeyError, TypeError):
                self.reply(403)

        def do_GET(self):
            self.reply(405)
    return Consume


def resource_handler(bridge, secret):
    class Resource(QuietHandler):
        served, lock = 0, threading.Lock()

        def do_GET(self):
            if self.path == "/_stats":
                with self.lock:
                    return self.reply(200, json.dumps({"served": type(self).served}).encode())
            if self.path != PATH:
                return self.reply(404)
            try:
                token = single(self.headers, "X-PEP-Handoff", r"[A-Za-z0-9_-]{43}")
            except ValueError:
                return self.reply(403)
            try:
                status, _ = upstream(bridge + "/consume", {"token": token, "method": "GET", "path": PATH},
                                     {"Authorization": "Bearer " + secret})
                if status != 200:
                    return self.reply(403)
            except (OSError, ValueError, http.client.HTTPException):
                return self.reply(503)
            with self.lock:
                type(self).served += 1
            self.reply(200, DOCUMENT, {"Content-Type": "text/plain"})

        def do_POST(self):
            self.reply(405)
    return Resource


def probe(request):
    """Raw headers preserve duplicate-header tests; never follow redirects/retry."""
    started = time.perf_counter()
    try:
        connection = http.client.HTTPConnection(request.get("host", "127.0.0.1"),
                                                request.get("port", 8000), timeout=4)
        connection.putrequest(request.get("method", "GET"), request["path"])
        for name, value in request.get("headers", []):
            connection.putheader(name, value)
        data = request.get("payload")
        data = json.dumps(data).encode() if data is not None else None
        if data is not None:
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(data)))
        connection.endheaders(data)
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("oversize")
        result = {"status": response.status, "body_sha256": hashlib.sha256(body).hexdigest()}
        if request.get("private_control"):
            result["body"] = body.decode()
            result["handoff"] = response.getheader("X-PEP-Handoff")
        connection.close()
    except (OSError, ValueError, http.client.HTTPException):
        result = {"status": 0, "body_sha256": None}
    return result | {"elapsed_ms": (time.perf_counter() - started) * 1000}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["bridge", "resource", "probe", "rpc-probe"])
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--core-tls-profile", type=Path)
    args = parser.parse_args()
    def dispatch(request):
        if isinstance(request, list):
            with ThreadPoolExecutor(max_workers=8) as pool:
                return list(pool.map(probe, request))
        return probe(request)

    if args.mode == "rpc-probe":
        # Parent-only Docker exec pipe; no network listener or credential persistence.
        while line := sys.stdin.readline(1048577):
            if len(line) > 1048576 or not line.endswith("\n"):
                raise ValueError("probe_input_size")
            print(json.dumps(dispatch(json.loads(line))), flush=True)
        return
    if args.mode == "probe":
        print(json.dumps(dispatch(json.load(sys.stdin))))
        return
    secret = args.secret_file.read_text().strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", secret):
        raise ValueError("invalid_service_secret")
    if args.mode == "bridge":
        tickets = Handoffs()
        private = ThreadingHTTPServer(("0.0.0.0", 8082), consume_handler(secret, tickets))
        threading.Thread(target=private.serve_forever, daemon=True).start()
        handler = authorization_handler("http://core:8000", tickets, args.core_tls_profile)
        port = 8081
    else:
        handler, port = resource_handler("http://bridge:8082", secret), 8083
    ThreadingHTTPServer(("0.0.0.0", port), handler).serve_forever()


if __name__ == "__main__":
    main()
