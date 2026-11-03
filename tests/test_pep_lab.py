"""Boundary regressions for C02; detector/policy behavior remains unchanged."""

import json
import secrets
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

import pytest

from scripts import pep_lab as pep


@contextmanager
def server(handler):
    instance = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance.server_port
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join()


def decision(**changes):
    return json.dumps({"allowed": True, "reason_code": "ACCESS_GRANTED", "session_version": 1,
                       "enforcement_mode": "local_simulation", **changes}).encode()


@pytest.mark.parametrize("changes", [
    {"allowed": "true"}, {"allowed": 1}, {"allowed": False}, {"session_version": True},
    {"session_version": 0}, {"session_version": None}, {"session_version": "1"},
    {"reason_code": "ALLOW"}, {"enforcement_mode": "production"}])
def test_unexpected_core_allow_shape_fails_closed(changes):
    with pytest.raises(ValueError):
        pep.strict_allow(200, decision(**changes))


@pytest.mark.parametrize("status", [201, 204, 301, 302, 401, 403, 404, 429, 500, 503])
def test_only_exact_200_can_allow(status):
    assert pep.strict_allow(status, decision()) is None


@pytest.mark.parametrize("body", [b"null", b"[]", b"{", b"{}"])
def test_bad_core_json_fails_closed(body):
    with pytest.raises(ValueError):
        pep.strict_allow(200, body)


def test_ticket_expiry_binding_capacity_restart_and_no_plaintext_storage():
    now = [10.0]
    tickets = pep.Handoffs(clock=lambda: now[0], capacity=1)
    token = tickets.issue("session-one", 1)
    assert token not in repr(tickets.entries)
    with pytest.raises(ValueError):
        tickets.issue("session-two", 2)
    assert not tickets.consume(token, "GET", "/other")
    assert not tickets.consume(token, "GET", "/documents")  # mismatch burns the ticket
    token = tickets.issue("session-two", 2)
    now[0] += 3
    assert not tickets.consume(token, "GET", "/documents")  # exact expiry boundary
    token = tickets.issue("session-three", 3)
    assert not pep.Handoffs().consume(token, "GET", "/documents")


def test_concurrent_ticket_consumption_exactly_once():
    from concurrent.futures import ThreadPoolExecutor
    tickets = pep.Handoffs()
    token = tickets.issue("session-one", 1)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: tickets.consume(token, "GET", pep.PATH), range(32)))
    assert sum(results) == 1


def headers():
    return [("X-API-Key", "k" * 43), ("X-Session-ID", "session-one"), ("X-Grant-Token", "g" * 43)]


@pytest.mark.parametrize("variant", ["missing", "duplicate", "comma", "space", "oversize", "path", "post"])
def test_auth_bridge_rejects_untrusted_input_before_core(monkeypatch, variant):
    def never(*args):
        pytest.fail("Invalid input must not reach core")
    monkeypatch.setattr(pep, "upstream", never)
    request = {"path": pep.PATH, "headers": headers()}
    if variant == "missing":
        request["headers"].pop()
    elif variant == "duplicate":
        request["headers"].append(request["headers"][0])
    elif variant in {"comma", "space", "oversize"}:
        request["headers"][0] = ("X-API-Key", {"comma": "k" * 43 + ",x", "space": "x y",
                                                           "oversize": "x" * 129}[variant])
    elif variant == "path":
        request["path"] += "?resource=secret"
    else:
        request["method"] = "POST"
    with server(pep.authorization_handler("http://core", pep.Handoffs())) as port:
        assert pep.probe(request | {"port": port})["status"] in {403, 405}


@pytest.mark.parametrize("failure", ["timeout", "redirect", "malformed", "truthy", "capacity"])
def test_auth_bridge_failure_never_emits_handoff(monkeypatch, failure):
    def core(*args):
        if failure == "timeout":
            raise TimeoutError()
        return {"redirect": (302, decision()), "malformed": (200, b"null"),
                "truthy": (200, decision(allowed="yes")), "capacity": (200, decision())}[failure]
    monkeypatch.setattr(pep, "upstream", core)
    tickets = pep.Handoffs(capacity=0 if failure == "capacity" else 1024)
    with server(pep.authorization_handler("http://core", tickets)) as port:
        assert pep.probe({"port": port, "path": pep.PATH, "headers": headers()})["status"] == 503
    assert not tickets.entries


def test_resource_needs_private_authenticated_atomic_consume(monkeypatch):
    secret, tickets = secrets.token_urlsafe(32), pep.Handoffs()
    with server(pep.consume_handler(secret, tickets)) as port:
        consume_url = f"http://127.0.0.1:{port}"
        with server(pep.resource_handler(consume_url, secret)) as resource:
            token = tickets.issue("session-one", 1)
            request = {"port": resource, "path": pep.PATH, "headers": [("X-PEP-Handoff", token)]}
            # Possession of the ticket alone cannot call the private consumption service.
            status, _ = pep.upstream(consume_url + "/consume", {
                "token": token, "method": "GET", "path": pep.PATH}, {"Authorization": "Bearer " + "a" * 43})
            assert status == 403
            assert pep.probe(request)["body_sha256"] == pep.DOCUMENT_HASH
            assert pep.probe(request)["status"] == 403
            assert pep.probe(request | {"headers": [("X-PEP-Handoff", "a" * 43)]})["status"] == 403
            assert pep.probe(request | {"headers": []})["status"] == 403
            def unavailable(*args):
                raise TimeoutError()
            monkeypatch.setattr(pep, "upstream", unavailable)
            request["headers"] = [("X-PEP-Handoff", tickets.issue("session-two", 2))]
            assert pep.probe(request)["status"] == 503


def test_persistent_probe_frames_separate_requests_without_disclosing_capabilities():
    class Fixture(pep.QuietHandler):
        def do_GET(self):
            self.reply(403 if self.path == "/deny" else 200, b"fixture", {"X-PEP-Handoff": "secret-fixture"})
    with server(Fixture) as port:
        requests = [{"port": port, "path": "/deny"}, {"port": port, "path": "/allow"}]
        process = subprocess.run([sys.executable, "-m", "scripts.pep_lab", "rpc-probe"],
            input="".join(json.dumps(req) + "\n" for req in requests), capture_output=True,
            text=True, timeout=10, check=True)
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        assert [row["status"] for row in responses] == [403, 200]
        assert "secret-fixture" not in process.stdout
        assert all("body" not in row and "handoff" not in row for row in responses)
