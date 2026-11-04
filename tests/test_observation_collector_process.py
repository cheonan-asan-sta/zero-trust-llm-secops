"""Real collector processes and HTTP commit/ACK faults against a local Uvicorn API."""

import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest
import uvicorn
from fastapi import FastAPI

from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import InboxMissing, SignalInbox
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import install_zero_trust_error_handlers, zero_trust_router
from app.zero_trust_models import ProtectedAccessRequest, SessionEvaluationRequest

ROOT = Path(__file__).parents[1]
PRINCIPAL = Principal("collector-process-test", "tenant-a", frozenset({Role.ADMIN}), "api_key")


def wait_until(predicate, *, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.03)
    raise AssertionError("Collector process did not reach the expected durable state")


def run_cli(directory, *args, environment=None):
    result = subprocess.run(
        [sys.executable, "-m", "scripts.continuous_signal_collector", *args,
         "--directory", str(directory)], cwd=ROOT, env=environment or os.environ.copy(),
        capture_output=True, text=True, timeout=15, check=False,
    )
    return result


def cli_metadata(result):
    assert result.returncode == 0, "Collector CLI returned an unsuccessful exit code"
    assert "PRIVATE KEY" not in result.stdout + result.stderr
    return json.loads(result.stdout.splitlines()[-1])


@contextmanager
def collector_process(directory, base_url, *, environment=None):
    process = subprocess.Popen(
        [sys.executable, "-m", "scripts.continuous_signal_collector", "run",
         "--directory", str(directory), "--base-url", base_url, "--poll-seconds", "0.05"],
        cwd=ROOT, env=environment or os.environ.copy(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


@contextmanager
def running_api(application):
    # Pass a prebound socket to Uvicorn so selecting a free port has no race.
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        application, host="127.0.0.1", port=port, loop="asyncio", http="h11",
        lifespan="off", access_log=False, log_level="critical",
    ))
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    try:
        wait_until(lambda: server.started)
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=5)
        listener.close()


class FaultProxy(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, backend_port):
        self.backend_port = backend_port
        self.mode = "normal"
        self.requests = []
        self.lock = threading.Lock()
        self.committed = threading.Event()
        self.release_response = threading.Event()
        super().__init__(("127.0.0.1", 0), FaultHandler)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def records(self):
        with self.lock:
            return list(self.requests)


class FaultHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length < 65536:
            return self.reply(400, b"{}")
        raw = self.rfile.read(length)
        payload = json.loads(raw)
        # Keep only digests and synthetic IDs: never put signed payloads in test logs.
        record = {"event_id": payload.get("event_id"),
                  # JSON key ordering on the wire is not part of the signed
                  # contract. Include every field, including the signature, in
                  # this canonical envelope hash across disk restoration.
                  "payload_sha256": hashlib.sha256(json.dumps(
                      payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                  ).encode()).hexdigest(),
                  "logical_sha256": hashlib.sha256(json.dumps({
                      key: payload.get(key) for key in ("event_id", "observed_at", "observation")
                  }, sort_keys=True).encode()).hexdigest()}
        with self.server.lock:
            self.server.requests.append(record)
            mode = self.server.mode
        if mode == "outage":
            record["status"] = 503
            return self.reply(503, b'{"detail":"controlled outage"}')
        if mode == "false_ack":
            record["status"] = 202
            return self.reply(202, b'{"event_id":"wrong-event","state":"pending"}')
        connection = http.client.HTTPConnection("127.0.0.1", self.server.backend_port, timeout=5)
        try:
            connection.request("POST", self.path, body=raw,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(65536)
            status = response.status
        finally:
            connection.close()
        record["status"] = status
        if status == 202:
            self.server.committed.set()
        if mode == "block_ack" and status == 202:
            # The test kills the collector while its request is still waiting
            # for an ACK, rather than racing a completed local acknowledge.
            self.server.release_response.wait(timeout=8)
        if mode in {"drop_ack", "block_ack"} and status == 202:
            # The real receiver has committed. Close before any response reaches
            # the real collector, preserving an unknown transmission outcome.
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return None
        return self.reply(status, body)


@contextmanager
def proxy_to(backend_port):
    server = FaultProxy(backend_port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release_response.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def collector_lab(tmp_path):
    directory = tmp_path / "collector"
    environment = os.environ | {"APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule"}
    cli_metadata(run_cli(
        directory, "init", "--tenant", PRINCIPAL.tenant_id, "--source-id", "identity-collector",
        "--key-id", "key-1", "--kind", "identity", "--subject", "signed-user",
        environment=environment,
    ))
    operations = ZeroTrustOperations(
        tmp_path / "receiver.sqlite3", signal_verifier=SignalVerifier(directory / "sources.json"),
    )
    inbox = SignalInbox(operations.path)
    continuous = ContinuousSignalService(operations, inbox)
    application = FastAPI()
    application.include_router(zero_trust_router(operations, continuous))
    install_zero_trust_error_handlers(application)
    application.dependency_overrides[get_principal] = lambda: PRINCIPAL
    with running_api(application) as port, proxy_to(port) as proxy:
        yield SimpleNamespace(directory=directory, env=environment, operations=operations,
                              inbox=inbox, service=continuous, proxy=proxy)


def append_source(lab, event_id, *, active=False, authentication_result="failure", when=None):
    line = {"event_id": event_id,
            "observed_at": (when or datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
            "observation": {"kind": "identity", "subject_id": "signed-user", "active": active,
                            "authentication_result": authentication_result}}
    with (lab.directory / "input.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line) + "\n")
    return line


def receipt_if_present(lab, event_id):
    try:
        return lab.inbox.get(PRINCIPAL.tenant_id, event_id)
    except InboxMissing:
        return None


def initial_session(lab):
    now = datetime.now(UTC) - timedelta(seconds=2)
    event = synthetic_events()[0].model_copy(deep=True)
    event.event_id, event.timestamp = "process-initial-event", now
    event.user.user_id, event.user.role, event.user.active = "signed-user", "employee", True
    event.device.device_id, event.device.managed = "signed-device", True
    event.device.security_posture = "healthy"
    event.resource.resource_id = "zt-demo-documents"
    event.auth_context.authentication_result = event.auth_context.mfa = "success"
    return lab.operations.evaluate(SessionEvaluationRequest(
        session_id="process-session", expected_version=0, event=event,
    ), PRINCIPAL, now=now)


def assert_restricted_once(lab, token):
    while lab.service.process_one() is not None:
        pass
    history = lab.operations.history("process-session", PRINCIPAL)
    assert len(history) == 2 and history[-1].status == "REVOKED"
    denied = lab.operations.access(ProtectedAccessRequest(
        session_id="process-session", resource_id="zt-demo-documents", action="READ", grant_token=token,
    ), PRINCIPAL)
    assert not denied.allowed and denied.reason_code == "SESSION_NOT_AUTHORIZED"


def status(lab):
    return cli_metadata(run_cli(lab.directory, "status", "--base-url", lab.proxy.url,
                                environment=lab.env))


def wait_acknowledged(lab, count):
    return wait_until(lambda: status(lab)["acknowledged"] == count)


def test_cli_once_delivers_a_real_http_receipt_and_restart_does_not_resend(collector_lab):
    lab = collector_lab
    initial = initial_session(lab)
    append_source(lab, "process-risk")
    first = cli_metadata(run_cli(lab.directory, "run", "--base-url", lab.proxy.url,
                                  "--once", environment=lab.env))
    assert first["collector"] == "acknowledged"
    assert status(lab)["acknowledged"] == 1
    assert receipt_if_present(lab, "process-risk")["state"] == "pending"
    count = len(lab.proxy.records())
    restarted = cli_metadata(run_cli(lab.directory, "run", "--base-url", lab.proxy.url,
                                      "--once", environment=lab.env))
    assert restarted["collector"] == "idle" and len(lab.proxy.records()) == count
    assert_restricted_once(lab, initial.grant_token)


def test_kill_after_api_commit_replays_exact_envelope_then_captures_next_source_line(collector_lab):
    lab = collector_lab
    initial = initial_session(lab)
    append_source(lab, "process-risk")
    lab.proxy.mode = "block_ack"
    with collector_process(lab.directory, lab.proxy.url, environment=lab.env) as process:
        assert lab.proxy.committed.wait(timeout=10)
        assert receipt_if_present(lab, "process-risk") is not None
        # Append while the first transmission is still pending. A restart must
        # neither overwrite its signed bytes nor skip this source checkpoint.
        append_source(lab, "process-positive", active=True, authentication_result="success")
        process.kill()
        process.wait(timeout=10)
    lab.proxy.release_response.set()
    assert status(lab)["acknowledged"] == 0
    lab.proxy.mode = "normal"
    with collector_process(lab.directory, lab.proxy.url, environment=lab.env):
        wait_acknowledged(lab, 2)
    assert status(lab)["captured"] == 2
    risk = [record for record in lab.proxy.records() if record["event_id"] == "process-risk"]
    assert len(risk) >= 2
    assert len({record["payload_sha256"] for record in risk}) == 1
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 2
    assert status(lab)["offset"] == (lab.directory / "input.jsonl").stat().st_size
    assert_restricted_once(lab, initial.grant_token)


def test_network_outage_keeps_payload_and_checkpoint_until_real_receipt(collector_lab):
    lab = collector_lab
    append_source(lab, "process-outage")
    lab.proxy.mode = "outage"
    failed = run_cli(lab.directory, "run", "--base-url", lab.proxy.url,
                     "--once", environment=lab.env)
    assert failed.returncode == 1
    assert receipt_if_present(lab, "process-outage") is None
    checkpoint = status(lab)
    assert checkpoint["captured"] == checkpoint["pending"] == 1
    assert checkpoint["acknowledged"] == 0
    lab.proxy.mode = "normal"
    with collector_process(lab.directory, lab.proxy.url, environment=lab.env):
        wait_acknowledged(lab, 1)
    assert len({record["payload_sha256"] for record in lab.proxy.records()}) == 1
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 1
    assert status(lab)["offset"] == checkpoint["offset"]


def test_forged_202_does_not_acknowledge_or_advance_delivery(collector_lab):
    lab = collector_lab
    append_source(lab, "process-forged-ack")
    lab.proxy.mode = "false_ack"
    result = run_cli(lab.directory, "run", "--base-url", lab.proxy.url,
                     "--once", environment=lab.env)
    assert result.returncode == 1
    metadata = status(lab)
    assert metadata["captured"] == metadata["pending"] == 1
    assert metadata["acknowledged"] == 0
    assert receipt_if_present(lab, "process-forged-ack") is None


def test_cli_loopback_delivery_does_not_use_environment_proxy(collector_lab):
    lab = collector_lab
    append_source(lab, "process-no-env-proxy")
    with proxy_to(lab.proxy.backend_port) as trap:
        trap.mode = "outage"
        environment = lab.env | {
            "HTTP_PROXY": trap.url, "http_proxy": trap.url,
            "HTTPS_PROXY": trap.url, "https_proxy": trap.url, "NO_PROXY": "", "no_proxy": "",
        }
        cli_metadata(run_cli(lab.directory, "run", "--base-url", lab.proxy.url,
                             "--once", environment=environment))
        assert trap.records() == []
    assert status(lab)["acknowledged"] == 1


def test_previously_unreceived_old_envelope_reseals_as_persisted_variant_over_real_http(collector_lab):
    from scripts.continuous_signal_collector import ContinuousCollector

    lab = collector_lab
    initial = initial_session(lab)
    old = datetime.now(UTC) - timedelta(seconds=70)
    registry_path = lab.directory / "sources.json"
    registry = json.loads(registry_path.read_text("utf-8"))
    registry["sources"][0]["keys"][0]["not_before"] = (old - timedelta(days=1)).isoformat()
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    append_source(lab, "process-aged", when=old - timedelta(seconds=1))
    prepared = ContinuousCollector(lab.directory, lab.proxy.url, clock=lambda: old,
                                   transport=lambda *args, **kwargs: (503, {}))
    assert prepared.capture_one()
    assert prepared.deliver_one() == "retry"
    assert receipt_if_present(lab, "process-aged") is None
    # The actual CLI uses the current clock and real HTTP. Its first old envelope
    # must be rejected, then a separately persisted fresh envelope may be accepted.
    result = cli_metadata(run_cli(lab.directory, "run", "--base-url", lab.proxy.url,
                                  "--once", environment=lab.env))
    assert result["collector"] == "acknowledged"
    records = lab.proxy.records()
    assert len(records) == 2 and len({record["payload_sha256"] for record in records}) == 2
    assert len({record["logical_sha256"] for record in records}) == 1
    assert status(lab)["captured"] == status(lab)["acknowledged"] == 1
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 1
    assert_restricted_once(lab, initial.grant_token)


def test_restart_probes_persisted_old_variant_after_new_variant_gets_real_409(collector_lab, monkeypatch):
    from app.continuous_signal_models import SignedContinuousSignal
    from scripts.continuous_signal_collector import ContinuousCollector, post_observation

    lab = collector_lab
    initial = initial_session(lab)
    old = datetime.now(UTC) - timedelta(seconds=70)
    clock = [old]
    registry_path = lab.directory / "sources.json"
    registry = json.loads(registry_path.read_text("utf-8"))
    registry["sources"][0]["keys"][0]["not_before"] = (old - timedelta(days=1)).isoformat()
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    append_source(lab, "process-variant-race", when=old - timedelta(seconds=1))
    prepared = ContinuousCollector(lab.directory, lab.proxy.url, clock=lambda: clock[0],
                                   transport=lambda *args, **kwargs: (503, {}))
    assert prepared.capture_one() and prepared.deliver_one() == "retry"
    delivery = prepared.spool.next_pending(now=datetime.now(UTC))
    old_envelope = delivery["envelopes"][0]
    # Advance only the receiving service's injected clock for this first arrival.
    # This represents an old in-flight request accepted within its freshness
    # window, without sleeping 70 seconds or bypassing HTTP/signature validation.
    accept = lab.service.accept

    def accept_at_original_time(signal, principal, **kwargs):
        return accept(signal, principal, now=old)

    monkeypatch.setattr(lab.service, "accept", accept_at_original_time)
    lab.proxy.mode = "drop_ack"
    with pytest.raises((OSError, URLError, http.client.HTTPException)):
        post_observation(lab.proxy.url, old_envelope)
    assert lab.proxy.committed.is_set()
    monkeypatch.setattr(lab.service, "accept", accept)
    clock[0] = datetime.now(UTC)
    fresh = prepared._envelope(delivery["event"])
    prepared.spool.stage(delivery["event_id"], fresh)
    # The first accepted immutable payload is still the old variant. Restart
    # cannot treat the new variant's conflict as an acknowledgement.
    first = SignedContinuousSignal.model_validate(old_envelope)
    assert first.observed_at == datetime.fromisoformat(fresh["observed_at"])
    prior_count = len(lab.proxy.records())
    lab.proxy.mode = "normal"
    result = cli_metadata(run_cli(lab.directory, "run", "--base-url", lab.proxy.url,
                                  "--once", environment=lab.env))
    assert result["collector"] == "acknowledged"
    sent = lab.proxy.records()[prior_count:]
    assert [record["status"] for record in sent] == [409, 202]
    assert len({record["logical_sha256"] for record in sent}) == 1
    assert status(lab)["acknowledged"] == status(lab)["captured"] == 1
    assert lab.inbox.metrics(PRINCIPAL.tenant_id)["total"] == 1
    assert_restricted_once(lab, initial.grant_token)
