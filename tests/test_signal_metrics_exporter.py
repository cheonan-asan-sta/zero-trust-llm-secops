import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest

from scripts import signal_metrics_exporter as exporter
from scripts.observability_lab import notification_seen


@pytest.fixture
def summary():
    return {"pending": 1, "processing": 0, "completed": 2, "failed": 0, "total": 3,
            "oldest_pending_age_seconds": 4.5, "oldest_processing_age_seconds": None}


@contextmanager
def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_export_is_aggregate_and_never_includes_identity_or_secret(summary):
    summary.update(user_id="sensitive-user", signature="private-data", api_key="secret-value")
    text = exporter.render_summary(summary)
    assert 'secops_signal_inbox_records{state="pending"} 1' in text
    assert 'secops_signal_inbox_oldest_pending_age_seconds 4.5' in text
    assert 'secops_signal_inbox_oldest_processing_age_seconds 0' in text
    assert all(value not in text for value in ["sensitive-user", "private-data", "secret-value"])


@pytest.mark.parametrize("field,value", [
    ("pending", True), ("pending", -1), ("pending", "1"), ("pending", 100001),
    ("total", True), ("total", 4), ("oldest_pending_age_seconds", None),
    ("oldest_pending_age_seconds", float("nan")), ("oldest_pending_age_seconds", float("inf")),
    ("oldest_pending_age_seconds", -1), ("oldest_pending_age_seconds", True),
])
def test_invalid_state_cannot_be_exported_as_healthy(summary, field, value):
    summary[field] = value
    with pytest.raises((ValueError, TypeError)):
        exporter.render_summary(summary)


def test_failed_poll_does_not_reuse_previous_good_values(summary):
    assert 'collection_success 1' in exporter.metrics("unused", "secret", lambda *_: exporter.render_summary(summary))

    def failing(*_):
        raise OSError("sensitive-server-error-with-secret")
    result = exporter.metrics("unused", "secret", failing)
    assert 'collection_success 0' in result
    assert 'inbox_records' not in result
    assert 'secret' not in result


@pytest.mark.parametrize("url", [
    "file:///zero-trust/signals/inbox", "http://user:password@example.com/zero-trust/signals/inbox",
    "https://example.com/analysis", "http://example.com/zero-trust/signals/inbox?token=secret",
    "http://example.com/zero-trust/signals/inbox#fragment",
])
def test_upstream_is_a_fixed_read_only_endpoint(url):
    with pytest.raises(ValueError):
        exporter.validate_upstream(url)


def test_authentication_rejects_missing_wrong_and_unusual_headers():
    assert exporter.authorized("Bearer expected", "expected")
    assert not exporter.authorized(None, "expected")
    assert not exporter.authorized("Bearer wrong", "expected")
    assert not exporter.authorized("Bearer 한글", "expected")
    assert not exporter.authorized("Bearer " + "x" * 1000, "expected")


def test_new_fault_cannot_pass_using_old_startup_notifications():
    old = [{"alertname": "C01ExporterDown", "status": "firing"},
           {"alertname": "C01ExporterDown", "status": "resolved"}]
    assert not notification_seen(old, "C01ExporterDown", "firing", 2)
    assert not notification_seen(old, "C01ExporterDown", "resolved", 2)
    new = old + [{"alertname": "C01ExporterDown", "status": "firing"}]
    assert notification_seen(new, "C01ExporterDown", "firing", 2)
    assert not notification_seen(new, "C01ExporterDown", "resolved", 2)
    assert not notification_seen(new, "C01SignalQueueBacklog", "firing", 2)
    with pytest.raises(ValueError):
        notification_seen(new, "C01ExporterDown", "firing", -1)


def test_resolution_is_bound_to_the_same_instance_and_alert_lifecycle():
    binding = {"instance": "exporter:9101", "fingerprint": "new", "starts_at": "second"}
    events = [
        {"alertname": "C01ExporterDown", "status": "resolved", "instance": None,
         "fingerprint": "startup", "starts_at": "first"},
        {"alertname": "C01ExporterDown", "status": "resolved", "instance": "exporter:9101",
         "fingerprint": "new", "starts_at": "first"},
    ]
    assert not notification_seen(events, "C01ExporterDown", "resolved", 0, binding)
    events.append({"alertname": "C01ExporterDown", "status": "resolved", **binding})
    assert notification_seen(events, "C01ExporterDown", "resolved", 0, binding)
    assert not notification_seen(events, "C01ExporterDown", "resolved", 3, binding)


def test_new_experiment_replaces_old_success_before_preparation(tmp_path, monkeypatch):
    from scripts import compare_observability as comparison

    directory = tmp_path / "runtime/c01"
    directory.mkdir(parents=True)
    (directory / "summary.json").write_text('{"completed":true,"runs":["old"]}', encoding="utf-8")
    (tmp_path / "infra/observability").mkdir(parents=True)
    (tmp_path / "infra/observability/tools.lock.json").write_text('{"tools":[]}', encoding="utf-8")
    monkeypatch.setattr(comparison, "ROOT", tmp_path)
    monkeypatch.setattr(comparison, "command", lambda *_args, **_kwargs: "frozen-commit\n")
    comparison.Lab(directory)
    current = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    assert current["completed"] is False
    assert current["runs"] == []
    assert current["source_commit"] == "frozen-commit"


def upstream(summary, observations, *, redirect=None, oversized=False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            observations.append(self.headers.get("X-API-Key"))
            body = b"x" * (exporter.MAX_BODY + 1) if oversized else json.dumps(summary).encode()
            self.send_response(302 if redirect else 200)
            if redirect:
                self.send_header("Location", redirect)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


def test_redirect_never_forwards_upstream_credential(summary):
    received = []
    with (
        serve(upstream(summary, received)) as destination,
        serve(upstream(summary, [], redirect=destination + "/zero-trust/signals/inbox")) as origin,
        pytest.raises(HTTPError),
    ):
        exporter.fetch_summary(origin + "/zero-trust/signals/inbox", "viewer-only-key")
    assert received == []


def test_oversized_upstream_response_is_unavailable(summary):
    with serve(upstream(summary, [], oversized=True)) as origin:
        text = exporter.metrics(origin + "/zero-trust/signals/inbox", "viewer-only-key")
    assert "collection_success 0" in text
    assert "inbox_records" not in text


def test_real_http_server_authenticates_before_reading_upstream(summary):
    received = []
    opener = build_opener(ProxyHandler({}))
    with (
        serve(upstream(summary, received)) as origin,
        serve(exporter.handler(origin + "/zero-trust/signals/inbox", "viewer-only-key", "scrape-token")) as server,
    ):
        for header in [None, "Bearer wrong"]:
            request = Request(server + "/metrics", headers={"Authorization": header} if header else {})
            with pytest.raises(HTTPError) as error:
                opener.open(request, timeout=2)
            assert error.value.code == 401
            assert error.value.read() == b""
        assert received == []
        request = Request(server + "/metrics", headers={"Authorization": "Bearer scrape-token"})
        with opener.open(request, timeout=2) as response:
            assert response.code == 200
            assert b"collection_success 1" in response.read()
        with pytest.raises(HTTPError) as rejected:
            opener.open(Request(server + "/metrics", data=b"{}", headers={"Authorization": "Bearer scrape-token"}), timeout=2)
        assert rejected.value.code == 501
    assert received == ["viewer-only-key"]
