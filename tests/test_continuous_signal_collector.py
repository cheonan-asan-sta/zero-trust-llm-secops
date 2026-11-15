"""Authority, input durability and ambiguous delivery boundaries of the collector."""

import json
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.continuous_signal_models import SignedContinuousSignal
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import InboxConflict, SignalInbox
from app.services.trusted_signals import SignalRejected, SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
from scripts import continuous_signal_collector as module


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "get_settings", lambda: SimpleNamespace(app_environment="test"))
    directory = tmp_path / "observer"
    module.initialize(directory, "tenant-a", "identity", "key-1", "identity", ["user-a"])
    now = datetime.now(UTC)
    record = {"event_id": "source-event", "observed_at": now.isoformat(),
              "observation": {"kind": "identity", "subject_id": "user-a", "active": False,
                              "authentication_result": "failure"}}
    feed = directory / "input.jsonl"
    feed.write_text(json.dumps(record) + "\n", encoding="utf-8")
    clock = [now]
    verifier = SignalVerifier(directory / "sources.json")
    operations = ZeroTrustOperations(tmp_path / "server.sqlite3", signal_verifier=verifier)
    service = ContinuousSignalService(operations, SignalInbox(operations.path))
    calls = []

    def send(_base, envelope, **_kwargs):
        calls.append(json.loads(json.dumps(envelope)))
        try:
            result = service.accept(SignedContinuousSignal.model_validate(envelope),
                                    collector.principal, now=clock[0])
            return 202, result
        except SignalRejected:
            return 401, {}
        except InboxConflict:
            return 409, {}

    collector = module.ContinuousCollector(directory, "http://127.0.0.1:18080",
                                            clock=lambda: clock[0], transport=send)
    return SimpleNamespace(directory=directory, now=now, record=record, feed=feed, clock=clock,
                           collector=collector, service=service, calls=calls, send=send)


def test_lost_ack_replays_exact_envelope_even_after_freshness_window(lab):
    def lost(*args, **kwargs):
        lab.send(*args, **kwargs)
        raise OSError("private details must never be retained")

    lab.collector.transport = lost
    assert lab.collector.capture_one()
    assert lab.collector.deliver_one() == "retry"
    original = lab.calls[0]
    lab.clock[0] += timedelta(seconds=180)
    lab.collector.transport = lab.send
    assert lab.collector.deliver_one() == "acknowledged"
    assert lab.calls == [original, original]
    assert lab.service.inbox.metrics("tenant-a")["total"] == 1
    assert lab.collector.spool.summary()["acknowledged"] == 1
    assert "private details" not in json.dumps(lab.collector.spool.summary())


def test_old_inflight_variant_is_reconciled_when_new_variant_conflicts(lab):
    assert lab.collector.capture_one()
    original = lab.collector._envelope(lab.collector.spool.next_pending(now=lab.now)["event"])
    lab.collector.spool.stage("source-event", original)
    lab.clock[0] += timedelta(seconds=70)
    first = True

    def race(base, envelope, **kwargs):
        nonlocal first
        if first:
            first = False
            # An earlier request validated at t0, but commits after the new
            # replay has observed 401. Its immutable envelope wins the event ID.
            lab.service.accept(SignedContinuousSignal.model_validate(original),
                               lab.collector.principal, now=lab.now)
            return 401, {}
        return lab.send(base, envelope, **kwargs)

    lab.collector.transport = race
    assert lab.collector.deliver_one() == "acknowledged"
    assert lab.calls[0]["issued_at"] != original["issued_at"]  # New variant was 409.
    assert lab.calls[1] == original  # Exact old variant was 202.
    assert lab.service.inbox.metrics("tenant-a")["total"] == 1


def test_revoked_authority_does_not_refresh_or_send_pending_envelope(lab):
    assert lab.collector.capture_one()
    envelope = lab.collector._envelope(lab.collector.spool.next_pending(now=lab.now)["event"])
    lab.collector.spool.stage("source-event", envelope)
    registry = lab.directory / "sources.json"
    data = json.loads(registry.read_text())
    data["sources"][0]["enabled"] = False
    registry.write_text(json.dumps(data))
    lab.clock[0] += timedelta(seconds=70)
    assert lab.collector.deliver_one() == "retry"
    assert lab.calls == []
    row = lab.collector.spool.next_pending(now=lab.clock[0] + timedelta(seconds=2))
    assert row["envelopes"] == [envelope]
    assert lab.collector.spool.summary()["acknowledged"] == 0


def test_unresolved_conflict_keeps_original_event_and_capture_evidence(lab):
    lab.collector.capture_one()
    lab.collector.transport = lambda *_args, **_kwargs: (409, {})
    assert lab.collector.deliver_one() == "retry"
    row = lab.collector.spool.next_pending(now=lab.now + timedelta(seconds=2))
    assert row["event_id"] == "source-event" and len(row["envelopes"]) == 1
    assert lab.collector.spool.summary()["pending"] == 1


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "another-tenant"), ("event_id", "different-event"),
    ("state", "invented"), ("duplicate", "false"),
])
def test_wrong_202_receipt_does_not_acknowledge(lab, field, value):
    receipt = {"tenant_id": "tenant-a", "event_id": "source-event", "state": "pending",
               "duplicate": False, field: value}
    lab.collector.transport = lambda *_args, **_kwargs: (202, receipt)
    lab.collector.capture_one()
    assert lab.collector.deliver_one() == "retry"
    assert lab.collector.spool.summary()["pending"] == 1


def test_partial_line_waits_and_same_source_event_is_captured_once(lab):
    data = lab.feed.read_bytes()
    lab.feed.write_bytes(data[:-1])
    assert not lab.collector.capture_one()
    assert lab.collector.spool.checkpoint()["offset"] == 0
    with lab.feed.open("ab") as file:
        file.write(b"\n" + data)
    assert lab.collector.capture_one()
    assert not lab.collector.capture_one()  # Duplicate occurrence, cursor still advances.
    assert lab.collector.spool.summary()["captured"] == 1
    assert lab.collector.spool.checkpoint()["offset"] == len(data) * 2


@pytest.mark.parametrize("replacement", [b"", b"changed\n"])
def test_captured_prefix_truncation_or_rewrite_stops_without_reset(lab, replacement):
    lab.collector.capture_one()
    original = lab.collector.spool.checkpoint()
    lab.feed.write_bytes(replacement)
    with pytest.raises(ValueError, match="prefix changed"):
        lab.collector.capture_one()
    assert lab.collector.spool.checkpoint() == original
    assert lab.collector.spool.summary()["pending"] == 1


@pytest.mark.parametrize("change", ["scope", "future", "extra", "invalid"])
def test_bad_source_input_never_advances_capture_cursor(lab, change):
    record = lab.record.copy()
    if change == "scope":
        record["observation"] = {**record["observation"], "subject_id": "outside-scope"}
    elif change == "future":
        record["observed_at"] = (lab.now + timedelta(seconds=1)).isoformat()
    elif change == "extra":
        record["mfa"] = "success"
    line = "bad-json\n" if change == "invalid" else json.dumps(record) + "\n"
    lab.feed.write_text(line)
    with pytest.raises(ValueError):
        lab.collector.capture_one()
    assert lab.collector.spool.checkpoint()["offset"] == 0


def test_process_lock_prevents_two_active_senders(lab):
    with (module.exclusive_collector(lab.directory), pytest.raises(OSError),
          module.exclusive_collector(lab.directory)):
        pytest.fail("second sender must not own the spool")


def test_production_refused_before_creating_a_spool(tmp_path, monkeypatch):
    directory = tmp_path / "production"
    module.initialize(directory, "tenant-a", "identity", "key-1", "identity", ["user-a"])
    monkeypatch.setattr(module, "get_settings", lambda: SimpleNamespace(app_environment="production"))
    with pytest.raises(ValueError, match="local/test"):
        module.ContinuousCollector(directory, "http://127.0.0.1:18080")
    assert not (directory / "state.sqlite3").exists()


def test_device_source_sends_only_device_observations(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "get_settings", lambda: SimpleNamespace(app_environment="test"))
    directory = tmp_path / "device"
    module.initialize(directory, "tenant-a", "device", "key-1", "device", ["device-a"])
    record = {"event_id": "device-event", "observed_at": datetime.now(UTC).isoformat(),
              "observation": {"kind": "device", "subject_id": "device-a", "managed": False,
                              "security_posture": "compromised"}}
    (directory / "input.jsonl").write_text(json.dumps(record) + "\n")
    collector = module.ContinuousCollector(directory, "http://127.0.0.1:18080")
    assert collector.capture_one()
    envelope = collector._envelope(collector.spool.next_pending(now=datetime.now(UTC))["event"])
    assert envelope["observation"] == record["observation"]
    assert envelope["source_id"] == "device"


def test_initializer_does_not_replace_existing_keys(lab):
    before = (lab.directory / "private.pem").read_bytes()
    with pytest.raises(FileExistsError):
        module.initialize(lab.directory, "tenant-a", "identity", "key-1", "identity", ["user-a"])
    assert (lab.directory / "private.pem").read_bytes() == before


def test_backoff_prevents_a_retry_spin(lab):
    lab.collector.transport = lambda *_args, **_kwargs: (503, {})
    lab.collector.capture_one()
    assert lab.collector.deliver_one() == "retry"
    assert lab.collector.deliver_one() == "idle"
    lab.clock[0] += timedelta(seconds=1)
    assert lab.collector.deliver_one() == "retry"


def test_mtls_uses_bound_profile_canonical_payload_and_no_http_fallback(tmp_path, monkeypatch):
    from scripts import mtls_transport

    monkeypatch.setattr(module, "get_settings", lambda: SimpleNamespace(app_environment="test"))
    directory = tmp_path / "tls-collector"
    module.initialize(directory, "tenant-a", "identity", "key-1", "identity", ["user-a"])
    tls_profile = tmp_path / "client.json"
    tls_profile.write_text(json.dumps({"host": "gateway", "port": 8443}))
    record = {"event_id": "tls-event", "observed_at": datetime.now(UTC).isoformat(),
              "observation": {"kind": "identity", "subject_id": "user-a", "active": False,
                              "authentication_result": "failure"}}
    (directory / "input.jsonl").write_text(json.dumps(record) + "\n")
    calls = []

    def send(profile, path, payload, headers):
        calls.append((profile, path, payload, headers))
        return 202, json.dumps({"tenant_id": "tenant-a", "event_id": "tls-event",
                                "state": "pending", "duplicate": False}).encode()

    monkeypatch.setattr(mtls_transport, "request", send)
    monkeypatch.setattr(module, "build_opener", lambda *_: pytest.fail("HTTP fallback"))
    monkeypatch.setenv("SIGNAL_COLLECTOR_API_KEY", "test-only-analyst-key")
    collector = module.ContinuousCollector(directory, "https://gateway:8443", tls_profile=tls_profile)
    collector.capture_one()
    assert collector.deliver_one() == "acknowledged"
    profile, path, payload, headers = calls[0]
    assert profile == tls_profile and path == module.INBOX
    assert payload == json.dumps(json.loads(payload), sort_keys=True, ensure_ascii=False,
                                 separators=(",", ":")).encode()
    assert headers == {"X-API-Key": "test-only-analyst-key"}
    assert b"test-only-analyst-key" not in (directory / "state.sqlite3").read_bytes()
    def tls_failure(*_args):
        raise ssl.SSLError("server_pin_rejected")

    monkeypatch.setattr(mtls_transport, "request", tls_failure)
    with pytest.raises(ssl.SSLError):
        module.post_observation("https://gateway:8443", {}, tls_profile=tls_profile)


@pytest.mark.parametrize("url", ["http://example.com", "https://127.0.0.1", "http://u:p@localhost"])
def test_transport_rejects_wrong_destination_before_credentials_are_sent(monkeypatch, url):
    monkeypatch.setattr(module, "build_opener", lambda *_: pytest.fail("unexpected send"))
    with pytest.raises(ValueError):
        module.post_observation(url, {})
