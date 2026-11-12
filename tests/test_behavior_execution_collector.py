"""Execution evidence collector: authenticated receipt, durable replay and protected feed."""

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.behavior_context_api import behavior_context_router
from app.security import get_principal
from app.services.trusted_signals import SignalRejected, canonical_behavior_capture
from scripts import behavior_execution_collector as module
from scripts.m7_context_dataset import build_dataset
from scripts.m7_context_runtime import ContextLab


@pytest.fixture
def lab(tmp_path, monkeypatch):
    inputs, labels = build_dataset(repetitions=1)
    identifier = next(row["case_id"] for row in labels if row["family"] == "approved_upload")
    spec = next(row for row in inputs if row["case_id"] == identifier)
    runtime = ContextLab(spec, tmp_path / "app")
    runtime.prepare_context()
    capture = runtime.capture(spec["target"])
    clock = SimpleNamespace(now=runtime.at(11))
    directory = tmp_path / "collector"
    module.initialize(directory, runtime.tenant, "execution-observer", "key-1",
                      [runtime.scope.model_dump(mode="json")], now=clock.now)
    registry = json.loads(runtime.registry.read_text())
    registry["sources"] += json.loads((directory / "sources.json").read_text())["sources"]
    runtime.registry.write_text(json.dumps(registry))

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock.now.astimezone(tz) if tz else clock.now.replace(tzinfo=None)

    monkeypatch.setattr("app.services.behavior_context.datetime", Clock)
    application = FastAPI()
    application.include_router(behavior_context_router(runtime.service))
    application.dependency_overrides[get_principal] = lambda: runtime.operator
    client = TestClient(application)
    sent = []

    def transport(base_url, payload, *, tls_profile=None):
        sent.append(json.loads(json.dumps(payload)))
        response = client.post(module.ENDPOINT, json=payload)
        return response.status_code, response.json()

    record = {
        "evidence_id": "execution-record-1", "observed_at": clock.now.isoformat(),
        "scope": runtime.scope.model_dump(mode="json"),
        "session_id": capture.session_id, "session_version": capture.session_version,
        "session_input_sha256": capture.session_input_sha256,
        "capture_id": capture.capture_id,
        "capture_input_sha256": hashlib.sha256(canonical_behavior_capture(capture)).hexdigest(),
        "event_ids": [event.id for event in capture.activity.events],
        "connection_ids": capture.connection_ids,
        "actor": {"principal_id": runtime.scope.user_id, "workload_id": "backup-job",
                  "executable_sha256": "4" * 64},
        "destinations": [{"kind": "https", "host": "archive.example.test", "port": 443,
                          "path": "/approved-backup"}],
    }

    def collector(**options):
        return module.ExecutionCollector(directory, "http://127.0.0.1:18080",
                                         clock=lambda: clock.now, transport=options.pop("transport", transport),
                                         **options)

    return SimpleNamespace(directory=directory, runtime=runtime, record=record, clock=clock,
                           collector=collector, sent=sent, transport=transport, client=client)


def stored(lab):
    with sqlite3.connect(lab.directory / "execution-spool.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute("SELECT * FROM records ORDER BY seq")]


def test_actual_api_receipt_is_bound_and_missing_fields_remain_missing(lab):
    record = lab.record | {"actor": None, "destinations": None}
    collector = lab.collector()
    queued = collector.enqueue(record)
    assert collector.send_once()["state"] == "acknowledged"
    assert collector.status()["acknowledged"] == 1
    assert lab.sent[0]["actor"] is None and lab.sent[0]["destinations"] is None
    records = [entry for entry in lab.runtime.store.read(lab.runtime.tenant) if entry["kind"] == "execution"]
    assert len(records) == 1 and records[0]["payload"]["input_digest"] == queued["input_digest"]
    assert collector.enqueue(record)["duplicate"] is True
    assert collector.send_once()["state"] == "idle"


def test_lost_response_restart_replays_exact_bytes_and_receiver_deduplicates(lab):
    def lost(base_url, payload, **options):
        status, receipt = lab.transport(base_url, payload, **options)
        assert status == 201 and receipt["duplicate"] is False
        raise OSError("response lost with private transport details")

    first = lab.collector(transport=lost)
    first.enqueue(lab.record)
    assert first.send_once()["state"] == "pending"
    before = stored(lab)[0]["envelope"]
    lab.clock.now += timedelta(seconds=3)
    restarted = lab.collector()
    assert restarted.send_once()["state"] == "acknowledged"
    assert stored(lab)[0]["envelope"] == before
    assert lab.sent[0] == lab.sent[1]
    assert len([row for row in lab.runtime.store.read(lab.runtime.tenant) if row["kind"] == "execution"]) == 1


def test_expired_lost_ack_can_only_replay_same_envelope(lab):
    def lost(base_url, payload, **options):
        lab.transport(base_url, payload, **options)
        raise OSError("lost")

    collector = lab.collector(transport=lost, lifetime_seconds=2)
    collector.enqueue(lab.record)
    collector.send_once()
    before = stored(lab)[0]["envelope"]
    lab.clock.now += timedelta(seconds=5)
    assert lab.collector(lifetime_seconds=2).send_once()["state"] == "acknowledged"
    assert stored(lab)[0]["envelope"] == before


def test_expired_unreceived_record_is_rejected_without_reseal(lab):
    collector = lab.collector(lifetime_seconds=2)
    collector.enqueue(lab.record)
    before = stored(lab)[0]["envelope"]
    lab.clock.now += timedelta(seconds=3)
    result = collector.send_once()
    assert result["state"] == "rejected" and result["error_code"] == "HTTP_403"
    assert stored(lab)[0]["envelope"] == before
    assert collector.status()["rejected"] == 1


@pytest.mark.parametrize("status", [401, 403, 409, 422])
def test_permanent_rejection_is_preserved_and_not_treated_as_ack(lab, status):
    collector = lab.collector(transport=lambda *a, **k: (status, {}))
    collector.enqueue(lab.record)
    before = stored(lab)[0]["envelope"]
    assert collector.send_once()["state"] == "rejected"
    assert collector.send_once()["state"] == "idle"
    assert stored(lab)[0]["envelope"] == before
    assert collector.status()["acknowledged"] == 0


@pytest.mark.parametrize("field,value", [("evidence_id", "other-record"), ("input_digest", "0" * 64),
                                        ("duplicate", "yes")])
def test_forged_success_receipt_never_acknowledges(lab, field, value):
    def forged(base_url, payload, **options):
        status, receipt = lab.transport(base_url, payload, **options)
        return status, receipt | {field: value}

    collector = lab.collector(transport=forged)
    collector.enqueue(lab.record)
    result = collector.send_once()
    assert result["state"] == "pending"
    assert result["error_code"] == "TRANSPORT_OR_RECEIPT_INVALID"
    assert collector.status()["acknowledged"] == 0


def test_same_identifier_new_content_conflicts_without_replacing_original(lab):
    collector = lab.collector()
    collector.enqueue(lab.record)
    before = stored(lab)[0]["envelope"]
    with pytest.raises(ValueError, match="identifier_conflict"):
        collector.enqueue(lab.record | {"actor": None})
    assert stored(lab)[0]["envelope"] == before


def test_invalid_source_scope_cannot_be_signed_or_enqueued(lab):
    collector = lab.collector()
    bad = lab.record | {"scope": lab.record["scope"] | {"user_id": "unauthorized-user"}}
    with pytest.raises(SignalRejected):
        collector.enqueue(bad)
    assert collector.status()["records"] == 0


def test_revoked_key_blocks_outbound_delivery_and_preserves_pending(lab):
    collector = lab.collector()
    collector.enqueue(lab.record)
    path = lab.directory / "sources.json"
    registry = json.loads(path.read_text())
    registry["sources"][0]["keys"][0]["enabled"] = False
    path.write_text(json.dumps(registry))
    result = collector.send_once()
    assert result["state"] == "pending" and result["error_code"] == "AUTHORITY_UNAVAILABLE"
    assert lab.sent == []


def test_private_feed_permissions_and_symlink_checked_before_signing(lab, tmp_path):
    collector = lab.collector()
    path = tmp_path / "upstream.json"
    path.write_text(json.dumps(lab.record))
    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner_only"):
        collector.enqueue_file(path)
    path.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        collector.enqueue_file(link)
    assert collector.enqueue_file(path)["state"] == "pending"


def test_spool_content_tamper_is_rejected(lab):
    collector = lab.collector()
    collector.enqueue(lab.record)
    with sqlite3.connect(collector.database) as connection:
        connection.execute("UPDATE records SET envelope = envelope || ' '")
    with pytest.raises(ValueError, match="spool_corrupt"):
        lab.collector()


def test_changed_endpoint_cannot_rebind_existing_spool(lab):
    lab.collector().enqueue(lab.record)
    with pytest.raises(ValueError, match="spool_binding"):
        module.ExecutionCollector(lab.directory, "http://127.0.0.1:18081")


@pytest.mark.parametrize("origin", ["http://example.test", "https://example.test", "http://user:secret@localhost"])
def test_remote_or_credentialed_origin_rejected_without_explicit_tls(lab, origin):
    with pytest.raises(ValueError):
        module.ExecutionCollector(lab.directory, origin)


def test_spool_capacity_never_discards_pending(lab, monkeypatch):
    collector = lab.collector()
    collector.enqueue(lab.record)
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="spool_capacity"):
        collector.enqueue(lab.record | {"evidence_id": "execution-record-2"})
    assert collector.status()["pending"] == 1


def test_caller_authority_or_label_fields_are_not_input_contract(lab):
    for field in ("verified", "approved", "label", "source_id"):
        with pytest.raises(ValueError):
            lab.collector().enqueue(lab.record | {field: True})


def test_cli_failure_redacts_input_and_key_details(lab, tmp_path, capsys):
    path = tmp_path / "untrusted.json"
    path.write_text('{"private_key":"must-not-print"}')
    path.chmod(0o600)
    with pytest.raises(SystemExit) as result:
        module.main(["enqueue", "--directory", str(lab.directory), "--input", str(path)])
    output = capsys.readouterr()
    assert result.value.code == 2 and "must-not-print" not in output.err
    assert "private_key" not in output.err
