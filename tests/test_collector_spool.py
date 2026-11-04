import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.services.collector_spool import (
    CollectorSpool,
    SpoolBindingMismatch,
    SpoolConflict,
    SpoolFull,
    SpoolUnavailable,
    SpoolVariantLimit,
)

NOW = datetime(2026, 11, 4, 0, 0, tzinfo=UTC)
BINDING = {
    "input_path": "/local/input.jsonl", "tenant_id": "tenant-a", "source_id": "identity-source",
    "key_id": "key-a", "public_key_sha256": "a" * 64,
    "base_url": "http://127.0.0.1:18080", "tls_profile": None,
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def event(event_id="event-a", *, when=NOW, active=False):
    return {"event_id": event_id, "observed_at": when.isoformat(),
            "observation": {"kind": "identity", "subject_id": "user-a", "active": active,
                            "authentication_result": "failure"}}


def envelope(value=None, *, issued=NOW, **updates):
    value = value or event()
    result = {"schema_version": "zt-observation-1", "algorithm": "Ed25519",
              "tenant_id": BINDING["tenant_id"], "source_id": BINDING["source_id"],
              "key_id": BINDING["key_id"], "event_id": value["event_id"],
              "observed_at": value["observed_at"], "observation": value["observation"],
              "issued_at": issued.isoformat(),
              "expires_at": (issued + timedelta(seconds=90)).isoformat(), "signature": "A" * 86}
    return result | updates


def capture(spool, value=None, *, offset=10, prefix=None):
    return spool.enqueue(value or event(), offset=offset, prefix_sha256=prefix or digest(str(offset)))


@pytest.fixture
def spool(tmp_path):
    return CollectorSpool(tmp_path / "collector.sqlite3", BINDING)


def test_capture_and_checkpoint_survive_restart_without_ack(spool):
    assert spool.checkpoint() == {"offset": 0, "prefix_sha256": digest("")}
    assert capture(spool)
    restarted = CollectorSpool(spool.path, BINDING)
    assert restarted.checkpoint() == {"offset": 10, "prefix_sha256": digest("10")}
    pending = restarted.next_pending(NOW)
    assert pending["event_id"] == "event-a"
    assert pending["event"]["observation"] == event()["observation"]
    assert pending["envelopes"] == [] and pending["attempts"] == 0
    assert restarted.summary() == {
        "captured": 1, "acknowledged": 0, "pending": 1, "offset": 10, "last_error": None,
    }
    if os.name != "nt":
        assert spool.path.stat().st_mode & 0o777 == 0o600


def test_duplicate_event_advances_capture_cursor_without_another_row(spool):
    assert capture(spool)
    assert not capture(spool, offset=20)
    assert spool.checkpoint()["offset"] == 20
    assert spool.summary()["captured"] == 1
    spool.stage("event-a", envelope())
    spool.acknowledge("event-a", now=NOW)
    assert not capture(spool, offset=30)
    assert spool.summary()["acknowledged"] == 1
    assert spool.next_pending(NOW) is None


@pytest.mark.parametrize("changed", [event(active=True), event(when=NOW - timedelta(seconds=1))])
def test_same_identifier_changed_content_never_advances_cursor(spool, changed):
    capture(spool)
    with pytest.raises(SpoolConflict):
        capture(spool, changed, offset=20)
    assert spool.checkpoint()["offset"] == 10
    assert spool.next_pending(NOW)["event"]["observation"]["active"] is False


@pytest.mark.parametrize("offset,prefix", [(9, None), (10, "f" * 64)])
def test_rewound_or_replaced_checkpoint_is_rejected(spool, offset, prefix):
    capture(spool)
    with pytest.raises(SpoolConflict):
        capture(spool, offset=offset, prefix=prefix)
    assert spool.checkpoint()["offset"] == 10


def test_metadata_write_failure_rolls_back_insert_and_cursor(spool):
    with sqlite3.connect(spool.path) as connection:
        connection.execute("CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON collector_spool_metadata "
                           "BEGIN SELECT RAISE(ABORT,'unavailable'); END")
    with pytest.raises(SpoolUnavailable):
        capture(spool)
    assert spool.summary()["captured"] == 0
    assert spool.checkpoint()["offset"] == 0
    with sqlite3.connect(spool.path) as connection:
        connection.execute("DROP TRIGGER reject_checkpoint")
    assert capture(spool)


@pytest.mark.parametrize("operation", ["capture", "stage", "acknowledge"])
def test_commit_failure_does_not_publish_uncommitted_state(spool, monkeypatch, operation):
    if operation != "capture":
        capture(spool)
    if operation == "acknowledge":
        spool.stage("event-a", envelope())
    before = spool.summary()
    original = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected fsync failure")

    def connect(*args, **kwargs):
        return original(*args, **kwargs, factory=FailedCommit)

    with monkeypatch.context() as context:
        context.setattr("app.services.collector_spool.sqlite3.connect", connect)
        with pytest.raises(SpoolUnavailable):
            if operation == "capture":
                capture(spool)
            elif operation == "stage":
                spool.stage("event-a", envelope())
            else:
                spool.acknowledge("event-a", now=NOW)
    assert spool.summary() == before
    if operation == "stage":
        assert spool.next_pending(NOW)["envelopes"] == []


@pytest.mark.parametrize("field", list(BINDING))
def test_persisted_binding_cannot_be_reused_for_another_input_key_or_receiver(spool, field):
    changed = BINDING | {field: "another-value"}
    with pytest.raises(SpoolBindingMismatch):
        CollectorSpool(spool.path, changed)
    assert spool.summary()["captured"] == 0


def test_pending_capacity_retains_unsent_data_and_checkpoint(tmp_path):
    spool = CollectorSpool(tmp_path / "collector.sqlite3", BINDING, max_pending=1)
    capture(spool)
    with pytest.raises(SpoolFull):
        capture(spool, event("event-b"), offset=20)
    assert spool.checkpoint()["offset"] == 10
    spool.stage("event-a", envelope())
    spool.acknowledge("event-a", now=NOW)
    assert capture(spool, event("event-b"), offset=20)


def test_retention_capacity_preserves_acknowledged_duplicate_history(tmp_path):
    spool = CollectorSpool(tmp_path / "collector.sqlite3", BINDING, max_records=1)
    capture(spool)
    spool.stage("event-a", envelope())
    spool.acknowledge("event-a", now=NOW)
    assert not capture(spool, offset=20)
    with pytest.raises(SpoolFull):
        capture(spool, event("event-b"), offset=30)
    assert spool.checkpoint()["offset"] == 20
    assert spool.summary()["acknowledged"] == 1


def test_envelope_variants_are_immutable_durable_and_bounded(tmp_path):
    spool = CollectorSpool(tmp_path / "collector.sqlite3", BINDING, max_variants=2)
    capture(spool)
    first = envelope()
    second = envelope(issued=NOW + timedelta(seconds=120))
    spool.stage("event-a", first)
    spool.stage("event-a", first)
    spool.stage("event-a", second)
    with pytest.raises(SpoolVariantLimit):
        spool.stage("event-a", envelope(issued=NOW + timedelta(seconds=240)))
    reopened = CollectorSpool(spool.path, BINDING)
    variants = reopened.next_pending(NOW + timedelta(days=1))["envelopes"]
    assert len(variants) == 2
    assert datetime.fromisoformat(variants[0]["issued_at"]) == NOW
    assert datetime.fromisoformat(variants[1]["issued_at"]) == NOW + timedelta(seconds=120)
    assert variants[0]["observed_at"] == variants[1]["observed_at"]


@pytest.mark.parametrize("changes", [
    {"tenant_id": "tenant-b"}, {"source_id": "another-source"}, {"key_id": "another-key"},
    {"event_id": "event-b"}, {"observed_at": (NOW - timedelta(seconds=1)).isoformat()},
    {"observation": {"kind": "identity", "subject_id": "user-a", "active": True,
                     "authentication_result": "success"}},
    {"signature": "invalid"}, {"issued_at": NOW.replace(tzinfo=None).isoformat()},
])
def test_staging_cannot_change_event_or_signing_authority(spool, changes):
    capture(spool)
    with pytest.raises(SpoolConflict):
        spool.stage("event-a", envelope(**changes))
    assert spool.next_pending(NOW)["envelopes"] == []


def test_deferred_head_preserves_feed_order_and_retry_state_after_restart(spool):
    capture(spool)
    capture(spool, event("event-b"), offset=20)
    spool.defer("event-a", "HTTP_503", NOW, 2)
    reopened = CollectorSpool(spool.path, BINDING)
    assert reopened.next_pending(NOW + timedelta(seconds=1)) is None
    pending = reopened.next_pending(NOW + timedelta(seconds=2))
    assert pending["event_id"] == "event-a" and pending["attempts"] == 1
    assert reopened.summary()["last_error"] == "HTTP_503"
    reopened.stage("event-a", envelope())
    reopened.acknowledge("event-a", now=NOW + timedelta(seconds=2))
    assert reopened.next_pending(NOW + timedelta(seconds=2))["event_id"] == "event-b"


def test_acknowledgement_is_idempotent_and_does_not_touch_capture_position(spool):
    capture(spool)
    with pytest.raises(SpoolConflict):
        spool.acknowledge("event-a", now=NOW)
    spool.stage("event-a", envelope())
    spool.acknowledge("event-a", now=NOW)
    spool.acknowledge("event-a", now=NOW + timedelta(seconds=1))
    assert spool.summary()["acknowledged"] == 1
    assert spool.checkpoint()["offset"] == 10
    with pytest.raises(SpoolConflict):
        spool.defer("event-a", "HTTP_500", NOW, 1)
    with pytest.raises(SpoolConflict):
        spool.stage("event-a", envelope(issued=NOW + timedelta(seconds=2)))


@pytest.mark.parametrize("sql", [
    "UPDATE collector_spool_records SET record_json='{}'",
    "UPDATE collector_spool_records SET record_digest='bad'",
    "UPDATE collector_spool_records SET event_id='different'",
    "DELETE FROM collector_spool_records",
    "UPDATE collector_spool_metadata SET checkpoint='{}'",
    "UPDATE collector_spool_metadata SET binding='{}'",
    "DELETE FROM collector_spool_metadata",
])
def test_corruption_fails_closed_in_all_reads_and_restart(spool, sql):
    capture(spool)
    with sqlite3.connect(spool.path) as connection:
        connection.execute(sql)
    for operation in (spool.checkpoint, spool.summary, lambda: spool.next_pending(NOW),
                      lambda: CollectorSpool(spool.path, BINDING)):
        with pytest.raises(SpoolUnavailable):
            operation()


def test_valid_hash_does_not_make_malformed_stored_state_acceptable(spool):
    capture(spool)
    with sqlite3.connect(spool.path) as connection:
        record = json.loads(connection.execute(
            "SELECT record_json FROM collector_spool_records").fetchone()[0])
        record["state"] = "acknowledged"
        serialized = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        connection.execute("UPDATE collector_spool_records SET record_json=?,record_digest=?",
                           (serialized, digest(serialized)))
    with pytest.raises(SpoolUnavailable):
        spool.summary()


def test_concurrent_capture_duplicate_keeps_one_row_and_checkpoint(spool):
    def enqueue(_):
        return capture(CollectorSpool(spool.path, BINDING))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(enqueue, range(16)))
    assert sum(results) == 1
    assert spool.summary()["captured"] == 1
    assert spool.checkpoint()["offset"] == 10


def test_input_timestamp_and_errors_are_validated(spool):
    with pytest.raises(SpoolConflict):
        capture(spool, event(when=NOW.replace(tzinfo=None)))
    capture(spool)
    with pytest.raises(ValueError):
        spool.next_pending(NOW.replace(tzinfo=None))
    with pytest.raises(SpoolConflict):
        spool.defer("event-a", "secret exception details", NOW, 1)
    with pytest.raises(SpoolConflict):
        spool.defer("event-a", "HTTP_500", NOW, float("nan"))
