"""Confirmed-history maintenance without losing capture or delivery evidence."""

import hashlib
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.services.collector_spool import (
    CollectorSpool,
    SpoolConflict,
    SpoolFull,
    SpoolUnavailable,
)

NOW = datetime(2026, 11, 4, tzinfo=UTC)
BINDING = {"tenant_id": "local", "source_id": "observer", "key_id": "key-a"}
ROOT = Path(__file__).resolve().parents[1]


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event(identifier, *, active=False):
    return {"event_id": identifier, "observed_at": NOW.isoformat(), "observation": {
        "kind": "identity", "subject_id": "user-a", "active": active,
        "authentication_result": "success" if active else "failure",
    }}


def capture(spool, identifier, offset):
    value = event(identifier)
    spool.enqueue(value, offset=offset, prefix_sha256=digest(str(offset)))
    return value


def stage(spool, value):
    spool.stage(value["event_id"], {
        "schema_version": "zt-observation-1", "algorithm": "Ed25519", **BINDING,
        **value, "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(seconds=90)).isoformat(), "signature": "A" * 86,
    })


def acknowledge(spool, identifier, offset):
    stage(spool, capture(spool, identifier, offset))
    spool.acknowledge(identifier, now=NOW)


def table(path, name):
    with sqlite3.connect(path) as connection:
        return connection.execute("SELECT * FROM " + name + " ORDER BY 1").fetchall()


def state(path):
    return {name: table(path, name) for name in (
        "collector_spool_metadata", "collector_spool_records", "collector_spool_history",
        "collector_spool_rotation", "collector_spool_rotations",
    )}


@pytest.fixture
def spool(tmp_path):
    return CollectorSpool(tmp_path / "spool.sqlite3", BINDING)


def test_compaction_keeps_pending_bytes_retry_order_and_total_counters(spool):
    acknowledge(spool, "confirmed-a", 10)
    value = capture(spool, "pending", 20)
    stage(spool, value)
    spool.defer("pending", "HTTP_503", NOW, 15)
    acknowledge(spool, "confirmed-b", 30)
    before = state(spool.path)
    summary = spool.summary()
    pending = next(row for row in before["collector_spool_records"] if row[1] == "pending")
    assert spool.compact() == 2
    assert table(spool.path, "collector_spool_records") == [pending]
    assert table(spool.path, "collector_spool_metadata") == before["collector_spool_metadata"]
    assert spool.summary() == summary
    assert spool.storage_summary() == {
        "retained": 1, "compacted": 2, "max_records": 10000, "max_history": 100000,
        "max_rotations": 100000,
    }
    restarted = CollectorSpool(spool.path, BINDING)
    assert restarted.next_pending(NOW + timedelta(seconds=14)) is None
    assert restarted.next_pending(NOW + timedelta(seconds=15))["attempts"] == 1
    history = table(spool.path, "collector_spool_history")
    assert [row[0] for row in history] == [1, 3]
    assert all(len(canonical(row)) < 400 for row in history)
    assert "signature" not in canonical(history) and "observation" not in canonical(history)
    assert restarted.compact() == 0


def test_history_duplicate_and_conflict_survive_restart_and_input_rotation(spool):
    acknowledge(spool, "event-a", 10)
    assert spool.compact() == 1
    restarted = CollectorSpool(spool.path, BINDING)
    assert not restarted.enqueue(event("event-a"), offset=20, prefix_sha256=digest("20"))
    before = restarted.checkpoint()
    with pytest.raises(SpoolConflict):
        restarted.enqueue(event("event-a", active=True), offset=30, prefix_sha256=digest("30"))
    assert restarted.checkpoint() == before
    restarted.rotate_input(before, "rotation-a")
    assert not restarted.enqueue(event("event-a"), offset=7, prefix_sha256=digest("7"))
    restarted.acknowledge("event-a", now=NOW)  # Late duplicate ACK is harmless after maintenance.
    capture(restarted, "event-b", 14)
    assert table(spool.path, "collector_spool_records")[0][0] == 2
    assert restarted.summary() == {
        "captured": 2, "acknowledged": 1, "pending": 1, "offset": 14, "last_error": None,
    }


def test_hot_and_history_limits_apply_without_forgetting_ids(tmp_path):
    spool = CollectorSpool(tmp_path / "spool.sqlite3", BINDING, max_records=1, max_history=1)
    acknowledge(spool, "event-a", 10)
    assert spool.compact() == 1
    acknowledge(spool, "event-b", 20)
    before = state(spool.path)
    with pytest.raises(SpoolFull):
        spool.compact()
    assert state(spool.path) == before
    with pytest.raises(SpoolFull):
        capture(spool, "event-c", 30)
    assert spool.checkpoint()["offset"] == 20
    assert not spool.enqueue(event("event-a"), offset=40, prefix_sha256=digest("40"))
    assert spool.summary()["captured"] == spool.summary()["acknowledged"] == 2


def test_compaction_limit_and_remaining_history_capacity_are_respected(tmp_path):
    spool = CollectorSpool(tmp_path / "spool.sqlite3", BINDING, max_history=2)
    for index in range(3):
        acknowledge(spool, "event-" + str(index), (index + 1) * 10)
    assert spool.compact(limit=1) == 1
    assert spool.compact(limit=256) == 1
    with pytest.raises(SpoolFull):
        spool.compact(limit=1)
    assert spool.storage_summary()["retained"] == 1
    assert spool.summary()["captured"] == 3


@pytest.mark.parametrize("limit", [0, -1, True, 1.0, "1"])
def test_compaction_rejects_invalid_batch_limits_without_changes(spool, limit):
    acknowledge(spool, "event-a", 10)
    before = state(spool.path)
    with pytest.raises(SpoolConflict):
        spool.compact(limit=limit)
    assert state(spool.path) == before


@pytest.mark.parametrize("limit", [0, -1, True, 1.0])
def test_history_limit_is_explicit_and_positive(tmp_path, limit):
    with pytest.raises(ValueError):
        CollectorSpool(tmp_path / "spool.sqlite3", BINDING, max_history=limit)


@pytest.mark.parametrize("limit", [0, -1, True, 1.0])
def test_rotation_history_limit_is_explicit_and_positive(tmp_path, limit):
    with pytest.raises(ValueError):
        CollectorSpool(tmp_path / "spool.sqlite3", BINDING, max_rotations=limit)


def test_rotation_limit_preserves_state_and_allows_current_id_reconfirmation(tmp_path):
    spool = CollectorSpool(tmp_path / "spool.sqlite3", BINDING, max_rotations=1)
    acknowledge(spool, "confirmed", 10)
    spool.compact()
    stage(spool, capture(spool, "pending", 20))
    spool.defer("pending", "HTTP_503", NOW, 10)
    first = spool.checkpoint()
    spool.rotate_input(first, "rotation-a")
    capture(spool, "new-feed", 7)
    before = state(spool.path)
    with pytest.raises(SpoolFull):
        spool.rotate_input(spool.checkpoint(), "rotation-b")
    assert state(spool.path) == before
    restarted = CollectorSpool(spool.path, BINDING, max_rotations=1)
    restarted.rotate_input(first, "rotation-a")
    assert state(spool.path) == before
    assert restarted.checkpoint()["offset"] == 7
    assert restarted.storage_summary()["max_rotations"] == 1
    assert restarted.rotation_checkpoint() == {"generation": 1, "rotation_id": "rotation-a"}
    with pytest.raises(SpoolFull):
        restarted.rotate_input(restarted.checkpoint(), "rotation-b")
    assert state(spool.path) == before


@pytest.mark.parametrize("sql", [
    ("CREATE TRIGGER reject_history BEFORE INSERT ON collector_spool_history "
     "BEGIN SELECT RAISE(ABORT,'failure'); END"),
    ("CREATE TRIGGER reject_move BEFORE DELETE ON collector_spool_records "
     "WHEN OLD.event_id='event-b' BEGIN SELECT RAISE(ABORT,'failure'); END"),
])
def test_move_failure_rolls_back_the_entire_batch(spool, sql):
    acknowledge(spool, "event-a", 10)
    acknowledge(spool, "event-b", 20)
    before = state(spool.path)
    with sqlite3.connect(spool.path) as connection:
        connection.execute(sql)
    with pytest.raises(SpoolUnavailable):
        spool.compact()
    assert state(spool.path) == before


@pytest.mark.parametrize("operation", ["compact", "rotate"])
def test_failed_commit_rolls_back_all_maintenance_state(spool, monkeypatch, operation):
    acknowledge(spool, "event-a", 10)
    before = state(spool.path)
    original = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

    with monkeypatch.context() as context:
        context.setattr("app.services.collector_spool.sqlite3.connect",
                        lambda *args, **kwargs: original(*args, **kwargs, factory=FailedCommit))
        with pytest.raises(SpoolUnavailable):
            if operation == "compact":
                spool.compact()
            else:
                spool.rotate_input(spool.checkpoint(), "rotation-a")
    assert state(spool.path) == before


def test_concurrent_compactors_move_each_confirmation_once(spool):
    for index in range(12):
        acknowledge(spool, "event-" + str(index), index + 1)
    with ThreadPoolExecutor(max_workers=8) as pool:
        moved = list(pool.map(lambda _: CollectorSpool(spool.path, BINDING).compact(limit=2), range(12)))
    assert sum(moved) == 12
    assert spool.storage_summary()["retained"] == 0
    assert spool.summary()["captured"] == spool.summary()["acknowledged"] == 12


@pytest.mark.parametrize("sql", [
    "DELETE FROM collector_spool_history",
    "UPDATE collector_spool_history SET seq=9",
    "UPDATE collector_spool_history SET event_sha256='bad'",
    "UPDATE collector_spool_history SET acknowledged_at='bad'",
    "UPDATE collector_spool_history SET tombstone_digest='bad'",
    "UPDATE collector_spool_records SET seq=1",
    "UPDATE collector_spool_records SET event_id='event-a'",
    "DELETE FROM collector_spool_records",
    "DROP TABLE collector_spool_history",
])
def test_union_count_sequence_and_history_corruption_fail_closed(spool, sql):
    acknowledge(spool, "event-a", 10)
    capture(spool, "event-b", 20)
    spool.compact()
    with sqlite3.connect(spool.path) as connection:
        connection.execute(sql)
    for read in (spool.summary, spool.storage_summary, spool.checkpoint, spool.rotation_checkpoint,
                 lambda: spool.next_pending(NOW), lambda: CollectorSpool(spool.path, BINDING)):
        with pytest.raises(SpoolUnavailable):
            read()


def test_correct_digest_does_not_make_invalid_history_timestamp_valid(spool):
    acknowledge(spool, "event-a", 10)
    spool.compact()
    with sqlite3.connect(spool.path) as connection:
        row = connection.execute("SELECT * FROM collector_spool_history").fetchone()
        entry = dict(zip(("seq", "event_id", "event_sha256", "acknowledged_at"), row[:4], strict=True))
        entry["acknowledged_at"] = "2026-11-04T00:00:00"  # No timezone.
        connection.execute("UPDATE collector_spool_history SET acknowledged_at=?,tombstone_digest=?",
                           (entry["acknowledged_at"], digest(canonical(entry))))
    with pytest.raises(SpoolUnavailable):
        spool.summary()


def legacy_copy(source, target):
    with sqlite3.connect(source) as source_db, sqlite3.connect(target) as target_db:
        target_db.execute("CREATE TABLE collector_spool_metadata (id INTEGER PRIMARY KEY CHECK(id=1), "
                          "binding TEXT NOT NULL,binding_digest TEXT NOT NULL,checkpoint TEXT NOT NULL, "
                          "checkpoint_digest TEXT NOT NULL)")
        target_db.execute("CREATE TABLE collector_spool_records (seq INTEGER PRIMARY KEY, "
                          "event_id TEXT NOT NULL UNIQUE,record_json TEXT NOT NULL,record_digest TEXT NOT NULL)")
        target_db.executemany("INSERT INTO collector_spool_metadata VALUES (?,?,?,?,?)", source_db.execute(
            "SELECT id,binding,binding_digest,checkpoint,checkpoint_digest FROM collector_spool_metadata"))
        target_db.executemany("INSERT INTO collector_spool_records VALUES (?,?,?,?)", source_db.execute(
            "SELECT * FROM collector_spool_records"))


def test_existing_database_migrates_without_changing_rows_or_binding(spool, tmp_path):
    acknowledge(spool, "event-a", 10)
    stage(spool, capture(spool, "event-b", 20))
    spool.defer("event-b", "HTTP_503", NOW, 10)
    path = tmp_path / "legacy.sqlite3"
    legacy_copy(spool.path, path)
    before = table(path, "collector_spool_records")
    migrated = CollectorSpool(path, BINDING)
    assert table(path, "collector_spool_records") == before
    assert migrated.summary() == spool.summary()
    assert migrated.rotation_checkpoint() == {"generation": 0, "rotation_id": None}
    assert migrated.compact() == 1
    assert migrated.next_pending(NOW + timedelta(seconds=10))["attempts"] == 1


def test_failed_migration_commit_leaves_legacy_database_reopenable(spool, tmp_path, monkeypatch):
    acknowledge(spool, "event-a", 10)
    path = tmp_path / "legacy.sqlite3"
    legacy_copy(spool.path, path)
    before = table(path, "collector_spool_records")
    original = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected migration failure")

    with monkeypatch.context() as context:
        context.setattr("app.services.collector_spool.sqlite3.connect",
                        lambda *args, **kwargs: original(*args, **kwargs, factory=FailedCommit))
        with pytest.raises(SpoolUnavailable):
            CollectorSpool(path, BINDING)
    assert table(path, "collector_spool_records") == before
    with sqlite3.connect(path) as connection:
        assert "storage_version" not in {row[1] for row in connection.execute(
            "PRAGMA table_info(collector_spool_metadata)")}
    assert CollectorSpool(path, BINDING).summary()["acknowledged"] == 1


@pytest.mark.parametrize("boundary", ["insert", "delete", "migration"])
def test_real_process_exit_before_commit_recovers_original_state(spool, tmp_path, boundary):
    acknowledge(spool, "event-a", 10)
    acknowledge(spool, "event-b", 20)
    stage(spool, capture(spool, "pending", 30))
    spool.defer("pending", "HTTP_503", NOW, 10)
    path = spool.path
    if boundary == "migration":
        path = tmp_path / "legacy.sqlite3"
        legacy_copy(spool.path, path)
    before_records = table(path, "collector_spool_records")
    program = """import os,sqlite3,sys
from app.services.collector_spool import CollectorSpool
original=sqlite3.connect
boundary=sys.argv[2]
class Crash(sqlite3.Connection):
 def execute(self,sql,*args,**kwargs):
  result=super().execute(sql,*args,**kwargs)
  if ((boundary=='insert' and sql.startswith('INSERT INTO collector_spool_history'))
      or (boundary=='delete' and sql.startswith('DELETE FROM collector_spool_records'))
      or (boundary=='migration' and sql.startswith('CREATE TABLE collector_spool_history'))):
   os._exit(73)
  return result
sqlite3.connect=lambda *a,**k:original(*a,**k,factory=Crash)
spool=CollectorSpool(sys.argv[1],{'tenant_id':'local','source_id':'observer','key_id':'key-a'})
spool.compact()
raise SystemExit(1)
"""
    child = subprocess.run([sys.executable, "-c", program, str(path), boundary], cwd=ROOT,
                           capture_output=True, timeout=20, check=False)
    assert child.returncode == 73 and not child.stdout
    assert table(path, "collector_spool_records") == before_records
    reopened = CollectorSpool(path, BINDING)
    assert reopened.storage_summary()["compacted"] == 0
    assert reopened.summary() == spool.summary()
    assert reopened.next_pending(NOW + timedelta(seconds=10))["attempts"] == 1
    assert reopened.compact() == 2


def test_rotation_cas_idempotence_and_old_id_rejection_preserve_delivery_state(spool):
    stage(spool, capture(spool, "pending", 10))
    spool.defer("pending", "HTTP_503", NOW, 20)
    records = table(spool.path, "collector_spool_records")
    checkpoint = spool.checkpoint()
    with pytest.raises(SpoolConflict):
        spool.rotate_input(checkpoint | {"offset": 11}, "rotation-a")
    assert spool.rotation_checkpoint() == {"generation": 0, "rotation_id": None}
    spool.rotate_input(checkpoint, "rotation-a")
    assert spool.checkpoint() == {"offset": 0, "prefix_sha256": digest("")}
    assert spool.rotation_checkpoint() == {"generation": 1, "rotation_id": "rotation-a"}
    capture(spool, "next", 7)
    spool.rotate_input(checkpoint, "rotation-a")
    assert spool.checkpoint()["offset"] == 7
    with pytest.raises(SpoolConflict):
        spool.rotate_input(spool.checkpoint(), "rotation-a")
    spool.rotate_input(spool.checkpoint(), "rotation-b")
    with pytest.raises(SpoolConflict):
        spool.rotate_input(checkpoint, "rotation-a")
    assert table(spool.path, "collector_spool_records")[0] == records[0]
    assert CollectorSpool(spool.path, BINDING).rotation_checkpoint() == {
        "generation": 2, "rotation_id": "rotation-b",
    }


@pytest.mark.parametrize("checkpoint,identifier", [
    ({"offset": -1, "prefix_sha256": "a" * 64}, "rotation-a"),
    ({"offset": True, "prefix_sha256": "a" * 64}, "rotation-a"),
    ({"offset": 0, "prefix_sha256": "bad"}, "rotation-a"),
    ({"offset": 0, "prefix_sha256": "a" * 64, "extra": 1}, "rotation-a"),
    ({"offset": 0, "prefix_sha256": "a" * 64}, "../rotation"),
    ({"offset": 0, "prefix_sha256": "a" * 64}, ""),
])
def test_rotation_rejects_invalid_arguments_without_any_write(spool, checkpoint, identifier):
    before = state(spool.path)
    with pytest.raises(SpoolConflict):
        spool.rotate_input(checkpoint, identifier)
    assert state(spool.path) == before


@pytest.mark.parametrize("sql", [
    "DELETE FROM collector_spool_rotation",
    "DELETE FROM collector_spool_rotations",
    "UPDATE collector_spool_rotation SET rotation_digest='bad'",
    "UPDATE collector_spool_rotations SET rotation_id='different'",
    "UPDATE collector_spool_rotations SET generation=2",
    "DROP TABLE collector_spool_rotations",
])
def test_rotation_metadata_is_validated_on_every_read_and_not_reinitialized(spool, sql):
    capture(spool, "event-a", 10)
    spool.rotate_input(spool.checkpoint(), "rotation-a")
    with sqlite3.connect(spool.path) as connection:
        connection.execute(sql)
    for read in (spool.summary, spool.rotation_checkpoint, lambda: CollectorSpool(spool.path, BINDING)):
        with pytest.raises(SpoolUnavailable):
            read()
