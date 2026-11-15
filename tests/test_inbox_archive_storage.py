"""Lossless inbox terminal retention, finite quotas and transaction recovery."""

import hashlib
import json
import sqlite3
import subprocess
import sys
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.services import inbox_archive as archive
from app.services import policy_journal
from app.services.signal_inbox import (
    InboxConflict,
    InboxFull,
    InboxLeaseLost,
    InboxUnavailable,
    SignalInbox,
)

NOW = datetime(2026, 11, 5, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def accept(inbox, identifier="event-a", *, tenant="tenant-a", payload=None):
    value = {"event_id": identifier, "value": 1} if payload is None else payload
    return inbox.accept(tenant, identifier, value, digest(archive.canonical(value)), "operator", NOW)


def terminal(inbox, identifier="event-a", *, tenant="tenant-a", failed=False):
    accept(inbox, identifier, tenant=tenant)
    delivery = inbox.claim(now=NOW)
    assert (delivery["tenant_id"], delivery["event_id"]) == (tenant, identifier)
    if failed:
        return inbox.fail(tenant, identifier, delivery["lease_token"], "PROCESSING_ERROR", NOW)
    return inbox.complete(tenant, identifier, delivery["lease_token"], {"changed_sessions": 1}, NOW)


def snapshot(path):
    with sqlite3.connect(path) as connection:
        result = {name: connection.execute("SELECT * FROM " + name + " ORDER BY 1").fetchall()
                  for name in archive.TABLES}
        result["markers"] = (connection.execute("PRAGMA application_id").fetchone()[0],
                             connection.execute("PRAGMA user_version").fetchone()[0])
        return result


@pytest.fixture
def inbox(tmp_path):
    return SignalInbox(tmp_path / "inbox.sqlite3", max_attempts=1)


def test_full_original_rows_and_receipts_survive_terminal_archive(inbox):
    completed = terminal(inbox, "00-completed")
    failed = terminal(inbox, "01-failed", failed=True)
    accept(inbox, "10-processing")
    processing = inbox.claim(now=NOW)
    accept(inbox, "20-pending")
    before = snapshot(inbox.path)
    metrics = inbox.metrics("tenant-a", now=NOW)
    result = inbox.compact()
    assert result["compacted"] == 2 and result["segments_created"] == 1
    stored = snapshot(inbox.path)
    assert stored["signal_inbox"] == [row for row in before["signal_inbox"] if row[7] in {"pending", "processing"}]
    decoded = json.loads(zlib.decompress(stored["signal_inbox_archive_segments"][0][4]))
    original = [dict(zip(archive.FIELDS, row, strict=True)) for row in before["signal_inbox"]
                if row[7] in {"completed", "failed"}]
    assert decoded == original
    assert inbox.get("tenant-a", "00-completed") == completed
    assert inbox.get("tenant-a", "01-failed") == failed
    reopened = SignalInbox(inbox.path)
    after = reopened.metrics("tenant-a", now=NOW)
    for key in metrics.keys() - {"active_records", "archived_records"}:
        assert after[key] == metrics[key]
    assert (after["active_records"], after["archived_records"]) == (2, 2)
    assert reopened.get("tenant-a", "10-processing")["attempts"] == processing["attempts"]
    assert reopened.compact()["compacted"] == 0


def test_automatic_archive_frees_hot_capacity_and_keeps_exact_duplicate_contract(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_records=1, max_attempts=1, max_archive_records=1)
    original = terminal(inbox)
    accept(inbox, "event-b")
    assert inbox.storage_status()["archived_records"] == 1
    assert inbox.get("tenant-a", "event-a") == original
    duplicate = accept(inbox)
    assert duplicate == original | {"duplicate": True}
    before = snapshot(inbox.path)
    with pytest.raises(InboxConflict):
        accept(inbox, payload={"event_id": "event-a", "value": 2})
    with pytest.raises(InboxConflict):
        inbox.accept("tenant-a", "event-a", {"other_signature": True},
                     digest(archive.canonical({"event_id": "event-a", "value": 1})), "operator", NOW)
    with pytest.raises(InboxFull):
        accept(inbox, "event-c")
    assert snapshot(inbox.path) == before
    assert inbox.metrics("tenant-a", now=NOW)["total"] == 2


@pytest.mark.parametrize("limits", [
    {"max_archive_records": 0},
    {"max_archive_records": 1},
    {"max_archive_segments": 1, "archive_batch_size": 1},
])
def test_finite_archive_caps_keep_full_reads_and_reject_new_intake(tmp_path, limits):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_records=1, max_attempts=1, **limits)
    terminal(inbox, "event-a")
    if limits.get("max_archive_records") != 0:
        accept(inbox, "event-b")
        delivery = inbox.claim(now=NOW)
        inbox.complete("tenant-a", "event-b", delivery["lease_token"], {}, NOW)
    before = snapshot(inbox.path)
    with pytest.raises(InboxFull):
        accept(inbox, "event-c")
    assert snapshot(inbox.path) == before
    assert inbox.get("tenant-a", "event-a")["state"] == "completed"


def test_tenant_hot_archive_quotas_do_not_block_another_tenant(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_records=4, max_records_per_tenant=1,
                        max_archive_records_per_tenant=1, max_attempts=1)
    terminal(inbox, "event-a")
    accept(inbox, "event-b")
    delivery = inbox.claim(now=NOW)
    inbox.complete("tenant-a", "event-b", delivery["lease_token"], {}, NOW)
    before = snapshot(inbox.path)
    with pytest.raises(InboxFull):
        accept(inbox, "event-c")
    assert snapshot(inbox.path) == before
    terminal(inbox, "event-a", tenant="tenant-b")
    accept(inbox, "event-b", tenant="tenant-b")
    own = inbox.metrics("tenant-b", now=NOW)
    assert own["total"] == 2 and own["archived_records"] == 1
    assert "archive_segments" not in own and "archive_bytes" not in own
    assert inbox.metrics("missing-tenant", now=NOW)["total"] == 0


def test_global_archive_skips_a_tenant_whose_cold_quota_is_full(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_records=2,
                        max_archive_records_per_tenant=1, max_attempts=1)
    terminal(inbox, "event-a")
    terminal(inbox, "event-b")
    accept(inbox, "event-a", tenant="tenant-b")
    delivery = inbox.claim(now=NOW)
    inbox.complete("tenant-b", "event-a", delivery["lease_token"], {}, NOW)
    accept(inbox, "event-a", tenant="tenant-c")
    assert inbox.metrics("tenant-a", now=NOW)["archived_records"] == 1
    assert inbox.metrics("tenant-b", now=NOW)["archived_records"] == 1
    assert inbox.metrics("tenant-c", now=NOW)["pending"] == 1


def test_pending_limit_rejects_without_archiving_unrelated_terminal_rows(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_records=2, max_pending=1)
    terminal(inbox)
    accept(inbox, "event-b")
    before = snapshot(inbox.path)
    with pytest.raises(InboxFull):
        accept(inbox, "event-c")
    assert snapshot(inbox.path) == before


def test_compaction_never_changes_leases_and_stale_worker_remains_fenced(inbox):
    terminal(inbox, "00-completed")
    accept(inbox, "10-processing")
    first = inbox.claim(now=NOW)
    inbox.compact()
    second = inbox.claim(now=NOW + timedelta(seconds=31), reconcile_exhausted=True)
    assert second["event_id"] == first["event_id"] and second["reconcile_only"]
    with pytest.raises(InboxLeaseLost):
        inbox.complete("tenant-a", first["event_id"], first["lease_token"], {}, NOW + timedelta(seconds=31))
    inbox.complete("tenant-a", second["event_id"], second["lease_token"], {}, NOW + timedelta(seconds=31))
    assert inbox.compact()["compacted"] == 1
    assert inbox.claim(now=NOW + timedelta(seconds=90)) is None


def test_expired_lease_batch_and_next_claim_refresh_checkpoint_once(inbox, monkeypatch):
    for index in range(3):
        accept(inbox, "event-" + str(index))
        assert inbox.claim(now=NOW)["event_id"] == "event-" + str(index)
    accept(inbox, "event-z")
    calls = []
    original = archive.refresh

    def refresh(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(archive, "refresh", refresh)
    delivery = inbox.claim(now=NOW + timedelta(seconds=31))
    assert delivery["event_id"] == "event-z"
    assert len(calls) == 1
    metrics = inbox.metrics("tenant-a", now=NOW + timedelta(seconds=31))
    assert metrics["failed"] == 3 and metrics["processing"] == 1


@pytest.mark.parametrize("kwargs", [
    {"max_records": 100001}, {"max_records": True}, {"archive_batch_size": 0},
    {"archive_batch_size": 100001}, {"max_archive_records": -1}, {"max_archive_records": 1000001},
    {"max_archive_segments": 10001}, {"max_archive_segments": True},
    {"max_archive_records_per_tenant": 1000001},
])
def test_configuration_limits_are_bounded_and_reject_booleans(tmp_path, kwargs):
    with pytest.raises(ValueError):
        SignalInbox(tmp_path / "inbox.sqlite3", **kwargs)


@pytest.mark.parametrize("sql", [
    ("CREATE TRIGGER reject_archive BEFORE INSERT ON signal_inbox_archive_segments "
     "BEGIN SELECT RAISE(ABORT,'failure'); END"),
    ("CREATE TRIGGER reject_delete BEFORE DELETE ON signal_inbox "
     "WHEN OLD.event_id='event-b' BEGIN SELECT RAISE(ABORT,'failure'); END"),
    ("CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON signal_inbox_archive_metadata "
     "BEGIN SELECT RAISE(ABORT,'failure'); END"),
])
def test_archive_insert_delete_or_checkpoint_failure_rolls_back_batch(inbox, sql):
    terminal(inbox)
    terminal(inbox, "event-b")
    before = snapshot(inbox.path)
    with sqlite3.connect(inbox.path) as connection:
        connection.execute(sql)
    with pytest.raises(InboxUnavailable):
        inbox.compact()
    assert snapshot(inbox.path) == before


def test_compaction_commit_failure_preserves_active_and_cold_generation(inbox, monkeypatch):
    terminal(inbox)
    before = snapshot(inbox.path)
    original = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

    with monkeypatch.context() as context:
        context.setattr("app.services.signal_inbox.sqlite3.connect",
                        lambda *a, **k: original(*a, **k, factory=FailedCommit))
        with pytest.raises(InboxUnavailable):
            inbox.compact()
    assert snapshot(inbox.path) == before


@pytest.mark.parametrize("sql", [
    "DELETE FROM signal_inbox_archive_segments",
    "UPDATE signal_inbox_archive_segments SET segment_no=3",
    "UPDATE signal_inbox_archive_segments SET record_count=99",
    "UPDATE signal_inbox_archive_segments SET prior_hash='bad'",
    "UPDATE signal_inbox_archive_segments SET payload=x'00'",
    "UPDATE signal_inbox_archive_segments SET uncompressed_size=999999999",
    "UPDATE signal_inbox_archive_segments SET segment_digest='bad'",
    "UPDATE signal_inbox_archive_metadata SET metadata_json='{}'",
    "DELETE FROM signal_inbox_archive_metadata",
    "DELETE FROM signal_inbox_format",
    "UPDATE signal_inbox_format SET version=3",
    "DELETE FROM signal_inbox",
    "UPDATE signal_inbox SET attempts=1",
])
def test_archive_and_active_checkpoint_corruption_fail_closed_on_all_reads(inbox, sql):
    terminal(inbox)
    inbox.compact()
    accept(inbox, "event-b")
    with sqlite3.connect(inbox.path) as connection:
        connection.execute(sql)
    for read in (inbox.storage_status, lambda: inbox.get("tenant-a", "event-a"),
                 lambda: inbox.metrics("tenant-a", now=NOW), lambda: SignalInbox(inbox.path)):
        with pytest.raises(InboxUnavailable):
            read()


@pytest.mark.parametrize("table", sorted(archive.TABLES))
def test_namespace_marker_prevents_recreating_any_missing_table(inbox, table):
    with sqlite3.connect(inbox.path) as connection:
        connection.execute("DROP TABLE " + table)
    with pytest.raises(InboxUnavailable):
        SignalInbox(inbox.path)
    with sqlite3.connect(inbox.path) as connection:
        assert table not in {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


@pytest.mark.parametrize("marker", [0, 7, archive.APPLICATION_ID + 1])
def test_foreign_or_missing_namespace_marker_never_overwrites_existing_archive(inbox, marker):
    terminal(inbox)
    inbox.compact()
    with sqlite3.connect(inbox.path) as connection:
        connection.execute("PRAGMA application_id=" + str(marker))
    before = snapshot(inbox.path)
    with pytest.raises(InboxUnavailable):
        SignalInbox(inbox.path)
    assert snapshot(inbox.path) == before


def legacy_copy(source, target):
    with sqlite3.connect(source) as source_db, sqlite3.connect(target) as target_db:
        schema = source_db.execute("SELECT sql FROM sqlite_master WHERE name='signal_inbox'").fetchone()[0]
        target_db.execute(schema)
        target_db.executemany("INSERT INTO signal_inbox VALUES (" + ",".join("?" for _ in archive.FIELDS) + ")",
                             source_db.execute("SELECT * FROM signal_inbox"))


def test_legacy_migration_preserves_original_rows_and_shared_policy_journal(inbox, tmp_path):
    original = terminal(inbox)
    accept(inbox, "event-b")
    path = tmp_path / "legacy.sqlite3"
    legacy_copy(inbox.path, path)
    limits = policy_journal.JournalLimits()
    policy_journal.initialize(path, limits)
    with policy_journal.transaction(path, limits) as txn:
        policy_journal.append(txn, {"kind": "access", "allowed": False})
    with sqlite3.connect(path) as connection:
        policy_before = {name: connection.execute("SELECT * FROM " + name).fetchall()
                         for name in ("journal", "journal_storage_metadata", "journal_archive_segments")}
    migrated = SignalInbox(path)
    assert migrated.get("tenant-a", "event-a") == original
    assert migrated.compact()["compacted"] == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("PRAGMA application_id").fetchone()[0] == archive.APPLICATION_ID
        for name, rows in policy_before.items():
            assert connection.execute("SELECT * FROM " + name).fetchall() == rows
    with policy_journal.transaction(path, limits) as txn:
        assert txn[1] == [{"kind": "access", "allowed": False}]


def test_migration_commit_failure_keeps_v1_rows_marker_and_schema(inbox, tmp_path, monkeypatch):
    terminal(inbox)
    path = tmp_path / "legacy.sqlite3"
    legacy_copy(inbox.path, path)
    original = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected migration failure")

    with monkeypatch.context() as context:
        context.setattr("app.services.signal_inbox.sqlite3.connect", lambda *a, **k: original(*a, **k, factory=FailedCommit))
        with pytest.raises(InboxUnavailable):
            SignalInbox(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM signal_inbox").fetchone()[0] == 1
        assert {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")} == {"signal_inbox"}
    assert SignalInbox(path).get("tenant-a", "event-a")["state"] == "completed"


def test_reduced_limits_fail_without_deleting_original_receipts(inbox):
    terminal(inbox)
    terminal(inbox, "event-b")
    inbox.compact()
    before = snapshot(inbox.path)
    with pytest.raises(InboxUnavailable):
        SignalInbox(inbox.path, max_archive_records=1)
    assert snapshot(inbox.path) == before
    assert inbox.metrics("tenant-a", now=NOW)["total"] == 2


def test_raw_byte_limit_rejects_intake_before_mutating_or_archiving(inbox, monkeypatch):
    terminal(inbox)
    before = snapshot(inbox.path)
    monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", inbox.storage_status()["active_bytes"] + 10)
    with pytest.raises(InboxFull):
        accept(inbox, "event-b")
    assert snapshot(inbox.path) == before
    assert inbox.get("tenant-a", "event-a")["state"] == "completed"


def test_completion_size_failure_is_retryable_storage_error_and_preserves_lease(inbox, monkeypatch):
    accept(inbox)
    delivery = inbox.claim(now=NOW)
    before = snapshot(inbox.path)
    monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", inbox.storage_status()["active_bytes"] + 10)
    with pytest.raises(InboxUnavailable):
        inbox.complete("tenant-a", "event-a", delivery["lease_token"], {"large": "x" * 1000}, NOW)
    assert snapshot(inbox.path) == before
    assert inbox.get("tenant-a", "event-a")["state"] == "processing"


def test_bounded_decode_rejects_compression_bomb_and_trailing_stream():
    with pytest.raises(ValueError):
        archive._decode(zlib.compress(b"x" * (archive.MAX_SEGMENT_BYTES + 1)), 1)
    for suffix in (b"junk", zlib.compress(b"second")):
        with pytest.raises(ValueError):
            archive._decode(zlib.compress(b"[]") + suffix, 2)


def test_consistently_checksummed_invalid_zlib_is_a_redacted_storage_failure(inbox):
    terminal(inbox)
    inbox.compact()
    with sqlite3.connect(inbox.path) as connection:
        number, count, raw_size, prior, _, _ = connection.execute(
            "SELECT * FROM signal_inbox_archive_segments").fetchone()
        blob = b"malformed"
        checksum = archive._segment_digest(number, count, raw_size, prior, blob)
        connection.execute("UPDATE signal_inbox_archive_segments SET payload=?,segment_digest=?", (blob, checksum))
        meta = json.loads(connection.execute("SELECT metadata_json FROM signal_inbox_archive_metadata").fetchone()[0])
        meta["archive_digest"] = checksum
        raw = archive.canonical(meta)
        connection.execute("UPDATE signal_inbox_archive_metadata SET metadata_json=?,metadata_digest=?",
                           (raw, digest(raw)))
    with pytest.raises(InboxUnavailable):
        inbox.get("tenant-a", "event-a")
    assert inbox.integrity()["ok"] is False
    with pytest.raises(InboxUnavailable):
        SignalInbox(inbox.path)


def test_concurrent_compactors_and_claimers_keep_one_fenced_delivery(inbox):
    terminal(inbox)
    accept(inbox, "event-b")

    def work(index):
        local = SignalInbox(inbox.path)
        return local.compact()["compacted"] if index % 2 else local.claim(now=NOW)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(work, range(16)))
    assert sum(value for value in results if isinstance(value, int)) == 1
    claims = [value for value in results if isinstance(value, dict)]
    assert len(claims) == 1 and claims[0]["event_id"] == "event-b"
    assert inbox.storage_status()["total_records"] == 2


@pytest.mark.parametrize("boundary", ["insert", "delete", "checkpoint", "committed", "migration"])
def test_real_process_death_recovers_one_complete_storage_generation(inbox, tmp_path, boundary):
    terminal(inbox)
    terminal(inbox, "event-b")
    path = inbox.path
    if boundary == "migration":
        path = tmp_path / "legacy.sqlite3"
        legacy_copy(inbox.path, path)
    program = """import os,sqlite3,sys
from app.services.signal_inbox import SignalInbox
original=sqlite3.connect
boundary=sys.argv[2]
class Crash(sqlite3.Connection):
 changed=False
 def execute(self,sql,*args,**kwargs):
  result=super().execute(sql,*args,**kwargs)
  if sql.startswith('INSERT INTO signal_inbox_archive_segments'):self.changed=True
  if ((boundary=='insert' and sql.startswith('INSERT INTO signal_inbox_archive_segments'))
   or (boundary=='delete' and sql.startswith('DELETE FROM signal_inbox '))
   or (boundary=='checkpoint' and self.changed and sql.startswith('UPDATE signal_inbox_archive_metadata'))
   or (boundary=='migration' and sql.startswith('CREATE TABLE signal_inbox_archive_segments'))):os._exit(73)
  return result
 def commit(self):
  super().commit()
  if self.changed and boundary=='committed':os._exit(73)
sqlite3.connect=lambda *a,**k:original(*a,**k,factory=Crash)
SignalInbox(sys.argv[1]).compact()
raise SystemExit(1)
"""
    child = subprocess.run([sys.executable, "-c", program, str(path), boundary], cwd=ROOT,
                           capture_output=True, timeout=20, check=False)
    assert child.returncode == 73 and not child.stdout
    reopened = SignalInbox(path)
    assert reopened.storage_status()["archived_records"] == (2 if boundary == "committed" else 0)
    assert reopened.get("tenant-a", "event-a") == inbox.get("tenant-a", "event-a")
    assert reopened.metrics("tenant-a", now=NOW)["total"] == 2
    reopened.compact()
    assert reopened.storage_status()["archived_records"] == 2
