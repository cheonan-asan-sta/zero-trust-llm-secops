"""Storage atomicity and bounded full-history reconstruction for policy journals."""

import hashlib
import json
import sqlite3
import subprocess
import sys
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.services import policy_journal as journal

ROOT = Path(__file__).resolve().parents[1]
LIMITS = journal.JournalLimits(max_active_records=3, archive_batch_size=2,
                               max_archive_records=100, max_archive_segments=50)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def entry(index):
    return {"kind": "access", "index": index, "label": "관측"}


def write(path, index, limits=LIMITS):
    with journal.transaction(path, limits) as txn:
        journal.append(txn, entry(index))


def read(path, limits=LIMITS):
    with journal.transaction(path, limits) as txn:
        return txn[1], journal.status(txn)


def snapshot(path):
    with sqlite3.connect(path) as connection:
        return {name: connection.execute("SELECT * FROM " + name + " ORDER BY 1").fetchall()
                for name in ("journal", "journal_archive_segments", "journal_storage_metadata")}


@pytest.fixture
def path(tmp_path):
    result = tmp_path / "policy.sqlite3"
    journal.initialize(result, LIMITS)
    return result


def test_automatic_archives_reconstruct_original_payload_and_global_sequence(path):
    previous = "0" * 64
    originals = []
    for index in range(12):
        payload = canonical(entry(index))
        record_hash = digest(previous + "." + payload)
        originals.append([index + 1, payload, previous, record_hash])
        previous = record_hash
        write(path, index)
    entries, status = read(path)
    assert entries == [entry(index) for index in range(12)]
    assert status["active_records"] == 2
    assert status["archived_records"] == 10
    assert status["archive_segments"] == 5
    assert status["total_records"] == 12
    stored = snapshot(path)
    archived = [row for segment in stored["journal_archive_segments"] for row in json.loads(zlib.decompress(segment[7]))]
    assert archived + [list(row) for row in stored["journal"]] == originals
    with journal.transaction(path, LIMITS) as txn:
        assert len(txn) == 3 and txn[2] == previous
        result = journal.compact(txn)
        assert result["compacted"] == 2 and result["active_records"] == 0
    write(path, 12)
    assert snapshot(path)["journal"][0][0] == 13
    assert read(path)[0][-1] == entry(12)


def legacy(path, count=3):
    previous = "0" * 64
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE journal (seq INTEGER PRIMARY KEY,payload TEXT NOT NULL,"
                           "previous_hash TEXT NOT NULL,record_hash TEXT NOT NULL)")
        connection.execute("CREATE TABLE unrelated_receipts (id TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO unrelated_receipts VALUES ('preserve')")
        for index in range(count):
            payload = canonical(entry(index))
            current = digest(previous + "." + payload)
            connection.execute("INSERT INTO journal VALUES (?,?,?,?)", (index + 1, payload, previous, current))
            previous = current


def test_legacy_migration_preserves_exact_rows_and_unrelated_shared_tables(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    legacy(path)
    with sqlite3.connect(path) as connection:
        before = connection.execute("SELECT * FROM journal ORDER BY seq").fetchall()
    journal.initialize(path, LIMITS)
    assert snapshot(path)["journal"] == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("SELECT * FROM unrelated_receipts").fetchall() == [("preserve",)]
    write(path, 3)
    assert read(path)[0] == [entry(index) for index in range(4)]


@pytest.mark.parametrize("field,value", [
    ("max_active_records", 0), ("max_active_records", True), ("archive_batch_size", -1),
    ("archive_batch_size", 1.0), ("max_archive_records", -1), ("max_archive_segments", 0),
    ("max_active_records", 100001), ("archive_batch_size", 100001),
    ("max_archive_records", 1000001), ("max_archive_segments", 10001),
])
def test_limits_reject_invalid_configuration(field, value):
    with pytest.raises(ValueError):
        journal.JournalLimits(**{field: value})


@pytest.mark.parametrize("limits,accepted", [
    (journal.JournalLimits(max_active_records=2, max_archive_records=0), 2),
    (journal.JournalLimits(max_active_records=2, archive_batch_size=2, max_archive_records=3), 5),
    (journal.JournalLimits(max_active_records=2, archive_batch_size=2,
                           max_archive_records=100, max_archive_segments=1), 4),
])
def test_finite_caps_preserve_all_history_and_allow_reads_when_full(tmp_path, limits, accepted):
    path = tmp_path / "bounded.sqlite3"
    journal.initialize(path, limits)
    for index in range(accepted):
        write(path, index, limits)
    before = snapshot(path)
    with pytest.raises(journal.JournalUnavailable):
        write(path, accepted, limits)
    assert snapshot(path) == before
    assert read(path, limits)[0] == [entry(index) for index in range(accepted)]
    with journal.transaction(path, limits) as txn:
        assert journal.status(txn)["total_records"] == accepted
        with pytest.raises(journal.JournalUnavailable):
            journal.compact(txn)
    assert snapshot(path) == before


@pytest.mark.parametrize("limits", [
    journal.JournalLimits(max_active_records=1),
    journal.JournalLimits(max_archive_records=1),
    journal.JournalLimits(max_archive_records=0),
])
def test_reduced_read_limits_fail_without_deleting_retained_history(path, limits):
    for index in range(4):
        write(path, index)
    before = snapshot(path)
    with pytest.raises(journal.JournalUnavailable):
        read(path, limits)
    with pytest.raises(journal.JournalUnavailable):
        journal.initialize(path, limits)
    assert snapshot(path) == before
    assert len(read(path)[0]) == 4


def test_reduced_segment_read_limit_fails_without_loading_archives(path, monkeypatch):
    for index in range(6):
        write(path, index)
    before = snapshot(path)
    limits = journal.JournalLimits(max_archive_segments=1)
    monkeypatch.setattr(journal, "_decompress", lambda *args: pytest.fail("excess archive count was decompressed"))
    with pytest.raises(journal.JournalUnavailable):
        read(path, limits)
    assert snapshot(path) == before


def test_legacy_migration_respects_current_active_limit_without_reset(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    legacy(path)
    limits = journal.JournalLimits(max_active_records=2)
    with pytest.raises(journal.JournalUnavailable):
        journal.initialize(path, limits)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM journal").fetchone()[0] == 3
    journal.initialize(path, LIMITS)
    assert len(read(path)[0]) == 3


def test_preflight_reserves_whole_batch_and_rejects_oversized_single_fanout(path):
    for index in range(3):
        write(path, index)
    before = snapshot(path)
    with pytest.raises(journal.JournalUnavailable), journal.transaction(path, LIMITS) as txn:
        journal.ensure_capacity(txn, 4)
    assert snapshot(path) == before
    with journal.transaction(path, LIMITS) as txn:
        journal.ensure_capacity(txn, 3)
        assert txn.active_records == 0
        for index in range(3, 6):
            journal.append(txn, entry(index))
    assert read(path)[0] == [entry(index) for index in range(6)]


@pytest.mark.parametrize("exception", [ValueError, LookupError])
def test_consumer_exceptions_keep_their_type_and_roll_back_archive_and_append(path, exception):
    for index in range(3):
        write(path, index)
    before = snapshot(path)
    failure = exception("consumer policy failure")
    with pytest.raises(exception) as raised, journal.transaction(path, LIMITS) as txn:
        journal.append(txn, entry(3))
        raise failure
    assert raised.value is failure
    assert snapshot(path) == before


@pytest.mark.parametrize("sql", [
    ("CREATE TRIGGER reject_archive BEFORE INSERT ON journal_archive_segments "
     "BEGIN SELECT RAISE(ABORT,'failure'); END"),
    ("CREATE TRIGGER reject_delete BEFORE DELETE ON journal "
     "BEGIN SELECT RAISE(ABORT,'failure'); END"),
    ("CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON journal_storage_metadata "
     "BEGIN SELECT RAISE(ABORT,'failure'); END"),
])
def test_archive_move_or_checkpoint_write_failure_rolls_back_everything(path, sql):
    for index in range(3):
        write(path, index)
    before = snapshot(path)
    with sqlite3.connect(path) as connection:
        connection.execute(sql)
    with pytest.raises(journal.JournalUnavailable):
        write(path, 3)
    assert snapshot(path) == before


def test_commit_failure_rolls_back_archive_and_new_tail(path, monkeypatch):
    for index in range(3):
        write(path, index)
    before = snapshot(path)
    original = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

    with monkeypatch.context() as context:
        context.setattr(journal.sqlite3, "connect", lambda *a, **k: original(*a, **k, factory=FailedCommit))
        with pytest.raises(journal.JournalUnavailable):
            write(path, 3)
    assert snapshot(path) == before


@pytest.mark.parametrize("sql", [
    "DELETE FROM journal_archive_segments",
    "UPDATE journal_archive_segments SET start_seq=2",
    "UPDATE journal_archive_segments SET end_seq=9",
    "UPDATE journal_archive_segments SET terminal_hash='bad'",
    "UPDATE journal_archive_segments SET record_count=999",
    "UPDATE journal_archive_segments SET payload=x'00'",
    "UPDATE journal_archive_segments SET segment_digest='bad'",
    "UPDATE journal_archive_segments SET uncompressed_size=999999999",
    "UPDATE journal SET previous_hash='bad'",
    "UPDATE journal SET seq=99 WHERE seq=(SELECT max(seq) FROM journal)",
    "DELETE FROM journal WHERE seq=(SELECT max(seq) FROM journal)",
    "DELETE FROM journal_storage_metadata",
    "UPDATE journal_storage_metadata SET metadata_digest='bad'",
])
def test_archive_header_tail_checkpoint_and_deletion_corruption_fail_closed(path, sql):
    for index in range(4):
        write(path, index)
    with sqlite3.connect(path) as connection:
        connection.execute(sql)
    for operation in (lambda: read(path), lambda: journal.initialize(path, LIMITS)):
        with pytest.raises(journal.JournalUnavailable):
            operation()


@pytest.mark.parametrize("table", ["journal", "journal_archive_segments", "journal_storage_metadata"])
def test_version_marker_prevents_recreating_missing_v2_tables(path, table):
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE " + table)
    with pytest.raises(journal.JournalUnavailable):
        journal.initialize(path, LIMITS)
    with sqlite3.connect(path) as connection:
        assert table not in {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


@pytest.mark.parametrize("version", [0, 1, 3])
def test_wrong_version_or_unmarked_archive_is_not_migrated(path, version):
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=" + str(version))
    before = snapshot(path)
    with pytest.raises(journal.JournalUnavailable):
        journal.initialize(path, LIMITS)
    assert snapshot(path) == before


def rewrite_archive(path, transform):
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT * FROM journal_archive_segments WHERE segment_no=1").fetchone()
        header = dict(zip(("segment_no", "start_seq", "end_seq", "prior_hash", "terminal_hash",
                           "record_count", "uncompressed_size"), row[:7], strict=True))
        blob = transform(row[7])
        checksum = digest(canonical(header | {"payload_sha256": hashlib.sha256(blob).hexdigest()}))
        connection.execute("UPDATE journal_archive_segments SET payload=?,segment_digest=? WHERE segment_no=1",
                           (blob, checksum))


@pytest.mark.parametrize("suffix", [b"trailing", zlib.compress(b"second stream")])
def test_valid_blob_checksum_cannot_hide_trailing_or_concatenated_compressed_data(path, suffix):
    for index in range(4):
        write(path, index)
    rewrite_archive(path, lambda blob: blob + suffix)
    with pytest.raises(journal.JournalUnavailable):
        read(path)


def test_bounded_decompression_rejects_output_larger_than_declared_size():
    blob = zlib.compress(b"x" * (journal.MAX_SEGMENT_BYTES + 1))
    with pytest.raises(ValueError):
        journal._decompress(blob, 1)


def test_canonical_json_and_original_record_hash_are_both_verified_inside_archive(path):
    for index in range(4):
        write(path, index)

    def change(blob):
        rows = json.loads(zlib.decompress(blob))
        rows[0][1] = rows[0][1].replace('"index":0', '"index":9')
        return zlib.compress(canonical(rows).encode())

    rewrite_archive(path, change)
    with pytest.raises(journal.JournalUnavailable):
        read(path)


def test_segment_byte_bound_splits_archive_and_segment_cap_leaves_tail_intact(path, monkeypatch):
    limits = journal.JournalLimits(max_active_records=8, archive_batch_size=8,
                                   max_archive_records=100, max_archive_segments=2)
    with journal.transaction(path, limits) as txn:
        for index in range(8):
            journal.append(txn, entry(index) | {"padding": "a" * 100})
    original = read(path, limits)[0]
    monkeypatch.setattr(journal, "MAX_SEGMENT_BYTES", 512)
    with journal.transaction(path, limits) as txn:
        result = journal.compact(txn, 8)
        assert result["segments_created"] == 2
        assert 0 < result["compacted"] < 8
    assert read(path, limits)[0] == original
    with journal.transaction(path, limits) as txn, pytest.raises(journal.JournalUnavailable):
        journal.compact(txn)


def test_aggregate_byte_cap_rejects_new_write_without_losing_original_history(path, monkeypatch):
    monkeypatch.setattr(journal, "MAX_TOTAL_BYTES", 1024)
    accepted = 0
    while True:
        before = snapshot(path)
        try:
            write(path, accepted)
        except journal.JournalUnavailable:
            assert snapshot(path) == before
            break
        accepted += 1
        assert accepted < 30
    assert read(path)[0] == [entry(index) for index in range(accepted)]


def test_nonfinite_or_oversized_entry_is_rejected_before_any_archive(path, monkeypatch):
    for index in range(3):
        write(path, index)
    before = snapshot(path)
    monkeypatch.setattr(journal, "MAX_ENTRY_BYTES", 1024)
    for invalid in (entry(3) | {"number": float("nan")}, entry(3) | {"padding": "a" * 1200}):
        with pytest.raises(journal.JournalUnavailable), journal.transaction(path, LIMITS) as txn:
            journal.append(txn, invalid)
        assert snapshot(path) == before


def test_unknown_entry_kind_preserves_legacy_corruption_detection_boundary(path):
    with journal.transaction(path, LIMITS) as txn:
        journal.append(txn, {"kind": "unknown"})
    with pytest.raises(journal.JournalUnavailable):
        read(path)


def test_concurrent_writers_preserve_unique_monotonic_logical_history(path):
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda index: write(path, index), range(24)))
    entries, status = read(path)
    assert sorted(item["index"] for item in entries) == list(range(24))
    assert status["total_records"] == 24
    assert status["active_records"] <= LIMITS.max_active_records


@pytest.mark.parametrize("boundary", ["insert", "delete", "checkpoint", "committed", "migration"])
def test_real_process_death_preserves_one_atomic_generation(tmp_path, boundary):
    path = tmp_path / "crash.sqlite3"
    legacy(path, count=3)
    if boundary != "migration":
        journal.initialize(path, LIMITS)
    program = """import os,sqlite3,sys
from app.services import policy_journal as j
original=sqlite3.connect
boundary=sys.argv[2]
class Crash(sqlite3.Connection):
 changed=False
 def execute(self,sql,*args,**kwargs):
  result=super().execute(sql,*args,**kwargs)
  if sql.startswith('INSERT INTO journal_archive_segments'):self.changed=True
  hit=((boundary=='insert' and sql.startswith('INSERT INTO journal_archive_segments'))
    or (boundary=='delete' and sql.startswith('DELETE FROM journal'))
    or (boundary=='checkpoint' and self.changed and sql.startswith('UPDATE journal_storage_metadata'))
    or (boundary=='migration' and sql.startswith('CREATE TABLE journal_archive_segments')))
  if hit:os._exit(73)
  return result
 def commit(self):
  super().commit()
  if self.changed and boundary=='committed':os._exit(73)
sqlite3.connect=lambda *a,**k:original(*a,**k,factory=Crash)
limits=j.JournalLimits(max_active_records=3,archive_batch_size=2,max_archive_records=100,max_archive_segments=50)
j.initialize(sys.argv[1],limits)
with j.transaction(sys.argv[1],limits) as t:j.append(t,{'kind':'access','index':3,'label':'관측'})
raise SystemExit(1)
"""
    child = subprocess.run([sys.executable, "-c", program, str(path), boundary], cwd=ROOT,
                           capture_output=True, timeout=20, check=False)
    assert child.returncode == 73 and not child.stdout
    journal.initialize(path, LIMITS)
    expected = 4 if boundary == "committed" else 3
    assert read(path)[0] == [entry(index) for index in range(expected)]
    if boundary != "committed":
        assert read(path)[1]["archived_records"] == 0
        write(path, 3)
        assert len(read(path)[0]) == 4


def test_migration_commit_failure_rolls_back_schema_marker_and_new_tables(tmp_path, monkeypatch):
    path = tmp_path / "legacy.sqlite3"
    legacy(path)
    original = sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected migration commit failure")

    with monkeypatch.context() as context:
        context.setattr(journal.sqlite3, "connect", lambda *a, **k: original(*a, **k, factory=FailedCommit))
        with pytest.raises(journal.JournalUnavailable):
            journal.initialize(path, LIMITS)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert tables == {"journal", "unrelated_receipts"}
    journal.initialize(path, LIMITS)
    assert read(path)[0] == [entry(index) for index in range(3)]
