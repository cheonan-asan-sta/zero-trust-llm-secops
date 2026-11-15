import copy
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.services.behavior_context_store import BehaviorContextStore, ContextStoreUnavailable
from scripts import behavior_context_recovery as recovery

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def append(store, identifier="capture-a"):
    with store.transaction() as transaction:
        transaction.put("capture", "tenant-a", identifier, {"capture": "서명된 관측"}, "collector", NOW)


def rows(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
        return connection.execute("SELECT * FROM behavior_context_entries ORDER BY seq").fetchall()


@pytest.fixture
def source(tmp_path):
    directory = tmp_path / "source"
    directory.mkdir()
    store = BehaviorContextStore(directory / recovery.NAME)
    append(store)
    with store.transaction() as transaction:
        transaction.put("baseline", "tenant-a", "baseline-a", {"training": ["capture-a"]}, "reviewer", NOW)
        transaction.put("approval", "tenant-a", "approval-a", {"max_uses": 1}, "responder", NOW)
        transaction.put("evaluation", "tenant-a", "evaluation-a", {
            "capture_id": "capture-a", "verdict": "normal", "approval_id": "approval-a",
        }, "analyst", NOW)
        transaction.put("revocation", "tenant-a", "revocation-a", {
            "target_kind": "approval", "target_id": "approval-a", "reason": "작업 승인 취소",
        }, "responder", NOW)
    return store


def test_snapshot_preserves_exact_history_without_writing_source(source, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    original = source.path.read_bytes()
    metadata = source.path.stat()
    source.path.chmod(0o400)
    expected = recovery.inspect(source.path.parent)
    copied = recovery.capture(source.path.parent, target)
    assert copied == expected and copied["records"] == 5
    assert rows(source.path) == rows(target / recovery.NAME)
    assert source.path.read_bytes() == original
    assert source.path.stat().st_mtime_ns == metadata.st_mtime_ns
    assert list(source.path.parent.iterdir()) == [source.path]
    with BehaviorContextStore(target / recovery.NAME).transaction() as transaction:
        assert transaction.revoked("approval", "tenant-a", "approval-a")
        assert transaction.get("evaluation", "tenant-a", "evaluation-a")["payload"]["verdict"] == "normal"


def test_missing_source_is_materialized_only_in_target_and_missing_admitted_file_is_rejected(tmp_path):
    source = tmp_path / "never-created" / "source"
    target = tmp_path / "target"
    target.mkdir()
    expected = recovery.inspect(source, allow_missing=True)
    assert not source.parent.exists()
    assert recovery.capture(source, target) == expected
    assert expected["records"] == expected["bytes"] == 0
    assert recovery.verify_prefix(target, expected) == expected
    assert not source.parent.exists()
    (target / recovery.NAME).unlink()
    with pytest.raises(ContextStoreUnavailable, match="missing"):
        recovery.verify_prefix(target, expected)


def test_valid_empty_source_has_same_pin_as_absence_without_initializing_missing_source(tmp_path):
    empty = tmp_path / "empty"
    BehaviorContextStore(empty / recovery.NAME)
    absent = tmp_path / "absent"
    assert recovery.inspect(empty) == recovery.inspect(absent, allow_missing=True)
    with pytest.raises(ContextStoreUnavailable):
        recovery.inspect(absent)
    assert not absent.exists()


def test_admission_accepts_new_valid_records_and_preserves_prior_approval_usage(source):
    pin = recovery.inspect(source.path.parent)
    append(source, "new-capture")
    current = recovery.verify_prefix(source.path.parent, pin)
    assert current["records"] == pin["records"] + 1
    assert current["head_sha256"] != pin["head_sha256"]
    assert BehaviorContextStore(source.path).read("tenant-a")[3]["payload"]["approval_id"] == "approval-a"


def test_valid_but_truncated_history_is_rejected_by_admission(source, tmp_path):
    pin = recovery.inspect(source.path.parent)
    earlier = tmp_path / "earlier"
    prior = BehaviorContextStore(earlier / recovery.NAME)
    append(prior)
    assert recovery.inspect(earlier)["records"] == 1
    with pytest.raises(ContextStoreUnavailable, match="prefix_missing"):
        recovery.verify_prefix(earlier, pin)


def test_valid_rewritten_history_cannot_replace_the_admitted_prefix(source, tmp_path):
    pin = recovery.inspect(source.path.parent)
    replacement = BehaviorContextStore(tmp_path / "replacement" / recovery.NAME)
    with source.transaction() as source_tx, replacement.transaction() as replacement_tx:
        for entry in source_tx.entries:
            if entry["kind"] == "approval":
                entry["payload"]["max_uses"] = 99
            replacement_tx.append(entry)
    assert recovery.inspect(replacement.path.parent)["records"] == pin["records"]
    with pytest.raises(ContextStoreUnavailable, match="prefix_changed"):
        recovery.verify_prefix(replacement.path.parent, pin)


@pytest.mark.parametrize("mutation", ["delete", "change", "head", "schema", "truncate"])
def test_corruption_is_rejected_without_source_repair(source, mutation):
    if mutation == "truncate":
        source.path.write_bytes(source.path.read_bytes()[:100])
    else:
        with sqlite3.connect(source.path) as connection:
            if mutation == "delete":
                connection.execute("DELETE FROM behavior_context_entries WHERE seq=2")
            elif mutation == "change":
                connection.execute("UPDATE behavior_context_entries SET payload='{}' WHERE seq=3")
            elif mutation == "head":
                connection.execute("DELETE FROM behavior_context_head")
            else:
                connection.execute("CREATE INDEX unexpected_index ON behavior_context_entries(kind)")
    original = source.path.read_bytes()
    with pytest.raises(ContextStoreUnavailable):
        recovery.inspect(source.path.parent)
    assert source.path.read_bytes() == original
    assert list(source.path.parent.iterdir()) == [source.path]


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
@pytest.mark.parametrize("has_database", [False, True])
def test_sidecars_are_not_ignored_even_when_database_is_absent(tmp_path, suffix, has_database):
    if has_database:
        BehaviorContextStore(tmp_path / recovery.NAME)
    sidecar = tmp_path / (recovery.NAME + suffix)
    sidecar.write_bytes(b"unrecovered state")
    original = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    with pytest.raises(ContextStoreUnavailable, match="sidecars"):
        recovery.inspect(tmp_path, allow_missing=True)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == original


@pytest.mark.parametrize("kind", ["file-symlink", "directory-symlink", "empty-file", "directory"])
def test_nonregular_or_symlink_source_is_rejected(tmp_path, kind):
    original = tmp_path / "original"
    BehaviorContextStore(original / recovery.NAME)
    source = tmp_path / "source"
    if kind == "directory-symlink":
        source.symlink_to(original, target_is_directory=True)
    else:
        source.mkdir()
        path = source / recovery.NAME
        if kind == "file-symlink":
            path.symlink_to(original / recovery.NAME)
        elif kind == "empty-file":
            path.touch()
        else:
            path.mkdir()
    with pytest.raises(ContextStoreUnavailable):
        recovery.inspect(source, allow_missing=True)


def test_oversized_source_is_rejected_without_reading_or_truncating(source, monkeypatch):
    original = source.path.read_bytes()
    monkeypatch.setattr(recovery, "MAX_DATABASE", len(original) - 1)
    with pytest.raises(ContextStoreUnavailable, match="size_limit"):
        recovery.inspect(source.path.parent)
    assert source.path.read_bytes() == original


def test_source_advance_during_sqlite_backup_does_not_publish_a_snapshot(source, tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    connect = sqlite3.connect

    class AdvancingConnection(sqlite3.Connection):
        def backup(self, destination, *args, **kwargs):
            result = super().backup(destination, *args, **kwargs)
            append(source, "concurrent-capture")
            return result

    def racing_connect(database, *args, **kwargs):
        if str(database).startswith(source.path.resolve().as_uri() + "?"):
            kwargs["factory"] = AdvancingConnection
        return connect(database, *args, **kwargs)

    monkeypatch.setattr(recovery.sqlite3, "connect", racing_connect)
    with pytest.raises(ContextStoreUnavailable, match="changed_during_snapshot"):
        recovery.capture(source.path.parent, target)
    assert recovery.inspect(source.path.parent)["records"] == 6
    assert recovery.inspect(target)["records"] == 5


def test_source_appearing_during_empty_snapshot_is_rejected(tmp_path, monkeypatch):
    source, target = tmp_path / "source", tmp_path / "target"
    target.mkdir()
    inspect = recovery.inspect

    def interrupted_inspect(directory, **kwargs):
        result = inspect(directory, **kwargs)
        if Path(directory) == target:
            append(BehaviorContextStore(source / recovery.NAME))
        return result

    monkeypatch.setattr(recovery, "inspect", interrupted_inspect)
    with pytest.raises(ContextStoreUnavailable, match="changed_during_snapshot"):
        recovery.capture(source, target)


def test_interrupted_snapshot_can_retry_with_new_destination_and_original_history(source, tmp_path, monkeypatch):
    interrupted, retry = tmp_path / "interrupted", tmp_path / "retry"
    interrupted.mkdir()
    retry.mkdir()
    original = rows(source.path)
    connect = sqlite3.connect

    class BrokenConnection(sqlite3.Connection):
        def backup(self, *args, **kwargs):
            raise sqlite3.OperationalError("simulated process storage failure")

    def broken_connect(database, *args, **kwargs):
        if str(database).startswith(source.path.resolve().as_uri() + "?"):
            kwargs["factory"] = BrokenConnection
        return connect(database, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(recovery.sqlite3, "connect", broken_connect)
        with pytest.raises(ContextStoreUnavailable):
            recovery.capture(source.path.parent, interrupted)
    with pytest.raises(ContextStoreUnavailable):
        recovery.inspect(interrupted)
    assert recovery.capture(source.path.parent, retry) == recovery.inspect(source.path.parent)
    assert rows(source.path) == rows(retry / recovery.NAME) == original


@pytest.mark.parametrize("change", [
    {"records": True}, {"format": True}, {"records": -1}, {"bytes": -1},
    {"head_sha256": "not-a-hash"}, {"schema_sha256": "0" * 64}, {"extra": "value"},
])
def test_invalid_or_wrong_admission_pin_is_rejected(source, change):
    pin = copy.deepcopy(recovery.inspect(source.path.parent))
    pin.update(change)
    with pytest.raises(ContextStoreUnavailable):
        recovery.verify_prefix(source.path.parent, pin)


def test_existing_destination_is_not_overwritten(source, tmp_path):
    target = tmp_path / "target"
    store = BehaviorContextStore(target / recovery.NAME)
    append(store, "original-target")
    original = store.path.read_bytes()
    with pytest.raises(ContextStoreUnavailable, match="fresh_context_snapshot"):
        recovery.capture(source.path.parent, target)
    assert store.path.read_bytes() == original


def test_backup_deadline_does_not_modify_original(source, tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    original = source.path.read_bytes()
    ticks = iter([0, 100])
    monkeypatch.setattr(recovery.time, "monotonic", lambda: next(ticks))
    with pytest.raises(ContextStoreUnavailable, match="deadline"):
        recovery.capture(source.path.parent, target, timeout=1)
    assert source.path.read_bytes() == original
    assert not (target / recovery.NAME).exists()
