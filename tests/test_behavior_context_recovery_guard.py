import sqlite3
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.services.behavior_context_store import BehaviorContextStore, ContextStoreUnavailable
from scripts import app_state_recovery as recovery
from scripts import behavior_context_recovery as context_storage
from scripts import serve_recovered_app as gate
from scripts.app_recovery_fixture import prepare

NOW = datetime(2026, 11, 10, tzinfo=UTC)
CONTEXT_NAME = "app-behavior-context.sqlite3"


def populated(path):
    store = BehaviorContextStore(path)
    with store.transaction() as transaction:
        transaction.put("approval", "tenant-a", "approved-work", {"scope": "fixture"}, "admin", NOW)
    return store


def test_absent_guard_never_creates_source_or_parent_directory(tmp_path):
    path = tmp_path / "absent-parent" / CONTEXT_NAME
    assert context_storage.inspect(path.parent, allow_missing=True)["records"] == 0
    assert not path.parent.exists()


def test_valid_empty_guard_is_read_only_and_makes_no_sidecars(tmp_path):
    path = tmp_path / CONTEXT_NAME
    BehaviorContextStore(path)
    before, names = path.read_bytes(), set(tmp_path.iterdir())
    stat = path.stat()
    assert context_storage.inspect(path.parent)["records"] == 0
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == stat.st_mtime_ns
    assert set(tmp_path.iterdir()) == names


@pytest.mark.parametrize("state", ["damaged", "zero-bytes", "symlink", "orphan-sidecar"])
def test_unsupported_context_is_rejected_without_source_changes(tmp_path, state):
    path = tmp_path / CONTEXT_NAME
    if state == "damaged":
        BehaviorContextStore(path)
        with sqlite3.connect(path) as connection:
            connection.execute("DELETE FROM behavior_context_head")
    elif state == "zero-bytes":
        path.write_bytes(b"")
    elif state == "symlink":
        target = tmp_path / "original.sqlite3"
        BehaviorContextStore(target)
        path.symlink_to(target)
    else:
        (tmp_path / (CONTEXT_NAME + "-wal")).write_bytes(b"unaccounted")
    before = {item.name: item.read_bytes() for item in tmp_path.iterdir() if item.is_file()}
    with pytest.raises(ContextStoreUnavailable):
        context_storage.inspect(path.parent, allow_missing=True)
    assert {item.name: item.read_bytes() for item in tmp_path.iterdir() if item.is_file()} == before


def test_snapshot_and_initialize_include_nonempty_context_without_source_changes(tmp_path):
    source, target = tmp_path / "data", tmp_path / "snapshot"
    prepare(source)
    populated(source / CONTEXT_NAME)
    before = (source / CONTEXT_NAME).read_bytes()
    result = recovery.snapshot(source, target)
    assert result["state"]["behavior_context"]["records"] == 1
    assert BehaviorContextStore(target / CONTEXT_NAME).read("tenant-a") == BehaviorContextStore(source / CONTEXT_NAME).read("tenant-a")
    assert recovery.Store(tmp_path).initialize()["initialized"]
    assert (source / CONTEXT_NAME).read_bytes() == before


def test_explicit_external_context_cannot_be_silently_omitted(tmp_path, monkeypatch):
    source = tmp_path / "data"
    prepare(source)
    external = tmp_path / "elsewhere" / "context.sqlite3"
    populated(external)
    monkeypatch.setattr(recovery, "get_settings", lambda: SimpleNamespace(behavior_context_db_path=external))
    with pytest.raises(recovery.RecoveryError, match="behavior_context_path_mismatch"):
        recovery.snapshot(source, tmp_path / "snapshot")


def test_new_context_record_during_snapshot_is_detected(tmp_path, monkeypatch):
    source, target = tmp_path / "data", tmp_path / "snapshot"
    prepare(source)
    BehaviorContextStore(source / CONTEXT_NAME)
    original = sqlite3.connect

    class MutatingBackup(sqlite3.Connection):
        def backup(self, destination, *args, **kwargs):
            result = super().backup(destination, *args, **kwargs)
            populated(source / CONTEXT_NAME)
            return result

    def connect(*args, **kwargs):
        if kwargs.get("uri") and "mode=ro" in str(args[0]) and "immutable" not in str(args[0]):
            kwargs["factory"] = MutatingBackup
        return original(*args, **kwargs)

    monkeypatch.setattr(recovery.sqlite3, "connect", connect)
    with pytest.raises(recovery.RecoveryError, match="behavior_context_changed_during_snapshot"):
        recovery.snapshot(source, target)


def test_empty_context_does_not_break_recovery_and_restored_context_is_guarded(tmp_path, recovery_clock, monkeypatch):
    source = tmp_path / "data"
    prepare(source)
    BehaviorContextStore(source / CONTEXT_NAME)
    store = recovery.Store(tmp_path)
    store.initialize()
    store.checkpoint()
    backup = store.backup()
    result = store.restore(backup["backup_id"])
    stage = tmp_path / "restores" / result["restore_id"]
    assert recovery.verify_admission(stage, tmp_path / "public")["admission_verified"]
    settings = SimpleNamespace(
        analyzer_mode="rule", auth_mode="api_key", zero_trust_db_path=stage / "app.sqlite3",
        trusted_signal_sources_path=stage / "sources.json", behavior_context_db_path=None,
    )
    monkeypatch.setattr(gate, "get_settings", lambda: settings)
    assert gate.admit(stage, tmp_path / "public")["admission_verified"]
    settings.behavior_context_db_path = source / CONTEXT_NAME
    with pytest.raises(recovery.RecoveryError, match="behavior_context_path_mismatch"):
        gate.admit(stage, tmp_path / "public")
    settings.behavior_context_db_path = stage / CONTEXT_NAME
    BehaviorContextStore(stage / CONTEXT_NAME)
    assert gate.admit(stage, tmp_path / "public")["admission_verified"]
    populated(stage / CONTEXT_NAME)
    assert gate.admit(stage, tmp_path / "public")["context_records"] == 1
    (stage / CONTEXT_NAME).unlink()
    with pytest.raises(recovery.RecoveryError, match="admission_context_changed"):
        recovery.verify_admission(stage, tmp_path / "public")


def test_context_added_after_checkpoint_blocks_backup(tmp_path, recovery_clock):
    source = tmp_path / "data"
    prepare(source)
    store = recovery.Store(tmp_path)
    store.initialize()
    store.checkpoint()
    populated(source / CONTEXT_NAME)
    with pytest.raises(recovery.RecoveryError, match="source_advanced_since_checkpoint"):
        store.backup()
    assert list((tmp_path / "backups").iterdir()) == []


def test_context_file_counts_toward_combined_backup_size_and_is_never_truncated(
    tmp_path, recovery_clock, monkeypatch,
):
    source = tmp_path / "data"
    prepare(source)
    populated(source / CONTEXT_NAME)
    store = recovery.Store(tmp_path)
    store.initialize()
    store.checkpoint()
    before = (source / CONTEXT_NAME).read_bytes()
    # Enough for the old SQLite/registry pair, but not the added context file.
    old_size = sum((source / name).stat().st_size for name in ("app.sqlite3", "sources.json"))
    monkeypatch.setattr(recovery, "MAX_BACKUP_COMPONENT_BYTES", old_size + 1)
    with pytest.raises(recovery.RecoveryError, match="backup_components_size_limit"):
        store.backup()
    assert list((tmp_path / "backups").iterdir()) == []
    assert (source / CONTEXT_NAME).read_bytes() == before
