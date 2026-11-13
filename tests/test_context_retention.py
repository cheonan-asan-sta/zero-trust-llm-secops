"""Lossless context retention across capacity, interrupted writes and restore admission."""

import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.behavior_context_models import ContextRevocation
from app.services import context_archive
from app.services.behavior_context_store import (
    BehaviorContextStore,
    ContextRecordConflict,
    ContextStoreUnavailable,
)
from scripts import behavior_context_recovery as recovery
from tests import test_behavior_context_recovery as integration

NOW = datetime(2026, 11, 13, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def add(store, count, *, start=0):
    with store.transaction() as tx:
        for index in range(start, start + count):
            tx.put("capture", "tenant-a", f"record-{index}", {"value": index}, "observer", NOW)


def test_more_than_ten_thousand_preserves_original_history_and_duplicate_identity(tmp_path):
    store = BehaviorContextStore(tmp_path / recovery.NAME)
    add(store, 10_005)
    status = store.storage_status()
    assert status["total_records"] == 10_005
    assert status["active_records"] <= 10_000 and status["archived_records"] > 0
    restarted = BehaviorContextStore(store.path)
    with restarted.transaction() as tx:
        repeated = tx.put("capture", "tenant-a", "record-0", {"value": 0}, "other", NOW)
        assert repeated["duplicate"] and repeated["entry"]["actor"] == "observer"
    with pytest.raises(ContextRecordConflict), restarted.transaction() as tx:
        tx.put("capture", "tenant-a", "record-0", {"value": -1}, "observer", NOW)
    assert len(restarted.read("tenant-a")) == 10_005
    assert restarted.read("tenant-b") == []


def test_migration_and_compaction_preserve_legacy_admission_prefix(tmp_path):
    store = BehaviorContextStore(tmp_path / recovery.NAME)
    add(store, 5)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE behavior_context_archive")
        connection.execute("PRAGMA user_version=1")
    legacy_pin = recovery.inspect(tmp_path)
    store = BehaviorContextStore(store.path)
    before = store.read("tenant-a")
    assert store.compact(limit=3) == {"compacted": 3}
    add(store, 1, start=5)
    assert recovery.verify_prefix(tmp_path, legacy_pin)["records"] == 6
    target = tmp_path / "snapshot"
    target.mkdir()
    assert recovery.capture(tmp_path, target)["records"] == 6
    assert BehaviorContextStore(target / recovery.NAME).read("tenant-a")[:5] == before


def test_process_dies_after_archive_insert_and_delete_but_before_commit(tmp_path):
    store = BehaviorContextStore(tmp_path / recovery.NAME)
    add(store, 6)
    before = store.read("tenant-a")
    program = """
import os,sys
from app.services.behavior_context_store import BehaviorContextStore
from app.services.context_archive import compact
s=BehaviorContextStore(sys.argv[1])
with s.transaction() as t:
    assert compact(t._connection,3)==3
    os._exit(73)
"""
    child = subprocess.run([sys.executable, "-c", program, str(store.path)], cwd=ROOT, check=False)
    assert child.returncode == 73
    restarted = BehaviorContextStore(store.path)
    assert restarted.read("tenant-a") == before
    assert restarted.storage_status()["archived_records"] == 0
    assert restarted.compact(limit=3)["compacted"] == 3
    assert restarted.read("tenant-a") == before


@pytest.mark.parametrize("mutation", [
    "UPDATE behavior_context_archive SET payload=x'0001'",
    "UPDATE behavior_context_archive SET raw_bytes=16777217",
    "UPDATE behavior_context_archive SET record_count=1",
    "DELETE FROM behavior_context_archive",
    "UPDATE behavior_context_archive SET sha256='changed'",
])
def test_corrupt_or_missing_archive_fails_closed(tmp_path, mutation):
    store = BehaviorContextStore(tmp_path / recovery.NAME)
    add(store, 5)
    store.compact(limit=3)
    with sqlite3.connect(store.path) as connection:
        connection.execute(mutation)
    with pytest.raises(ContextStoreUnavailable):
        BehaviorContextStore(store.path)
    with pytest.raises(ContextStoreUnavailable):
        recovery.inspect(tmp_path)


def test_archive_full_rolls_back_new_record_but_duplicate_still_works(tmp_path, monkeypatch):
    store = BehaviorContextStore(tmp_path / recovery.NAME, max_active_records=2)
    add(store, 3)
    before = store.read("tenant-a")
    monkeypatch.setattr(context_archive, "MAX_SEGMENTS", 1)
    with pytest.raises(ContextStoreUnavailable):
        add(store, 1, start=3)
    assert store.read("tenant-a") == before
    with store.transaction() as tx:
        assert tx.put("capture", "tenant-a", "record-0", {"value": 0}, "observer", NOW)["duplicate"]


@pytest.fixture
def context_lab(tmp_path, monkeypatch):
    return integration.recovery_context.__wrapped__(tmp_path, monkeypatch)


def test_archived_approval_use_survives_full_restore(context_lab, tmp_path, monkeypatch):
    lab = context_lab
    original, _ = integration.seed(lab, max_uses=1)
    before = lab.store.read("tenant-a")
    assert lab.store.compact(limit=1000)["compacted"] > 0
    saved = integration.backup(lab, tmp_path, monkeypatch)
    restored = integration.restore(saved, lab)
    assert restored.service.store.read("tenant-a") == before
    assert integration.access(restored, original.session).status_code == 403
    target = integration.fresh_capture(restored, lab, "after-archive-restore", 7)
    result = restored.service.evaluate(target.id, lab.analyst, now=lab.at(7))
    assert result["verdict"] == "unknown"
    assert result["reason"] == "CONTEXT_REQUIRED"
    assert integration.access(restored, target.session).status_code == 200


@pytest.mark.parametrize("kind,identifier", [("baseline", "baseline-a"), ("approval", "approval-a")])
def test_archived_revocation_still_excludes_previously_normal_work(context_lab, kind, identifier):
    lab = context_lab
    target, _ = integration.seed(lab)
    lab.service.revoke(kind, identifier, ContextRevocation(reason="Permission withdrawn before archive"),
                       lab.operator, now=lab.at(5))
    lab.store.compact(limit=1000)
    with BehaviorContextStore(lab.store_path).transaction() as transaction:
        assert transaction.revoked(kind, "tenant-a", identifier)
    assert lab.service.evaluate(target.id, lab.analyst, now=lab.at(6))["verdict"] == "unknown"
