import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.services.behavior_context_store import (
    MAX_ENTRY_BYTES,
    BehaviorContextStore,
    ContextRecordConflict,
    ContextStoreUnavailable,
)

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def put(store, identifier="sample", *, tenant="tenant-a", payload=None, actor="reviewer", now=NOW):
    with store.transaction() as transaction:
        return transaction.put("capture", tenant, identifier,
                               payload if payload is not None else {"value": "original"}, actor, now)


@pytest.fixture
def store(tmp_path):
    return BehaviorContextStore(tmp_path / "behavior-context.sqlite3")


def test_committed_capture_reopens_with_original_attribution(store):
    original = put(store)
    reopened = BehaviorContextStore(store.path)
    repeated = put(reopened, now=NOW + timedelta(hours=1), actor="another-reviewer")
    assert original["duplicate"] is False
    assert repeated == original | {"duplicate": True}
    assert repeated["entry"]["actor"] == "reviewer"
    assert repeated["entry"]["created_at"] == NOW.isoformat()
    assert reopened.read("tenant-a") == [original["entry"]]


def test_changed_record_conflicts_and_does_not_replace_history(store):
    original = put(store)
    with pytest.raises(ContextRecordConflict):
        put(store, payload={"value": "changed"})
    assert store.read("tenant-a") == [original["entry"]]


def test_identity_is_kind_and_tenant_scoped(store):
    put(store)
    put(store, tenant="tenant-b")
    with store.transaction() as transaction:
        transaction.put("baseline", "tenant-a", "sample", {"reviewed": True}, "admin", NOW)
        assert transaction.get("approval", "tenant-a", "sample") is None
        assert transaction.get("capture", "tenant-c", "sample") is None
    assert len(store.read("tenant-a")) == 2
    assert len(store.read("tenant-b")) == 1
    assert store.read("tenant-c") == []


def test_mutating_returned_dicts_cannot_change_in_memory_or_saved_authority(store):
    put(store, payload={"nested": {"trusted": False}})
    with store.transaction() as transaction:
        transaction.entries[0]["payload"]["nested"]["trusted"] = True
        transaction.get("capture", "tenant-a", "sample")["payload"]["nested"]["trusted"] = True
        assert not transaction.get("capture", "tenant-a", "sample")["payload"]["nested"]["trusted"]
    assert not store.read("tenant-a")[0]["payload"]["nested"]["trusted"]


def test_revocations_survive_restart_and_do_not_cross_tenants_or_types(store):
    with store.transaction() as transaction:
        transaction.put("baseline", "tenant-a", "normal-work", {"bounds": 100}, "admin", NOW)
        transaction.put("revocation", "tenant-a", "revoke-1", {
            "target_kind": "baseline", "target_id": "normal-work", "reason": "policy changed",
        }, "admin", NOW)
        assert transaction.revoked("baseline", "tenant-a", "normal-work")
        assert not transaction.revoked("approval", "tenant-a", "normal-work")
        assert not transaction.revoked("baseline", "tenant-b", "normal-work")
    with BehaviorContextStore(store.path).transaction() as transaction:
        assert transaction.revoked("baseline", "tenant-a", "normal-work")


def test_whole_transaction_rolls_back_on_service_error(store):
    class ExpectedRejection(ValueError):
        pass

    with pytest.raises(ExpectedRejection), store.transaction() as transaction:
        transaction.put("capture", "tenant-a", "first", {}, "reviewer", NOW)
        transaction.put("baseline", "tenant-a", "second", {}, "admin", NOW)
        raise ExpectedRejection("binding mismatch")
    assert BehaviorContextStore(store.path).read("tenant-a") == []


def test_process_exit_during_transaction_leaves_no_half_record(store):
    with pytest.raises(KeyboardInterrupt), store.transaction() as transaction:
        transaction.put("capture", "tenant-a", "interrupted", {}, "reviewer", NOW)
        raise KeyboardInterrupt()
    assert BehaviorContextStore(store.path).read("tenant-a") == []


def test_commit_failure_is_unavailable_and_never_acknowledged(store, monkeypatch):
    original_connect = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("simulated commit failure")

    with monkeypatch.context() as patch:
        patch.setattr("app.services.behavior_context_store.sqlite3.connect",
                      lambda *args, **kwargs: original_connect(*args, **kwargs, factory=FailingConnection))
        with pytest.raises(ContextStoreUnavailable):
            put(store)
    assert BehaviorContextStore(store.path).read("tenant-a") == []


@pytest.mark.parametrize("mutation", [
    "UPDATE behavior_context_entries SET payload='{}' WHERE seq=1",
    "UPDATE behavior_context_entries SET tenant_id='tenant-b' WHERE seq=1",
    "UPDATE behavior_context_entries SET prior_hash='changed' WHERE seq=2",
    "UPDATE behavior_context_entries SET digest='changed' WHERE seq=1",
    "DELETE FROM behavior_context_entries WHERE seq=1",
    "DELETE FROM behavior_context_entries WHERE seq=2",
    "DELETE FROM behavior_context_head",
    "UPDATE behavior_context_head SET record_count=1",
    "UPDATE behavior_context_head SET total_bytes=0",
    "UPDATE behavior_context_head SET last_hash='changed'",
])
def test_changed_or_missing_history_fails_closed(store, mutation):
    put(store, "first")
    put(store, "second")
    with sqlite3.connect(store.path) as connection:
        connection.execute(mutation)
    with pytest.raises(ContextStoreUnavailable):
        store.read("tenant-a")
    with pytest.raises(ContextStoreUnavailable):
        BehaviorContextStore(store.path)


def test_existing_other_database_is_not_modified(tmp_path):
    path = tmp_path / "policy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE journal (value TEXT)")
        connection.execute("INSERT INTO journal VALUES ('preserve')")
    before = path.read_bytes()
    with pytest.raises(ContextStoreUnavailable):
        BehaviorContextStore(path)
    assert path.read_bytes() == before


def test_capacity_preserves_history_and_allows_exact_duplicate(tmp_path):
    store = BehaviorContextStore(tmp_path / "small.sqlite3", max_records=1)
    original = put(store)
    with pytest.raises(ContextStoreUnavailable, match="capacity"):
        put(store, "new")
    assert put(store)["duplicate"] is True
    assert store.read("tenant-a") == [original["entry"]]


def test_byte_limit_rolls_back_entire_multi_record_transaction(tmp_path):
    store = BehaviorContextStore(tmp_path / "small.sqlite3", max_bytes=300)
    with pytest.raises(ContextStoreUnavailable, match="capacity"), store.transaction() as transaction:
        transaction.put("capture", "tenant-a", "first", {}, "reviewer", NOW)
        transaction.put("capture", "tenant-a", "second", {"data": "x" * 200}, "reviewer", NOW)
    assert store.read("tenant-a") == []


def test_oversized_payload_does_not_enter_storage(store):
    with pytest.raises(ValueError, match="size limit"):
        put(store, payload={"data": "x" * MAX_ENTRY_BYTES})
    assert store.read("tenant-a") == []


@pytest.mark.parametrize("payload", [{"invalid": float("nan")}, {"invalid": object()}])
def test_noncanonical_payloads_are_rejected(store, payload):
    with pytest.raises((ValueError, TypeError)):
        put(store, payload=payload)
    assert store.read("tenant-a") == []


def test_closed_transactions_cannot_be_reused(store):
    with store.transaction() as transaction:
        transaction.put("capture", "tenant-a", "sample", {}, "reviewer", NOW)
    with pytest.raises(ContextStoreUnavailable, match="closed"):
        transaction.get("capture", "tenant-a", "sample")
    with pytest.raises(ContextStoreUnavailable, match="closed"):
        transaction.put("capture", "tenant-a", "another", {}, "reviewer", NOW)


def test_unexpected_trigger_cannot_hide_an_appended_record(store):
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "CREATE TRIGGER hide_record AFTER INSERT ON behavior_context_entries "
            "BEGIN DELETE FROM behavior_context_entries WHERE seq=NEW.seq; END",
        )
    with pytest.raises(ContextStoreUnavailable):
        put(store)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM behavior_context_entries").fetchone()[0] == 0


def test_parallel_duplicate_deliveries_have_one_durable_record(store):
    def write(_):
        return put(BehaviorContextStore(store.path))

    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(write, range(12)))
    assert sum(not receipt["duplicate"] for receipt in receipts) == 1
    assert len(store.read("tenant-a")) == 1
    with sqlite3.connect(store.path) as connection:
        count = connection.execute("SELECT record_count FROM behavior_context_head").fetchone()[0]
        data = connection.execute("SELECT payload FROM behavior_context_entries").fetchone()[0]
    assert count == 1
    assert json.loads(data)["payload"] == {"value": "original"}


def test_naive_timestamps_and_malformed_revocations_are_rejected(store):
    with pytest.raises(ValueError, match="timezone"):
        put(store, now=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="revocation"), store.transaction() as transaction:
        transaction.put("revocation", "tenant-a", "bad", {"target_kind": "capture"}, "admin", NOW)
    assert store.read("tenant-a") == []
