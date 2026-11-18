"""A successful response requires its own committed SQLite row, above the floor."""

import asyncio
import sqlite3
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_sqlite_audit import initial, review

from app import main
from app.scenarios import synthetic_events
from app.services.audit_checkpoint import capture_checkpoint
from app.services.federated_audit import AuditQueryUnavailable
from app.services.guarded_sqlite_audit import GuardedSQLiteAuditStore
from app.services.sqlite_audit import SQLiteAuditStore


@pytest.mark.parametrize("guard_enabled", [False, True])
def test_response_rejects_lost_new_row_even_when_old_database_satisfies_floor(
    api, tmp_path, monkeypatch, guard_enabled
):
    floor_bytes = api.store.path.read_bytes()
    selected = api.store
    if guard_enabled:
        path = tmp_path / "floor.json"
        receipt = capture_checkpoint(api.store.path, path)
        selected = GuardedSQLiteAuditStore.open_guarded(
            api.store.path, path, receipt["checkpoint_sha256"]
        )
    monkeypatch.setattr(main, "audit_store", selected)
    original = selected.save

    async def save_and_restore_floor(record):
        await original(record)
        api.store.path.write_bytes(floor_bytes)

    monkeypatch.setattr(selected, "save", save_and_restore_floor)
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = api.client.post(
        "/analysis", headers=api.headers, json=synthetic_events()[0].model_dump(mode="json")
    )
    assert response.status_code == 502 and model.analyze.await_count == 1
    assert selected.integrity()["ok"]
    assert api.store.path.read_bytes() == floor_bytes


def test_verified_row_survives_later_analysis_with_the_same_event_id(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1)
    latest = initial(2).model_copy(
        update={"event_id": first.event_id, "analyzed_at": first.analyzed_at + timedelta(seconds=1)}
    )
    asyncio.run(store.save(first))
    asyncio.run(store.save(latest))
    assert store.get(first.event_id) == latest
    assert store.verify_saved(first) is None


def test_exact_original_row_is_still_verified_after_review(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1)
    asyncio.run(store.save(first))
    reviewed = review(first).model_copy(
        update={"review_updated_at": first.analyzed_at + timedelta(seconds=1)}
    )
    asyncio.run(store.save_review(reviewed, first))
    assert store.get(first.event_id) == reviewed
    assert store.verify_saved(first) is None


def test_saved_trace_uses_the_json_wire_contract_without_false_rejection(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1).model_copy(
        update={"llm_trace": {"tools": ("first", "second"), "counts": {1: 2}}}
    )
    asyncio.run(store.save(first))
    stored = store.get(first.event_id)
    assert stored.llm_trace == {"tools": ["first", "second"], "counts": {"1": 2}}
    assert stored != first
    assert store.verify_saved(first) is None


def test_json_boolean_is_not_accepted_as_the_same_numeric_trace_value(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1).model_copy(update={"llm_trace": {"value": True}})
    asyncio.run(store.save(first))
    expected = first.model_copy(update={"llm_trace": {"value": 1}})
    # Python dict equality merges these values; the JSON response contract does not.
    assert first == expected
    with pytest.raises(AuditQueryUnavailable, match="not preserved"):
        store.verify_saved(expected)


@pytest.mark.parametrize("change", ["event", "tenant", "latency", "id"])
def test_analysis_identity_alone_does_not_prove_exact_saved_payload(tmp_path, change):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1)
    asyncio.run(store.save(first))
    fields = {
        "event": {"event_id": "different-event"},
        "tenant": {"tenant_id": "other"},
        "latency": {"latency_ms": 42},
        "id": {"analysis_id": "a" * 32},
    }[change]
    expected = first.model_copy(update=fields)
    with pytest.raises(AuditQueryUnavailable, match="not preserved"):
        store.verify_saved(expected)


def test_matching_row_cannot_short_circuit_corrupt_later_history(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1)
    asyncio.run(store.save(first))
    asyncio.run(store.save(initial(2)))
    with sqlite3.connect(store.path) as con:
        con.execute("UPDATE audit_entries SET digest=? WHERE seq=2", ("f" * 64,))
    before = store.path.read_bytes()
    with pytest.raises(AuditQueryUnavailable, match="integrity"):
        store.verify_saved(first)
    assert store.path.read_bytes() == before


def test_guarded_row_proof_rechecks_checkpoint_after_scan(tmp_path, monkeypatch):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1)
    asyncio.run(store.save(first))
    path = tmp_path / "floor.json"
    receipt = capture_checkpoint(store.path, path)
    live = GuardedSQLiteAuditStore.open_guarded(store.path, path, receipt["checkpoint_sha256"])
    original = SQLiteAuditStore._read

    def withdraw(*args, **kwargs):
        result = original(*args, **kwargs)
        path.unlink()
        return result

    monkeypatch.setattr(SQLiteAuditStore, "_read", withdraw)
    with pytest.raises(AuditQueryUnavailable):
        live.verify_saved(first)


def test_store_swap_during_row_proof_denies_delivery_without_deleting_history(
    api, tmp_path, monkeypatch
):
    original = api.store.verify_saved
    other = SQLiteAuditStore(tmp_path / "other.sqlite3")

    def swap(record):
        original(record)
        monkeypatch.setattr(main, "audit_store", other)

    monkeypatch.setattr(api.store, "verify_saved", swap)
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = api.client.post(
        "/analysis", headers=api.headers, json=synthetic_events()[0].model_dump(mode="json")
    )
    assert response.status_code == 502 and model.analyze.await_count == 1
    assert len(api.store._records()) == 3 and other.metrics().total_analyses == 0
