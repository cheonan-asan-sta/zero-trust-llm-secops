"""Disk-backed proof for process-owned JSONL analyses; not model quality cases."""

import asyncio
import json
import threading
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_sqlite_audit import initial, review

from app import main
from app.scenarios import synthetic_events
from app.services import audit as audit_module
from app.services import audit_paging, audit_wire
from app.services.audit import AuditStore
from app.services.federated_audit import AuditQueryUnavailable, FederatedAuditStore
from app.services.settled_io import settled_io


def make_store(tmp_path, kind):
    base = tmp_path / "audit.jsonl"
    return (
        FederatedAuditStore(tmp_path / "audit.worker-1.jsonl", base)
        if kind == "federated"
        else AuditStore(base)
    )


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_lost_own_row_cannot_be_hidden_by_cached_history_or_manifest_floor(
    api, tmp_path, monkeypatch, kind
):
    store = make_store(tmp_path, kind)
    asyncio.run(store.save(initial(1)))
    floor = store._path.read_bytes()
    monkeypatch.setattr(main, "audit_store", store)
    original = store.save

    async def save_then_restore(record):
        await original(record)
        store._path.write_bytes(floor)

    monkeypatch.setattr(store, "save", save_then_restore)
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = api.client.post(
        "/analysis", headers=api.headers, json=synthetic_events()[0].model_dump(mode="json")
    )
    assert response.status_code == 502 and model.analyze.await_count == 1
    assert store._path.read_bytes() == floor


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_disk_proof_does_not_require_cached_history(tmp_path, kind):
    store = make_store(tmp_path, kind)
    record = initial(1)
    asyncio.run(store.save(record))
    store._history.clear()
    store._records.clear()
    assert store.verify_saved(record) is None


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_original_row_survives_later_review_and_same_event_analysis(tmp_path, kind):
    store = make_store(tmp_path, kind)
    first = initial(1)
    asyncio.run(store.save(first))
    updated = review(first).model_copy(
        update={"review_updated_at": first.analyzed_at + timedelta(seconds=1)}
    )
    asyncio.run(store.save(updated))
    latest = initial(2).model_copy(
        update={"event_id": first.event_id, "analyzed_at": first.analyzed_at + timedelta(seconds=2)}
    )
    asyncio.run(store.save(latest))
    assert store.get(first.event_id) == latest
    assert store.verify_saved(first) is None


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_cached_row_cannot_replace_missing_writer_file(tmp_path, kind):
    store = make_store(tmp_path, kind)
    first = initial(1)
    asyncio.run(store.save(first))
    store._path.unlink()
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(first)
    assert not store._path.exists()


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_correct_first_row_cannot_hide_corrupt_later_disk_data(tmp_path, kind):
    store = make_store(tmp_path, kind)
    first = initial(1)
    asyncio.run(store.save(first))
    with store._path.open("ab") as stream:
        stream.write(b'{"partial":\n')
    before = store._path.read_bytes()
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(first)
    assert store._path.read_bytes() == before


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_wire_arrays_normalized_but_boolean_number_substitution_rejected(tmp_path, kind):
    store = make_store(tmp_path, kind)
    first = initial(1).model_copy(update={"llm_trace": {"tools": ("one",), "value": True}})
    asyncio.run(store.save(first))
    assert store.verify_saved(first) is None
    changed = first.model_copy(update={"llm_trace": {"tools": ("one",), "value": 1}})
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(changed)


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_bounds_are_applied_to_disk_proof(tmp_path, monkeypatch, kind):
    store = make_store(tmp_path, kind)
    first = initial(1)
    asyncio.run(store.save(first))
    monkeypatch.setattr(audit_paging, "MAX_JSONL_BYTES", 16)
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(first)


def test_file_change_during_payload_comparison_denies_proof(tmp_path, monkeypatch):
    store = make_store(tmp_path, "jsonl")
    first = initial(1)
    asyncio.run(store.save(first))
    original = audit_wire.analysis_wire
    calls = 0

    def changed(record):
        nonlocal calls
        calls += 1
        value = original(record)
        if calls == 2:
            store._path.write_bytes(b"")
        return value

    monkeypatch.setattr(audit_wire, "analysis_wire", changed)
    with pytest.raises(AuditQueryUnavailable, match="changed"):
        store.verify_saved(first)
    assert calls == 2


def test_legacy_prefix_remains_compatible_but_cannot_witness_a_saved_row(tmp_path):
    path = tmp_path / "audit.jsonl"
    old, new = initial(1), initial(2)
    path.write_text(old.model_dump_json() + "\n", encoding="utf-8")
    store = AuditStore(path)
    asyncio.run(store.save(new))
    assert store.verify_saved(new) is None
    with pytest.raises(AuditQueryUnavailable, match="not preserved"):
        store.verify_saved(old)
    # Cursor paging keeps its existing all-hashed requirement.
    with pytest.raises(AuditQueryUnavailable):
        audit_paging.AuditPager().page(store, "local", 1, None)


def test_legacy_suffix_is_not_a_hash_chain_witness(tmp_path):
    store = make_store(tmp_path, "jsonl")
    first = initial(1)
    asyncio.run(store.save(first))
    with store._path.open("a", encoding="utf-8") as stream:
        stream.write(initial(2).model_dump_json() + "\n")
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(first)


def test_federated_replica_cannot_substitute_for_lost_own_append(tmp_path):
    store = make_store(tmp_path, "federated")
    asyncio.run(store.save(initial(1)))
    assert store.integrity()["ok"]
    floor = store._path.read_bytes()
    second = initial(2)
    asyncio.run(store.save(second))
    asyncio.run(AuditStore(tmp_path / "audit.worker-2.jsonl").save(second))
    store._path.write_bytes(floor)
    assert store.get(second.event_id) == second
    with pytest.raises(AuditQueryUnavailable, match="writer shard"):
        store.verify_saved(second)


def test_federated_other_shard_corruption_blocks_valid_own_row(tmp_path):
    store = make_store(tmp_path, "federated")
    first = initial(1)
    asyncio.run(store.save(first))
    (tmp_path / "audit.worker-2.jsonl").write_bytes(b'{"broken":\n')
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(first)


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_healthy_http_analysis_preserves_response_row_on_disk(api, tmp_path, monkeypatch, kind):
    store = make_store(tmp_path, kind)
    monkeypatch.setattr(main, "audit_store", store)
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = api.client.post(
        "/analysis", headers=api.headers, json=synthetic_events()[0].model_dump(mode="json")
    )
    assert response.status_code == 200 and model.analyze.await_count == 1
    restored = AuditStore(store._path)
    assert restored.get(response.json()["event_id"]).analysis_id == response.json()["analysis_id"]


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_own_proof_waits_for_inflight_owned_append_and_then_verifies(tmp_path, monkeypatch, kind):
    store = make_store(tmp_path, kind)
    first, second = initial(1), initial(2)
    asyncio.run(store.save(first))
    entered, release, proof_entered, proof_finished = (threading.Event() for _ in range(4))
    original_hash = audit_module._record_hash

    def blocked_hash(previous, payload):
        result = original_hash(previous, payload)
        if json.loads(payload)["event_id"] == second.event_id:
            entered.set()
            assert release.wait(3)
        return result

    monkeypatch.setattr(audit_module, "_record_hash", blocked_hash)
    original_proof = store.verify_saved

    def observed(record):
        proof_entered.set()
        original_proof(record)
        proof_finished.set()

    monkeypatch.setattr(store, "verify_saved", observed)

    async def run():
        writer = asyncio.create_task(store.save(second))
        proof = None
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            proof = asyncio.create_task(settled_io(store.verify_saved, first))
            assert await asyncio.to_thread(proof_entered.wait, 2)
            assert not await asyncio.to_thread(proof_finished.wait, 0.05)
        finally:
            release.set()
            outcomes = await asyncio.gather(
                writer, *([proof] if proof else []), return_exceptions=True
            )
        assert outcomes == [None, None]

    asyncio.run(run())
    assert proof_finished.is_set() and store.get(second.event_id) == second
