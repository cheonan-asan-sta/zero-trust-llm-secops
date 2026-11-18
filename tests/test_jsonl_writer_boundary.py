"""Live writer-prefix checks before provider work and before any disk append."""

import asyncio
import os
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_jsonl_row_preservation import make_store
from test_sqlite_audit import initial, review

from app import main
from app.scenarios import synthetic_events
from app.services import audit as module
from app.services.audit import AuditStore
from app.services.federated_audit import AuditQueryUnavailable


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
@pytest.mark.parametrize("change", ["rollback", "external_append"])
def test_append_refuses_a_valid_disk_chain_that_no_longer_matches_owned_head(
    tmp_path, kind, change
):
    store = make_store(tmp_path, kind)
    asyncio.run(store.save(initial(1)))
    floor = store._path.read_bytes()
    if change == "rollback":
        asyncio.run(store.save(initial(2)))
        store._path.write_bytes(floor)
    else:
        asyncio.run(AuditStore(store._path).save(initial(2)))
    before = store._path.read_bytes()
    with pytest.raises(AuditQueryUnavailable):
        asyncio.run(store.save(initial(3)))
    assert store._path.read_bytes() == before


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
@pytest.mark.parametrize("change", ["rollback", "missing"])
def test_provider_is_not_called_after_live_writer_prefix_loss(
    api, tmp_path, monkeypatch, kind, change
):
    store = make_store(tmp_path, kind)
    asyncio.run(store.save(initial(1)))
    floor = store._path.read_bytes()
    asyncio.run(store.save(initial(2)))
    if change == "rollback":
        store._path.write_bytes(floor)
    else:
        store._path.unlink()
    before = store._path.read_bytes() if store._path.exists() else None
    monkeypatch.setattr(main, "audit_store", store)
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = api.client.post(
        "/analysis", headers=api.headers, json=synthetic_events()[0].model_dump(mode="json")
    )
    assert response.status_code == 502 and model.analyze.await_count == 0
    ready = api.client.get("/health/ready")
    assert ready.status_code == 503 and ready.json()["audit"]["writer_head_verified"] is False
    assert api.client.get("/health/live").status_code == 200
    assert (store._path.read_bytes() if store._path.exists() else None) == before


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_legacy_bytes_rewrite_with_same_row_count_is_detected(tmp_path, kind):
    store = make_store(tmp_path, kind)
    first = initial(1)
    store._path.write_text(first.model_dump_json() + "\n", encoding="utf-8")
    store = make_store(tmp_path, kind)
    changed = first.model_copy(update={"event_id": "audit-cancel-9"})
    store._path.write_text(changed.model_dump_json() + "\n", encoding="utf-8")
    before = store._path.read_bytes()
    assert store._last_hash == "0" * 64 and store._legacy_lines == 1
    assert store.writer_integrity()["writer_head_verified"] is False
    with pytest.raises(AuditQueryUnavailable):
        asyncio.run(store.save(initial(2)))
    assert store._path.read_bytes() == before


def test_fresh_explicit_reader_can_resume_the_current_valid_chain(tmp_path):
    store = make_store(tmp_path, "jsonl")
    asyncio.run(store.save(initial(1)))
    asyncio.run(AuditStore(store._path).save(initial(2)))
    assert not store.writer_integrity()["ok"]
    fresh = AuditStore(store._path)
    assert fresh.writer_integrity()["ok"]
    asyncio.run(fresh.save(initial(3)))
    assert fresh.integrity()["verified_lines"] == 3


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_model_time_rollback_denies_append_without_modifying_the_candidate(
    api, tmp_path, monkeypatch, kind
):
    store = make_store(tmp_path, kind)
    asyncio.run(store.save(initial(1)))
    floor = store._path.read_bytes()
    asyncio.run(store.save(initial(2)))
    monkeypatch.setattr(main, "audit_store", store)

    async def infer(_):
        store._path.write_bytes(floor)
        return initial(99).assessment

    model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = api.client.post(
        "/analysis", headers=api.headers, json=synthetic_events()[0].model_dump(mode="json")
    )
    assert response.status_code == 502 and model.analyze.await_count == 1
    assert store._path.read_bytes() == floor and not store.integrity()["ok"]


@pytest.mark.parametrize("kind", ["jsonl", "federated"])
def test_identical_file_replacement_after_validation_is_refused_before_write(
    tmp_path, monkeypatch, kind
):
    store = make_store(tmp_path, kind)
    first, second = initial(1), initial(2)
    asyncio.run(store.save(first))
    before = store._path.read_bytes()
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_bytes(before)
    original = module._record_hash

    def replace(previous, payload):
        digest = original(previous, payload)
        os.replace(replacement, store._path)
        return digest

    monkeypatch.setattr(module, "_record_hash", replace)
    with pytest.raises(AuditQueryUnavailable, match="before write"):
        asyncio.run(store.save(second))
    assert store._path.read_bytes() == before and not store.integrity()["ok"]


def test_partial_os_writes_are_completed_and_flushed(tmp_path, monkeypatch):
    store = make_store(tmp_path, "jsonl")
    original = module.os.write
    calls = 0

    def short(fd, data):
        nonlocal calls
        calls += 1
        return original(fd, data[:11])

    monkeypatch.setattr(module.os, "write", short)
    record = initial(1)
    asyncio.run(store.save(record))
    assert calls > 1 and store.writer_integrity()["ok"]
    assert AuditStore(store._path).get(record.event_id) == record


def test_fsync_failure_retains_uncertain_bytes_and_closes_the_writer(tmp_path, monkeypatch):
    store = make_store(tmp_path, "jsonl")

    def fail(_):
        raise OSError("controlled local flush failure")

    monkeypatch.setattr(module.os, "fsync", fail)
    with pytest.raises(OSError, match="flush failure"):
        asyncio.run(store.save(initial(1)))
    before = store._path.read_bytes()
    assert before and store.integrity()["ok"] is False
    assert store.integrity()["verified_lines"] == 0 and store.metrics().total_analyses == 0
    with pytest.raises(RuntimeError, match="integrity"):
        asyncio.run(store.save(initial(2)))
    assert store._path.read_bytes() == before


@pytest.mark.parametrize("limit", ["row", "bytes", "rows"])
def test_capacity_is_rejected_before_creating_or_extending_output(tmp_path, monkeypatch, limit):
    store = make_store(tmp_path, "jsonl")
    if limit == "rows":
        asyncio.run(store.save(initial(1)))
        monkeypatch.setattr(store, "MAX_ROWS", 1)
    else:
        monkeypatch.setattr(store, "MAX_ROW_BYTES" if limit == "row" else "MAX_BYTES", 16)
    before = store._path.read_bytes() if store._path.exists() else None
    with pytest.raises(AuditQueryUnavailable, match="capacity"):
        asyncio.run(store.save(initial(2)))
    assert (store._path.read_bytes() if store._path.exists() else None) == before


@pytest.mark.parametrize("strict", [False, True])
def test_bootstrap_capacity_is_bounded_and_never_repairs(tmp_path, monkeypatch, strict):
    path = tmp_path / "large.jsonl"
    before = (initial(1).model_dump_json() + "\n").encode()
    path.write_bytes(before)
    monkeypatch.setattr(AuditStore, "MAX_BYTES", 16)
    if strict:
        with pytest.raises(OSError):
            AuditStore(path, strict_reads=True)
    else:
        store = AuditStore(path)
        assert not store.integrity()["ok"] and store.recent() == []
    assert path.read_bytes() == before


@pytest.mark.parametrize("limit", ["row", "rows"])
def test_bootstrap_limits_rows_before_parsing_further_models(tmp_path, monkeypatch, limit):
    path = tmp_path / "bounded.jsonl"
    path.write_text(
        initial(1).model_dump_json() + "\n" + initial(2).model_dump_json() + "\n", encoding="utf-8"
    )
    before = path.read_bytes()
    monkeypatch.setattr(
        AuditStore, "MAX_ROW_BYTES" if limit == "row" else "MAX_ROWS", 16 if limit == "row" else 1
    )
    with pytest.raises(OSError, match="row capacity"):
        AuditStore(path, strict_reads=True)
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO contract")
def test_fifo_cannot_block_bootstrap_or_a_live_disk_proof(tmp_path):
    store = make_store(tmp_path, "jsonl")
    record = initial(1)
    asyncio.run(store.save(record))
    store._path.unlink()
    os.mkfifo(store._path)
    assert not AuditStore(store._path).integrity()["ok"]
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(record)


def test_cross_file_review_does_not_disable_the_federated_writer(tmp_path):
    first = initial(1)
    asyncio.run(AuditStore(tmp_path / "audit.worker-2.jsonl").save(first))
    store = make_store(tmp_path, "federated")
    updated = review(first).model_copy(
        update={"review_updated_at": first.analyzed_at + timedelta(seconds=1)}
    )
    asyncio.run(store.save(updated))
    second = initial(2)
    assert store.writer_integrity()["ok"]
    asyncio.run(store.save(second))
    store.verify_saved(second)
    assert store.get(first.event_id) == updated and store.writer_integrity()["ok"]


def test_standalone_orphan_review_is_not_given_federated_semantics(tmp_path):
    store = make_store(tmp_path, "jsonl")
    first = initial(1)
    updated = review(first).model_copy(
        update={"review_updated_at": first.analyzed_at + timedelta(seconds=1)}
    )
    asyncio.run(store.save(updated))
    before = store._path.read_bytes()
    assert not store.writer_integrity()["ok"]
    with pytest.raises(AuditQueryUnavailable):
        asyncio.run(store.save(initial(2)))
    assert store._path.read_bytes() == before
