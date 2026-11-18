import asyncio
from datetime import UTC, datetime

import pytest
from test_audit_cancellation import record

from app.services.audit import AuditStore
from app.services.federated_audit import AuditQueryUnavailable, FederatedAuditStore


def test_other_worker_and_legacy_file_are_visible_with_tenant_isolation(tmp_path):
    first, second = record(1), record(2).model_copy(update={"tenant_id": "other"})
    asyncio.run(AuditStore(tmp_path / "audit.jsonl").save(first))
    asyncio.run(AuditStore(tmp_path / "audit.worker-2.jsonl").save(second))
    store = FederatedAuditStore(tmp_path / "audit.worker-1.jsonl", tmp_path / "audit.jsonl")
    assert store.get(first.event_id) == first
    assert store.get(second.event_id) is None
    assert store.get(second.event_id, "other") == second
    assert store.metrics().total_analyses == 1
    assert store.integrity()["shards"] == 2


def test_review_in_another_worker_is_deduplicated_and_visible(tmp_path):
    original = record(1)
    asyncio.run(AuditStore(tmp_path / "audit.worker-1.jsonl").save(original))
    store = FederatedAuditStore(tmp_path / "audit.worker-2.jsonl", tmp_path / "audit.jsonl")
    updated = original.model_copy(update={"review_status": "RESOLVED", "reviewer": "operator",
                                         "review_note": "Reviewed locally", "review_updated_at": datetime.now(UTC)})
    asyncio.run(store.save(updated))
    assert store.get(original.event_id).reviewer == "operator"
    assert store.metrics().total_analyses == 1


@pytest.mark.parametrize("kind", ["corrupt", "conflict", "capacity"])
def test_bad_shard_cannot_be_hidden_by_other_valid_results(tmp_path, kind):
    original = record(1)
    asyncio.run(AuditStore(tmp_path / "audit.worker-1.jsonl").save(original))
    path = tmp_path / "audit.worker-2.jsonl"
    if kind == "corrupt":
        path.write_text('{"partial":', encoding="utf-8")
    else:
        asyncio.run(AuditStore(path).save(original.model_copy(update={"tenant_id": "forged"})))
    store = FederatedAuditStore(tmp_path / "audit.worker-3.jsonl", tmp_path / "audit.jsonl")
    if kind == "capacity":
        store.MAX_FILES = 1
    with pytest.raises(AuditQueryUnavailable):
        store.recent()
    assert store.integrity()["ok"] is False


def test_new_worker_file_is_discovered_on_next_read(tmp_path):
    store = FederatedAuditStore(tmp_path / "audit.worker-1.jsonl", tmp_path / "audit.jsonl")
    assert store.recent() == []
    original = record(1)
    asyncio.run(AuditStore(tmp_path / "audit.worker-2.jsonl").save(original))
    assert store.recent() == [original]
