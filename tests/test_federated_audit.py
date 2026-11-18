import asyncio
from datetime import UTC, datetime

import pytest
from test_audit_cancellation import record

from app.models import ReviewStatus
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
    updated = original.model_copy(
        update={
            "review_status": ReviewStatus.RESOLVED,
            "reviewer": "operator",
            "review_note": "Reviewed locally",
            "review_updated_at": datetime.now(UTC),
        }
    )
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


@pytest.mark.parametrize("change", ["delete", "truncate", "rewrite"])
def test_checkpoint_detects_loss_even_before_next_reader_discovery(tmp_path, change):
    base = tmp_path / "audit.jsonl"
    writer = tmp_path / "audit.worker-1.jsonl"
    original = record(1)
    asyncio.run(AuditStore(writer).save(original))
    first = FederatedAuditStore(tmp_path / "audit.worker-2.jsonl", base)
    assert first.get(original.event_id) == original
    if change == "delete":
        writer.unlink()
    elif change == "truncate":
        writer.write_bytes(b"")
    else:
        writer.unlink()
        asyncio.run(AuditStore(writer).save(record(2)))
    restarted = FederatedAuditStore(tmp_path / "audit.worker-3.jsonl", base)
    with pytest.raises(AuditQueryUnavailable):
        restarted.recent()


def test_manifest_loss_in_live_reader_does_not_create_empty_replacement(tmp_path):
    store = FederatedAuditStore(tmp_path / "audit.worker-1.jsonl", tmp_path / "audit.jsonl")
    store._manifest.path.unlink()
    with pytest.raises(AuditQueryUnavailable):
        store.recent()
    assert not store._manifest.path.exists()


def test_writer_announces_shard_before_any_reader_has_discovered_it(tmp_path):
    base = tmp_path / "audit.jsonl"
    writer = tmp_path / "audit.worker-1.jsonl"
    asyncio.run(FederatedAuditStore(writer, base).save(record(1)))
    writer.unlink()
    restarted = FederatedAuditStore(tmp_path / "audit.worker-2.jsonl", base)
    with pytest.raises(AuditQueryUnavailable):
        restarted.get("audit-cancel-1")


def test_valid_append_advances_checkpoint_without_duplicate_metrics(tmp_path):
    base = tmp_path / "audit.jsonl"
    writer = AuditStore(tmp_path / "audit.worker-1.jsonl")
    asyncio.run(writer.save(record(1)))
    reader = FederatedAuditStore(tmp_path / "audit.worker-2.jsonl", base)
    assert reader.metrics().total_analyses == 1
    asyncio.run(writer.save(record(2)))
    assert reader.metrics().total_analyses == 2
    reader.MAX_BYTES = 1
    with pytest.raises(AuditQueryUnavailable):
        reader.recent()


def test_http_other_worker_results_review_and_metrics(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app import main, security
    from app.security import Principal, Role

    original = record(1).model_copy(update={"review_status": ReviewStatus.PENDING})
    asyncio.run(AuditStore(tmp_path / "audit.worker-1.jsonl").save(original))
    reader = FederatedAuditStore(tmp_path / "audit.worker-2.jsonl", tmp_path / "audit.jsonl")
    monkeypatch.setattr(main, "audit_store", reader)
    main.app.dependency_overrides[security.get_principal] = lambda: Principal(
        "audit-reviewer", "local", frozenset({Role.RESPONDER}), "api_key"
    )
    try:
        with TestClient(main.app) as client:
            assert client.get(f"/results/{original.event_id}").status_code == 200
            assert client.get("/metrics").json()["total_analyses"] == 1
            assert len(client.get("/results").json()) == 1
            response = client.patch(
                f"/results/{original.event_id}/review",
                json={
                    "status": "RESOLVED",
                    "note": "Cross worker local review",
                },
            )
            assert response.status_code == 200, response.text
            other = FederatedAuditStore(tmp_path / "audit.worker-3.jsonl", tmp_path / "audit.jsonl")
            assert other.get(original.event_id).reviewer == "audit-reviewer"
            assert other.metrics().total_analyses == 1
            (tmp_path / "audit.worker-1.jsonl").unlink()
            assert client.get("/results").status_code == 503
    finally:
        main.app.dependency_overrides.pop(security.get_principal, None)
