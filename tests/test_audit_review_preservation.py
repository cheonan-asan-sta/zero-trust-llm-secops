"""A successful review response must have its own exact persisted audit row."""

import asyncio
import threading
from datetime import timedelta

import httpx
import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from app.models import ReviewStatus
from app.services.audit import AuditStore
from app.services.audit_checkpoint import capture_checkpoint
from app.services.federated_audit import AuditQueryUnavailable, FederatedAuditStore
from app.services.guarded_sqlite_audit import GuardedSQLiteAuditStore


@pytest.mark.parametrize("backend", ["sqlite", "guarded", "jsonl"])
def test_lost_committed_review_cannot_be_reported_as_success(api, tmp_path, monkeypatch, backend):
    store = api.store
    method, path = "save_review", store.path
    if backend == "guarded":
        checkpoint = tmp_path / "floor.json"
        receipt = capture_checkpoint(path, checkpoint)
        store = GuardedSQLiteAuditStore.open_guarded(path, checkpoint, receipt["checkpoint_sha256"])
    elif backend == "jsonl":
        path = tmp_path / "reviews.jsonl"
        store = AuditStore(path)
        for record in api.store._records():
            asyncio.run(store.save(record))
        method = "save"
    monkeypatch.setattr(main, "audit_store", store)
    baseline = path.read_bytes()
    original = getattr(store, method)

    async def save_and_lose_review(*args):
        await original(*args)
        path.write_bytes(baseline)

    monkeypatch.setattr(store, method, save_and_lose_review)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "IN_REVIEW", "note": "review row must remain persisted"},
    )
    assert response.status_code == 503 and "reviewer" not in response.json()
    assert path.read_bytes() == baseline


@pytest.mark.parametrize("later", ["review", "analysis"])
def test_review_proof_accepts_its_preserved_historical_row_after_another_writer(
    api, monkeypatch, later
):
    original = api.store.save_review

    async def save_then_advance(updated, expected):
        await original(updated, expected)
        if later == "review":
            advanced = updated.model_copy(
                update={
                    "review_status": ReviewStatus.RESOLVED,
                    "reviewer": "later-reviewer",
                    "review_note": "a later legitimate review remains separate",
                    "review_updated_at": updated.review_updated_at + timedelta(seconds=1),
                }
            )
            await original(advanced, updated)
        else:
            advanced = api.first.model_copy(
                update={
                    "analysis_id": "later-analysis-same-event",
                    "analyzed_at": api.first.analyzed_at + timedelta(seconds=1),
                }
            )
            await api.store.save(advanced)

    monkeypatch.setattr(api.store, "save_review", save_then_advance)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "IN_REVIEW", "note": "this exact committed row must remain valid"},
    )
    assert response.status_code == 200 and response.json()["analysis_id"] == api.first.analysis_id
    assert response.json()["review_status"] == "IN_REVIEW"
    assert api.store.integrity()["verified_lines"] == 4
    assert api.store.get("audit-cancel-1", "local").review_status == (
        ReviewStatus.RESOLVED if later == "review" else ReviewStatus.PENDING
    )


@pytest.mark.parametrize("failed", [False, True])
def test_cancelled_review_proof_retains_query_slot_until_its_worker_finishes(
    api, monkeypatch, failed
):
    entered, release = threading.Event(), threading.Event()
    original = api.store.verify_saved

    def verify(record):
        entered.set()
        assert release.wait(3)
        if failed:
            raise AuditQueryUnavailable("controlled proof failure after cancellation")
        return original(record)

    monkeypatch.setattr(api.store, "verify_saved", verify)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.patch(
                    "/results/audit-cancel-1/review",
                    headers=api.headers,
                    json={"status": "IN_REVIEW", "note": "committed before proof cancellation"},
                )
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
                busy = await client.get("/metrics", headers=api.headers)
                assert busy.status_code == 503 and busy.headers["Retry-After"] == "1"
                assert not task.done() and api.capacity._value == 0
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert api.capacity._value == 1 and api.store.integrity()["verified_lines"] == 3
            assert api.store.get("audit-cancel-1", "local").review_status == ReviewStatus.IN_REVIEW

    asyncio.run(run())


def test_authority_withdrawn_during_added_review_proof_blocks_delivery_but_keeps_history(
    api, monkeypatch
):
    original = api.store.verify_saved

    def withdraw(record):
        original(record)
        api.withdraw()

    monkeypatch.setattr(api.store, "verify_saved", withdraw)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "IN_REVIEW", "note": "proof cannot outlive caller authority"},
    )
    assert response.status_code == 401 and api.store.integrity()["verified_lines"] == 3
    assert api.store.get("audit-cancel-1", "local").review_status == ReviewStatus.IN_REVIEW


def test_review_proof_from_replaced_store_cannot_be_delivered(api, tmp_path, monkeypatch):
    original = api.store.verify_saved
    replacement = AuditStore(tmp_path / "replacement.jsonl")

    def replace(record):
        original(record)
        main.audit_store = replacement

    monkeypatch.setattr(api.store, "verify_saved", replace)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "IN_REVIEW", "note": "selected store identity must remain stable"},
    )
    assert response.status_code == 503 and api.store.integrity()["verified_lines"] == 3


def test_another_federated_shard_cannot_witness_a_lost_local_review(api, tmp_path, monkeypatch):
    base = tmp_path / "audit.jsonl"
    one = FederatedAuditStore(tmp_path / "audit.worker-one.jsonl", base)
    two = FederatedAuditStore(tmp_path / "audit.worker-two.jsonl", base)
    asyncio.run(one.save(api.first))
    monkeypatch.setattr(main, "audit_store", one)
    baseline = one._path.read_bytes()
    original = one.save

    async def save_and_copy_then_lose(record):
        await original(record)
        await two.save(record)
        one._path.write_bytes(baseline)

    monkeypatch.setattr(one, "save", save_and_copy_then_lose)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "IN_REVIEW", "note": "copy is not proof of our committed writer row"},
    )
    assert response.status_code == 503 and one._path.read_bytes() == baseline
    assert two._path.is_file()
