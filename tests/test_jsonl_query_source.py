"""Legacy JSONL HTTP views must verify current disk authority, not cached rows."""

import asyncio
import threading
from datetime import timedelta

import httpx
import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from app.models import ReviewStatus, RiskLevel
from app.services.audit import AuditStore
from app.services.federated_audit import AuditQueryUnavailable


@pytest.fixture
def local_jsonl(api, tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "audit.jsonl")
    for record in api.store._records():
        asyncio.run(store.save(record))
    monkeypatch.setattr(main, "audit_store", store)
    return store


@pytest.mark.parametrize("url", ["/results", "/results/audit-cancel-1", "/metrics"])
@pytest.mark.parametrize("damage", ["missing", "empty_rollback", "broken_row", "peer_append"])
def test_jsonl_cached_view_cannot_hide_current_source_change(
    api, tmp_path, monkeypatch, url, damage
):
    path = tmp_path / "audit.jsonl"
    store = AuditStore(path)
    for record in api.store._records():
        asyncio.run(store.save(record))
    monkeypatch.setattr(main, "audit_store", store)
    assert api.client.get(url, headers=api.headers).status_code == 200
    baseline = path.read_bytes()
    if damage == "missing":
        path.unlink()
    elif damage == "empty_rollback":
        path.write_bytes(b"")
    elif damage == "broken_row":
        path.write_bytes(baseline[:-2] + b"]\n")
    else:
        peer = AuditStore(path)
        asyncio.run(peer.save(api.first.model_copy(update={"analysis_id": "peer-new-analysis"})))
    damaged = path.read_bytes() if path.exists() else None
    response = api.client.get(url, headers=api.headers)
    assert response.status_code == 503
    assert "analysis_id" not in response.json() and "total_analyses" not in response.json()
    assert (path.read_bytes() if path.exists() else None) == damaged
    assert api.client.get("/health/live").status_code == 200 and api.capacity._value == 1


@pytest.mark.parametrize("url", ["/results", "/results/audit-cancel-1", "/metrics"])
def test_memory_only_mutation_is_not_published_as_disk_authority(api, local_jsonl, url):
    local_jsonl._history[0].assessment.rationale = "memory-only modification"
    local_jsonl._history[0].assessment.risk_level = RiskLevel.HIGH
    response = api.client.get(url, headers=api.headers)
    assert response.status_code == 200
    if url == "/metrics":
        assert response.json()["risk_counts"][api.first.assessment.risk_level.value] == 1
        assert response.json()["risk_counts"].get("HIGH", 0) == 0
    else:
        record = response.json()[0] if url == "/results" else response.json()
        assert record["assessment"]["rationale"] == api.first.assessment.rationale
        assert record["assessment"]["risk_level"] == api.first.assessment.risk_level.value


def test_returned_models_do_not_mutate_subsequent_source_verified_reads(local_jsonl):
    record = local_jsonl.get("audit-cancel-1", "local")
    expected = record.assessment.rationale
    record.assessment.rationale = "caller modified its returned object"
    assert local_jsonl.get("audit-cancel-1", "local").assessment.rationale == expected


def test_first_use_empty_source_is_not_confused_with_lost_existing_source(
    api, tmp_path, monkeypatch
):
    path = tmp_path / "not-created.jsonl"
    monkeypatch.setattr(main, "audit_store", AuditStore(path))
    assert api.client.get("/results", headers=api.headers).json() == []
    metrics = api.client.get("/metrics", headers=api.headers)
    assert metrics.status_code == 200 and metrics.json()["total_analyses"] == 0
    assert api.client.get("/results/missing", headers=api.headers).status_code == 404
    assert not path.exists()


def test_legacy_prefix_remains_readable_but_is_not_a_hashed_row_witness(api, tmp_path):
    path = tmp_path / "legacy.jsonl"
    body = (api.first.model_dump_json() + "\n").encode()
    path.write_bytes(body)
    store = AuditStore(path)
    assert store.get(api.first.event_id) == api.first
    assert store.metrics().total_analyses == 1 and path.read_bytes() == body
    with pytest.raises(AuditQueryUnavailable):
        store.verify_saved(api.first)


def test_later_review_of_older_analysis_does_not_replace_newer_event_analysis(api, local_jsonl):
    latest = api.first.model_copy(
        update={
            "analysis_id": "newer-same-event-analysis",
            "analyzed_at": api.first.analyzed_at + timedelta(seconds=1),
        }
    )
    asyncio.run(local_jsonl.save(latest))
    reviewed = api.first.model_copy(
        update={
            "review_status": ReviewStatus.IN_REVIEW,
            "reviewer": "old-result-reviewer",
            "review_note": "the old result remains historical",
            "review_updated_at": latest.analyzed_at + timedelta(seconds=1),
        }
    )
    asyncio.run(local_jsonl.save(reviewed))
    assert local_jsonl.get(latest.event_id).analysis_id == latest.analysis_id
    assert local_jsonl.metrics().total_analyses == 2


def test_read_rejection_never_rewrites_source_and_known_prefix_can_be_restored(api, local_jsonl):
    body = local_jsonl._path.read_bytes()
    local_jsonl._path.write_bytes(b"")
    assert api.client.get("/results", headers=api.headers).status_code == 503
    assert local_jsonl._path.read_bytes() == b""
    local_jsonl._path.write_bytes(body)
    assert api.client.get("/results", headers=api.headers).status_code == 200
    assert local_jsonl._path.read_bytes() == body


@pytest.mark.parametrize("failed", [False, True])
def test_cancellation_of_live_jsonl_read_keeps_query_capacity_until_worker_settles(
    api, local_jsonl, monkeypatch, failed
):
    entered, release = threading.Event(), threading.Event()
    original = local_jsonl._check_writer_view

    def blocked(**kwargs):
        entered.set()
        assert release.wait(3)
        if failed:
            raise AuditQueryUnavailable("controlled JSONL read failure")
        return original(**kwargs)

    monkeypatch.setattr(local_jsonl, "_check_writer_view", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/results", headers=api.headers))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert (await client.get("/health/live")).status_code == 200
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
                busy = await client.get("/metrics", headers=api.headers)
                assert busy.status_code == 503 and busy.headers["Retry-After"] == "1"
                assert not task.done() and api.capacity._value == 0
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError) and api.capacity._value == 1

    asyncio.run(run())


def test_caller_revoked_during_live_jsonl_read_receives_no_cached_result(
    api, local_jsonl, monkeypatch
):
    original = local_jsonl._check_writer_view

    def withdraw(**kwargs):
        value = original(**kwargs)
        api.withdraw()
        return value

    monkeypatch.setattr(local_jsonl, "_check_writer_view", withdraw)
    before = local_jsonl._path.read_bytes()
    response = api.client.get("/results/audit-cancel-1", headers=api.headers)
    assert response.status_code == 401 and "ETag" not in response.headers
    assert local_jsonl._path.read_bytes() == before
