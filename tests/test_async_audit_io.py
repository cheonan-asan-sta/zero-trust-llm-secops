"""A cancelled request must not leave unbounded I/O behind released slots."""

import asyncio
import threading
from unittest.mock import AsyncMock, Mock

from test_audit_cancellation import record

from app import main
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.federated_audit import FederatedAuditStore
from app.services.sqlite_audit import SQLiteAuditStore


def setup_analysis(tmp_path, monkeypatch):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    event = synthetic_events()[0].model_copy(update={"ground_truth": None})
    provider = Mock(name="free-local-provider")
    provider.name = "rule"
    provider.analyze = AsyncMock(return_value=RuleBasedAnalyzer().assess(event))
    capacity = asyncio.Semaphore(1)
    monkeypatch.setattr(main, "audit_store", store)
    monkeypatch.setattr(main, "analysis_capacity", capacity)
    actor = Principal("audit-io-operator", "local", frozenset({Role.ADMIN}), "api_key")
    return store, event, provider, capacity, actor


def test_reconfiguration_releases_original_capacity_not_new_semaphore(tmp_path, monkeypatch):
    store, event, provider, original, actor = setup_analysis(tmp_path, monkeypatch)
    replacement = asyncio.Semaphore(0)

    async def infer(_):
        monkeypatch.setattr(main, "analysis_capacity", replacement)
        return RuleBasedAnalyzer().assess(event)

    provider.analyze.side_effect = infer
    asyncio.run(main._analyze_event(event, provider, actor, "capacity-reconfiguration"))
    assert original._value == 1 and replacement._value == 0
    assert store.metrics().total_analyses == 1


def test_asgi_request_cancellations_keep_bounded_preflight_and_allow_recovery(
    tmp_path, monkeypatch
):
    import httpx

    store, event, provider, _, _ = setup_analysis(tmp_path, monkeypatch)
    capacity = asyncio.Semaphore(2)
    monkeypatch.setattr(main, "analysis_capacity", capacity)
    monkeypatch.setattr(main, "get_analyzer", lambda: provider)
    monkeypatch.setattr(
        main, "settings", main.settings.model_copy(update={"analysis_queue_timeout_seconds": 0.02})
    )
    entered, release = threading.Event(), threading.Event()
    lock = threading.Lock()
    calls = 0
    original = store.integrity

    def blocked():
        nonlocal calls
        with lock:
            calls += 1
            if calls == 2:
                entered.set()
        assert release.wait(5)
        return original()

    monkeypatch.setattr(store, "integrity", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            jobs = [
                asyncio.create_task(client.post("/analysis", json=event.model_dump(mode="json")))
                for _ in range(8)
            ]
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                await asyncio.sleep(0.1)
                waiting = [job for job in jobs if not job.done()]
                rejected = [job.result() for job in jobs if job.done()]
                assert len(waiting) == 2 and len(rejected) == 6
                assert all(response.status_code == 429 for response in rejected)
                for job in waiting:
                    job.cancel()
                await asyncio.sleep(0)
                assert capacity._value == 0 and calls == 2
                assert (await client.get("/health/live")).status_code == 200
                extra = await client.post("/analysis", json=event.model_dump(mode="json"))
                assert extra.status_code == 429 and calls == 2
            finally:
                release.set()
                outcomes = await asyncio.gather(*jobs, return_exceptions=True)
            assert sum(isinstance(outcome, asyncio.CancelledError) for outcome in outcomes) == 2
            assert capacity._value == 2 and provider.analyze.await_count == 0
            response = await client.post("/analysis", json=event.model_dump(mode="json"))
            assert response.status_code == 200 and provider.analyze.await_count == 1
            assert store.metrics().total_analyses == 1 and capacity._value == 2

    asyncio.run(run())


def test_blocked_integrity_allows_event_loop_heartbeat(tmp_path, monkeypatch):
    store, event, provider, _, actor = setup_analysis(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = store.integrity

    def blocked():
        entered.set()
        if not release.wait(1):
            raise RuntimeError("event loop heartbeat could not release audit I/O")
        return original()

    monkeypatch.setattr(store, "integrity", blocked)

    async def run():
        task = asyncio.create_task(main._analyze_event(event, provider, actor, "heartbeat-test"))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            await asyncio.sleep(0)
            assert not task.done()
        finally:
            release.set()
        result = await task
        assert result.event_id == event.event_id and provider.analyze.await_count == 1

    asyncio.run(run())


def test_cancellation_during_integrity_keeps_slot_until_worker_settles(tmp_path, monkeypatch):
    store, event, provider, capacity, actor = setup_analysis(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = store.integrity

    def blocked():
        entered.set()
        assert release.wait(3)
        return original()

    monkeypatch.setattr(store, "integrity", blocked)

    async def run():
        task = asyncio.create_task(main._analyze_event(event, provider, actor, "cancel-preflight"))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert capacity._value == 0 and not task.done()
        finally:
            release.set()
            result = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(result[0], asyncio.CancelledError)
        assert capacity._value == 1 and provider.analyze.await_count == 0
        assert store.metrics().total_analyses == 0

    asyncio.run(run())


def test_cancelled_sqlite_append_waits_for_committed_or_rolled_back_outcome(tmp_path, monkeypatch):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    entered, release = threading.Event(), threading.Event()
    write = store._write

    def blocked(*args):
        entered.set()
        assert release.wait(3)
        return write(*args)

    monkeypatch.setattr(store, "_write", blocked)

    async def run():
        task = asyncio.create_task(store.save(record(1)))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
        finally:
            release.set()
            outcomes = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(outcomes[0], asyncio.CancelledError)
        assert store.integrity()["ok"] and store.metrics().total_analyses == 1

    asyncio.run(run())


def test_cancelled_manifest_announcement_leaves_valid_empty_shard(tmp_path, monkeypatch):
    store = FederatedAuditStore(tmp_path / "audit.worker-1.jsonl", tmp_path / "audit.jsonl")
    entered, release = threading.Event(), threading.Event()
    announce = store._manifest.announce

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return announce(*args, **kwargs)

    monkeypatch.setattr(store._manifest, "announce", blocked)

    async def run():
        task = asyncio.create_task(store.save(record(1)))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
        finally:
            release.set()
            outcomes = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(outcomes[0], asyncio.CancelledError)
        assert store._path.read_bytes() == b""
        assert store.integrity()["ok"] and store.metrics().total_analyses == 0
        await store.save(record(2))
        assert store.metrics().total_analyses == 1

    asyncio.run(run())


def test_cancel_during_real_sqlite_writer_transaction_does_not_break_next_writer(
    tmp_path, monkeypatch
):
    from app.services import sqlite_audit as module

    first_store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    second_store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    entered, release = threading.Event(), threading.Event()
    original = module._record_hash

    def blocked(previous, payload):
        if '"event_id":"audit-cancel-1"' in payload:
            entered.set()
            assert release.wait(3)
        return original(previous, payload)

    monkeypatch.setattr(module, "_record_hash", blocked)

    async def run():
        first = asyncio.create_task(first_store.save(record(1)))
        second = None
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            first.cancel()
            await asyncio.sleep(0)
            first.cancel()
            second = asyncio.create_task(second_store.save(record(2)))
            await asyncio.sleep(0)
            assert not first.done()
        finally:
            release.set()
            outcomes = await asyncio.gather(
                first, *([second] if second else []), return_exceptions=True
            )
        assert isinstance(outcomes[0], asyncio.CancelledError)
        assert outcomes[1] is None
        assert first_store.integrity()["ok"] and second_store.integrity()["verified_lines"] == 2

    asyncio.run(run())
