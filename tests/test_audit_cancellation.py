"""Cancel a request during the real append/hash boundary, not a model mock."""

import asyncio
import json
import threading

import pytest

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult
from app.scenarios import synthetic_events
from app.services import audit as module
from app.services.policy import response_preview


def record(index):
    event = synthetic_events()[0].model_copy(update={"event_id": f"audit-cancel-{index}"})
    assessment = RuleBasedAnalyzer().assess(event)
    return AnalysisResult(
        event_id=event.event_id,
        analyzer="rule",
        assessment=assessment,
        policy_decision=response_preview(assessment, event),
        latency_ms=1,
    )


def test_repeated_cancellation_during_append_keeps_writer_lock_and_memory_in_sync(
    tmp_path, monkeypatch
):
    async def run():
        path = tmp_path / "audit.jsonl"
        store = module.AuditStore(path)
        first_record, second_record = record(1), record(2)
        computed, second_entered, release = threading.Event(), threading.Event(), threading.Event()
        original_hash = module._record_hash

        def controlled_hash(previous, payload):
            result = original_hash(previous, payload)
            if json.loads(payload)["event_id"] == first_record.event_id:
                computed.set()
                assert release.wait(5), "test writer was not released"
            else:
                second_entered.set()
            return result

        monkeypatch.setattr(module, "_record_hash", controlled_hash)
        first = asyncio.create_task(store.save(first_record))
        second = None
        try:
            assert await asyncio.to_thread(computed.wait, 3)
            first.cancel()
            await asyncio.sleep(0)
            first.cancel()  # A second disconnect/shutdown cancellation cannot drop the lock.
            await asyncio.sleep(0)
            second = asyncio.create_task(store.save(second_record))
            overlapped = await asyncio.to_thread(second_entered.wait, 0.08)
        finally:
            release.set()
            outcomes = await asyncio.gather(
                first, *([second] if second else []), return_exceptions=True
            )
        assert overlapped is False
        assert isinstance(outcomes[0], asyncio.CancelledError)
        assert outcomes[1] is None
        assert store.metrics().total_analyses == 2
        restored = module.AuditStore(path)
        assert restored.integrity()["ok"] and restored.metrics().total_analyses == 2
        assert store.get(first_record.event_id) is not None
        assert restored.get(first_record.event_id) is not None

    asyncio.run(run())


def test_failed_partial_append_closes_store_before_any_later_write(tmp_path, monkeypatch):
    async def run():
        path = tmp_path / "audit.jsonl"
        store = module.AuditStore(path)
        original = store._append_jsonl

        def broken(_):
            path.write_text('{"partial":', encoding="utf-8")
            raise OSError("synthetic storage failure")

        monkeypatch.setattr(store, "_append_jsonl", broken)
        with pytest.raises(OSError):
            await store.save(record(1))
        assert store.integrity()["ok"] is False
        before = path.read_bytes()
        monkeypatch.setattr(store, "_append_jsonl", original)
        with pytest.raises(RuntimeError, match="integrity"):
            await store.save(record(2))
        assert path.read_bytes() == before

    asyncio.run(run())


def test_cancellation_while_waiting_for_writer_does_not_start_an_append(tmp_path, monkeypatch):
    async def run():
        store = module.AuditStore(tmp_path / "audit.jsonl")
        entered, release = threading.Event(), threading.Event()
        original = store._append_jsonl
        attempts = []

        def controlled(value):
            attempts.append(value.event_id)
            entered.set()
            assert release.wait(5)
            original(value)

        monkeypatch.setattr(store, "_append_jsonl", controlled)
        first = asyncio.create_task(store.save(record(1)))
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            second = asyncio.create_task(store.save(record(2)))
            await asyncio.sleep(0)
            second.cancel()
            with pytest.raises(asyncio.CancelledError):
                await second
        finally:
            release.set()
            await first
        assert attempts == ["audit-cancel-1"] and store.metrics().total_analyses == 1

    asyncio.run(run())
