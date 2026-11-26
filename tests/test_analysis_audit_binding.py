"""Keep one audit authority across model work, persistence, and response delivery."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_async_audit_io import setup_analysis
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_sqlite_audit import initial

from app import main
from app.scenarios import synthetic_events
from app.services.audit_checkpoint import capture_checkpoint
from app.services.guarded_sqlite_audit import GuardedSQLiteAuditStore
from app.services.sqlite_audit import SQLiteAuditStore


def provider(monkeypatch, action=None):
    async def analyze(event):
        if action is not None:
            action()
        return initial(99).assessment

    result = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=analyze))
    monkeypatch.setattr(main, "get_analyzer", lambda: result)
    return result


def request(api):
    return api.client.post(
        "/analysis", headers=api.headers, json=synthetic_events()[0].model_dump(mode="json")
    )


@pytest.mark.parametrize("stage", ["preflight", "model", "committed"])
def test_audit_store_swap_never_redirects_or_delivers_success(api, tmp_path, monkeypatch, stage):
    replacement = SQLiteAuditStore(tmp_path / "replacement.sqlite3")
    original_bytes = api.store.path.read_bytes()

    def swap():
        monkeypatch.setattr(main, "audit_store", replacement)

    model = provider(monkeypatch, swap if stage == "model" else None)
    if stage == "preflight":
        original = api.store.integrity

        def scan_and_swap():
            result = original()
            swap()
            return result

        monkeypatch.setattr(api.store, "integrity", scan_and_swap)
    if stage == "committed":
        original = api.store.save

        async def save_and_swap(record):
            await original(record)
            swap()

        monkeypatch.setattr(api.store, "save", save_and_swap)
    response = request(api)
    assert response.status_code == 502
    assert model.analyze.await_count == (0 if stage == "preflight" else 1)
    assert replacement.metrics().total_analyses == 0
    assert len(api.store._records()) == (3 if stage == "committed" else 2)
    if stage != "committed":
        assert api.store.path.read_bytes() == original_bytes


@pytest.mark.parametrize("stage", ["model", "committed"])
@pytest.mark.parametrize("change", ["checkpoint", "rollback"])
def test_guard_change_during_analysis_never_delivers_result(
    api, tmp_path, monkeypatch, stage, change
):
    old_bytes = api.store.path.read_bytes()
    asyncio.run(api.store.save(initial(3)))
    path = tmp_path / "minimum.json"
    receipt = capture_checkpoint(api.store.path, path)
    live = GuardedSQLiteAuditStore.open_guarded(api.store.path, path, receipt["checkpoint_sha256"])
    monkeypatch.setattr(main, "audit_store", live)

    def withdraw():
        if change == "checkpoint":
            path.unlink()
        else:
            api.store.path.write_bytes(old_bytes)

    model = provider(monkeypatch, withdraw if stage == "model" else None)
    if stage == "committed":
        original = live.save

        async def save_then_withdraw(record):
            await original(record)
            withdraw()

        monkeypatch.setattr(live, "save", save_then_withdraw)
    response = request(api)
    assert response.status_code == 502 and model.analyze.await_count == 1
    # Already committed history is preserved if only the checkpoint was removed.
    expected = (
        4
        if stage == "committed" and change == "checkpoint"
        else (3 if change == "checkpoint" else 2)
    )
    assert len(api.store._records()) == expected
    if change == "rollback":
        assert api.store.path.read_bytes() == old_bytes and api.store.integrity()["ok"]


def test_valid_guarded_analysis_retains_one_model_call_and_one_audit(api, tmp_path, monkeypatch):
    path = tmp_path / "minimum.json"
    receipt = capture_checkpoint(api.store.path, path)
    live = GuardedSQLiteAuditStore.open_guarded(api.store.path, path, receipt["checkpoint_sha256"])
    monkeypatch.setattr(main, "audit_store", live)
    model = provider(monkeypatch)
    response = request(api)
    assert response.status_code == 200 and model.analyze.await_count == 1
    assert len(api.store._records()) == 3
    assert live.get(response.json()["event_id"]).analysis_id == response.json()["analysis_id"]


def test_postcommit_scan_cancellation_keeps_capacity_and_history(tmp_path, monkeypatch):
    store, event, model, capacity, actor = setup_analysis(tmp_path, monkeypatch)
    original = store.verify_saved
    entered, release = threading.Event(), threading.Event()

    def blocked(record):
        entered.set()
        assert release.wait(3)
        return original(record)

    monkeypatch.setattr(store, "verify_saved", blocked)

    async def run():
        task = asyncio.create_task(main._analyze_event(event, model, actor, "postcommit-cancel"))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and capacity._value == 0
        finally:
            release.set()
            outcomes = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(outcomes[0], asyncio.CancelledError)
        assert capacity._value == 1 and model.analyze.await_count == 1

    asyncio.run(run())
    assert store.metrics().total_analyses == 1


def test_source_revalidation_stays_after_new_slow_audit_scan(tmp_path, monkeypatch):
    store, event, model, _, actor = setup_analysis(tmp_path, monkeypatch)
    source = {"enabled": True}
    original = store.verify_saved
    calls = 0

    def scan_and_withdraw_source(record):
        nonlocal calls
        calls += 1
        result = original(record)
        source["enabled"] = False
        return result

    monkeypatch.setattr(store, "verify_saved", scan_and_withdraw_source)

    async def revalidate(_):
        if not source["enabled"]:
            raise ValueError("controlled source withdrawal during final audit scan")

    context = SimpleNamespace(for_event=lambda _: None, revalidate=revalidate)
    with pytest.raises(ValueError, match="source withdrawal"):
        asyncio.run(
            main._analyze_event(
                event,
                model,
                actor,
                "source-after-scan",
                verification_context_supplier=lambda: context,
            )
        )
    assert calls == 1 and store.metrics().total_analyses == 1
