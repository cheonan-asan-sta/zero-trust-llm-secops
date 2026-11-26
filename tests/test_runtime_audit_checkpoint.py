"""Runtime minimum-prefix checks; synthetic storage cases, not detection metrics."""

import asyncio
import secrets
from datetime import timedelta
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from test_audit_checkpoint import ready
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_sqlite_audit import initial, review

from app import main
from app.config import Settings
from app.scenarios import synthetic_events
from app.services.audit import create_audit_store
from app.services.audit_backup import backup_sqlite, restore_sqlite
from app.services.audit_checkpoint import capture_checkpoint
from app.services.audit_paging import AuditPager
from app.services.federated_audit import AuditQueryUnavailable
from app.services.guarded_sqlite_audit import GuardedSQLiteAuditStore
from app.services.sqlite_audit import SQLiteAuditStore


def guarded(store, path, receipt):
    return GuardedSQLiteAuditStore.open_guarded(store.path, path, receipt["checkpoint_sha256"])


def test_factory_opts_in_only_with_complete_sqlite_configuration(tmp_path):
    store, original, path, receipt = ready(tmp_path)
    config = Settings(
        _env_file=None,
        audit_backend="sqlite",
        audit_db_path=store.path,
        audit_checkpoint_path=path,
        audit_checkpoint_sha256=receipt["checkpoint_sha256"],
    )
    result = create_audit_store(config)
    assert isinstance(result, GuardedSQLiteAuditStore) and isinstance(result, SQLiteAuditStore)
    assert result.get(original.event_id) == original
    assert result.integrity()["checkpoint_guard"] == {
        "configured": True,
        "minimum_head_verified": True,
        "latest_live_state_verified": False,
        "independent_storage_verified": False,
    }
    assert "checkpoint_guard" not in store.integrity()


@pytest.mark.parametrize(
    "constructor", [GuardedSQLiteAuditStore, GuardedSQLiteAuditStore.open_existing]
)
def test_guarded_store_cannot_initialize_or_open_without_a_checkpoint(tmp_path, constructor):
    path = tmp_path / "must-not-create.sqlite3"
    with pytest.raises(ValueError, match="open_guarded"):
        constructor(path)
    assert not path.exists()


@pytest.mark.parametrize(
    "options",
    [
        {"audit_checkpoint_path": "missing.json"},
        {"audit_checkpoint_sha256": "a" * 64},
        {"audit_checkpoint_path": "missing.json", "audit_checkpoint_sha256": "a" * 64},
        {
            "audit_backend": "dynamodb",
            "audit_checkpoint_path": "missing.json",
            "audit_checkpoint_sha256": "a" * 64,
        },
        {
            "audit_backend": "sqlite",
            "audit_checkpoint_path": "missing.json",
            "audit_checkpoint_sha256": "X" * 64,
        },
    ],
)
def test_invalid_configuration_never_falls_back(options):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **options)


@pytest.mark.parametrize("kind", ["missing", "empty", "older", "fork"])
def test_startup_rejects_invalid_candidate_without_creation_or_repair(tmp_path, kind):
    store, _, path, _ = ready(tmp_path)
    asyncio.run(store.save(initial(2)))
    receipt = capture_checkpoint(store.path, tmp_path / "head2.json")
    path = tmp_path / "head2.json"
    candidate = tmp_path / "candidate.sqlite3"
    if kind != "missing":
        other = SQLiteAuditStore(candidate)
        if kind == "older":
            asyncio.run(other.save(initial(1)))
        if kind == "fork":
            asyncio.run(other.save(initial(8)))
            asyncio.run(other.save(initial(9)))
    before = candidate.read_bytes() if candidate.exists() else None
    with pytest.raises(AuditQueryUnavailable):
        GuardedSQLiteAuditStore.open_guarded(candidate, path, receipt["checkpoint_sha256"])
    assert (candidate.read_bytes() if candidate.exists() else None) == before


@pytest.mark.parametrize("change", ["missing", "tampered", "wrong_pin"])
def test_live_checkpoint_withdrawal_has_no_cached_fallback(tmp_path, change):
    store, _, path, receipt = ready(tmp_path)
    live = guarded(store, path, receipt)
    if change == "missing":
        path.unlink()
    elif change == "tampered":
        path.write_bytes(path.read_bytes() + b" ")
    else:
        live.checkpoint_sha256 = "0" * 64
    before = store.path.read_bytes()
    assert not live.integrity()["ok"]
    with pytest.raises(AuditQueryUnavailable):
        live.recent()
    with pytest.raises(AuditQueryUnavailable):
        asyncio.run(live.save(initial(2)))
    assert store.path.read_bytes() == before


def test_checkpoint_withdrawn_during_full_scan_denies_read(tmp_path, monkeypatch):
    store, _, path, receipt = ready(tmp_path)
    live = guarded(store, path, receipt)
    original = SQLiteAuditStore._read

    def withdraw(*args, **kwargs):
        value = original(*args, **kwargs)
        path.unlink()
        return value

    monkeypatch.setattr(SQLiteAuditStore, "_read", withdraw)
    with pytest.raises(AuditQueryUnavailable):
        live.recent()


def test_checkpoint_withdrawn_after_insert_rolls_back_before_commit(tmp_path, monkeypatch):
    store, original, path, receipt = ready(tmp_path)
    live = guarded(store, path, receipt)
    before = store.path.read_bytes()
    original_prefix = live._require_prefix
    calls = 0

    def withdraw(con, checkpoint):
        nonlocal calls
        calls += 1
        if calls == 2:
            # The INSERT/head UPDATE happened in this write transaction already.
            assert con.execute("SELECT count(*) FROM audit_entries").fetchone()[0] == 2
            path.unlink()
            live._checkpoint()
        return original_prefix(con, checkpoint)

    monkeypatch.setattr(live, "_require_prefix", withdraw)
    with pytest.raises(AuditQueryUnavailable):
        asyncio.run(live.save(initial(2)))
    assert calls == 2 and store.path.read_bytes() == before
    assert store.get(original.event_id) == original and store.metrics().total_analyses == 1


def test_valid_rollback_blocks_all_storage_boundaries(tmp_path):
    store, original, path, receipt = ready(tmp_path)
    old = store.path.read_bytes()
    asyncio.run(store.save(initial(2)))
    path = tmp_path / "head2.json"
    receipt = capture_checkpoint(store.path, path)
    live = guarded(store, path, receipt)
    store.path.write_bytes(old)
    assert store.integrity()["ok"]  # A valid old whole DB passes chain verification alone.
    assert not live.integrity()["ok"]
    update = review(original).model_copy(
        update={"review_updated_at": original.analyzed_at + timedelta(seconds=1)}
    )
    operations = [
        lambda: live.get(original.event_id),
        live.recent,
        live.metrics,
        lambda: AuditPager().page(live, "local", 1, None),
        lambda: asyncio.run(live.save(initial(3))),
        lambda: asyncio.run(live.save_review(update, original)),
    ]
    for operation in operations:
        with pytest.raises(AuditQueryUnavailable):
            operation()
    assert store.path.read_bytes() == old


def test_guard_keeps_review_cas_and_historical_cursor_compatible(tmp_path):
    store, original, path, receipt = ready(tmp_path)
    asyncio.run(store.save(initial(2)))
    live = guarded(store, path, receipt)
    pager = AuditPager()
    first = pager.page(live, "local", 1, None)
    update = review(original).model_copy(
        update={"review_updated_at": original.analyzed_at + timedelta(seconds=1)}
    )
    asyncio.run(live.save_review(update, original))
    second = pager.page(live, "local", 1, first.next_cursor)
    assert second.snapshot_id == first.snapshot_id and second.total_matches == 2
    assert second.items[0].review_status == original.review_status
    assert live.get(original.event_id) == update and live.integrity()["verified_lines"] == 3


def test_backup_does_not_silently_drop_runtime_guard(tmp_path):
    store, _, path, receipt = ready(tmp_path)
    live = guarded(store, path, receipt)
    key = secrets.token_bytes(32)
    target = tmp_path / "good.backup"
    info = backup_sqlite(live, target, key)
    restored = tmp_path / "restored.sqlite3"
    restore_sqlite(target, restored, info["backup_sha256"], key)
    assert GuardedSQLiteAuditStore.open_guarded(
        restored, path, receipt["checkpoint_sha256"]
    ).integrity()["ok"]
    path.unlink()
    rejected = tmp_path / "not-published.backup"
    with pytest.raises(AuditQueryUnavailable):
        backup_sqlite(live, rejected, key)
    assert not rejected.exists() and not list(tmp_path.glob(".audit-transfer-*"))


@pytest.mark.parametrize(
    "url", ["/results", "/metrics", "/results/audit-cancel-1", "/audit/results", "/health/ready"]
)
def test_http_rollback_is_unavailable_and_liveness_survives(api, tmp_path, monkeypatch, url):
    old = api.store.path.read_bytes()
    asyncio.run(api.store.save(initial(3)))
    path = tmp_path / "runtime.json"
    receipt = capture_checkpoint(api.store.path, path)
    live = guarded(api.store, path, receipt)
    monkeypatch.setattr(main, "audit_store", live)
    api.store.path.write_bytes(old)
    response = api.client.get(url, headers=api.headers)
    assert response.status_code == 503 and "audit-cancel-1" not in response.text
    assert api.client.get("/health/live").status_code == 200
    assert api.store.path.read_bytes() == old


def test_http_analysis_denies_before_provider_on_valid_rollback(api, tmp_path, monkeypatch):
    old = api.store.path.read_bytes()
    asyncio.run(api.store.save(initial(3)))
    path = tmp_path / "runtime.json"
    receipt = capture_checkpoint(api.store.path, path)
    monkeypatch.setattr(main, "audit_store", guarded(api.store, path, receipt))
    analyzer = Mock()
    monkeypatch.setattr(main, "get_analyzer", lambda: analyzer)
    api.store.path.write_bytes(old)
    response = api.client.post(
        "/analysis",
        json=synthetic_events()[0].model_dump(mode="json"),
        headers=api.headers,
    )
    assert response.status_code == 502  # Existing analysis provider-error contract.
    analyzer.analyze.assert_not_called()
    assert api.store.path.read_bytes() == old
