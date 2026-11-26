"""Local audit history pagination; these are storage fixtures, not F1 cases."""

import asyncio
import base64
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from test_sqlite_audit import initial, review

from app.config import Settings
from app.models import ReviewStatus, RiskLevel
from app.services.audit import AuditStore
from app.services.audit_paging import (
    AuditCursorExpired,
    AuditCursorInvalid,
    AuditPager,
    AuditSnapshotChanged,
    create_audit_pager,
)
from app.services.audit_transfer import AuditTransferError
from app.services.federated_audit import AuditQueryUnavailable, FederatedAuditStore
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.local_process_runtime import direct_python


@pytest.fixture(params=["sqlite", "jsonl", "federated"])
def store(tmp_path, request):
    if request.param == "sqlite":
        return SQLiteAuditStore(tmp_path / "audit.sqlite3")
    if request.param == "federated":
        return FederatedAuditStore(tmp_path / "audit.worker-1.jsonl", tmp_path / "audit.jsonl")
    return AuditStore(tmp_path / "audit.jsonl")


def seed(store, count=3, *, tenant="local", start=1, pending=True):
    rows = [
        initial(i).model_copy(
            update={
                "analysis_id": f"{i:032x}",
                "tenant_id": tenant,
                "analyzed_at": datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=i // 3),
                "review_status": ReviewStatus.PENDING if pending else ReviewStatus.NOT_REQUIRED,
            }
        )
        for i in range(start, start + count)
    ]

    async def write():
        for row in rows:
            await store.save(row)

    asyncio.run(write())
    return rows


def pager(clock=None):
    return AuditPager(lambda: b"local-page-fixture-key-32-bytes!!!"[:32], clock=clock)


def test_current_page_cursor_returns_to_same_first_page_and_expiry(store):
    seed(store, 27)
    service = pager()
    first = service.page(store, "local", 12)
    second = service.page(store, "local", 12, first.next_cursor)
    last = service.page(store, "local", 12, second.next_cursor)
    back = service.page(store, "local", 12, first.page_cursor)
    assert len(first.items) == len(second.items) == 12 and len(last.items) == 3
    assert back.items == first.items and back.total_matches == 27
    assert back.snapshot_id == first.snapshot_id == second.snapshot_id == last.snapshot_id
    assert back.snapshot_created_at == first.snapshot_created_at
    assert back.snapshot_expires_at == first.snapshot_expires_at
    assert service.page(store, "local", 12, second.page_cursor).items == second.items


def test_first_page_cursor_does_not_silently_include_new_sqlite_rows(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    rows = seed(store, 3)
    service = pager()
    first = service.page(store, "local", 2)
    seed(store, 1, start=9)
    asyncio.run(store.save_review(review(rows[-1]), rows[-1]))
    back = service.page(store, "local", 2, first.page_cursor)
    assert back.items == first.items and back.total_matches == 3
    fresh = service.page(store, "local", 2)
    assert fresh.total_matches == 4 and fresh.snapshot_id != back.snapshot_id


def test_first_page_cursor_keeps_original_expiry(store):
    seed(store, 3)
    clock = {"now": 1000}
    service = pager(clock=lambda: clock["now"])
    first = service.page(store, "local", 2)
    clock["now"] = 1100
    assert service.page(store, "local", 2, first.page_cursor).snapshot_expires_at == first.snapshot_expires_at
    clock["now"] = 1900
    with pytest.raises(AuditCursorExpired):
        service.page(store, "local", 2, first.page_cursor)


def test_pages_cover_more_than_recent_window_without_duplicates_or_other_tenant(store):
    rows = seed(store, 125)
    seed(store, 1, tenant="other", start=999)
    service, cursor, ids, snapshots = pager(), None, [], set()
    while True:
        page = service.page(store, "local", 17, cursor)
        assert page.total_matches == 125
        assert page.historical_audit_snapshot and all(r.tenant_id == "local" for r in page.items)
        snapshots.add(page.snapshot_id)
        ids.extend(r.analysis_id for r in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        assert b'"tenant":"local"' not in raw and b'"head_seq"' not in raw
    assert len(snapshots) == 1
    assert ids == [r.analysis_id for r in reversed(rows)] and len(set(ids)) == 125
    assert len(store.recent(100)) == 100


def test_filters_run_over_complete_tenant_snapshot_before_page_limit(store):
    oldest = seed(store, 1)[0]
    seed(store, 120, start=2, pending=False)
    page = pager().page(
        store, "local", 1, review_status=ReviewStatus.PENDING, risk_level=RiskLevel.LOW
    )
    assert page.total_matches == 1 and page.items == [oldest] and page.next_cursor is None


def test_other_tenant_append_does_not_change_own_continuation(store):
    rows = seed(store)
    service = pager()
    first = service.page(store, "local", 1)
    seed(store, 1, start=999, tenant="other")
    second = service.page(store, "local", 1, first.next_cursor)
    assert second.items == [rows[1]] and second.snapshot_id == first.snapshot_id


def test_sqlite_historical_prefix_survives_append_and_review_with_original_expiry(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    rows = seed(store)
    clock = {"now": 1000}
    service = pager(lambda: clock["now"])
    first = service.page(store, "local", 1)
    seed(store, 1, start=4)
    asyncio.run(store.save_review(review(rows[1]), rows[1]))
    clock["now"] += 100
    second = service.page(store, "local", 1, first.next_cursor)
    third = service.page(store, "local", 1, second.next_cursor)
    assert second.items == [rows[1]] and third.items == [rows[0]]
    assert third.next_cursor is None and second.total_matches == 3
    assert first.snapshot_id == second.snapshot_id == third.snapshot_id
    assert first.snapshot_expires_at == second.snapshot_expires_at
    current = service.page(store, "local", 100)
    assert current.total_matches == 4
    assert (
        next(r for r in current.items if r.analysis_id == rows[1].analysis_id).review_status
        == ReviewStatus.RESOLVED
    )
    clock["now"] = 1900
    with pytest.raises(AuditCursorExpired):
        service.page(store, "local", 1, second.next_cursor)


@pytest.mark.parametrize("change", ["append", "review"])
def test_jsonl_own_view_change_requires_explicit_restart(store, change):
    if isinstance(store, SQLiteAuditStore):
        pytest.skip("SQLite prefix stability has a separate test")
    rows = seed(store)
    service = pager()
    first = service.page(store, "local", 1)
    if change == "append":
        seed(store, 1, start=4)
    else:
        asyncio.run(store.save(review(rows[1])))
    with pytest.raises(AuditSnapshotChanged):
        service.page(store, "local", 1, first.next_cursor)


def test_current_source_corruption_after_anchor_is_never_hidden_by_cursor(store):
    seed(store)
    service = pager()
    first = service.page(store, "local", 1)
    seed(store, 1, start=999, tenant="other")
    if isinstance(store, SQLiteAuditStore):
        with store._transaction(write=True) as con:
            con.execute("UPDATE audit_entries SET digest=? WHERE seq=4", ("f" * 64,))
    else:
        with store._path.open("ab") as stream:
            stream.write(b"{bad tail\n")
    with pytest.raises(AuditQueryUnavailable):
        service.page(store, "local", 1, first.next_cursor)


@pytest.mark.parametrize(
    "change", ["tenant", "review", "risk", "key", "tamper", "truncate", "source"]
)
def test_cursor_cannot_change_scope_or_be_reused_with_different_key(store, tmp_path, change):
    seed(store)
    service = pager()
    first = service.page(store, "local", 1)
    cursor, tenant, options = first.next_cursor, "local", {}
    if change == "tenant":
        tenant = "other"
    elif change == "review":
        options["review_status"] = ReviewStatus.RESOLVED
    elif change == "risk":
        options["risk_level"] = RiskLevel.HIGH
    elif change == "key":
        service = AuditPager(lambda: b"different-key-local-fixture-00000"[:32])
    elif change == "tamper":
        cursor = cursor[:20] + ("A" if cursor[20] != "A" else "B") + cursor[21:]
    elif change == "truncate":
        cursor = cursor[:-10]
    else:
        store = SQLiteAuditStore(tmp_path / "different.sqlite3")
    with pytest.raises(AuditCursorInvalid):
        service.page(store, tenant, 1, cursor, **options)


def test_empty_page_does_not_create_an_audit_record(store):
    page = pager().page(store, "local")
    assert page.items == [] and page.total_matches == 0 and page.next_cursor is None
    assert store.integrity()["verified_lines"] == 0


def test_pinned_key_is_shared_by_new_pager_and_withdrawal_is_not_ignored(tmp_path, monkeypatch):
    path = tmp_path / "cursor.key"
    key = b"local-cursor-key-fixture-32bytes!!"[:32]
    path.write_bytes(key)
    path.chmod(0o600)
    config = Settings(
        _env_file=None,
        audit_cursor_key_path=path,
        audit_cursor_key_sha256=hashlib.sha256(key).hexdigest(),
    )
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    rows = seed(store)
    first = create_audit_pager(config).page(store, "local", 1)
    second = create_audit_pager(config).page(store, "local", 1, first.next_cursor)
    assert second.items == [rows[1]] and first.snapshot_id == second.snapshot_id
    read = store._read

    def withdrawn(*args, **kwargs):
        result = read(*args, **kwargs)
        path.write_bytes(b"withdrawn-key-fixture-not-current"[:32])
        return result

    monkeypatch.setattr(store, "_read", withdrawn)
    with pytest.raises(AuditQueryUnavailable):
        create_audit_pager(config).page(store, "local", 1, first.next_cursor)
    with pytest.raises(AuditTransferError, match="pin mismatch"):
        create_audit_pager(config)


@pytest.mark.parametrize(
    "options",
    [
        {"audit_cursor_key_path": "missing.key"},
        {"audit_cursor_key_sha256": "a" * 64},
        {"audit_cursor_key_path": "missing.key", "audit_cursor_key_sha256": "invalid"},
    ],
)
def test_cursor_key_configuration_never_silently_falls_back(options):
    with pytest.raises(ValueError):
        Settings(_env_file=None, **options)


def test_pinned_cursor_resumes_in_an_actual_new_reader_process(tmp_path):
    key = b"portable-cursor-fixture-32-bytes!!"[:32]
    path = tmp_path / "cursor.key"
    path.write_bytes(key)
    path.chmod(0o600)
    pin = hashlib.sha256(key).hexdigest()
    config = Settings(_env_file=None, audit_cursor_key_path=path, audit_cursor_key_sha256=pin)
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    rows = seed(store)
    first = create_audit_pager(config).page(store, "local", 1)
    data = {"key_path": str(path), "pin": pin, "db": str(store.path), "cursor": first.next_cursor}
    code = """import json,sys
from app.config import Settings
from app.services.audit_paging import create_audit_pager
from app.services.sqlite_audit import SQLiteAuditStore
x=json.load(sys.stdin)
p=create_audit_pager(Settings(_env_file=None,audit_cursor_key_path=x['key_path'],audit_cursor_key_sha256=x['pin']))
r=p.page(SQLiteAuditStore.open_existing(x['db']),'local',1,x['cursor'])
print(json.dumps({'ids':[v.analysis_id for v in r.items],'snapshot_id':r.snapshot_id}))
"""
    env = dict(os.environ, AWS_EC2_METADATA_DISABLED="true")
    env.pop("OPENAI_API_KEY", None)
    executable, env = direct_python(env)
    result = subprocess.run(
        [executable, "-c", code],
        input=json.dumps(data),
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=True,
    )
    value = json.loads(result.stdout)
    assert value["ids"] == [rows[1].analysis_id] and value["snapshot_id"] == first.snapshot_id


def test_valid_but_replaced_sqlite_prefix_requires_restart(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    seed(store)
    service = pager()
    first = service.page(store, "local", 1)
    with store._transaction(write=True) as con:
        con.execute("DELETE FROM audit_entries")
        con.execute("UPDATE audit_head SET seq=0,digest=? WHERE id=1", ("0" * 64,))
    seed(store, 2, start=100)
    assert store.integrity()["ok"]
    with pytest.raises(AuditSnapshotChanged):
        service.page(store, "local", 1, first.next_cursor)


def test_jsonl_disappearance_after_observation_is_not_an_empty_new_page(tmp_path):
    path = tmp_path / "audit.jsonl"
    reader = AuditStore(path)
    seed(AuditStore(path))
    service = pager()
    assert service.page(reader, "local").total_matches == 3
    assert reader._history == []
    path.unlink()
    with pytest.raises(AuditQueryUnavailable):
        service.page(reader, "local")


@pytest.mark.parametrize("backend", ["jsonl", "federated"])
def test_unhashed_legacy_is_not_reported_as_verified_paged_history(tmp_path, backend):
    path = tmp_path / "audit.jsonl"
    path.write_text(initial(1).model_dump_json() + "\n", encoding="utf-8")
    store = (
        AuditStore(path)
        if backend == "jsonl"
        else FederatedAuditStore(tmp_path / "audit.worker-1.jsonl", path)
    )
    assert store.get("audit-cancel-1") is not None
    with pytest.raises(AuditQueryUnavailable):
        pager().page(store, "local")
