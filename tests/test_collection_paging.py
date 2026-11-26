import asyncio
import threading
from dataclasses import replace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_incident_cases import _correlation
from test_zero_trust_operations import PRINCIPAL, evaluate, event

from app import main
from app.models import StrictModel
from app.services.audit_paging import AuditCursorExpired, AuditCursorInvalid, AuditSnapshotChanged
from app.services.cases import CaseStore, IncidentCaseService
from app.services.collection_paging import CollectionPager, case_rows
from app.services.federated_audit import AuditQueryUnavailable
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_api import zero_trust_router


class Row(StrictModel):
    tenant_id: str = "tenant-a"
    number: int


def test_live_pages_round_trip_and_bind_all_scope_dimensions():
    service = CollectionPager(lambda: b"a" * 32)
    rows = [Row(number=i) for i in range(29)]
    first = service.page(rows, PRINCIPAL, "cases", limit=12, filters={"status": "NEW"})
    second = service.page(
        rows, PRINCIPAL, "cases", limit=12, cursor=first.next_cursor, filters={"status": "NEW"}
    )
    back = service.page(
        rows, PRINCIPAL, "cases", limit=12, cursor=first.page_cursor, filters={"status": "NEW"}
    )
    assert back.items == first.items and first.snapshot_id == second.snapshot_id
    assert first.snapshot_expires_at == second.snapshot_expires_at
    for principal, source, limit, filters in [
        (replace(PRINCIPAL, subject="other"), "cases", 12, {"status": "NEW"}),
        (PRINCIPAL, "sessions", 12, {"status": "NEW"}),
        (PRINCIPAL, "cases", 20, {"status": "NEW"}),
        (PRINCIPAL, "cases", 12, {"status": "CLOSED"}),
    ]:
        with pytest.raises(AuditCursorInvalid):
            service.page(
                rows, principal, source, limit=limit, cursor=first.next_cursor, filters=filters
            )
    with pytest.raises(AuditQueryUnavailable):
        service.page(rows, replace(PRINCIPAL, tenant_id="other"), "cases")


def test_view_change_expiry_key_change_and_invalid_cursor_fail_closed():
    now = {"time": 1000}
    key = {"value": b"a" * 32}
    service = CollectionPager(lambda: key["value"], lambda: now["time"])
    rows = [Row(number=i) for i in range(3)]
    first = service.page(rows, PRINCIPAL, "sessions", limit=1)
    with pytest.raises(AuditSnapshotChanged):
        service.page(
            rows + [Row(number=4)], PRINCIPAL, "sessions", limit=1, cursor=first.next_cursor
        )
    now["time"] = 1900
    with pytest.raises(AuditCursorExpired):
        service.page(rows, PRINCIPAL, "sessions", limit=1, cursor=first.next_cursor)
    now["time"] = 1000
    key["value"] = b"b" * 32
    with pytest.raises(AuditCursorInvalid):
        service.page(rows, PRINCIPAL, "sessions", limit=1, cursor=first.next_cursor)
    for token in ("x", "bad cursor", "x" * 2049):
        with pytest.raises(AuditCursorInvalid):
            service.page(rows, PRINCIPAL, "sessions", cursor=token)


def cases(path, count=27, tenant="local"):
    store = CaseStore(path)
    records, _, _ = asyncio.run(
        IncidentCaseService(store).create_from_correlation(
            _correlation("collection", tenant), tenant, "tester", "Local case pagination fixture"
        )
    )
    original = records[0]
    for i in range(1, count):
        asyncio.run(store.save(original.model_copy(update={"case_id": f"case-{i:032x}"})))
    return store


def test_case_reader_checks_actual_disk_and_known_prefix(tmp_path):
    store = cases(tmp_path / "cases.jsonl", 4)
    assert len(case_rows(store, "local")) == 4
    raw = store._path.read_bytes()
    store._path.write_bytes(raw.splitlines(keepends=True)[0])
    with pytest.raises(AuditQueryUnavailable):
        case_rows(store, "local")
    store._path.write_bytes(raw.replace(b'"schema_version":1', b'"schema_version":2', 1))
    with pytest.raises(AuditQueryUnavailable):
        case_rows(store, "local")


def test_case_http_pages_auth_scope_change_and_missing_source(api, monkeypatch, tmp_path):
    store = cases(tmp_path / "cases.jsonl")
    monkeypatch.setattr(main, "case_store", store)
    url = "/case-pages"
    first = api.client.get(url, headers=api.headers).json()
    assert first["total_matches"] == 27 and len(first["items"]) == 12
    second = api.client.get(url, headers=api.headers, params={"cursor": first["next_cursor"]})
    assert second.status_code == 200 and second.json()["snapshot_id"] == first["snapshot_id"]
    assert api.client.get(url).status_code == 401
    assert (
        api.client.get(
            url, headers=api.headers, params={"status": "CLOSED", "cursor": first["next_cursor"]}
        ).status_code
        == 400
    )
    main.settings.api_key_subject = "another-viewer"
    assert (
        api.client.get(
            url, headers=api.headers, params={"cursor": first["next_cursor"]}
        ).status_code
        == 400
    )
    store._path.unlink()
    assert api.client.get(url, headers=api.headers).status_code == 503


@pytest.mark.parametrize("change", ["revoke", "subject", "source"])
def test_authority_and_source_rechecked_after_case_io(api, monkeypatch, tmp_path, change):
    store = cases(tmp_path / "cases.jsonl", 2)
    monkeypatch.setattr(main, "case_store", store)
    original = main.case_rows

    def changed(*args):
        result = original(*args)
        if change == "revoke":
            api.withdraw()
        elif change == "subject":
            main.settings.api_key_subject = "changed-after-collection-read"
        else:
            monkeypatch.setattr(main, "case_store", CaseStore(tmp_path / "new-source.jsonl"))
        return result

    monkeypatch.setattr(main, "case_rows", changed)
    response = api.client.get("/case-pages", headers=api.headers)
    assert response.status_code == (503 if change == "source" else 401)
    assert "items" not in response.json() and api.capacity._value == 1


def test_case_pages_detect_disk_changes_even_with_old_repository_cache(api, monkeypatch, tmp_path):
    path = tmp_path / "cases.jsonl"
    store = cases(path, 15)
    monkeypatch.setattr(main, "case_store", store)
    first = api.client.get("/case-pages", headers=api.headers).json()
    # Independent writer appends a valid version1 case. Reader's in-memory cache stays old.
    writer = CaseStore(path)
    row = next(iter(writer._records.values())).model_copy(update={"case_id": "case-" + "f" * 32})
    asyncio.run(writer.save(row))
    denied = api.client.get(
        "/case-pages", headers=api.headers, params={"cursor": first["next_cursor"]}
    )
    assert denied.status_code == 409
    assert api.client.get("/case-pages", headers=api.headers).json()["total_matches"] == 16


def test_cancelled_case_read_holds_slot_until_owned_disk_worker_finishes(
    api, monkeypatch, tmp_path
):
    store = cases(tmp_path / "cases.jsonl", 2)
    monkeypatch.setattr(main, "case_store", store)
    entered, release = threading.Event(), threading.Event()
    original = main.case_rows

    def blocked(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(main, "case_rows", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/case-pages", headers=api.headers))
            try:
                assert await asyncio.to_thread(entered.wait, 3)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and api.capacity._value == 0
                full = await client.get("/case-pages", headers=api.headers)
                assert full.status_code == 503 and full.headers["Retry-After"] == "1"
            finally:
                release.set()
                result = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(result[0], asyncio.CancelledError) and api.capacity._value == 1

    asyncio.run(run())


def test_session_http_pages_exceed_legacy100_and_refuse_changed_view(api, tmp_path):
    operations = ZeroTrustOperations(tmp_path / "sessions.sqlite3")
    principal = replace(PRINCIPAL, tenant_id="local")
    for i in range(103):
        evaluate(
            operations,
            e=event(f"page-event-{i:03}"),
            session_id=f"session-{i:03}",
            principal=principal,
        )
    app = FastAPI()
    app.include_router(
        zero_trust_router(
            operations, page_service=lambda: main.collection_pager, page_slot=main._audit_query_slot
        )
    )

    async def changed(_request, _error):
        return JSONResponse({"detail": "changed view"}, status_code=409)

    app.add_exception_handler(AuditSnapshotChanged, changed)
    with TestClient(app) as client:
        first = client.get("/zero-trust/session-pages", headers=api.headers).json()
        assert first["total_matches"] == 103 and len(first["items"]) == 12
        assert "grant_token" not in str(first) and "grant_hash" not in str(first)
        ids = {row["session_id"] for row in first["items"]}
        current = first
        while current["next_cursor"]:
            current = client.get(
                "/zero-trust/session-pages",
                headers=api.headers,
                params={"cursor": current["next_cursor"]},
            ).json()
            ids.update(row["session_id"] for row in current["items"])
        assert len(ids) == 103
        evaluate(
            operations, e=event("new-page-event"), session_id="new-session", principal=principal
        )
        assert (
            client.get(
                "/zero-trust/session-pages",
                headers=api.headers,
                params={"cursor": first["next_cursor"]},
            ).status_code
            == 409
        )
