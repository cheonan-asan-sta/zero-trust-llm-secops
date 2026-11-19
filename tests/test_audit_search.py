"""Whole-tenant literal search is a cursor scope, never an authorization source."""

import asyncio

import pytest
from test_audit_paging import pager, seed
from test_audit_paging import store as store  # noqa: PLC0414
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_sqlite_audit import review

from app.services.audit_paging import AuditCursorInvalid
from app.services.sqlite_audit import SQLiteAuditStore


def test_search_reaches_old_rows_without_cross_tenant_leak(store):
    rows = seed(store, 125)
    seed(store, 1, tenant="other", start=999)
    result = pager().page(store, "local", q=rows[0].analysis_id, analyzer=rows[0].analyzer)
    assert result.total_matches == 1 and result.items[0].analysis_id == rows[0].analysis_id
    assert pager().page(store, "local", q=f"{999:032x}").total_matches == 0


def test_query_and_analyzer_are_bound_to_cursor(store):
    seed(store, 4)
    service = pager()
    first = service.page(store, "local", 1, q="  RULE  ", analyzer="rule")
    assert first.total_matches == 4
    second = service.page(store, "local", 1, first.next_cursor, q="rule", analyzer="rule")
    assert first.snapshot_id == second.snapshot_id
    assert first.snapshot_expires_at == second.snapshot_expires_at
    for changes in ({"q": None, "analyzer": "rule"}, {"q": "rule", "analyzer": "openai"}):
        with pytest.raises(AuditCursorInvalid):
            service.page(store, "local", 1, first.next_cursor, **changes)


def test_literal_not_regex_and_nfkc_casefold(store):
    original = seed(store, 1)[0]
    row = review(original).model_copy(update={"review_note": "운영 검토 ＡＢＣ .*"})
    if isinstance(store, SQLiteAuditStore):
        asyncio.run(store.save_review(row, original))
    else:
        asyncio.run(store.save(row))
    assert pager().page(store, "local", q="abc").total_matches == 1
    assert pager().page(store, "local", q="운영 검토").total_matches == 1
    assert pager().page(store, "local", q=".*").total_matches == 1
    assert pager().page(store, "local", q="^.*$").total_matches == 0


@pytest.mark.parametrize("q", ["x" * 257, "😀" * 256, "a\x00b", 42])
def test_invalid_search_is_rejected_before_opening_store(q):
    with pytest.raises(AuditCursorInvalid):
        pager().page(object(), "local", q=q)


def test_http_search_and_parameter_limits(api):
    response = api.client.get(
        "/audit/results", headers=api.headers, params={"q": "audit-cancel-1", "analyzer": "rule"}
    )
    assert response.status_code == 200 and response.json()["total_matches"] == 1
    assert response.headers["Cache-Control"] == "no-store"
    for params in ({"q": "x" * 257}, {"analyzer": "../rule"}):
        assert (
            api.client.get("/audit/results", headers=api.headers, params=params).status_code == 422
        )
    denied = api.client.get("/audit/results", params={"q": "audit-cancel-1"})
    assert denied.status_code == 401


def test_maximum_search_stays_inside_cursor_wire_budget(store):
    service = pager()
    q = "가" * 170
    page = service.page(store, "t" * 64, q=q, analyzer="a" * 64)
    assert len(page.page_cursor) <= 2048
    assert service.page(store, "t" * 64, cursor=page.page_cursor, q=q, analyzer="a" * 64).snapshot_id == page.snapshot_id
