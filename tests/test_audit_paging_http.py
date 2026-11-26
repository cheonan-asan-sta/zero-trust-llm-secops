"""Actual API authentication and query admission for paginated audit reads."""

import asyncio
import hashlib
import threading

import httpx
import pytest
from test_audit_paging import seed
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main, security
from app.config import Settings
from app.services.audit import DynamoDBAuditStore
from app.services.audit_paging import AuditPager, create_audit_pager


def test_authenticated_paged_collection_is_not_cacheable(api):
    seed(api.store, 2, start=3)
    response = api.client.get("/audit/results", headers=api.headers, params={"limit": 1})
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    first = response.json()
    assert first["total_matches"] == 3 and first["snapshot_mode"] == "sqlite_prefix"
    assert first["historical_audit_snapshot"]
    second = api.client.get(
        "/audit/results", headers=api.headers, params={"limit": 1, "cursor": first["next_cursor"]}
    )
    assert second.status_code == 200
    assert second.json()["snapshot_id"] == first["snapshot_id"]
    assert second.json()["items"][0]["analysis_id"] != first["items"][0]["analysis_id"]
    assert "audit-cancel-2" not in response.text + second.text


@pytest.mark.parametrize(
    "options", [{"limit": 0}, {"limit": 101}, {"cursor": "x" * 2049}, {"cursor": "bad+encoding"}]
)
def test_invalid_page_input_is_rejected_before_audit_query(api, monkeypatch, options):
    def fail(*args, **kwargs):
        raise AssertionError("invalid request must not scan audit data")

    monkeypatch.setattr(api.store, "_read", fail)
    response = api.client.get("/audit/results", headers=api.headers, params=options)
    assert response.status_code == 422


def test_current_caller_tenant_cannot_reuse_previous_tenant_cursor(api, monkeypatch):
    seed(api.store, 2, start=3)
    first = api.client.get("/audit/results", headers=api.headers, params={"limit": 1}).json()
    config = Settings(
        _env_file=None,
        auth_mode="api_key",
        api_key_sha256=hashlib.sha256(api.headers["X-API-Key"].encode()).hexdigest(),
        api_key_subject="local-auditor",
        api_key_tenant_id="other",
        api_key_roles="viewer",
    )
    monkeypatch.setattr(security, "get_settings", lambda: config)
    response = api.client.get(
        "/audit/results", headers=api.headers, params={"cursor": first["next_cursor"]}
    )
    assert response.status_code == 400 and "audit-cancel-1" not in response.text
    own = api.client.get("/audit/results", headers=api.headers)
    assert own.status_code == 200 and own.json()["total_matches"] == 1
    assert own.json()["items"][0]["tenant_id"] == "other"


def test_page_revalidates_current_caller_after_snapshot_read(api, monkeypatch):
    original = api.store._read

    def withdrawn(*args, **kwargs):
        result = original(*args, **kwargs)
        api.withdraw()
        return result

    monkeypatch.setattr(api.store, "_read", withdrawn)
    response = api.client.get("/audit/results", headers=api.headers)
    assert response.status_code == 401 and "audit-cancel-1" not in response.text
    assert api.capacity._value == 1


def test_expired_cursor_returns410_without_silently_starting_again(api, monkeypatch):
    seed(api.store, 2, start=3)
    clock = {"now": 1000}
    monkeypatch.setattr(main, "audit_pager", AuditPager(clock=lambda: clock["now"]))
    first = api.client.get("/audit/results", headers=api.headers, params={"limit": 1}).json()
    clock["now"] = 1900
    response = api.client.get(
        "/audit/results", headers=api.headers, params={"cursor": first["next_cursor"]}
    )
    assert response.status_code == 410 and response.headers["Cache-Control"] == "no-store"
    assert "items" not in response.json()


def test_cancelled_page_read_keeps_shared_query_capacity_until_io_finishes(api, monkeypatch):
    original = api.store._read
    entered, release = threading.Event(), threading.Event()
    calls = 0

    def blocked(*args, **kwargs):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(4)
        return original(*args, **kwargs)

    monkeypatch.setattr(api.store, "_read", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/audit/results", headers=api.headers))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and api.capacity._value == 0
                response = await client.get("/results", headers=api.headers)
                assert response.status_code == 503 and calls == 1
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert api.capacity._value == 1
            assert (await client.get("/audit/results", headers=api.headers)).status_code == 200

    asyncio.run(run())


def test_unsupported_cloud_backend_never_calls_aws_for_paging(api, monkeypatch):
    # Deliberately do not construct a boto3 client or cloud resource.
    store = DynamoDBAuditStore.__new__(DynamoDBAuditStore)
    monkeypatch.setattr(main, "audit_store", store)
    response = api.client.get("/audit/results", headers=api.headers)
    assert response.status_code == 501
    assert api.capacity._value == 1


def test_legacy_literal_event_id_page_remains_readable(api):
    event_id = "page"
    row = api.first.model_copy(update={"analysis_id": "c" * 32, "event_id": event_id})
    asyncio.run(api.store.save(row))
    response = api.client.get(f"/results/{event_id}", headers=api.headers)
    assert response.status_code == 200
    assert response.json().get("event_id") == event_id and "items" not in response.json()


def test_cursor_key_withdrawal_is_visible_in_readiness_without_disabling_liveness(
    api, tmp_path, monkeypatch
):
    path = tmp_path / "cursor.key"
    key = b"local-readiness-fixture-key-00000"[:32]
    path.write_bytes(key)
    path.chmod(0o600)
    config = Settings(
        _env_file=None,
        audit_cursor_key_path=path,
        audit_cursor_key_sha256=hashlib.sha256(key).hexdigest(),
    )
    monkeypatch.setattr(main, "audit_pager", create_audit_pager(config))
    before = api.client.get("/health/ready")
    assert before.json().get("audit_paging", {}).get("ok") is True
    path.write_bytes(b"invalid-replacement-fixture-00000"[:32])
    after = api.client.get("/health/ready")
    assert after.status_code == 503 and after.json()["audit_paging"]["ok"] is False
    assert "cursor.key" not in after.text and config.audit_cursor_key_sha256 not in after.text
    assert api.client.get("/audit/results", headers=api.headers).status_code == 503
    assert api.client.get("/health/live").status_code == 200
