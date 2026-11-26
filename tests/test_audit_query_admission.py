"""Authenticated audit reads and review writes under cancellation and withdrawal."""

import asyncio
import hashlib
import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from test_audit_cancellation import record

from app import main, security
from app.config import Settings
from app.models import ReviewStatus
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.local_oidc_authority import LocalOIDCAuthority


@pytest.fixture
def api(tmp_path, monkeypatch):
    key = "local-audit-query-placeholder"
    config = Settings(
        _env_file=None,
        auth_mode="api_key",
        api_key_sha256=hashlib.sha256(key.encode()).hexdigest(),
        api_key_subject="local-auditor",
        api_key_tenant_id="local",
        api_key_roles="responder",
        audit_query_queue_timeout_seconds=0.01,
    )
    store = SQLiteAuditStore(tmp_path / "query.sqlite3")
    first = record(1)
    first = first.model_copy(
        update={
            "assessment": first.assessment.model_copy(update={"requires_human_review": True}),
            "review_status": ReviewStatus.PENDING,
        }
    )
    asyncio.run(store.save(first))
    asyncio.run(store.save(record(2).model_copy(update={"tenant_id": "other"})))
    capacity = asyncio.Semaphore(1)
    monkeypatch.setattr(main, "audit_query_capacity", capacity, raising=False)
    monkeypatch.setattr(main, "audit_store", store)
    monkeypatch.setattr(main, "settings", config)
    monkeypatch.setattr(security, "get_settings", lambda: config)

    def withdraw():
        config.api_key_sha256 = SecretStr(hashlib.sha256(b"rotated-local-query-key").hexdigest())

    with TestClient(main.app) as client:
        yield SimpleNamespace(
            client=client,
            store=store,
            capacity=capacity,
            headers={"X-API-Key": key},
            first=first,
            withdraw=withdraw,
        )


@pytest.mark.parametrize(
    "url,method",
    [
        ("/results", "recent"),
        ("/metrics", "metrics"),
        ("/results/audit-cancel-1", "get"),
    ],
)
def test_cancelled_query_holds_capacity_until_disk_read_finishes(api, monkeypatch, url, method):
    entered, release = threading.Event(), threading.Event()
    original = getattr(api.store, method)
    calls = 0

    def blocked(*args, **kwargs):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(api.store, method, blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get(url, headers=api.headers))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert (await client.get("/health/live")).status_code == 200
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and api.capacity._value == 0
                full = await client.get(url, headers=api.headers)
                assert full.status_code == 503 and full.headers["Retry-After"] == "1"
                assert calls == 1
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert api.capacity._value == 1 and api.store.integrity()["verified_lines"] == 2
            recovered = await client.get(url, headers=api.headers)
            assert recovered.status_code == 200 and "audit-cancel-2" not in recovered.text

    asyncio.run(run())


@pytest.mark.parametrize(
    "url,method",
    [
        ("/results", "recent"),
        ("/metrics", "metrics"),
        ("/results/audit-cancel-1", "get"),
    ],
)
def test_authority_withdrawn_during_read_cannot_receive_old_results(api, monkeypatch, url, method):
    original = getattr(api.store, method)

    def withdrawn(*args, **kwargs):
        result = original(*args, **kwargs)
        api.withdraw()
        return result

    monkeypatch.setattr(api.store, method, withdrawn)
    response = api.client.get(url, headers=api.headers)
    assert response.status_code == 401 and "audit-cancel-1" not in response.text
    assert api.capacity._value == 1 and api.store.integrity()["verified_lines"] == 2


def test_store_swap_during_query_does_not_deliver_previous_store_result(api, monkeypatch, tmp_path):
    original = api.store.get
    replacement = SQLiteAuditStore(tmp_path / "replacement.sqlite3")

    def swapped(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr(main, "audit_store", replacement)
        return result

    monkeypatch.setattr(api.store, "get", swapped)
    response = api.client.get("/results/audit-cancel-1", headers=api.headers)
    assert response.status_code == 503 and "audit-cancel-1" not in response.text
    assert api.capacity._value == 1


def test_review_rechecks_authority_after_lookup_before_append(api, monkeypatch):
    original = api.store.get

    def withdrawn(*args, **kwargs):
        result = original(*args, **kwargs)
        api.withdraw()
        return result

    monkeypatch.setattr(api.store, "get", withdrawn)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "RESOLVED", "note": "Local query boundary review"},
    )
    assert response.status_code == 401
    assert api.store.integrity()["verified_lines"] == 2
    assert original(api.first.event_id).review_status == ReviewStatus.PENDING


def test_review_authority_withdrawn_after_commit_denies_delivery_and_keeps_history(
    api, monkeypatch
):
    original = api.store._write

    def withdrawn(*args, **kwargs):
        result = original(*args, **kwargs)
        api.withdraw()
        return result

    monkeypatch.setattr(api.store, "_write", withdrawn)
    response = api.client.patch(
        "/results/audit-cancel-1/review",
        headers=api.headers,
        json={"status": "RESOLVED", "note": "Local query boundary review"},
    )
    assert response.status_code == 401
    assert api.store.integrity()["verified_lines"] == 3
    saved = api.store.get(api.first.event_id)
    assert saved.review_status == ReviewStatus.RESOLVED and saved.reviewer == "local-auditor"
    assert api.capacity._value == 1


def test_cancelled_review_commit_keeps_shared_query_slot_until_writer_settles(api, monkeypatch):
    original = api.store._write
    entered, release = threading.Event(), threading.Event()

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(api.store, "_write", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.patch(
                    "/results/audit-cancel-1/review",
                    headers=api.headers,
                    json={"status": "RESOLVED", "note": "Local query boundary review"},
                )
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and api.capacity._value == 0
                full = await client.get("/results", headers=api.headers)
                assert full.status_code == 503
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert api.capacity._value == 1 and api.store.integrity()["verified_lines"] == 3
            assert api.store.get(api.first.event_id).reviewer == "local-auditor"
            assert (await client.get("/results", headers=api.headers)).status_code == 200

    asyncio.run(run())


def test_mixed_read_burst_and_review_share_a_bounded_query_pool(api, monkeypatch):
    capacity = asyncio.Semaphore(2)
    monkeypatch.setattr(main, "audit_query_capacity", capacity)
    original = api.store._records
    entered, release = threading.Event(), threading.Event()
    lock = threading.Lock()
    calls = 0

    def blocked():
        nonlocal calls
        with lock:
            calls += 1
            if calls == 2:
                entered.set()
        assert release.wait(4)
        return original()

    monkeypatch.setattr(api.store, "_records", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            urls = ["/metrics", "/results", "/results/audit-cancel-1"]
            jobs = [
                asyncio.create_task(client.get(urls[i % 3], headers=api.headers)) for i in range(8)
            ]
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                done, pending = await asyncio.wait(jobs, timeout=0.25)
                assert len(done) == 6 and len(pending) == 2
                assert all(job.result().status_code == 503 for job in done)
                for task in pending:
                    task.cancel()
                await asyncio.sleep(0)
                assert capacity._value == 0 and calls == 2
                response = await client.patch(
                    "/results/audit-cancel-1/review",
                    headers=api.headers,
                    json={"status": "IN_REVIEW"},
                )
                assert response.status_code == 503
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                outcomes = await asyncio.gather(*jobs, return_exceptions=True)
            assert sum(isinstance(value, asyncio.CancelledError) for value in outcomes) == 2
            assert capacity._value == 2 and api.store.integrity()["verified_lines"] == 2
            response = await client.get("/results", headers=api.headers)
            assert response.status_code == 200 and "audit-cancel-2" not in response.text

    asyncio.run(run())


@pytest.mark.parametrize("method,phase", [("get", "read"), ("patch", "read"), ("patch", "write")])
def test_real_oidc_expiry_during_audit_io_denies_delivery(api, monkeypatch, method, phase):
    now = datetime.now(UTC)
    expiry = now + timedelta(seconds=60)
    clock = {"now": now}

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"].astimezone(tz) if tz else clock["now"].replace(tzinfo=None)

    monkeypatch.setattr(main, "datetime", Clock)
    name = "get" if phase == "read" else "_write"
    original = getattr(api.store, name)

    def expired(*args, **kwargs):
        value = original(*args, **kwargs)
        clock["now"] = expiry + timedelta(seconds=1)
        return value

    monkeypatch.setattr(api.store, name, expired)
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
        )
        monkeypatch.setattr(security, "get_settings", lambda: config)
        headers = {
            "Authorization": "Bearer "
            + authority.issue(
                tenant_id="local",
                roles=["responder"],
                exp=expiry,
            )
        }
        if method == "get":
            response = api.client.get("/results/audit-cancel-1", headers=headers)
        else:
            response = api.client.patch(
                "/results/audit-cancel-1/review",
                headers=headers,
                json={"status": "RESOLVED", "note": "Local OIDC boundary review"},
            )
        assert response.status_code == 401 and "audit-cancel-1" not in response.text
        assert authority.fetches >= 1
    security._jwks_client.cache_clear()
    assert api.capacity._value == 1
    assert api.store.integrity()["verified_lines"] == (3 if phase == "write" else 2)


@pytest.mark.parametrize(
    "options",
    [
        {"audit_query_max_concurrency": 0},
        {"audit_query_max_concurrency": 9},
        {"audit_query_queue_timeout_seconds": 0},
        {"audit_query_queue_timeout_seconds": 2.1},
        {"audit_query_queue_timeout_seconds": float("inf")},
        {"audit_query_queue_timeout_seconds": float("nan")},
    ],
)
def test_query_capacity_configuration_rejects_unbounded_values(options):
    with pytest.raises(ValueError):
        Settings(_env_file=None, **options)


def test_readiness_audit_scan_uses_same_pool_until_cancelled_io_settles(api, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = api.store.integrity

    def blocked():
        entered.set()
        assert release.wait(4)
        return original()

    monkeypatch.setattr(api.store, "integrity", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/health/ready"))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and api.capacity._value == 0
                assert (await client.get("/results", headers=api.headers)).status_code == 503
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                outcomes = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcomes[0], asyncio.CancelledError)
            assert api.capacity._value == 1
            assert (await client.get("/results", headers=api.headers)).status_code == 200

    asyncio.run(run())
