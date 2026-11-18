"""Ordinary and batch analysis must not outlive the caller's current authority."""

import asyncio
import hashlib
import json
import os
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException
from test_audit_query_admission import api as api  # noqa: PLC0414
from test_sqlite_audit import initial

from app import api_key_accounts, main, security
from app.config import Settings
from app.scenarios import synthetic_events
from app.security import Principal, Role
from scripts.local_oidc_authority import LocalOIDCAuthority


def send(api, batch=False, headers=None):
    event = synthetic_events()[0].model_dump(mode="json")
    return api.client.post(
        "/analysis/batch" if batch else "/analysis",
        headers=headers or api.headers,
        json={"events": [event]} if batch else event,
    )


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("stage", ["audit", "model", "saved", "proof"])
def test_api_key_withdrawal_denies_analysis_at_each_boundary(api, monkeypatch, batch, stage):
    async def infer(_):
        if stage == "model":
            api.withdraw()
        return initial(99).assessment

    model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    if stage in {"audit", "proof"}:
        method = "integrity" if stage == "audit" else "verify_saved"
        original = getattr(api.store, method)

        def withdraw(*args, **kwargs):
            result = original(*args, **kwargs)
            api.withdraw()
            return result

        monkeypatch.setattr(api.store, method, withdraw)
    if stage == "saved":
        original = api.store.save

        async def save(record):
            await original(record)
            api.withdraw()

        monkeypatch.setattr(api.store, "save", save)
    response = send(api, batch)
    assert response.status_code == 401 and "assessment" not in response.json()
    assert model.analyze.await_count == (0 if stage == "audit" else 1)
    assert len(api.store._records()) == (3 if stage in {"saved", "proof"} else 2)


@pytest.mark.parametrize("batch", [False, True])
def test_revoked_while_waiting_for_analysis_slot_never_reaches_provider(api, monkeypatch, batch):
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    monkeypatch.setattr(
        main, "settings", main.settings.model_copy(update={"analysis_queue_timeout_seconds": 1})
    )
    original_slot = main._analysis_slot

    async def run():
        queued = asyncio.Event()
        capacity = asyncio.Semaphore(0)
        monkeypatch.setattr(main, "analysis_capacity", capacity)

        @asynccontextmanager
        async def observed_slot():
            queued.set()
            async with original_slot():
                yield

        monkeypatch.setattr(main, "_analysis_slot", observed_slot)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            event = synthetic_events()[0].model_dump(mode="json")
            task = asyncio.create_task(
                client.post(
                    "/analysis/batch" if batch else "/analysis",
                    headers=api.headers,
                    json={"events": [event]} if batch else event,
                )
            )
            await asyncio.wait_for(queued.wait(), 2)
            api.withdraw()
            capacity.release()
            response = await task
        assert response.status_code == 401 and capacity._value == 1

    asyncio.run(run())
    assert model.analyze.await_count == 0 and len(api.store._records()) == 2


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("stage", ["audit", "model", "saved", "proof"])
def test_real_local_oidc_expiry_is_checked_after_every_blocking_boundary(
    api, monkeypatch, batch, stage
):
    now = datetime.now(UTC)
    expiry = now + timedelta(seconds=60)
    clock = {"now": now}

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"].astimezone(tz) if tz else clock["now"].replace(tzinfo=None)

    monkeypatch.setattr(main, "datetime", Clock)

    def expire():
        clock["now"] = expiry + timedelta(seconds=1)

    async def infer(_):
        if stage == "model":
            expire()
        return initial(99).assessment

    model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    if stage in {"audit", "proof"}:
        method = "integrity" if stage == "audit" else "verify_saved"
        original = getattr(api.store, method)

        def expire_after(*args, **kwargs):
            value = original(*args, **kwargs)
            expire()
            return value

        monkeypatch.setattr(api.store, method, expire_after)
    if stage == "saved":
        original = api.store.save

        async def save(record):
            await original(record)
            expire()

        monkeypatch.setattr(api.store, "save", save)
    security._jwks_client.cache_clear()
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
        )
        monkeypatch.setattr(security, "get_settings", lambda: config)
        headers = {
            "Authorization": "Bearer "
            + authority.issue(tenant_id="local", roles=["responder"], exp=expiry)
        }
        response = send(api, batch, headers)
    assert response.status_code == 401
    assert model.analyze.await_count == (0 if stage == "audit" else 1)
    assert len(api.store._records()) == (3 if stage in {"saved", "proof"} else 2)


@pytest.mark.parametrize(
    "field",
    [
        "oidc_issuer",
        "oidc_audience",
        "oidc_jwks_url",
        "oidc_roles_claim",
        "oidc_tenant_claim",
        "auth_mode",
    ],
)
def test_oidc_configuration_change_during_model_denies_old_identity(api, monkeypatch, field):
    security._jwks_client.cache_clear()
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
        )
        monkeypatch.setattr(security, "get_settings", lambda: config)

        async def infer(_):
            setattr(
                config,
                field,
                "disabled" if field == "auth_mode" else getattr(config, field) + "-changed",
            )
            return initial(99).assessment

        model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
        monkeypatch.setattr(main, "get_analyzer", lambda: model)
        response = send(
            api,
            headers={
                "Authorization": "Bearer " + authority.issue(tenant_id="local", roles=["analyst"])
            },
        )
    assert response.status_code == 401 and model.analyze.await_count == 1
    assert len(api.store._records()) == 2


@pytest.mark.parametrize(
    "change", ["disabled", "roles", "tenant", "subject", "missing", "malformed", "duplicate"]
)
def test_account_file_authority_is_reopened_before_persistence(api, tmp_path, monkeypatch, change):
    path = tmp_path / "accounts.json"
    key = "owned-local-account-file-caller"
    entry = {
        "subject": "file-caller",
        "sha256": hashlib.sha256(key.encode()).hexdigest(),
        "tenant_id": "local",
        "roles": ["analyst"],
        "enabled": True,
    }

    def save(entries):
        path.write_text(
            json.dumps({"schema": "api-key-accounts-1", "accounts": entries}), encoding="utf-8"
        )

    save([entry])
    main.settings.api_key_accounts_path = path

    async def infer(_):
        if change == "missing":
            path.unlink()
        elif change == "malformed":
            path.write_text('{"partial":', encoding="utf-8")
        else:
            updated = dict(entry)
            if change == "disabled":
                updated["enabled"] = False
            if change == "roles":
                updated["roles"] = ["viewer"]
            if change == "tenant":
                updated["tenant_id"] = "other"
            if change == "subject":
                updated["subject"] = "different-caller"
            save([updated, updated] if change == "duplicate" else [updated])
        return initial(99).assessment

    model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = send(api, headers={"X-API-Key": key})
    assert response.status_code == (503 if change in {"missing", "malformed", "duplicate"} else 401)
    assert model.analyze.await_count == 1 and len(api.store._records()) == 2


def test_changing_local_auth_disabled_to_enabled_denies_the_admitted_request(api, monkeypatch):
    current = {"config": Settings(_env_file=None, auth_mode="disabled")}
    monkeypatch.setattr(security, "get_settings", lambda: current["config"])

    async def infer(_):
        current["config"] = Settings(_env_file=None, auth_mode="api_key", api_key_sha256="a" * 64)
        return initial(99).assessment

    model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    response = send(api)
    assert response.status_code == 401 and model.analyze.await_count == 1
    assert len(api.store._records()) == 2


def test_unrelated_model_setting_change_does_not_revoke_caller(api, monkeypatch):
    async def infer(_):
        main.settings.openai_model = "local-fixture-model-change"
        return initial(99).assessment

    model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
    monkeypatch.setattr(main, "get_analyzer", lambda: model)
    assert send(api).status_code == 200
    assert model.analyze.await_count == 1 and len(api.store._records()) == 3


@pytest.mark.parametrize("case", ["oidc_missing_expiry", "expired", "viewer"])
def test_internal_pipeline_enforces_caller_expiry_and_role(api, monkeypatch, case):
    expiry = datetime.now(UTC) - timedelta(seconds=1) if case == "expired" else None
    actor = Principal(
        "local",
        "local",
        frozenset({Role.VIEWER if case == "viewer" else Role.ANALYST}),
        "oidc" if case.startswith("oidc") else "api_key",
        expiry,
    )
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))

    async def run():
        monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(1))
        with pytest.raises(HTTPException) as caught:
            await main._analyze_event(synthetic_events()[0], model, actor, "local-boundary")
        assert caught.value.status_code == (403 if case == "viewer" else 401)
        assert main.analysis_capacity._value == 1

    asyncio.run(run())
    assert model.analyze.await_count == 0 and len(api.store._records()) == 2


@pytest.mark.parametrize("failed", [False, True])
def test_cancelled_caller_io_keeps_analysis_slot_until_source_settles(api, monkeypatch, failed):
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def check():
        entered.set()
        assert release.wait(3)
        finished.set()
        if failed:
            raise OSError("controlled caller source failure")

    actor = Principal("local", "local", frozenset({Role.ANALYST}), "api_key")
    model = SimpleNamespace(name="rule", analyze=AsyncMock(return_value=initial(99).assessment))

    async def run():
        capacity = asyncio.Semaphore(1)
        monkeypatch.setattr(main, "analysis_capacity", capacity)
        task = asyncio.create_task(
            main._analyze_event(
                synthetic_events()[0], model, actor, "cancel-caller", caller_authority_check=check
            )
        )
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and capacity._value == 0
        finally:
            release.set()
            outcome = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(outcome[0], asyncio.CancelledError) and finished.is_set()
        assert capacity._value == 1

    asyncio.run(run())
    assert model.analyze.await_count == 0 and len(api.store._records()) == 2


def test_batch_authority_failure_cancels_queued_siblings_and_settles_them(api, monkeypatch):
    monkeypatch.setattr(
        main, "settings", main.settings.model_copy(update={"analysis_queue_timeout_seconds": 1})
    )

    async def run():
        started, release = asyncio.Event(), asyncio.Event()
        capacity = asyncio.Semaphore(1)
        monkeypatch.setattr(main, "analysis_capacity", capacity)

        async def infer(_):
            started.set()
            await release.wait()
            return initial(99).assessment

        model = SimpleNamespace(name="rule", analyze=AsyncMock(side_effect=infer))
        monkeypatch.setattr(main, "get_analyzer", lambda: model)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.post(
                    "/analysis/batch",
                    headers=api.headers,
                    json={"events": [e.model_dump(mode="json") for e in synthetic_events()[:5]]},
                )
            )
            await asyncio.wait_for(started.wait(), 2)
            api.withdraw()
            release.set()
            response = await task
        assert response.status_code == 401 and model.analyze.await_count == 1
        assert capacity._value == 1
        assert not [
            t
            for t in asyncio.all_tasks()
            if t is not asyncio.current_task()
            and not t.done()
            and "analyze_with_limit" in t.get_coro().__qualname__
        ]

    asyncio.run(run())
    assert len(api.store._records()) == 2


def test_account_file_drift_while_reading_is_rejected_without_caching(api, tmp_path, monkeypatch):
    path = tmp_path / "accounts.json"
    key = "local-caller-file-drift"
    path.write_text(
        json.dumps(
            {
                "schema": "api-key-accounts-1",
                "accounts": [
                    {
                        "subject": "local",
                        "sha256": hashlib.sha256(key.encode()).hexdigest(),
                        "tenant_id": "local",
                        "roles": ["analyst"],
                        "enabled": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    original = api_key_accounts.os.fstat
    calls = 0

    def changed(fd):
        nonlocal calls
        calls += 1
        result = original(fd)
        if calls == 2:
            os.utime(path, ns=(result.st_atime_ns, result.st_mtime_ns + 1_000_000_000))
        return result

    monkeypatch.setattr(api_key_accounts.os, "fstat", changed)
    with pytest.raises(ValueError, match="changed"):
        api_key_accounts.load_accounts(path, "a" * 64)
    assert len(api_key_accounts.load_accounts(path, "a" * 64)) == 1
