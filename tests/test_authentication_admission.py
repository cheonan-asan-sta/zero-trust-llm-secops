"""Initial authentication I/O is bounded, cancellable only after its worker settles."""

import asyncio
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import ValidationError
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main, security
from app.config import Settings
from app.services.authentication_admission import AuthenticationAdmission
from scripts.local_oidc_authority import LocalOIDCAuthority


def single_slot(monkeypatch, config):
    config.authentication_max_concurrency = 1
    config.authentication_queue_timeout_seconds = 0.02
    capacity = AuthenticationAdmission(1)
    monkeypatch.setattr(main.app.state, "_authentication_admission", capacity, raising=False)
    return capacity


def oidc_config():
    return Settings(
        _env_file=None,
        auth_mode="oidc",
        oidc_issuer="https://identity.example.test",
        oidc_audience="local",
        oidc_jwks_url="https://identity.example.test/keys",
    )


def claims():
    return {
        "sub": "local",
        "tenant_id": "local",
        "roles": ["viewer"],
        "exp": (datetime.now(UTC) + timedelta(seconds=60)).timestamp(),
    }


def test_initial_api_identity_io_does_not_block_liveness_on_the_event_loop(api, monkeypatch):
    entered, heartbeat, missed = threading.Event(), threading.Event(), threading.Event()
    original = security._api_key_principal

    def slow(*args):
        entered.set()
        if not heartbeat.wait(1):
            missed.set()
        return original(*args)

    monkeypatch.setattr(security, "_api_key_principal", slow)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/scenarios", headers=api.headers))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert (await client.get("/health/live")).status_code == 200
            finally:
                heartbeat.set()
                response = await task
            assert response.status_code == 200 and not missed.is_set()

    asyncio.run(run())


def test_cancelled_initial_oidc_decode_waits_for_the_worker_to_settle(api, monkeypatch):
    config = Settings(
        _env_file=None,
        auth_mode="oidc",
        oidc_issuer="https://identity.example.test",
        oidc_audience="local",
        oidc_jwks_url="https://identity.example.test/keys",
    )
    monkeypatch.setattr(security, "get_settings", lambda: config)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def slow(*_):
        entered.set()
        assert release.wait(3)
        finished.set()
        return {
            "sub": "local",
            "tenant_id": "local",
            "roles": ["viewer"],
            "exp": (datetime.now(UTC) + timedelta(seconds=60)).timestamp(),
        }

    monkeypatch.setattr(security, "_decode_oidc_token", slow)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.get("/scenarios", headers={"Authorization": "Bearer local-placeholder"})
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0.03)
                assert not task.done() and not finished.is_set()
            finally:
                release.set()
                outcome = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(outcome[0], asyncio.CancelledError) and finished.is_set()

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["api_key", "oidc"])
@pytest.mark.parametrize("failed", [False, True])
def test_cancelled_identity_worker_keeps_capacity_and_overload_never_starts_more_io(
    api, monkeypatch, mode, failed
):
    config = main.settings if mode == "api_key" else oidc_config()
    monkeypatch.setattr(security, "get_settings", lambda: config)
    capacity = single_slot(monkeypatch, config)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = security._api_key_principal
    calls = 0
    failing = {"enabled": failed}

    def slow(*args):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(3)
        finished.set()
        if failing["enabled"]:
            raise OSError("controlled initial identity source failure")
        return original(*args) if mode == "api_key" else claims()

    monkeypatch.setattr(
        security, "_api_key_principal" if mode == "api_key" else "_decode_oidc_token", slow
    )
    headers = api.headers if mode == "api_key" else {"Authorization": "Bearer local-placeholder"}

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/scenarios", headers=headers))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                await asyncio.sleep(0.01)
                assert not task.done() and capacity.snapshot()["active"] == 1
                busy = await client.get("/scenarios", headers=headers)
                assert busy.status_code == 503 and busy.headers["Retry-After"] == "1"
                assert calls == 1 and capacity.snapshot()["active"] == 1
                assert (await client.get("/health/live")).status_code == 200
            finally:
                release.set()
                result = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(result[0], asyncio.CancelledError) and finished.is_set()
            assert capacity.snapshot()["available"] == 1
            failing["enabled"] = False
            assert (await client.get("/scenarios", headers=headers)).status_code == 200
            assert calls == 2 and capacity.snapshot()["active"] == 0

    asyncio.run(run())


def test_cancelled_waiter_never_starts_identity_io_or_releases_anothers_slot(api, monkeypatch):
    config = main.settings
    capacity = single_slot(monkeypatch, config)
    config.authentication_queue_timeout_seconds = 1
    calls = []
    original = security._api_key_principal

    def observed(*args):
        calls.append(True)
        return original(*args)

    monkeypatch.setattr(security, "_api_key_principal", observed)
    assert capacity.acquire_nowait()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/scenarios", headers=api.headers))
            await asyncio.sleep(0.02)
            task.cancel()
            result = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(result[0], asyncio.CancelledError)

    try:
        asyncio.run(run())
        assert not calls and capacity.snapshot()["active"] == 1
    finally:
        capacity.release()
    assert capacity.snapshot()["available"] == 1


def test_app_state_replacement_does_not_change_the_lease_that_is_released(api, monkeypatch):
    old = single_slot(monkeypatch, main.settings)
    new = AuthenticationAdmission(1)
    entered, release = threading.Event(), threading.Event()
    original = security._api_key_principal

    def slow(*args):
        entered.set()
        assert release.wait(3)
        return original(*args)

    monkeypatch.setattr(security, "_api_key_principal", slow)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/scenarios", headers=api.headers))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                monkeypatch.setattr(main.app.state, "_authentication_admission", new)
                assert old.snapshot()["active"] == 1 and new.snapshot()["active"] == 0
            finally:
                release.set()
            assert (await task).status_code == 200

    asyncio.run(run())
    assert old.snapshot()["available"] == new.snapshot()["available"] == 1


@pytest.mark.parametrize("change", ["key", "mode"])
def test_waiter_uses_current_configuration_after_admission(api, monkeypatch, change):
    original_config = main.settings
    capacity = single_slot(monkeypatch, original_config)
    original_config.authentication_queue_timeout_seconds = 1
    current = {"config": original_config}
    settings_seen = threading.Event()

    def config():
        settings_seen.set()
        return current["config"]

    monkeypatch.setattr(security, "get_settings", config)
    lookups = []
    original = security._api_key_principal

    def observed(key, value):
        lookups.append(value.api_key_sha256.get_secret_value())
        return original(key, value)

    monkeypatch.setattr(security, "_api_key_principal", observed)
    assert capacity.acquire_nowait()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/scenarios", headers=api.headers))
            await asyncio.to_thread(settings_seen.wait, 2)
            current["config"] = (
                Settings(_env_file=None, auth_mode="disabled")
                if change == "mode"
                else Settings(_env_file=None, auth_mode="api_key", api_key_sha256="b" * 64)
            )
            capacity.release()
            response = await task
            assert response.status_code == 401

    asyncio.run(run())
    assert lookups == ([] if change == "mode" else ["b" * 64])
    assert capacity.snapshot()["available"] == 1


def test_decoder_gets_frozen_scope_and_changed_live_scope_is_denied(api, monkeypatch):
    config = oidc_config()
    capacity = single_slot(monkeypatch, config)
    monkeypatch.setattr(security, "get_settings", lambda: config)
    entered, release = threading.Event(), threading.Event()
    observed = []

    def decode(_token, snapshot):
        observed.append(snapshot.oidc_audience)
        entered.set()
        assert release.wait(3)
        observed.append(snapshot.oidc_audience)
        return claims()

    monkeypatch.setattr(security, "_decode_oidc_token", decode)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(
                client.get("/scenarios", headers={"Authorization": "Bearer local-placeholder"})
            )
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                config.oidc_audience = "changed"
            finally:
                release.set()
            assert (await task).status_code == 401

    asyncio.run(run())
    assert observed == ["local", "local"] and capacity.snapshot()["available"] == 1


def test_initial_identity_is_rechecked_before_exposing_it_to_fast_endpoints(api, monkeypatch):
    capacity = single_slot(monkeypatch, main.settings)
    original = security._api_key_principal

    def revoked(*args):
        result = original(*args)
        api.withdraw()
        return result

    monkeypatch.setattr(security, "_api_key_principal", revoked)
    response = api.client.get("/scenarios", headers=api.headers)
    assert response.status_code == 401 and capacity.snapshot()["available"] == 1


def test_expired_identity_is_not_exposed_even_if_decoder_finished_with_old_claims(api, monkeypatch):
    config = oidc_config()
    capacity = single_slot(monkeypatch, config)
    monkeypatch.setattr(security, "get_settings", lambda: config)
    monkeypatch.setattr(
        security,
        "_decode_oidc_token",
        lambda *_: {**claims(), "exp": (datetime.now(UTC) - timedelta(seconds=1)).timestamp()},
    )
    response = api.client.get("/scenarios", headers={"Authorization": "Bearer local-placeholder"})
    assert response.status_code == 401 and capacity.snapshot()["available"] == 1


@pytest.mark.parametrize(
    "kind", ["api_missing", "api_long", "oidc_missing", "oidc_long", "oidc_scheme"]
)
def test_cheap_invalid_input_is_rejected_without_waiting_for_full_io_capacity(
    api, monkeypatch, kind
):
    config = oidc_config() if kind.startswith("oidc") else main.settings
    capacity = single_slot(monkeypatch, config)
    monkeypatch.setattr(security, "get_settings", lambda: config)
    calls = []

    def unexpected(*_):
        calls.append(True)
        raise AssertionError("invalid input must never begin identity I/O")

    monkeypatch.setattr(security, "_api_key_principal", unexpected)
    monkeypatch.setattr(security, "_decode_oidc_token", unexpected)
    headers = {
        "api_missing": {},
        "api_long": {"X-API-Key": "x" * 4097},
        "oidc_missing": {},
        "oidc_long": {"Authorization": "Bearer " + "x" * 16385},
        "oidc_scheme": {"Authorization": "Basic local-placeholder"},
    }[kind]
    assert capacity.acquire_nowait()
    try:
        response = api.client.get("/scenarios", headers=headers)
        assert response.status_code == 401 and not calls and capacity.snapshot()["active"] == 1
    finally:
        capacity.release()


def test_same_app_capacity_works_across_separate_event_loops(api, monkeypatch):
    capacity = single_slot(monkeypatch, main.settings)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            assert (await client.get("/scenarios", headers=api.headers)).status_code == 200

    asyncio.run(run())
    asyncio.run(run())
    assert capacity.snapshot() == {"limit": 1, "active": 0, "available": 1}


def test_final_identity_recheck_is_inside_the_same_initial_authentication_lease(api, monkeypatch):
    capacity = single_slot(monkeypatch, main.settings)
    entered, release = threading.Event(), threading.Event()
    original = security._api_key_digest_principal
    calls = 0

    def observed(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            entered.set()
            assert release.wait(3)
        return original(*args)

    monkeypatch.setattr(security, "_api_key_digest_principal", observed)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            task = asyncio.create_task(client.get("/scenarios", headers=api.headers))
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                busy = await client.get("/scenarios", headers=api.headers)
                assert busy.status_code == 503 and calls == 2 and capacity.snapshot()["active"] == 1
            finally:
                release.set()
            assert (await task).status_code == 200

    asyncio.run(run())
    assert capacity.snapshot()["available"] == 1


def test_real_loopback_jwks_io_stays_admitted_after_request_cancellation(api, monkeypatch):
    security._jwks_client.cache_clear()
    entered, release = threading.Event(), threading.Event()
    with LocalOIDCAuthority() as authority:
        config = Settings(
            _env_file=None,
            auth_mode="oidc",
            oidc_issuer=authority.issuer,
            oidc_audience=authority.audience,
            oidc_jwks_url=authority.jwks_url,
        )
        capacity = single_slot(monkeypatch, config)
        monkeypatch.setattr(security, "get_settings", lambda: config)
        handler = authority._server.RequestHandlerClass
        original = handler.do_GET

        def slow(self):
            entered.set()
            assert release.wait(3)
            return original(self)

        monkeypatch.setattr(handler, "do_GET", slow)
        headers = {
            "Authorization": "Bearer " + authority.issue(tenant_id="local", roles=["viewer"])
        }

        async def run():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
            ) as client:
                task = asyncio.create_task(client.get("/scenarios", headers=headers))
                try:
                    assert await asyncio.to_thread(entered.wait, 2)
                    task.cancel()
                    await asyncio.sleep(0.01)
                    assert not task.done() and capacity.snapshot()["active"] == 1
                    assert (await client.get("/scenarios", headers=headers)).status_code == 503
                    assert (await client.get("/health/live")).status_code == 200
                finally:
                    release.set()
                    result = await asyncio.gather(task, return_exceptions=True)
                assert isinstance(result[0], asyncio.CancelledError)
                assert capacity.snapshot()["available"] == 1
                assert (await client.get("/scenarios", headers=headers)).status_code == 200

        asyncio.run(run())
        assert authority.fetches == 1


@pytest.mark.parametrize(
    "options",
    [
        {"authentication_max_concurrency": 0},
        {"authentication_max_concurrency": 17},
        {"authentication_queue_timeout_seconds": 0},
        {"authentication_queue_timeout_seconds": 2.1},
        {"authentication_queue_timeout_seconds": float("nan")},
        {"authentication_queue_timeout_seconds": float("inf")},
        {"authentication_max_token_chars": 0},
        {"authentication_max_token_chars": 131073},
    ],
)
def test_authentication_resource_settings_are_bounded(options):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **options)


def test_invalid_runtime_admission_configuration_fails_closed_before_io(api, monkeypatch):
    main.settings.authentication_queue_timeout_seconds = float("nan")
    calls = []
    monkeypatch.setattr(security, "_api_key_principal", lambda *_: calls.append(True))
    response = api.client.get("/scenarios", headers=api.headers)
    assert response.status_code == 503 and not calls
