"""Authenticated HTTP -> native evidence -> advisory guard -> real audit JSONL.

All provider calls below are explicit local stubs. No real API or AWS is used.
"""

import asyncio
import hashlib
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient
from test_service_analysis_evidence import assessment, journal_state
from test_service_analysis_evidence import executed as executed  # noqa: PLC0414

from app import main, security
from app.config import Settings
from app.services.audit import AuditStore
from app.services.native_analysis_registry import NativeAnalysisRegistry
from app.zero_trust_models import SessionRevocationRequest
from scripts.f1_lab.service_analysis_evidence import publish_service_analysis


@pytest.fixture
def api(executed, tmp_path, monkeypatch):
    lab, args, launches = executed
    key = "native-http-local-key-never-a-real-api-key"
    state = SimpleNamespace(
        config=Settings(
            _env_file=None,
            app_environment="test",
            auth_mode="api_key",
            api_key_sha256=hashlib.sha256(key.encode()).hexdigest(),
            api_key_subject=lab.principal.subject,
            api_key_tenant_id=lab.principal.tenant_id,
            api_key_roles="responder",
            openai_prompt_mode="grounded",
            analyzer_mode="openai",
            analysis_queue_timeout_seconds=0.01,
        )
    )
    registry = NativeAnalysisRegistry(lab.operations)
    ref = publish_service_analysis(registry, **args)
    audit = AuditStore(tmp_path / "http-audit.jsonl")
    provider = Mock(name="free-native-provider")
    provider.name = "openai"
    provider.analyze_with_evidence = AsyncMock(return_value=assessment())
    monkeypatch.setattr(main, "get_settings", lambda: state.config)
    monkeypatch.setattr(security, "get_settings", lambda: state.config)
    monkeypatch.setattr(main, "settings", state.config)
    monkeypatch.setattr(main, "zero_trust_operations", lab.operations)
    monkeypatch.setattr(main, "native_analysis_registry", registry)
    monkeypatch.setattr(main, "get_analyzer", lambda: provider)
    monkeypatch.setattr(main, "audit_store", audit)
    monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(2))
    assert security.get_principal not in main.app.dependency_overrides
    with TestClient(main.app) as client:
        state.client, state.lab, state.args, state.launches = client, lab, args, launches
        state.registry, state.ref, state.audit, state.provider = registry, ref, audit, provider
        state.headers = {"X-API-Key": key, "X-Request-ID": "native-http-local-review"}
        state.post = lambda **kw: client.post(
            "/analysis/native-service", json={"execution_ref": ref}, headers=state.headers, **kw
        )
        yield state


def test_http_response_and_reloaded_audit_bind_exact_evidence_and_request(api):
    before = journal_state(api.lab)
    response = api.post()
    assert response.status_code == 200, response.text
    payload = response.json()
    native = payload["verification_context"]["native_execution"]
    assert native["analysis_ref_sha256"] == hashlib.sha256(api.ref.encode()).hexdigest()
    assert native["event_sha256"] == api.args["event"].sha256
    assert native["invocation_id"] == api.args["event"].invocation_id
    assert payload["tenant_id"] == api.lab.principal.tenant_id
    assert payload["actor_id"] == api.lab.principal.subject
    assert payload["request_id"] == "native-http-local-review"
    assert payload["assessment"]["requires_human_review"]
    assert payload["assessment"]["violation_type"] == "NORMAL"
    assert payload["assessment"]["recommended_action"] == "HOLD_FOR_REVIEW"
    assert payload["verified_review_controls"]["action_before_guard"] == "ALLOW"
    assert payload["review_status"] == "PENDING"
    reloaded = AuditStore(api.audit._path)
    saved = reloaded.get(payload["event_id"], payload["tenant_id"])
    assert saved.model_dump(mode="json") == payload
    assert reloaded.integrity()["ok"] and reloaded.integrity()["verified_lines"] == 1
    stored = api.audit._path.read_text(encoding="utf-8")
    for secret in (
        api.ref,
        api.args["request"].nonce,
        api.args["receipt"].signature,
        api.args["signal"].signature,
        api.headers["X-API-Key"],
    ):
        assert secret not in response.text and secret not in stored
    assert api.client.get(f"/results/{payload['event_id']}", headers=api.headers).json() == payload
    assert api.provider.analyze_with_evidence.await_count == 1
    assert journal_state(api.lab) == before and len(api.launches) == 1


def test_saturated_native_request_does_not_start_source_collection(api, monkeypatch):
    resolve = Mock(wraps=api.registry.resolve)
    monkeypatch.setattr(api.registry, "resolve", resolve)
    monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(0))
    assert api.post().status_code == 429
    resolve.assert_not_called()
    api.provider.analyze_with_evidence.assert_not_awaited()
    assert api.audit.metrics().total_analyses == 0


def test_serving_store_swap_during_source_check_stops_before_provider(api, monkeypatch):
    original = api.registry.resolve

    def resolve(*args, **kwargs):
        signal, context = original(*args, **kwargs)

        def changed_during_check():
            context.verify_current()
            monkeypatch.setattr(main, "native_analysis_registry", object())

        return signal, replace(context, verify_current=changed_during_check)

    monkeypatch.setattr(api.registry, "resolve", resolve)
    assert api.post().status_code == 502
    api.provider.analyze_with_evidence.assert_not_awaited()
    assert api.audit.metrics().total_analyses == 0


def test_cancelled_native_collection_keeps_capacity_and_event_loop_responsive(api, monkeypatch):
    import httpx

    capacity = asyncio.Semaphore(1)
    monkeypatch.setattr(main, "analysis_capacity", capacity)
    entered, release = threading.Event(), threading.Event()
    original = api.registry.resolve
    calls = 0

    def blocked(*args, **kwargs):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(3)
        return original(*args, **kwargs)

    monkeypatch.setattr(api.registry, "resolve", blocked)

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:

            async def post():
                return await client.post(
                    "/analysis/native-service", json={"execution_ref": api.ref}, headers=api.headers
                )

            task = asyncio.create_task(post())
            try:
                assert await asyncio.to_thread(entered.wait, 2)
                assert not task.done()
                assert (await client.get("/health/live")).status_code == 200
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and capacity._value == 0
                assert (await post()).status_code == 429
                assert calls == 1
            finally:
                release.set()
                results = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(results[0], asyncio.CancelledError)
            assert capacity._value == 1
            api.provider.analyze_with_evidence.assert_not_awaited()
            assert api.audit.metrics().total_analyses == 0
            assert (await post()).status_code == 200
            assert calls == 2 and api.provider.analyze_with_evidence.await_count == 1

    asyncio.run(run())


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"execution_ref": "a"},
        {"execution_ref": "G" * 64},
        {"execution_ref": "a" * 64, "registry_path": "/tmp/attacker.json"},
        {"execution_ref": "a" * 64, "verification_context": {"trusted": True}},
        {"execution_ref": "a" * 64, "command": ["/usr/bin/true"]},
        {"execution_ref": "a" * 64, "signal": {}},
    ],
)
def test_http_never_accepts_client_facts_paths_or_commands(api, body):
    response = api.client.post("/analysis/native-service", json=body, headers=api.headers)
    assert response.status_code == 422
    api.provider.analyze_with_evidence.assert_not_called()
    assert not api.audit._path.exists()


@pytest.mark.parametrize(
    "kind, status",
    [
        ("missing_key", 401),
        ("wrong_key", 401),
        ("viewer", 403),
        ("other_subject", 404),
        ("other_tenant", 404),
        ("disabled_auth", 401),
        ("unknown_ref", 404),
        ("withdrawn_ref", 404),
        ("expired_ref", 404),
    ],
)
def test_reference_is_not_a_capability_and_discloses_no_other_owner(api, kind, status, monkeypatch):
    headers, ref = dict(api.headers), api.ref
    updates = {
        "viewer": {"api_key_roles": "viewer"},
        "other_subject": {"api_key_subject": "another-operator"},
        "other_tenant": {"api_key_tenant_id": "another-tenant"},
        "disabled_auth": {"auth_mode": "disabled"},
    }
    api.config = api.config.model_copy(update=updates.get(kind, {}))
    if kind == "missing_key":
        headers.pop("X-API-Key")
    if kind == "wrong_key":
        headers["X-API-Key"] = "not-the-key"
    if kind == "unknown_ref":
        ref = "e" * 64
    if kind == "withdrawn_ref":
        api.registry.revoke(ref)
    if kind == "expired_ref":
        from app.services import native_analysis_registry as module

        future = datetime.now(UTC) + timedelta(seconds=31)

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return future

        monkeypatch.setattr(module, "datetime", Clock)
    response = api.client.post(
        "/analysis/native-service", json={"execution_ref": ref}, headers=headers
    )
    assert response.status_code == status, response.text
    api.provider.analyze_with_evidence.assert_not_called()
    assert not api.audit._path.exists()
    if status == 404:
        assert response.json() == {"detail": "Native execution reference unavailable"}


@pytest.mark.parametrize(
    "kind",
    [
        "legacy_prompt",
        "rule_provider",
        "missing_provider",
        "missing_publisher",
        "wrong_store",
        "production",
    ],
)
def test_unconfigured_or_production_route_does_not_call_a_provider(api, kind, monkeypatch):
    if kind == "legacy_prompt":
        api.config = api.config.model_copy(update={"openai_prompt_mode": "legacy"})
    if kind == "rule_provider":
        monkeypatch.setattr(main, "get_analyzer", lambda: SimpleNamespace(name="rule"))
    if kind == "missing_provider":
        monkeypatch.setattr(main, "get_analyzer", Mock(side_effect=ValueError("missing key")))
    if kind == "missing_publisher":
        monkeypatch.setattr(main, "native_analysis_registry", None)
    if kind == "wrong_store":
        monkeypatch.setattr(main, "zero_trust_operations", object())
    if kind == "production":
        api.config = api.config.model_copy(update={"app_environment": "production"})
    response = api.post()
    assert response.status_code == (404 if kind == "production" else 503), response.text
    api.provider.analyze_with_evidence.assert_not_called()
    assert not api.audit._path.exists()


@pytest.mark.parametrize("stage", ["before", "during", "after_audit"])
@pytest.mark.parametrize("kind", ["reference", "source", "session", "caller", "service_pin"])
def test_authority_withdrawal_never_delivers_stale_success(api, kind, stage, monkeypatch):
    def withdraw():
        if kind == "reference":
            api.registry.revoke(api.ref)
        if kind == "source":
            api.lab.sources["sources"][0]["enabled"] = False
            api.lab.save_sources()
        if kind == "session":
            api.lab.operations.revoke(
                api.args["signal"].session_id,
                SessionRevocationRequest(expected_version=1, note="HTTP native review revocation"),
                api.lab.principal,
            )
        if kind == "caller":
            api.config = api.config.model_copy(update={"api_key_roles": "viewer"})
        if kind == "service_pin":
            pin = api.lab.broker.joiner.registry
            pin.path.write_bytes(pin.path.read_bytes() + b" ")

    if stage == "before":
        withdraw()
    elif stage == "during":

        async def infer(*_):
            withdraw()
            return assessment()

        api.provider.analyze_with_evidence.side_effect = infer
    else:
        original_save = api.audit.save

        async def save_and_withdraw(record):
            await original_save(record)
            withdraw()

        monkeypatch.setattr(api.audit, "save", save_and_withdraw)
    response = api.post()
    assert response.status_code != 200, response.text
    assert api.provider.analyze_with_evidence.await_count == (stage != "before")
    if stage == "after_audit":
        # A committed historical analysis is evidence of computation, not delivery.
        reloaded = AuditStore(api.audit._path)
        assert reloaded.integrity()["ok"] and reloaded.integrity()["verified_lines"] == 1
        assert reloaded.get(api.args["signal"].event.event_id, api.lab.principal.tenant_id)
    else:
        assert not api.audit._path.exists()


@pytest.mark.parametrize("failure", ["corrupt", "write_error", "provider_error", "queue_full"])
def test_failures_return_no_success_and_release_capacity(api, failure, monkeypatch):
    if failure == "corrupt":
        api.audit._path.write_text('{"partial":', encoding="utf-8")
        monkeypatch.setattr(main, "audit_store", AuditStore(api.audit._path))
    if failure == "write_error":
        monkeypatch.setattr(
            api.audit, "_append_jsonl", Mock(side_effect=OSError("local disk failure"))
        )
    if failure == "provider_error":
        api.provider.analyze_with_evidence.side_effect = RuntimeError("controlled provider failure")
    if failure == "queue_full":
        monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(0))
    response = api.post()
    assert response.status_code == (429 if failure == "queue_full" else 502), response.text
    assert api.provider.analyze_with_evidence.await_count == (
        failure in {"write_error", "provider_error"}
    )
    assert not api.audit.recent(20, api.lab.principal.tenant_id)
    if failure != "queue_full":
        assert main.analysis_capacity._value == 2


def test_same_tenant_viewer_can_read_historical_audit_but_other_tenant_cannot(api):
    result = api.post().json()
    api.config = api.config.model_copy(update={"api_key_roles": "viewer"})
    assert api.client.get(f"/results/{result['event_id']}", headers=api.headers).status_code == 200
    api.config = api.config.model_copy(update={"api_key_tenant_id": "other"})
    assert api.client.get(f"/results/{result['event_id']}", headers=api.headers).status_code == 404


def test_two_reviews_write_two_analyses_without_reexecuting_or_refunding_access(api):
    before = journal_state(api.lab)
    first, second = api.post(), api.post()
    assert first.status_code == second.status_code == 200
    assert first.json()["analysis_id"] != second.json()["analysis_id"]
    assert api.audit.integrity()["verified_lines"] == 2
    assert journal_state(api.lab) == before and len(api.launches) == 1
    assert api.provider.analyze_with_evidence.await_count == 2


def test_queue_withdrawal_is_rechecked_before_model_call(api, monkeypatch):
    async def acquire():
        api.registry.revoke(api.ref)
        return True

    gate = SimpleNamespace(acquire=acquire, release=Mock())
    monkeypatch.setattr(main, "analysis_capacity", gate)
    # Admission now precedes lookup: withdrawal while queued is a missing ref,
    # rather than a previously resolved context invalidated during inference.
    assert api.post().status_code == 404
    api.provider.analyze_with_evidence.assert_not_called()
    gate.release.assert_called_once()
    assert not api.audit._path.exists()


@pytest.mark.parametrize("kind", ["registry", "operations"])
def test_serving_store_replacement_during_model_cannot_publish_old_context(api, kind, monkeypatch):
    async def infer(*_):
        monkeypatch.setattr(
            main,
            "native_analysis_registry" if kind == "registry" else "zero_trust_operations",
            object(),
        )
        return assessment()

    api.provider.analyze_with_evidence.side_effect = infer
    assert api.post().status_code == 502
    assert not api.audit._path.exists()


def test_loopback_tcp_controls_use_actual_http_auth_and_audit(api, tmp_path):
    from scripts.f1_lab.service_http_controls import run

    passed = []
    args = api.args
    result = run(
        api.lab,
        args["request"],
        SimpleNamespace(session_id=args["signal"].session_id),
        args["receipt"],
        args["event"],
        args["proofs"],
        tmp_path,
        passed.append,
    )
    assert result["transport"] == "tcp_loopback" and result["audit_verified_lines"] == 1
    assert result["provider_stub_invocations"] == 1 and len(passed) == 9


def test_loopback_native_sqlite_backup_restore_and_candidate_review(api, tmp_path):
    from scripts.f1_lab.service_http_controls import run

    passed = []
    args = api.args
    result = run(
        api.lab,
        args["request"],
        SimpleNamespace(session_id=args["signal"].session_id),
        args["receipt"],
        args["event"],
        args["proofs"],
        tmp_path,
        passed.append,
        audit_recovery=True,
    )
    assert result["audit_writer_scope"] == "shared_sqlite_transaction"
    assert result["provider_stub_invocations"] == 1 and len(passed) == 17
    recovery = result["audit_recovery"]
    assert recovery["snapshot_head"]["seq"] == 1 and recovery["candidate_review_head"]["seq"] == 2
    assert recovery["original_database_unchanged"] is True
    assert recovery["automatic_activation_allowed"] is False
    assert recovery["checkpoint"]["head"] == recovery["candidate_review_head"]
    assert recovery["checkpoint"]["source_unchanged_by_capture"]
    assert recovery["checkpoint"]["external_pin_tamper_rejected"]
    assert recovery["checkpoint"]["independent_storage_verified"] is False
    assert recovery["checkpoint"]["latest_live_state_verified"] is False
