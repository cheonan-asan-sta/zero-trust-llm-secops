"""Shared evidence persistence is never a cached authorization decision."""

import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from test_native_analysis_http import api as api  # noqa: PLC0414
from test_service_analysis_evidence import executed as executed  # noqa: PLC0414
from test_service_analysis_evidence import journal_state

from app.config import Settings
from app.security import Principal, Role
from app.services.audit import create_audit_store
from app.services.native_analysis_registry import (
    NativeAnalysisMissing,
    create_native_analysis_registry,
)
from app.services.shared_native_analysis import SharedNativeAnalysisRegistry
from app.services.trusted_signals import SignalRegistryUnavailable, SignalRejected
from scripts.f1_lab.service_analysis_evidence import publish_service_analysis
from scripts.f1_lab.shared_execution_evidence import ServiceEvidenceJoiner
from scripts.f1_lab.shared_native_controls import configure, new_operations, probe
from scripts.f1_lab.shared_service_analysis import NativeServiceBundle, open_shared_service_registry


@pytest.fixture
def shared(executed, tmp_path):
    lab, args, _ = executed
    path, pin, config = configure(lab, tmp_path / "shared")
    registry = open_shared_service_registry(lab.operations, path, pin)
    ref = publish_service_analysis(registry, **args)
    return SimpleNamespace(
        lab=lab, args=args, path=path, pin=pin, config=config, registry=registry, ref=ref
    )


def reader(env):
    return open_shared_service_registry(new_operations(env.lab), env.path, env.pin)


def test_fresh_worker_reconstructs_same_execution_without_extending_expiry(shared):
    before = journal_state(shared.lab)
    signal, first = shared.registry.resolve(shared.ref, shared.lab.principal)
    other = reader(shared)
    assert other.operations is not shared.lab.operations
    signal2, second = other.resolve(shared.ref, shared.lab.principal)
    assert signal2 == signal and first.expires_at == second.expires_at
    assert (
        second.for_event(signal2.event)["native_execution"]["event_sha256"]
        == shared.args["event"].sha256
    )
    assert second.for_event(signal2.event)["session"]["approval_currently_usable"] is False
    before_db = shared.registry.store.path.read_bytes()
    for _ in range(2):
        first.verify_current()
        second.verify_current()
    assert shared.registry.store.path.read_bytes() == before_db
    assert journal_state(shared.lab) == before


def test_signed_bundle_and_nonce_are_encrypted_and_raw_reference_is_not_persisted(shared):
    raw = shared.registry.store.path.read_bytes()
    for secret in (
        shared.ref.encode(),
        shared.args["request"].nonce.encode(),
        shared.args["receipt"].signature.encode(),
        shared.args["signal"].signature.encode(),
        shared.lab.principal.subject.encode(),
        shared.lab.principal.tenant_id.encode(),
        Path(shared.config.encryption_key_path).read_bytes(),
    ):
        assert secret not in raw
    assert hashlib.sha256(shared.ref.encode()).hexdigest().encode() in raw


def test_durable_withdrawal_invalidates_an_already_collected_context_on_other_worker(shared):
    other = reader(shared)
    _, context = other.resolve(shared.ref, shared.lab.principal)
    shared.registry.revoke(shared.ref)
    with pytest.raises(SignalRejected):
        context.verify_current()
    with pytest.raises(NativeAnalysisMissing):
        reader(shared).resolve(shared.ref, shared.lab.principal)


@pytest.mark.parametrize("kind", ["subject", "tenant", "viewer", "unverified"])
def test_shared_reference_does_not_cross_owner_or_authentication_boundaries(shared, kind):
    p = shared.lab.principal
    actor = Principal(
        "another" if kind == "subject" else p.subject,
        "another" if kind == "tenant" else p.tenant_id,
        frozenset({Role.VIEWER}) if kind == "viewer" else p.roles,
        "unverified" if kind == "unverified" else p.auth_method,
    )
    with pytest.raises((NativeAnalysisMissing, SignalRejected)):
        reader(shared).resolve(shared.ref, actor)


@pytest.mark.parametrize(
    "kind",
    [
        "ciphertext",
        "expiry",
        "created",
        "store_id",
        "clock",
        "key",
        "deleted_key",
        "deleted_db",
        "capacity",
        "non_blob",
    ],
)
def test_tampering_or_missing_storage_fails_closed_without_recreating_read_db(shared, kind):
    if kind in {"key", "deleted_key"}:
        from pathlib import Path

        key = Path(shared.config.encryption_key_path)
        if kind == "key":
            key.write_bytes(b"x" * 32)
        else:
            key.unlink()
    elif kind == "deleted_db":
        shared.registry.store.path.unlink()
    else:
        with sqlite3.connect(shared.registry.store.path) as con:
            if kind == "ciphertext":
                con.execute("UPDATE native_references SET ciphertext=?", (b"x" * 60,))
            if kind == "non_blob":
                con.execute("UPDATE native_references SET ciphertext='not a blob'")
            if kind == "expiry":
                con.execute(
                    "UPDATE native_references SET expires=?",
                    ((datetime.now(UTC) + timedelta(seconds=30)).isoformat(),),
                )
            if kind == "created":
                con.execute(
                    "UPDATE native_references SET created=?",
                    ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),),
                )
            if kind == "store_id":
                con.execute("UPDATE native_reference_meta SET store_id=?", ("e" * 64,))
            if kind == "capacity":
                con.execute("UPDATE native_reference_meta SET capacity=999")
            if kind == "clock":
                con.execute(
                    "UPDATE native_reference_clock SET observed=?",
                    ((datetime.now(UTC) + timedelta(seconds=5)).isoformat(),),
                )
    with pytest.raises(SignalRegistryUnavailable):
        shared.registry.resolve(shared.ref, shared.lab.principal)
    if kind == "deleted_db":
        assert not shared.registry.store.path.exists()


def test_expired_shared_reference_does_not_renew_on_reopen(shared, monkeypatch):
    from app.services import shared_native_analysis as module

    future = datetime.now(UTC) + timedelta(seconds=31)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return future

    monkeypatch.setattr(module, "datetime", Clock)
    with pytest.raises(NativeAnalysisMissing):
        reader(shared).resolve(shared.ref, shared.lab.principal)


def test_shared_capacity_is_atomic_across_independent_connections(executed, tmp_path):
    lab, args, _ = executed
    path, pin, _ = configure(lab, tmp_path / "limited", capacity=2)

    def publish(_):
        registry = open_shared_service_registry(lab.operations, path, pin)
        try:
            return publish_service_analysis(registry, **args)
        except SignalRejected:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(publish, range(4)))
    assert len([ref for ref in results if ref is not None]) == 2


def test_encrypted_but_forged_signed_input_is_still_rejected(shared):
    data = {k: shared.args[k] for k in ("signal", "request", "event", "proofs", "receipt")}
    bundle = NativeServiceBundle(**data)
    bundle.receipt.signature = "e" * 86
    ref = shared.registry.store.publish(
        bundle.model_dump_json().encode(),
        shared.lab.principal,
        datetime.now(UTC) + timedelta(seconds=10),
    )
    with pytest.raises(SignalRejected):
        reader(shared).resolve(ref, shared.lab.principal)


def test_shared_ledger_never_deserializes_callbacks_or_arbitrary_types(shared):
    ref = shared.registry.store.publish(
        b'{"__reduce__":"do-not-execute"}',
        shared.lab.principal,
        datetime.now(UTC) + timedelta(seconds=10),
    )
    with pytest.raises(SignalRegistryUnavailable):
        reader(shared).resolve(ref, shared.lab.principal)


def test_readonly_http_joiner_cannot_admit_or_update_service_evidence(shared):
    joiner = ServiceEvidenceJoiner(
        shared.lab.broker.joiner.registry, shared.lab.broker.joiner.path, read_only=True
    )
    before = joiner.path.read_bytes()
    assert joiner.inspect(shared.args["event"], shared.args["proofs"]).state == "consistent"
    assert joiner.check(shared.args["event"], shared.args["proofs"]).state == "unavailable"
    with pytest.raises(ValueError), joiner.connect():
        pytest.fail("readonly writer must not open")
    assert joiner.path.read_bytes() == before


def test_independent_process_reopen_and_revocation_without_any_original_callback(shared):
    first = probe(shared.lab, shared.path, shared.pin, shared.ref)
    assert first["available"] and first["event_sha256"] == shared.args["event"].sha256
    assert probe(shared.lab, shared.path, shared.pin, shared.ref) == first
    shared.registry.revoke(shared.ref)
    assert probe(shared.lab, shared.path, shared.pin, shared.ref) == {"available": False}


def test_startup_factory_loads_only_pinned_shared_configuration(shared):
    config = Settings(
        _env_file=None,
        native_analysis_shared_config_path=shared.path,
        native_analysis_shared_config_sha256=shared.pin,
    )
    registry = create_native_analysis_registry(new_operations(shared.lab), config)
    assert isinstance(registry, SharedNativeAnalysisRegistry)
    registry.resolve(shared.ref, shared.lab.principal)
    shared.path.write_bytes(shared.path.read_bytes() + b" ")
    with pytest.raises(SignalRegistryUnavailable):
        create_native_analysis_registry(shared.lab.operations, config)


@pytest.mark.parametrize(
    "options",
    [
        {"native_analysis_shared_config_path": "local.json"},
        {"native_analysis_shared_config_sha256": "e" * 64},
        {
            "native_analysis_shared_config_path": "local.json",
            "native_analysis_shared_config_sha256": "wrong",
        },
    ],
)
def test_partial_or_unpinned_startup_settings_are_rejected(options):
    with pytest.raises(ValueError):
        Settings(_env_file=None, **options)


def test_shared_mode_uses_distinct_audit_hash_chain_files_per_process(tmp_path, monkeypatch):
    settings = Settings(
        _env_file=None,
        app_environment="test",
        audit_backend="jsonl",
        audit_log_path=tmp_path / "audit.jsonl",
        native_analysis_shared_config_path=tmp_path / "shared.json",
        native_analysis_shared_config_sha256="e" * 64,
    )
    monkeypatch.setattr(os, "getpid", Mock(return_value=123))
    first = create_audit_store(settings)
    monkeypatch.setattr(os, "getpid", Mock(return_value=124))
    second = create_audit_store(settings)
    assert first._path.name == "audit.worker-123.jsonl"
    assert second._path.name == "audit.worker-124.jsonl"


def test_ciphertext_cannot_be_moved_to_another_reference(shared):
    second = publish_service_analysis(shared.registry, **shared.args)
    with sqlite3.connect(shared.registry.store.path) as con:
        original = con.execute(
            "SELECT ciphertext FROM native_references WHERE ref=?",
            (hashlib.sha256(shared.ref.encode()).hexdigest(),),
        ).fetchone()[0]
        con.execute(
            "UPDATE native_references SET ciphertext=? WHERE ref=?",
            (
                original,
                hashlib.sha256(second.encode()).hexdigest(),
            ),
        )
    with pytest.raises(SignalRegistryUnavailable):
        shared.registry.resolve(second, shared.lab.principal)


@pytest.mark.skipif(os.name != "posix", reason="POSIX key permission contract")
def test_world_readable_encryption_key_is_rejected(shared):
    Path(shared.config.encryption_key_path).chmod(0o644)
    with pytest.raises(SignalRegistryUnavailable):
        shared.registry.resolve(shared.ref, shared.lab.principal)


@pytest.fixture
def shared_http(api, tmp_path, monkeypatch):
    # Reuse the actual API-key authenticated HTTP fixture, with separate PDP objects.
    from app import main

    path, pin, config = configure(api.lab, tmp_path / "http-shared")
    publisher = open_shared_service_registry(api.lab.operations, path, pin)
    api.ref = publish_service_analysis(publisher, **api.args)
    operations = new_operations(api.lab)
    api.registry = open_shared_service_registry(operations, path, pin)
    api.config = api.config.model_copy(
        update={
            "native_analysis_shared_config_path": path,
            "native_analysis_shared_config_sha256": pin,
            "audit_log_path": tmp_path / "worker-audit.jsonl",
        }
    )
    api.audit = create_audit_store(api.config)
    monkeypatch.setattr(main, "zero_trust_operations", operations)
    monkeypatch.setattr(main, "native_analysis_registry", api.registry)
    monkeypatch.setattr(main, "audit_store", api.audit)
    monkeypatch.setattr(main, "settings", api.config)
    api.shared_config, api.publisher = config, publisher
    api.post = lambda: api.client.post(
        "/analysis/native-service",
        json={"execution_ref": api.ref},
        headers=api.headers,
    )
    return api


def test_http_serves_shared_evidence_and_persists_its_guarded_snapshot(shared_http):
    from app.services.audit import AuditStore

    env = shared_http
    before = journal_state(env.lab)
    response = env.post()
    assert response.status_code == 200, response.text
    payload = response.json()
    assert (
        payload["verification_context"]["native_execution"]["event_sha256"]
        == env.args["event"].sha256
    )
    assert payload["assessment"]["recommended_action"] == "HOLD_FOR_REVIEW"
    reloaded = AuditStore(env.audit._path)
    assert (
        reloaded.get(payload["event_id"], env.lab.principal.tenant_id).model_dump(mode="json")
        == payload
    )
    assert f"worker-{os.getpid()}" in str(env.audit._path)
    assert journal_state(env.lab) == before


@pytest.mark.parametrize("stage", ["before", "during", "after_audit"])
@pytest.mark.parametrize("kind", ["reference", "key", "ciphertext"])
def test_other_worker_changes_block_http_provider_or_delivery(
    shared_http, stage, kind, monkeypatch
):
    from app.services.audit import AuditStore

    env = shared_http

    def change():
        if kind == "reference":
            env.publisher.revoke(env.ref)
        if kind == "key":
            Path(env.shared_config.encryption_key_path).unlink()
        if kind == "ciphertext":
            with sqlite3.connect(env.shared_config.reference_db_path) as con:
                con.execute("UPDATE native_references SET ciphertext=?", (b"e" * 60,))

    if stage == "before":
        change()
    elif stage == "during":
        from test_service_analysis_evidence import assessment

        async def infer(*_):
            change()
            return assessment()

        env.provider.analyze_with_evidence.side_effect = infer
    else:
        original = env.audit.save

        async def save_then_change(record):
            await original(record)
            change()

        monkeypatch.setattr(env.audit, "save", save_then_change)
    response = env.post()
    assert response.status_code != 200, response.text
    assert env.provider.analyze_with_evidence.await_count == (stage != "before")
    if stage == "after_audit":
        assert AuditStore(env.audit._path).integrity()["verified_lines"] == 1
    else:
        assert not env.audit._path.exists()


@pytest.mark.parametrize("target", ["service_ledger_path", "encryption_key_path", "operations_db"])
def test_shared_configuration_cannot_write_reference_tables_into_evidence_or_app_db(shared, target):
    config = shared.config.model_dump(mode="json")
    config["reference_db_path"] = (
        str(shared.lab.operations.path.resolve()) if target == "operations_db" else config[target]
    )
    before = shared.lab.operations.path.read_bytes(), shared.lab.broker.joiner.path.read_bytes()
    shared.path.write_text(json.dumps(config), encoding="utf-8")
    pin = hashlib.sha256(shared.path.read_bytes()).hexdigest()
    with pytest.raises(SignalRegistryUnavailable):
        open_shared_service_registry(shared.lab.operations, shared.path, pin)
    assert before == (
        shared.lab.operations.path.read_bytes(),
        shared.lab.broker.joiner.path.read_bytes(),
    )
