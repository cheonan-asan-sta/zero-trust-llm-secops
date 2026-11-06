import asyncio
import base64
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app.services.audit import AuditStore
from app.services.cases import CaseStore
from app.services.integration_outbox import IntegrationOutboxService, IntegrationOutboxStore
from scripts import app_state_recovery as recovery
from scripts import app_storage_contract as storage
from scripts import serve_recovered_app as gate
from scripts.app_recovery_fixture import prepare, verify
from scripts.app_storage_fixture import seed_logs


@pytest.fixture
def full(tmp_path):
    data = tmp_path / "data"
    prepare(data)
    expected = seed_logs(data)
    store = recovery.Store(tmp_path)
    store.initialize(full_state=True)
    store.checkpoint()
    backup = store.backup()
    return SimpleNamespace(root=tmp_path, data=data, expected=expected, store=store, backup=backup)


def restore(full):
    result = full.store.restore(full.backup["backup_id"])
    return full.root / "restores" / result["restore_id"]


def test_full_restore_preserves_exact_logs_all_statuses_and_denies_old_tokens(full):
    stage = restore(full)
    assert verify(stage, full.data)["old_grants_denied"] == 3
    assert storage.inspect(stage) == full.expected
    for name in ("storage.json", *storage.FILES.values()):
        assert (stage / name).read_bytes() == (full.data / name).read_bytes()
    outbox = IntegrationOutboxStore(stage / storage.FILES["outbox"])
    assert {row.status.value for row in outbox.recent(100, "recovery-tenant")} == {
        "PENDING", "DELIVERED", "RETRY_SCHEDULED", "DEAD_LETTER"}
    assert len(outbox.recent(100, "unrelated-tenant")) == 4
    assert recovery.verify_admission(stage, full.root / "public")["admission_verified"]


def test_reconcile_after_restore_and_restart_reuses_ids_and_keeps_attempts(full):
    stage = restore(full)
    cases = CaseStore(stage / storage.FILES["cases"])
    before = (stage / storage.FILES["outbox"]).read_bytes()
    for _ in range(2):
        service = IntegrationOutboxService(IntegrationOutboxStore(stage / storage.FILES["outbox"]))
        for tenant in ("recovery-tenant", "unrelated-tenant"):
            assert asyncio.run(service.reconcile_cases(cases.recent(100, tenant))) == (0, 4)
    assert (stage / storage.FILES["outbox"]).read_bytes() == before
    assert storage.inspect(stage) == full.expected


@pytest.mark.parametrize("name", ["storage.json", *storage.FILES.values()])
@pytest.mark.parametrize("operation", ["missing", "truncate", "symlink"])
def test_missing_corrupted_or_symlinked_storage_refuses_checkpoint_and_backup(full, name, operation):
    path = full.data / name
    if operation == "truncate":
        path.write_bytes(path.read_bytes()[:12])
    else:
        path.unlink()
        if operation == "symlink":
            try:
                path.symlink_to(full.data / "fixture.json")
            except OSError:
                pytest.skip("symlink creation is unavailable")
    with pytest.raises((ValueError, recovery.RecoveryError)):
        full.store.checkpoint()
    with pytest.raises(recovery.RecoveryError, match="publication_incomplete"):
        full.store.backup()


@pytest.mark.parametrize("name", list(storage.FILES.values()))
def test_valid_log_replacement_after_checkpoint_refuses_backup(full, name):
    (full.data / name).write_bytes(b"")
    with pytest.raises((ValueError, recovery.RecoveryError)):
        full.store.backup()


@pytest.mark.parametrize("name", ["storage.json", *storage.FILES.values()])
def test_missing_restored_file_refuses_admission(full, name):
    stage = restore(full)
    (stage / name).unlink()
    with pytest.raises((ValueError, recovery.RecoveryError)):
        recovery.verify_admission(stage, full.root / "public")


def test_valid_hash_chain_rollback_refuses_admission(full):
    stage = restore(full)
    path = stage / storage.FILES["outbox"]
    path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
    with pytest.raises(storage.StorageError, match="admission_prefix"):
        recovery.verify_admission(stage, full.root / "public")


def test_legitimate_audit_append_survives_admission_and_reopen(full):
    stage = restore(full)
    store = AuditStore(stage / storage.FILES["audit"])
    record = store.recent(1, "recovery-tenant")[0]
    asyncio.run(store.save(record))
    assert recovery.verify_admission(stage, full.root / "public")["admission_verified"]
    assert AuditStore(stage / storage.FILES["audit"]).integrity()["verified_lines"] == 3


def test_gate_requires_exact_full_storage_paths_and_jsonl_backend(full, monkeypatch):
    stage = restore(full)
    settings = SimpleNamespace(analyzer_mode="rule", auth_mode="api_key", audit_backend="jsonl",
        zero_trust_db_path=stage / "app.sqlite3", trusted_signal_sources_path=stage / "sources.json",
        audit_log_path=stage / storage.FILES["audit"], case_log_path=stage / storage.FILES["cases"],
        outbox_log_path=stage / storage.FILES["outbox"])
    monkeypatch.setattr(gate, "get_settings", lambda: settings)
    assert gate.admit(stage, full.root / "public")["admission_verified"]
    for field in ("audit_log_path", "case_log_path", "outbox_log_path"):
        original = getattr(settings, field)
        setattr(settings, field, full.data / "other.jsonl")
        with pytest.raises(recovery.RecoveryError, match="storage_path"):
            gate.admit(stage, full.root / "public")
        setattr(settings, field, original)
    settings.audit_backend = "dynamodb"
    with pytest.raises(recovery.RecoveryError, match="jsonl_backend"):
        gate.admit(stage, full.root / "public")


@pytest.mark.parametrize("fail_at", ["audit.jsonl", "integration-outbox.jsonl", "release.json", "publish"])
def test_process_exit_mid_restore_invalidates_old_copy_and_retry_recovers(full, fail_at):
    old = restore(full)
    program = """import json,os,sys
from pathlib import Path
from scripts import app_state_recovery as r
original=r.atomic
def fail(path,raw):
    if path.name==sys.argv[3]: os._exit(73)
    original(path,raw)
    if sys.argv[3]=='publish' and path.name=='current.json' and json.loads(raw).get('restore_id'):
        os._exit(73)
r.atomic=fail
r.Store(Path(sys.argv[1])).restore(sys.argv[2])
"""
    result = subprocess.run([sys.executable, "-c", program, str(full.root),
        full.backup["backup_id"], fail_at], env=os.environ.copy(), capture_output=True, timeout=30, check=False)
    assert result.returncode == 73
    with pytest.raises(recovery.RecoveryError, match="admission_pin"):
        recovery.verify_admission(old, full.root / "public")
    new = restore(full)
    assert storage.inspect(new) == full.expected
    assert verify(new, full.data)["old_grants_denied"] == 3


def test_explicit_empty_logs_are_valid_but_absence_is_not(tmp_path):
    (tmp_path / "storage.json").write_bytes(recovery.canonical(storage.CONTRACT))
    for name in storage.FILES.values():
        (tmp_path / name).write_bytes(b"")
    assert storage.inspect(tmp_path)["missing_case_events"] == 0
    assert all(row["lines"] == 0 for row in storage.inspect(tmp_path)["files"].values())
    (tmp_path / "cases.jsonl").unlink()
    with pytest.raises(storage.StorageError):
        storage.inspect(tmp_path)


def test_storage_contract_rejects_extra_path_or_backend(tmp_path):
    contract = dict(storage.CONTRACT, backend="dynamodb")
    (tmp_path / "storage.json").write_text(json.dumps(contract))
    with pytest.raises(storage.StorageError, match="contract_invalid"):
        storage.inspect(tmp_path)


def rewrite(path, payloads):
    previous, output = "0" * 64, []
    for payload in payloads:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        current = storage.digest((previous + "." + text).encode())
        output.append(json.dumps({"schema_version": 1, "payload": text,
            "previous_hash": previous, "record_hash": current}).encode() + b"\n")
        previous = current
    path.write_bytes(b"".join(output))


def payloads(path):
    return [json.loads(json.loads(line)["payload"]) for line in path.read_bytes().splitlines()]


def test_missing_outbox_commit_gap_is_preserved_and_reconciles_once(full):
    rows = payloads(full.data / storage.FILES["outbox"])
    removed = rows[-1]["event"]["id"]
    rewrite(full.data / storage.FILES["outbox"], [r for r in rows if r["event"]["id"] != removed])
    assert storage.inspect(full.data)["missing_case_events"] == 1
    full.store.checkpoint()
    full.backup = full.store.backup()
    stage = restore(full)
    assert storage.inspect(stage)["missing_case_events"] == 1
    cases = CaseStore(stage / storage.FILES["cases"])
    for expected in ((1, 3), (0, 4)):
        service = IntegrationOutboxService(IntegrationOutboxStore(stage / storage.FILES["outbox"]))
        assert asyncio.run(service.reconcile_cases(cases.recent(100, "unrelated-tenant"))) == expected
        assert service.store.get(removed, "unrelated-tenant") is not None
    assert storage.inspect(stage)["missing_case_events"] == 0
    assert recovery.verify_admission(stage, full.root / "public")["admission_verified"]


def test_full_mode_cannot_downgrade_when_all_logs_disappear(full):
    stage = restore(full)
    for name in ("storage.json", *storage.FILES.values()):
        (full.data / name).unlink()
    with pytest.raises(recovery.RecoveryError, match="checkpoint_storage_mode"):
        full.store.checkpoint()
    with pytest.raises(recovery.RecoveryError, match="publication_incomplete"):
        full.store.restore(full.backup["backup_id"])
    with pytest.raises(recovery.RecoveryError, match="admission_pin"):
        recovery.verify_admission(stage, full.root / "public")


def test_full_contract_requires_explicit_initialization(tmp_path):
    prepare(tmp_path / "data")
    seed_logs(tmp_path / "data")
    with pytest.raises(recovery.RecoveryError, match="explicit_full_storage"):
        recovery.Store(tmp_path).initialize()
    assert not (tmp_path / "control").exists()


@pytest.mark.parametrize("name", list(storage.FILES.values()))
@pytest.mark.parametrize("damage", ["hash", "partial", "blank", "legacy", "duplicate_key", "model"])
def test_strict_jsonl_rejects_malformed_or_legacy_records(full, name, damage):
    path = full.data / name
    raw = path.read_bytes()
    if damage == "hash":
        path.write_bytes(raw.replace(b'"record_hash":', b'"record_hash":"broken","extra":', 1))
    elif damage == "partial":
        path.write_bytes(raw[:-1])
    elif damage == "blank":
        path.write_bytes(raw + b"\n")
    elif damage == "legacy":
        path.write_bytes(json.dumps(payloads(path)[0]).encode() + b"\n")
    elif damage == "duplicate_key":
        path.write_bytes(raw.replace(b'{"schema_version":1', b'{"schema_version":1,"schema_version":1', 1))
    else:
        rows = payloads(path)
        rows[0]["unexpected_field"] = "invalid"
        rewrite(path, rows)
    with pytest.raises(ValueError):
        storage.inspect(full.data)


@pytest.mark.parametrize("kind", ["cases", "outbox"])
def test_rehashed_duplicate_or_skipped_version_is_denied(full, kind):
    path = full.data / storage.FILES[kind]
    rows = payloads(path)
    rewrite(path, [rows[0], rows[0], *rows[1:]])
    with pytest.raises(storage.StorageError, match="version_sequence"):
        storage.inspect(full.data)


def test_outbox_bound_to_exact_case_version_and_tenant(full):
    path = full.data / storage.FILES["cases"]
    rows = payloads(path)
    rewrite(path, [r for r in rows if r["tenant_id"] != "recovery-tenant"])
    with pytest.raises(storage.StorageError, match="outbox_case_missing"):
        storage.inspect(full.data)


def test_file_size_line_count_and_line_size_limits(full, monkeypatch):
    monkeypatch.setattr(storage, "MAX_LOG", 1)
    with pytest.raises(storage.StorageError, match="size_limit"):
        storage.inspect(full.data)
    monkeypatch.setattr(storage, "MAX_LOG", 8 * 1024**2)
    monkeypatch.setattr(storage, "MAX_LINE", 1)
    with pytest.raises(storage.StorageError, match="line_size"):
        storage.inspect(full.data)
    monkeypatch.setattr(storage, "MAX_LINE", 1024**2)
    monkeypatch.setattr(storage, "MAX_RECORDS", 1)
    with pytest.raises(storage.StorageError, match="record_limit"):
        storage.inspect(full.data)


def test_source_log_changes_during_sqlite_snapshot_are_rejected(full, tmp_path, monkeypatch):
    original = storage.capture
    calls = 0
    def capture(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            with (full.data / storage.FILES["audit"]).open("ab") as stream:
                stream.write(b"changed during snapshot\n")
        return original(path)
    monkeypatch.setattr(storage, "capture", capture)
    with pytest.raises(recovery.RecoveryError, match="storage_changed_during_snapshot"):
        recovery.snapshot(full.data, tmp_path / "snapshot")


def test_backup_envelope_cap_refuses_publication(full, monkeypatch):
    monkeypatch.setattr(recovery, "MAX_ENVELOPE", 1024)
    before = set((full.root / "backups").iterdir())
    with pytest.raises(recovery.RecoveryError, match="envelope_size_limit"):
        full.store.backup()
    assert set((full.root / "backups").iterdir()) == before


@pytest.mark.parametrize("damage", ["missing_file", "missing_mode", "mixed_generation"])
def test_authenticated_but_incomplete_or_mixed_storage_backup_denied(full, damage):
    path = full.root / "backups" / (full.backup["backup_id"] + ".sealed")
    original = path.read_bytes()
    assert b"recovery-tenant" not in original and b"Recovery transition" not in original
    envelope = recovery.read_json(path)
    key = recovery.read_file(full.root / "control/backup.key", 32)
    payload = recovery.opened(envelope, key)
    if damage == "missing_file":
        del payload["jsonl"]["cases.jsonl"]
    elif damage == "missing_mode":
        del payload["jsonl"]
    else:
        # An independently valid empty audit belongs to another logical snapshot.
        payload["jsonl"]["audit.jsonl"] = base64.b64encode(b"").decode()
    path.write_bytes(recovery.canonical(recovery.sealed(payload, key, envelope["manifest"])))
    with pytest.raises((ValueError, recovery.RecoveryError)):
        restore(full)
    assert recovery.read_json(full.root / "public/current.json")["restore_id"] is None


def test_outbox_retry_after_restore_preserves_old_terminal_states(full):
    from app.models import IntegrationDeliveryUpdateRequest
    from app.services.integration_outbox import OutboxTerminalStateError

    stage = restore(full)
    service = IntegrationOutboxService(IntegrationOutboxStore(stage / storage.FILES["outbox"]))
    rows = service.store.recent(100, "recovery-tenant")
    retry = next(row for row in rows if row.status == "RETRY_SCHEDULED")
    request = IntegrationDeliveryUpdateRequest(expected_version=retry.version, outcome="delivered", note="Retry restored event")
    updated = asyncio.run(service.record_attempt(retry.event.id, "recovery-tenant", "recovery-test",
        request, now=retry.next_attempt_at))
    assert updated.event == retry.event and updated.attempt_count == retry.attempt_count + 1
    assert updated.history[:-1] == retry.history
    for terminal in (row for row in rows if row.status in {"DELIVERED", "DEAD_LETTER"}):
        with pytest.raises(OutboxTerminalStateError):
            asyncio.run(service.record_attempt(terminal.event.id, "recovery-tenant", "recovery-test",
                request.model_copy(update={"expected_version": terminal.version})))
    assert recovery.verify_admission(stage, full.root / "public")["admission_verified"]
    assert IntegrationOutboxStore(stage / storage.FILES["outbox"]).get(retry.event.id, "recovery-tenant") == updated


def test_full_release_identity_cannot_pass_legacy_sqlite_only_gate(full, monkeypatch):
    stage = restore(full)
    release = recovery.read_json(stage / "release.json")["release"]
    assert release["application_sha256"] != recovery.app_digest()
    original = recovery.inspect_state
    def legacy(path):
        result = original(path)
        result["state"].pop("jsonl", None)
        result["state"]["application_sha256"] = recovery.app_digest()
        return result
    monkeypatch.setattr(recovery, "inspect_state", legacy)
    with pytest.raises(recovery.RecoveryError):
        recovery.verify_admission(stage, full.root / "public")


def test_full_checkpoint_refuses_changed_recovery_code_identity(full, monkeypatch):
    monkeypatch.setattr(recovery, "recovery_digest", lambda _mode: "f" * 64)
    with pytest.raises(recovery.RecoveryError, match="application_version_mismatch"):
        full.store.restore(full.backup["backup_id"])
