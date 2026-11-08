import json
import shutil
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.services.signal_inbox import SignalInbox
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations
from app.zero_trust_models import SessionRevocationRequest
from scripts import app_state_recovery as recovery
from scripts import serve_recovered_app as gate
from scripts.app_recovery_fixture import PRINCIPAL, accept, access, evaluate, prepare, verify


@pytest.fixture
def lab(tmp_path, recovery_clock):
    prepare(tmp_path / "data")
    store = recovery.Store(tmp_path)
    store.initialize()
    store.checkpoint()
    backup = store.backup()
    return SimpleNamespace(root=tmp_path, store=store, backup=backup,
        path=tmp_path / "backups" / (backup["backup_id"] + ".sealed"))


def restore(lab):
    result = lab.store.restore(lab.backup["backup_id"])
    return lab.root / "restores" / result["restore_id"], result


def write(path, value):
    path.write_bytes(recovery.canonical(value))


def fixture(lab):
    return json.loads((lab.root / "data/fixture.json").read_bytes())


def test_backup_is_encrypted_and_restore_fences_without_rewriting_source(lab):
    before = recovery.inspect_state(lab.root / "data")
    encrypted = lab.path.read_bytes()
    assert b"SQLite format" not in encrypted and b"synthetic-signature" not in encrypted
    assert all(token.encode() not in encrypted for token in fixture(lab)["tokens"].values())
    stage, result = restore(lab)
    assert result["fenced_sessions"] == 3 and result["restored_records"] == before["records"] + 2
    assert recovery.inspect_state(lab.root / "data")["state"] == before["state"]
    assert verify(stage, lab.root / "data")["fixed_clock"]
    assert recovery.verify_admission(stage, lab.root / "public")["admission_verified"]


def test_unfenced_control_still_allows_unconsumed_grant_at_same_clock(lab, tmp_path):
    recovery.snapshot(lab.root / "data", tmp_path / "control-copy")
    data = fixture(lab)
    now = datetime.fromisoformat(data["now"]) + timedelta(seconds=1)
    service = recovery.operations(tmp_path / "control-copy")
    assert access(service, "pending", data["tokens"]["pending"], now).allowed
    assert access(service, "consumed", data["tokens"]["consumed"], now).reason_code == "GRANT_ALREADY_USED"
    assert access(service, "revoked", data["tokens"]["revoked"], now).reason_code == "SESSION_NOT_AUTHORIZED"


def test_all_inbox_rows_archives_leases_and_duplicate_identity_retained(lab):
    before = recovery.inspect_state(lab.root / "data")["state"]["tables"]
    stage, _ = restore(lab)
    after = recovery.inspect_state(stage)["state"]["tables"]
    assert all(after[name] == digest for name, digest in before.items() if name.startswith("signal_inbox"))
    now = datetime.fromisoformat(fixture(lab)["now"])
    inbox = SignalInbox(stage / "app.sqlite3")
    assert inbox.get(PRINCIPAL.tenant_id, "completed")["state"] == "completed"
    assert inbox.get(PRINCIPAL.tenant_id, "processing")["attempts"] == 1
    assert inbox.get(PRINCIPAL.tenant_id, "pending")["state"] == "pending"
    assert accept(inbox, "completed", now)["duplicate"]
    with closing(sqlite3.connect(stage / "app.sqlite3")) as db:
        assert db.execute("SELECT count(*) FROM journal_archive_segments").fetchone()[0] > 0
        assert db.execute("SELECT count(*) FROM signal_inbox_archive_segments").fetchone()[0] > 0


def test_fence_is_not_limited_to_public_session_list_or_one_tenant(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    now = datetime.now(UTC)
    service = ZeroTrustOperations(data / "app.sqlite3")
    for index in range(101):
        evaluate(service, "session-" + str(index), now)
    other = PRINCIPAL.__class__(PRINCIPAL.subject, "other-tenant", PRINCIPAL.roles, PRINCIPAL.auth_method)
    evaluate(service, "session-0", now, other)
    assert len(service.sessions(PRINCIPAL)) == 100
    store = recovery.Store(tmp_path)
    store.initialize()
    store.checkpoint()
    result = store.restore(store.backup()["backup_id"])
    assert result["fenced_sessions"] == 102
    assert recovery.verify_admission(tmp_path / "restores" / result["restore_id"], tmp_path / "public")["fenced_sessions"] == 102


@pytest.mark.parametrize("change", ["consume", "revoke", "registry"])
def test_source_advanced_after_checkpoint_blocks_backup(lab, change):
    data = fixture(lab)
    service = recovery.operations(lab.root / "data")
    if change == "consume":
        assert access(service, "pending", data["tokens"]["pending"], datetime.fromisoformat(data["now"])).allowed
    elif change == "revoke":
        service.revoke("pending", SessionRevocationRequest(expected_version=1, note="new revocation"), PRINCIPAL)
    else:
        path = lab.root / "data/sources.json"
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(recovery.RecoveryError, match="source_advanced"):
        lab.store.backup()


@pytest.mark.parametrize("change", ["consume", "revoke", "registry"])
def test_new_checkpoint_rejects_old_backup_and_old_admission(lab, change):
    stage, _ = restore(lab)
    data = fixture(lab)
    service = recovery.operations(lab.root / "data")
    if change == "consume":
        access(service, "pending", data["tokens"]["pending"], datetime.fromisoformat(data["now"]))
    elif change == "revoke":
        service.revoke("pending", SessionRevocationRequest(expected_version=1, note="new revocation"), PRINCIPAL)
    else:
        registry = recovery.read_json(lab.root / "data/sources.json")
        registry["sources"][0]["keys"][0]["enabled"] = False
        write(lab.root / "data/sources.json", registry)
    lab.store.checkpoint()
    with pytest.raises(recovery.RecoveryError, match="backup_stale"):
        lab.store.restore(lab.backup["backup_id"])
    with pytest.raises(recovery.RecoveryError, match="admission_pin"):
        recovery.verify_admission(stage, lab.root / "public")


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "manifest"])
def test_backup_authenticated_envelope_tamper_denied(lab, field):
    envelope = recovery.read_json(lab.path)
    if field == "manifest":
        envelope[field]["generation"] += 1
    else:
        raw = envelope[field]
        envelope[field] = ("A" if raw[0] != "A" else "B") + raw[1:]
    write(lab.path, envelope)
    with pytest.raises(recovery.RecoveryError):
        restore(lab)
    assert not list((lab.root / "restores").iterdir())


@pytest.mark.parametrize("key", ["backup.key", "checkpoint.key"])
def test_wrong_authority_key_denied(lab, key):
    (lab.root / "control" / key).write_bytes(b"x" * 32)
    with pytest.raises(recovery.RecoveryError):
        restore(lab)


def test_cannot_replay_old_checkpoint_without_rolling_back_independent_anchor(lab):
    previous = (lab.root / "control/checkpoint.json").read_bytes()
    lab.store.checkpoint()
    (lab.root / "control/checkpoint.json").write_bytes(previous)
    with pytest.raises(recovery.RecoveryError, match="checkpoint_replay"):
        restore(lab)


@pytest.mark.parametrize("seconds", [-301, 60])
def test_checkpoint_expired_or_future_denied(lab, seconds):
    path = lab.root / "control/checkpoint.json"
    envelope = recovery.read_json(path)
    key = recovery.read_file(lab.root / "control/checkpoint.key")
    state = recovery.opened(envelope, key)
    envelope["manifest"]["created_at"] = (recovery.datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()
    envelope = recovery.sealed(state, key, envelope["manifest"])
    write(path, envelope)
    anchor = recovery.read_json(lab.root / "control/anchor.json")
    anchor["checkpoint_sha256"] = recovery.sha(recovery.canonical(envelope))
    write(lab.root / "control/anchor.json", anchor)
    with pytest.raises(recovery.RecoveryError, match="expired_or_future"):
        restore(lab)


@pytest.mark.parametrize("age", [0, -1, 3601, True])
def test_unbounded_checkpoint_age_denied(lab, age):
    with pytest.raises(recovery.RecoveryError, match="age_limit"):
        lab.store.restore(lab.backup["backup_id"], max_age=age)


def test_foreign_backup_denied_even_when_ciphertext_key_is_shared(lab, tmp_path):
    foreign = tmp_path / "foreign"
    prepare(foreign / "data")
    store = recovery.Store(foreign)
    store.initialize()
    store.checkpoint()
    shutil.copyfile(lab.root / "control/backup.key", foreign / "control/backup.key")
    shutil.copyfile(lab.path, foreign / "backups" / lab.path.name)
    with pytest.raises(recovery.RecoveryError, match="foreign"):
        store.restore(lab.backup["backup_id"])


def test_partial_revocation_failure_never_publishes_release(lab, monkeypatch):
    original = ZeroTrustOperations.revoke
    calls = []

    def failing(self, *args, **kwargs):
        calls.append(args[0])
        if len(calls) == 2:
            raise JournalUnavailable("injected commit failure")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ZeroTrustOperations, "revoke", failing)
    with pytest.raises(JournalUnavailable):
        restore(lab)
    stages = list((lab.root / "restores").iterdir())
    assert len(stages) == 1 and not (stages[0] / "release.json").exists()
    assert recovery.read_json(lab.root / "public/current.json")["restore_id"] is None
    assert recovery.inspect_state(lab.root / "data")["records"] == lab.backup["records"]


def test_previous_restore_release_is_not_admitted_after_new_restore(lab):
    old, _ = restore(lab)
    new, _ = restore(lab)
    assert recovery.verify_admission(new, lab.root / "public")["admission_verified"]
    with pytest.raises(recovery.RecoveryError, match="pin_mismatch"):
        recovery.verify_admission(old, lab.root / "public")


def test_signed_release_tamper_cannot_be_hidden_by_changing_public_pin(lab):
    stage, _ = restore(lab)
    signed = recovery.read_json(stage / "release.json")
    signed["release"]["fenced_sessions"] = []
    write(stage / "release.json", signed)
    pin = recovery.read_json(lab.root / "public/current.json")
    pin["release_sha256"] = recovery.sha(recovery.canonical(signed))
    write(lab.root / "public/current.json", pin)
    with pytest.raises(recovery.RecoveryError, match="signature"):
        recovery.verify_admission(stage, lab.root / "public")


def test_rollback_of_restored_db_is_detected_by_signed_prefix(lab):
    stage, _ = restore(lab)
    shutil.copyfile(lab.root / "data/app.sqlite3", stage / "app.sqlite3")
    with pytest.raises(recovery.RecoveryError, match="prefix_missing"):
        recovery.verify_admission(stage, lab.root / "public")


def test_new_audit_entries_do_not_break_restart_admission(lab):
    stage, _ = restore(lab)
    verify(stage, lab.root / "data")
    assert recovery.verify_admission(stage, lab.root / "public")["admission_verified"]


def test_disabled_source_key_is_preserved(lab):
    stage, _ = restore(lab)
    registry = recovery.read_json(stage / "sources.json")
    assert registry["sources"][0]["keys"][1]["enabled"] is False
    assert (stage / "sources.json").read_bytes() == (lab.root / "data/sources.json").read_bytes()


@pytest.mark.parametrize("kind", ["schema", "format", "corrupt"])
def test_unsupported_source_is_not_silently_migrated(lab, kind):
    path = lab.root / "data/app.sqlite3"
    if kind == "corrupt":
        path.write_bytes(b"corrupt")
    else:
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE extra(value TEXT)" if kind == "schema" else "PRAGMA user_version=1")
            db.commit()
    before = path.read_bytes()
    with pytest.raises((recovery.RecoveryError, sqlite3.Error)):
        lab.store.checkpoint()
    assert path.read_bytes() == before


@pytest.mark.parametrize("ident", ["../outside", "A" * 32, "", None])
def test_backup_path_traversal_denied(lab, ident):
    with pytest.raises(recovery.RecoveryError, match="backup_id"):
        lab.store.restore(ident)


def test_application_change_denies_old_checkpoint(lab, monkeypatch):
    monkeypatch.setattr(recovery, "app_digest", lambda: "f" * 64)
    with pytest.raises(recovery.RecoveryError, match="application_version"):
        restore(lab)


def test_registry_change_denies_admission(lab):
    stage, _ = restore(lab)
    (stage / "sources.json").write_text('{"sources": []}\n', encoding="utf-8")
    with pytest.raises(recovery.RecoveryError, match="configuration_changed"):
        recovery.verify_admission(stage, lab.root / "public")


def test_production_cli_denied_without_loading_artifacts(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(recovery, "get_settings", lambda: SimpleNamespace(app_environment="production"))
    assert recovery.main(["init", "--directory", str(tmp_path)]) == 1
    assert not list(tmp_path.iterdir())
    assert "RECOVERY_PRECONDITION_FAILED" in capsys.readouterr().err


def test_cli_path_scope_and_error_redaction(tmp_path, capsys):
    assert recovery.main(["restore", "--directory", str(tmp_path), "--backup-id", "private-token"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "private-token" not in captured.err and "Traceback" not in captured.err


def test_backup_can_recover_after_source_directory_is_lost(lab):
    shutil.rmtree(lab.root / "data")
    stage, _ = restore(lab)
    assert recovery.verify_admission(stage, lab.root / "public")["admission_verified"]


def test_failed_retry_invalidates_previous_published_admission(lab, monkeypatch):
    old, _ = restore(lab)
    monkeypatch.setattr(ZeroTrustOperations, "revoke", lambda *a, **kw: (_ for _ in ()).throw(JournalUnavailable()))
    with pytest.raises(JournalUnavailable):
        restore(lab)
    with pytest.raises(recovery.RecoveryError, match="pin_mismatch"):
        recovery.verify_admission(old, lab.root / "public")


@pytest.mark.parametrize("invalid", ["database", "registry", "authentication", "analyzer"])
def test_gate_rejects_app_configuration_that_bypasses_verified_state(lab, monkeypatch, invalid):
    stage, _ = restore(lab)
    settings = SimpleNamespace(analyzer_mode="rule", auth_mode="api_key", zero_trust_db_path=stage / "app.sqlite3",
                               trusted_signal_sources_path=stage / "sources.json")
    if invalid == "database":
        settings.zero_trust_db_path = lab.root / "data/app.sqlite3"
    elif invalid == "registry":
        settings.trusted_signal_sources_path = lab.root / "data/sources.json"
    elif invalid == "authentication":
        settings.auth_mode = "disabled"
    else:
        settings.analyzer_mode = "openai"
    monkeypatch.setattr(gate, "get_settings", lambda: settings)
    with pytest.raises(recovery.RecoveryError):
        gate.admit(stage, lab.root / "public")


def test_gate_admits_matching_authenticated_local_profile(lab, monkeypatch):
    stage, _ = restore(lab)
    settings = SimpleNamespace(analyzer_mode="rule", auth_mode="api_key", zero_trust_db_path=stage / "app.sqlite3",
                               trusted_signal_sources_path=stage / "sources.json")
    monkeypatch.setattr(gate, "get_settings", lambda: settings)
    assert gate.admit(stage, lab.root / "public")["admission_verified"]


def test_fresh_empty_mounted_authority_directories_are_supported(tmp_path):
    (tmp_path / "control").mkdir()
    (tmp_path / "public").mkdir()
    store = recovery.Store(tmp_path)
    assert store.initialize()["initialized"]
    with pytest.raises(recovery.RecoveryError, match="already_initialized"):
        store.initialize()


@pytest.mark.parametrize("phase", ["snapshot", "checkpoint.json", "anchor.json"])
def test_failed_checkpoint_cannot_fall_back_to_old_valid_authority(lab, monkeypatch, phase):
    old_stage, _ = restore(lab)
    service = recovery.operations(lab.root / "data")
    service.revoke("pending", SessionRevocationRequest(expected_version=1, note="new revocation"), PRINCIPAL)
    original = recovery.atomic

    def fail_write(path, body):
        if path.name == phase:
            raise OSError("injected checkpoint write failure")
        return original(path, body)

    with monkeypatch.context() as fault:
        if phase == "snapshot":
            fault.setattr(recovery, "snapshot", lambda *a, **kw: (_ for _ in ()).throw(OSError("snapshot failed")))
        else:
            fault.setattr(recovery, "atomic", fail_write)
        with pytest.raises(OSError):
            lab.store.checkpoint()
    for action in (lab.store.backup, lambda: lab.store.restore(lab.backup["backup_id"])):
        with pytest.raises(recovery.RecoveryError, match="publication_incomplete"):
            action()
    with pytest.raises(recovery.RecoveryError, match="pin_mismatch"):
        recovery.verify_admission(old_stage, lab.root / "public")
    # A deliberate new checkpoint of the stopped, current source can resume.
    lab.store.checkpoint()
    with pytest.raises(recovery.RecoveryError, match="backup_stale"):
        lab.store.restore(lab.backup["backup_id"])
    assert lab.store.restore(lab.store.backup()["backup_id"])["inbox_preserved"]
