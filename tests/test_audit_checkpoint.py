"""Operator-pinned checkpoint files, never automatic live restore activation."""

import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from test_sqlite_audit import initial, review

from app.services.audit_backup import backup_sqlite, restore_sqlite
from app.services.audit_checkpoint import capture_checkpoint, load_checkpoint
from app.services.audit_transfer import AuditTransferError, canonical
from app.services.federated_audit import AuditQueryUnavailable
from app.services.sqlite_audit import SQLiteAuditStore
from scripts import audit_storage


def ready(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    original = initial(1)
    asyncio.run(store.save(original))
    target = tmp_path / "checkpoint.json"
    receipt = capture_checkpoint(store.path, target)
    return store, original, target, receipt


def test_checkpoint_roundtrip_is_private_read_only_and_contains_no_event_payload(tmp_path):
    store, original, path, receipt = ready(tmp_path)
    before = store.path.read_bytes()
    doc = load_checkpoint(path, receipt["checkpoint_sha256"])
    assert doc["head"] == receipt["head"] and doc["head"]["seq"] == 1
    assert original.event_id.encode() not in path.read_bytes()
    assert str(store.path).encode() not in path.read_bytes()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt["checkpoint_sha256"]
    assert receipt["automatic_activation_allowed"] is False
    assert receipt["independent_storage_verified"] is False
    assert store.path.read_bytes() == before and not list(tmp_path.glob(".audit-transfer-*"))
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("target_kind", ["existing_output", "source_database"])
def test_checkpoint_export_never_replaces_existing_output_or_source(tmp_path, target_kind):
    store, _, path, _ = ready(tmp_path)
    target = path if target_kind == "existing_output" else store.path
    before = target.read_bytes()
    with pytest.raises(AuditTransferError):
        capture_checkpoint(store.path, target)
    assert target.read_bytes() == before


@pytest.mark.parametrize("source_kind", ["missing", "foreign", "corrupt"])
def test_checkpoint_export_never_repairs_or_creates_source_state(tmp_path, source_kind):
    source, target = tmp_path / "source.sqlite3", tmp_path / "head.json"
    if source_kind == "foreign":
        with sqlite3.connect(source) as con:
            con.execute("CREATE TABLE other_service (id TEXT)")
    elif source_kind == "corrupt":
        store = SQLiteAuditStore(source)
        asyncio.run(store.save(initial(1)))
        with store._transaction(write=True) as con:
            con.execute("UPDATE audit_head SET digest=?", ("f" * 64,))
    before = source.read_bytes() if source.exists() else None
    with pytest.raises(AuditQueryUnavailable):
        capture_checkpoint(source, target)
    assert not target.exists() and not list(tmp_path.glob(".audit-transfer-*"))
    assert (source.read_bytes() if source.exists() else None) == before


@pytest.mark.parametrize(
    "change",
    [
        "empty",
        "oversize",
        "naive_time",
        "broken_json",
        "duplicate",
        "extra_field",
        "seq_bool",
        "seq_negative",
        "seq_overflow",
        "zero_nonzero_digest",
        "bad_digest",
        "wrong_schema",
        "bad_source",
    ],
)
def test_even_externally_pinned_malformed_checkpoint_is_rejected(tmp_path, change):
    _, _, path, receipt = ready(tmp_path)
    value = load_checkpoint(path, receipt["checkpoint_sha256"])
    if change == "naive_time":
        value["captured_at"] = "2026-11-19T03:00:00"
    elif change == "extra_field":
        value["automatic_activation_allowed"] = True
    elif change in {"seq_bool", "seq_negative", "seq_overflow"}:
        value["head"]["seq"] = {"seq_bool": True, "seq_negative": -1, "seq_overflow": 100001}[
            change
        ]
    elif change == "zero_nonzero_digest":
        value["head"] = {"seq": 0, "digest": "f" * 64}
    elif change == "bad_digest":
        value["head"]["digest"] = "not-a-digest"
    elif change == "wrong_schema":
        value["schema"] = "unknown-checkpoint-2"
    elif change == "bad_source":
        value["source_locator_sha256"] = "local-path-is-not-an-identity"
    raw = canonical(value)
    if change == "empty":
        raw = b""
    elif change == "oversize":
        raw = b"x" * 16385
    elif change == "broken_json":
        raw = b"{bad"
    elif change == "duplicate":
        raw = raw[:-1] + b',"schema":"sqlite-audit-checkpoint-1"}'
    path.write_bytes(raw)
    with pytest.raises((AuditTransferError, ValueError)):
        load_checkpoint(path, hashlib.sha256(raw).hexdigest())


def test_changed_checkpoint_is_rejected_against_original_external_pin(tmp_path):
    _, _, path, receipt = ready(tmp_path)
    original = path.read_bytes()
    path.write_bytes(original.replace(b'"seq":1', b'"seq":0'))
    with pytest.raises(AuditTransferError, match="pin mismatch"):
        load_checkpoint(path, receipt["checkpoint_sha256"])


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions"])
def test_checkpoint_filesystem_contract_rejects_aliases_or_public_mode(tmp_path, kind):
    _, _, path, receipt = ready(tmp_path)
    if kind == "permissions":
        if os.name != "posix":
            pytest.skip("POSIX permission contract; Windows ACL is not assessed")
        path.chmod(0o644)
    else:
        alias = tmp_path / "alias.json"
        try:
            alias.symlink_to(path) if kind == "symlink" else os.link(path, alias)
        except OSError:
            pytest.skip("link creation unavailable in this local test environment")
        path = alias
    with pytest.raises(AuditTransferError):
        load_checkpoint(path, receipt["checkpoint_sha256"])


def key_options(tmp_path):
    key = tmp_path / "backup.key"
    key.write_bytes(secrets.token_bytes(32))
    key.chmod(0o600)
    return ["--key-file", str(key), "--key-sha256", hashlib.sha256(key.read_bytes()).hexdigest()]


def test_cli_checkpoint_rejects_old_authentic_backup_and_restores_current_candidate(
    tmp_path, capsys
):
    store, original, _, _ = ready(tmp_path)
    keys = key_options(tmp_path)
    old_package = tmp_path / "old.enc"
    audit_storage.main(
        ["backup", "--database", str(store.path), "--destination", str(old_package), *keys]
    )
    old_receipt = json.loads(capsys.readouterr().out)
    asyncio.run(store.save_review(review(original), original))
    before = store.path.read_bytes()
    path = tmp_path / "current-checkpoint.json"
    audit_storage.main(["checkpoint", "--database", str(store.path), "--destination", str(path)])
    checkpoint = json.loads(capsys.readouterr().out)
    pins = ["--checkpoint", str(path), "--checkpoint-sha256", checkpoint["checkpoint_sha256"]]
    stale_target = tmp_path / "stale.sqlite3"
    with pytest.raises(SystemExit) as stopped:
        audit_storage.main(
            [
                "restore",
                "--package",
                str(old_package),
                "--destination",
                str(stale_target),
                "--backup-sha256",
                old_receipt["backup_sha256"],
                *keys,
                *pins,
            ]
        )
    assert stopped.value.code == 1 and not stale_target.exists()
    assert "automatic activation is disabled" in capsys.readouterr().err
    current_package = tmp_path / "current.enc"
    audit_storage.main(
        [
            "backup",
            "--database",
            str(store.path),
            "--destination",
            str(current_package),
            *keys,
            *pins,
        ]
    )
    backup = json.loads(capsys.readouterr().out)
    target = tmp_path / "candidate.sqlite3"
    audit_storage.main(
        [
            "restore",
            "--package",
            str(current_package),
            "--destination",
            str(target),
            "--backup-sha256",
            backup["backup_sha256"],
            *keys,
            *pins,
        ]
    )
    restored = json.loads(capsys.readouterr().out)
    assert restored["head"] == checkpoint["head"]
    assert restored["freshness_check"]["minimum_head_verified"]
    assert restored["freshness_check"]["minimum_head_source"] == "operator_pinned_checkpoint_file"
    assert restored["freshness_check"]["latest_live_state_verified"] is False
    assert restored["freshness_check"]["independent_storage_verified"] is False
    assert restored["automatic_activation_allowed"] is False
    assert (
        SQLiteAuditStore.open_existing(target).get(original.event_id).review_status.value
        == "RESOLVED"
    )
    assert store.path.read_bytes() == before


@pytest.mark.parametrize(
    "options",
    [
        ["--checkpoint", "not-read.json"],
        ["--checkpoint-sha256", "a" * 64],
        [
            "--checkpoint",
            "not-read.json",
            "--checkpoint-sha256",
            "a" * 64,
            "--minimum-seq",
            "1",
            "--minimum-head",
            "b" * 64,
        ],
    ],
)
def test_cli_ambiguous_checkpoint_configuration_stops_before_key_access(options, monkeypatch):
    read = Mock(side_effect=AssertionError("key must not be read"))
    monkeypatch.setattr(audit_storage, "read_key", read)
    with pytest.raises(SystemExit) as stopped:
        audit_storage.main(
            [
                "backup",
                "--database",
                "not-read.sqlite3",
                "--destination",
                "not-written.enc",
                "--key-file",
                "not-read.key",
                "--key-sha256",
                "a" * 64,
                *options,
            ]
        )
    assert stopped.value.code == 2
    read.assert_not_called()


def test_checkpoint_of_different_valid_chain_rejects_backup_of_same_sequence(tmp_path):
    store, _, path, receipt = ready(tmp_path)
    other = SQLiteAuditStore(tmp_path / "other.sqlite3")
    asyncio.run(other.save(initial(9)))
    key = secrets.token_bytes(32)
    package = tmp_path / "other.enc"
    backup = backup_sqlite(other, package, key)
    head = load_checkpoint(path, receipt["checkpoint_sha256"])["head"]
    with pytest.raises(AuditTransferError, match="history conflict"):
        restore_sqlite(
            package, tmp_path / "rejected.sqlite3", backup["backup_sha256"], key, minimum_head=head
        )
    assert not (tmp_path / "rejected.sqlite3").exists()
    assert store.integrity()["ok"]


def test_capture_is_a_coherent_prefix_while_independent_writer_appends(tmp_path):
    store, _, _, _ = ready(tmp_path)

    def append():
        writer = SQLiteAuditStore.open_existing(store.path)
        for index in range(2, 9):
            asyncio.run(writer.save(initial(index)))

    path = tmp_path / "concurrent.json"
    with ThreadPoolExecutor(max_workers=1) as pool:
        writing = pool.submit(append)
        receipt = capture_checkpoint(store.path, path)
        writing.result(timeout=15)
    head = load_checkpoint(path, receipt["checkpoint_sha256"])["head"]
    assert 1 <= head["seq"] <= 8
    with store._transaction() as con:
        observed = con.execute(
            "SELECT digest FROM audit_entries WHERE seq=?", (head["seq"],)
        ).fetchone()[0]
    assert observed == head["digest"] and store.integrity()["verified_lines"] == 8


def test_empty_checkpoint_does_not_claim_nonempty_history_or_live_freshness(tmp_path, capsys):
    store = SQLiteAuditStore(tmp_path / "empty.sqlite3")
    path = tmp_path / "empty-head.json"
    receipt = capture_checkpoint(store.path, path)
    assert receipt["head"] == {"seq": 0, "digest": "0" * 64}
    audit_storage.main(
        [
            "backup",
            "--database",
            str(store.path),
            "--destination",
            str(tmp_path / "empty.enc"),
            *key_options(tmp_path),
            "--checkpoint",
            str(path),
            "--checkpoint-sha256",
            receipt["checkpoint_sha256"],
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert report["freshness_check"]["minimum_head_verified"]
    assert report["freshness_check"]["checkpoint_has_history"] is False
    assert report["freshness_check"]["latest_live_state_verified"] is False


def test_selected_old_checkpoint_only_asserts_its_operator_selected_minimum(tmp_path, capsys):
    store, _, path, checkpoint = ready(tmp_path)
    keys = key_options(tmp_path)
    package = tmp_path / "historical.enc"
    audit_storage.main(
        ["backup", "--database", str(store.path), "--destination", str(package), *keys]
    )
    backup = json.loads(capsys.readouterr().out)
    asyncio.run(store.save(initial(2)))
    target = tmp_path / "historical-candidate.sqlite3"
    audit_storage.main(
        [
            "restore",
            "--package",
            str(package),
            "--destination",
            str(target),
            *keys,
            "--backup-sha256",
            backup["backup_sha256"],
            "--checkpoint",
            str(path),
            "--checkpoint-sha256",
            checkpoint["checkpoint_sha256"],
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert report["head"]["seq"] == 1 and store.integrity()["verified_lines"] == 2
    assert report["freshness_check"]["minimum_head_verified"]
    assert report["freshness_check"]["latest_live_state_verified"] is False
    assert report["freshness_check"]["independent_storage_verified"] is False
    assert report["automatic_activation_allowed"] is False


def test_cli_bad_external_checkpoint_pin_stops_before_private_key_read(tmp_path, monkeypatch):
    _, _, path, _ = ready(tmp_path)
    read = Mock(
        side_effect=AssertionError("private key must not be read before checkpoint validation")
    )
    monkeypatch.setattr(audit_storage, "read_key", read)
    with pytest.raises(SystemExit) as stopped:
        audit_storage.main(
            [
                "restore",
                "--package",
                "not-read.enc",
                "--destination",
                "not-written.sqlite3",
                "--key-file",
                "not-read.key",
                "--key-sha256",
                "a" * 64,
                "--backup-sha256",
                "b" * 64,
                "--checkpoint",
                str(path),
                "--checkpoint-sha256",
                "c" * 64,
            ]
        )
    assert stopped.value.code == 1
    read.assert_not_called()
