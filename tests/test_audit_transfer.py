import asyncio
import hashlib
import json
import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.exceptions import InvalidTag
from test_sqlite_audit import initial, review

from app.services.audit import AuditStore
from app.services.audit_backup import backup_sqlite, restore_sqlite
from app.services.audit_transfer import AuditTransferError, migrate_jsonl, scan_jsonl
from app.services.federated_audit import AuditQueryUnavailable
from app.services.sqlite_audit import AuditReviewConflict, SQLiteAuditStore


def source(tmp_path):
    base = tmp_path / "audit.jsonl"
    original = initial(1)
    asyncio.run(AuditStore(base).save(original))
    updated = review(original)
    asyncio.run(AuditStore(tmp_path / "audit.worker-2.jsonl").save(updated))
    return base, original, updated


def test_migration_preserves_original_history_and_source_bytes(tmp_path):
    base, original, updated = source(tmp_path)
    paths = list(tmp_path.glob("*.jsonl"))
    before = {p: p.read_bytes() for p in paths}
    _, inventory = scan_jsonl(base)
    target = tmp_path / "migrated.sqlite3"
    receipt = migrate_jsonl(base, target, inventory["inventory_sha256"])
    restored = SQLiteAuditStore(target)
    assert restored.get(original.event_id) == updated
    assert restored.integrity()["verified_lines"] == receipt["imported_rows"] == 2
    assert restored.metrics().total_analyses == 1
    assert before == {p: p.read_bytes() for p in paths}


@pytest.mark.parametrize(
    "kind", ["wrong_pin", "missing_history", "corrupt", "existing_target", "legacy"]
)
def test_migration_rejects_unapproved_or_incomplete_inputs_without_output(tmp_path, kind):
    base, original, _updated = source(tmp_path)
    target = tmp_path / "migrated.sqlite3"
    if kind == "missing_history":
        base.unlink()
    if kind == "corrupt":
        base.write_text('{"partial":', encoding="utf-8")
    if kind == "legacy":
        base.write_text(original.model_dump_json() + "\n", encoding="utf-8")
    if kind == "existing_target":
        target.write_bytes(b"preserve me")
    try:
        _, inventory = scan_jsonl(base)
        pin = "e" * 64 if kind == "wrong_pin" else inventory["inventory_sha256"]
        with pytest.raises(AuditTransferError):
            migrate_jsonl(base, target, pin)
    except (AuditTransferError, ValueError):
        assert kind in {"corrupt", "legacy"}
    if kind == "existing_target":
        assert target.read_bytes() == b"preserve me"
    else:
        assert not target.exists()


def test_legacy_requires_optin_and_is_reported_without_inventing_verification(tmp_path):
    base = tmp_path / "legacy.jsonl"
    value = initial(1)
    base.write_text(value.model_dump_json() + "\n", encoding="utf-8")
    _, inventory = scan_jsonl(base, allow_legacy=True)
    receipt = migrate_jsonl(
        base, tmp_path / "new.sqlite3", inventory["inventory_sha256"], allow_legacy=True
    )
    assert receipt["legacy_rows"] == 1 and receipt["hashed_rows"] == 0


def test_fresh_review_cannot_be_written_as_an_initial_record(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    with pytest.raises(AuditReviewConflict):
        asyncio.run(store.save(review(initial(1))))
    assert store.integrity()["ok"] and store.integrity()["verified_lines"] == 0


def test_streaming_backup_restore_preserves_chain_and_can_append(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    original = initial(1)
    asyncio.run(store.save(original))
    key = secrets.token_bytes(32)
    package = tmp_path / "audit.enc"
    before = store.path.read_bytes()
    receipt = backup_sqlite(store, package, key)
    assert original.event_id.encode() not in package.read_bytes()
    target = tmp_path / "restored.sqlite3"
    restored_receipt = restore_sqlite(
        package, target, receipt["backup_sha256"], key, minimum_head=receipt["head"]
    )
    restored = SQLiteAuditStore(target)
    assert restored.get(original.event_id) == original
    assert restored_receipt["automatic_activation_allowed"] is False
    assert before == store.path.read_bytes()
    asyncio.run(restored.save(initial(2)))
    assert restored.integrity()["verified_lines"] == 2


@pytest.mark.parametrize(
    "kind", ["wrong_key", "wrong_pin", "tag", "truncated", "trailing", "existing_target"]
)
def test_backup_failure_never_overwrites_or_publishes_restore(tmp_path, kind):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    asyncio.run(store.save(initial(1)))
    key = secrets.token_bytes(32)
    package = tmp_path / "audit.enc"
    receipt = backup_sqlite(store, package, key)
    raw = package.read_bytes()
    if kind == "wrong_key":
        key = b"e" * 32
    if kind == "tag":
        package.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    if kind == "truncated":
        package.write_bytes(raw[:-17])
    if kind == "trailing":
        package.write_bytes(raw + b"extra")
    target = tmp_path / "restored.sqlite3"
    if kind == "existing_target":
        target.write_bytes(b"preserve me")
    pin = "e" * 64 if kind == "wrong_pin" else receipt["backup_sha256"]
    with pytest.raises((AuditTransferError, InvalidTag)):
        restore_sqlite(package, target, pin, key)
    if kind == "existing_target":
        assert target.read_bytes() == b"preserve me"
    else:
        assert not target.exists()


def test_source_change_before_publication_aborts_migration(tmp_path, monkeypatch):
    from app.services import audit_transfer as module

    base, _, _ = source(tmp_path)
    _, inventory = scan_jsonl(base)
    real, calls = module.scan_jsonl, 0

    def changing(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            asyncio.run(AuditStore(base).save(initial(2)))
        return real(*args, **kwargs)

    monkeypatch.setattr(module, "scan_jsonl", changing)
    target = tmp_path / "changed.sqlite3"
    with pytest.raises(AuditTransferError):
        migrate_jsonl(base, target, inventory["inventory_sha256"])
    assert not target.exists()


def test_destination_race_cannot_replace_other_writers_output(tmp_path, monkeypatch):
    from app.services import audit_transfer as module

    base, _, _ = source(tmp_path)
    _, inventory = scan_jsonl(base)
    real = module.os.link

    def competing(stage, destination):
        destination.write_bytes(b"other writer won")
        return real(stage, destination)

    monkeypatch.setattr(module.os, "link", competing)
    target = tmp_path / "race.sqlite3"
    with pytest.raises(FileExistsError):
        migrate_jsonl(base, target, inventory["inventory_sha256"])
    assert target.read_bytes() == b"other writer won"


def test_cli_scan_migrate_backup_restore_never_activates_config(tmp_path, capsys):
    from scripts.audit_storage import main

    base, original, _ = source(tmp_path)
    main(["scan", "--source", str(base)])
    inventory = json.loads(capsys.readouterr().out)
    target = tmp_path / "cli.sqlite3"
    main(
        [
            "migrate",
            "--source",
            str(base),
            "--destination",
            str(target),
            "--inventory-sha256",
            inventory["inventory_sha256"],
        ]
    )
    assert json.loads(capsys.readouterr().out)["automatic_activation_allowed"] is False
    key_path = tmp_path / "backup-key.bin"
    key_path.write_bytes(secrets.token_bytes(32))
    key_path.chmod(0o600)
    key_args = [
        "--key-file",
        str(key_path),
        "--key-sha256",
        hashlib.sha256(key_path.read_bytes()).hexdigest(),
    ]
    package = tmp_path / "cli.enc"
    main(["backup", "--database", str(target), "--destination", str(package), *key_args])
    backup = json.loads(capsys.readouterr().out)
    restored = tmp_path / "restored.sqlite3"
    main(
        [
            "restore",
            "--package",
            str(package),
            "--destination",
            str(restored),
            *key_args,
            "--backup-sha256",
            backup["backup_sha256"],
            "--minimum-seq",
            str(backup["head"]["seq"]),
            "--minimum-head",
            backup["head"]["digest"],
        ]
    )
    assert json.loads(capsys.readouterr().out)["automatic_activation_allowed"] is False
    assert SQLiteAuditStore.open_existing(restored).get(original.event_id).reviewer


def test_readonly_existing_opener_never_initializes_missing_or_foreign_db(tmp_path):
    import sqlite3

    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(AuditQueryUnavailable):
        SQLiteAuditStore.open_existing(missing)
    assert not missing.exists()
    foreign = tmp_path / "foreign.sqlite3"
    con = sqlite3.connect(foreign)
    con.close()
    before = foreign.read_bytes()
    with pytest.raises(AuditQueryUnavailable):
        SQLiteAuditStore.open_existing(foreign)
    assert before == foreign.read_bytes()


def test_old_authentic_backup_is_rejected_against_newer_trusted_head(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    asyncio.run(store.save(initial(1)))
    key = secrets.token_bytes(32)
    package = tmp_path / "audit.enc"
    receipt = backup_sqlite(store, package, key)
    asyncio.run(store.save(initial(2)))
    with store._transaction() as con:
        _, seq, digest, _ = store._read(con)
    with pytest.raises(AuditTransferError):
        restore_sqlite(
            package,
            tmp_path / "old.sqlite3",
            receipt["backup_sha256"],
            key,
            minimum_head={"seq": seq, "digest": digest},
        )


def test_online_backup_is_consistent_while_other_worker_appends(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    asyncio.run(store.save(initial(0)))

    def append():
        other = SQLiteAuditStore.open_existing(store.path)
        for index in range(1, 8):
            asyncio.run(other.save(initial(index)))

    key = secrets.token_bytes(32)
    package = tmp_path / "online.enc"
    with ThreadPoolExecutor(max_workers=1) as pool:
        writing = pool.submit(append)
        receipt = backup_sqlite(store, package, key)
        writing.result(timeout=15)
    restore_sqlite(
        package,
        tmp_path / "online.sqlite3",
        receipt["backup_sha256"],
        key,
        minimum_head=receipt["head"],
    )
    recovered = SQLiteAuditStore.open_existing(tmp_path / "online.sqlite3")
    assert 1 <= recovered.integrity()["verified_lines"] <= 8
    assert recovered.integrity()["verified_lines"] == receipt["head"]["seq"]
    assert store.integrity()["verified_lines"] == 8


def test_backup_payload_spans_multiple_crypto_stream_chunks(tmp_path):
    store = SQLiteAuditStore(tmp_path / "large.sqlite3")
    value = initial(1).model_copy(update={"verification_context": {"fixture_padding": "private-padding-" * 10000}})
    asyncio.run(store.save(value))
    key = secrets.token_bytes(32)
    package = tmp_path / "large.enc"
    receipt = backup_sqlite(store, package, key)
    assert package.stat().st_size > 65536
    assert b"private-padding-" not in package.read_bytes()
    target = tmp_path / "large-restored.sqlite3"
    restore_sqlite(package, target, receipt["backup_sha256"], key)
    assert SQLiteAuditStore.open_existing(target).get(value.event_id) == value
