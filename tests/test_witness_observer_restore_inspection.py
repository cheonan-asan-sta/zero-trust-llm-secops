"""Keyless monitoring verifies retained pins/ancestry without claiming freshness."""

import json
import os
import subprocess
from contextlib import contextmanager

import pytest
from test_witness_observer_backup import KEY, fixture, restore

from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import AuditTransferError, canonical, sha
from scripts.local_process_runtime import direct_python


def prepared(tmp_path):
    source, signer, _, original, pin, last, package, report = fixture(tmp_path)
    result = restore(tmp_path, pin, last, package, report)
    return source, signer, original, pin, last, package, report, result


def inspect(tmp_path, pin, minimum, package, report, result):
    return backup.inspect_restore(package, tmp_path / "restored", report["backup_sha256"],
                                  result["restore_receipt_sha256"], pin, minimum["receipt_sha256"])


def test_keyless_inspection_does_not_read_key_or_live_source_or_refresh_restore_time(tmp_path, monkeypatch):
    source, signer, _, pin, last, package, report, result = prepared(tmp_path)
    target = tmp_path / "restored"
    before = {p: p.read_bytes() for p in (target / "observer.sqlite3", target / "restore.receipt.json",
                                        target / "lease.sqlite3")}
    source.path.unlink()
    (signer / "private.key").unlink()
    (signer / "journal.sqlite3").unlink()
    monkeypatch.setattr(backup, "AESGCM", lambda *_: pytest.fail("keyless proof attempted decryption"))
    monkeypatch.setattr(observer, "status", lambda *a, **k: pytest.fail("live source read"))
    first = inspect(tmp_path, pin, last, package, report, result)
    second = inspect(tmp_path, pin, last, package, report, result)
    assert first == second
    assert first["ciphertext_pin_verified"] and first["signed_snapshot_minimum_present"]
    assert not first["decryption_checked"] and not first["live_source_checked"]
    assert not first["restore_completion_time_attested"]
    assert not first["independent_storage_verified"] and not first["automatic_activation_allowed"]
    for path, raw in before.items():
        assert path.read_bytes() == raw


def test_signed_descendants_preserve_snapshot_minimum_and_original_restore_start(tmp_path):
    _, _, _, pin, last, package, report, result = prepared(tmp_path)
    first = inspect(tmp_path, pin, last, package, report, result)
    newer = observer.cycle(tmp_path / "restored", pin, minimum_receipt=last["receipt_sha256"])
    second = inspect(tmp_path, pin, newer, package, report, result)
    assert second["snapshot_scope"] == first["snapshot_scope"]
    assert second["current_scope"]["anchor_count"] == 2
    assert second["snapshot_scope"]["anchor_count"] == 1
    assert second["restore_started_at"] == first["restore_started_at"]
    assert not second["decryption_checked"]


def test_restored_control_rollback_is_not_hidden_by_an_intact_receipt(tmp_path):
    _, _, _, pin, last, package, report, result = prepared(tmp_path)
    database = tmp_path / "restored/observer.sqlite3"
    old = database.read_bytes()
    newer = observer.cycle(tmp_path / "restored", pin, minimum_receipt=last["receipt_sha256"])
    database.write_bytes(old)
    with pytest.raises(AuditTransferError, match="behind required external minimum"):
        inspect(tmp_path, pin, newer, package, report, result)


@pytest.mark.parametrize("change", ["package", "receipt", "minimum", "marker", "other_package"])
def test_broken_bindings_never_become_a_verified_restore(tmp_path, change):
    _, _, original, pin, last, package, report, result = prepared(tmp_path)
    if change == "package":
        package.write_bytes(package.read_bytes() + b"x")
    elif change == "receipt":
        (tmp_path / "restored/restore.receipt.json").write_bytes(b"changed")
    elif change == "minimum":
        last["receipt_sha256"] = "f" * 64
    elif change == "marker":
        (tmp_path / "restored/restore.pending").write_bytes(b"unfinished")
    else:
        newer = observer.cycle(original, pin, minimum_receipt=last["receipt_sha256"])
        package = tmp_path / "other.aesgcm"
        report = backup.backup(original, pin, newer["receipt_sha256"], package, KEY)
    with pytest.raises(AuditTransferError):
        inspect(tmp_path, pin, last, package, report, result)


@pytest.mark.parametrize("field,value", [
    ("started_at", "2099-01-01T00:00:00+00:00"),
    ("started_at", "2000-01-01T00:00:00+00:00"),
    ("source_locators_preserved", False), ("automatic_activation_allowed", True),
    ("independent_storage_verified", True), ("private_signing_key_included", True),
    ("schema", "generic-sqlite-restore"),
])
def test_even_newly_pinned_receipt_must_obey_typed_chronology_and_false_flags(tmp_path, field, value):
    _, _, _, pin, last, package, report, result = prepared(tmp_path)
    path = tmp_path / "restored/restore.receipt.json"
    receipt = json.loads(path.read_bytes())
    receipt[field] = value
    raw = canonical(receipt) + b"\n"
    path.write_bytes(raw)
    result["restore_receipt_sha256"] = sha(raw)
    with pytest.raises(AuditTransferError):
        inspect(tmp_path, pin, last, package, report, result)


def test_cli_inspection_accepts_no_recovery_key_and_redacts_bad_pin_errors(tmp_path):
    _, _, _, pin, last, package, report, result = prepared(tmp_path)
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    argv = [binary, "-m", "scripts.audit_witness_observer_backup", "inspect-restore",
            "--directory", str(tmp_path / "restored"), "--package", str(package),
            "--backup-sha256", report["backup_sha256"], "--profile-sha256", pin,
            "--minimum-receipt", last["receipt_sha256"],
            "--restore-receipt-sha256", result["restore_receipt_sha256"]]
    child = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert child.returncode == 0, child.stderr
    assert not json.loads(child.stdout)["decryption_checked"]
    argv[-1] = "f" * 64
    rejected = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert rejected.returncode == 1 and "refused" in rejected.stderr
    assert str(package) not in rejected.stderr


def test_inspection_opens_only_read_transactions_and_does_not_acquire_collector_lease(tmp_path, monkeypatch):
    _, _, _, pin, last, package, report, result = prepared(tmp_path)
    original = observer._database
    opens = []

    @contextmanager
    def read_only(*args, **kwargs):
        assert not kwargs.get("write") and not kwargs.get("lease")
        opens.append(True)
        with original(*args, **kwargs) as con:
            yield con

    monkeypatch.setattr(observer, "_database", read_only)
    with original(tmp_path / "restored", lease=True, profile_pin=pin):
        value = inspect(tmp_path, pin, last, package, report, result)
    assert opens and value["signed_snapshot_minimum_present"]
