"""Separate local witness journal, signed receipts, explicit external minima."""

import asyncio
import copy
import json
import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_sqlite_audit import initial

from app.services import audit_witness as witness
from app.services.audit_backup import backup_sqlite, restore_sqlite
from app.services.audit_transfer import AuditTransferError, canonical, sha
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.local_process_runtime import direct_python


def ready(tmp_path):
    source = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    asyncio.run(source.save(initial(1)))
    directory = tmp_path / "witness"
    initialized = witness.initialize(directory, source.path, "local-audit")
    pin = initialized["public_key_sha256"]
    observed = witness.observe(directory, source.path, pin, expected_receipt=witness.GENESIS)
    return source, directory, pin, observed


def check(source, directory, pin, observed, **options):
    return witness.inspect(
        source.path,
        observed["receipt"],
        (directory / "public.key").read_bytes(),
        public_key_sha256=pin,
        stream_id="local-audit",
        expected_receipt=observed["receipt_sha256"],
        **options,
    )


def test_signed_receipt_is_read_only_and_contains_no_event_or_private_key(tmp_path):
    source, directory, pin, observed = ready(tmp_path)
    before = source.path.read_bytes()
    result = check(source, directory, pin, observed)
    assert result["minimum_head_verified"]
    assert result["observed_head"]["seq"] == 1
    assert not result["automatic_activation_allowed"]
    assert not result["independent_storage_verified"]
    assert not result["latest_live_state_verified"]
    raw = canonical(observed)
    assert initial(1).event_id.encode() not in raw
    assert (directory / "private.key").read_bytes().hex().encode() not in raw
    assert str(source.path).encode() not in raw
    assert source.path.read_bytes() == before
    (directory / "private.key").unlink()
    assert (
        witness.status(directory, pin, minimum_receipt=observed["receipt_sha256"])["receipt"]
        == observed["receipt"]
    )
    assert check(source, directory, pin, observed)["minimum_head_verified"]
    with pytest.raises(FileNotFoundError):
        witness.observe(directory, source.path, pin, expected_receipt=observed["receipt_sha256"])


def test_valid_old_db_and_witness_journal_rollback_fail_against_pinned_receipt(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    old_source = source.path.read_bytes()
    old_journal = (directory / "journal.sqlite3").read_bytes()
    asyncio.run(source.save(initial(2)))
    current = witness.observe(directory, source.path, pin, expected_receipt=first["receipt_sha256"])
    source.path.write_bytes(old_source)
    assert SQLiteAuditStore.open_existing(source.path).integrity()["ok"]
    journal_before = (directory / "journal.sqlite3").read_bytes()
    with pytest.raises(AuditTransferError, match="older"):
        witness.observe(directory, source.path, pin, expected_receipt=current["receipt_sha256"])
    with pytest.raises(AuditTransferError, match="older"):
        check(source, directory, pin, current)
    assert (directory / "journal.sqlite3").read_bytes() == journal_before
    (directory / "journal.sqlite3").write_bytes(old_journal)
    with pytest.raises(AuditTransferError, match="behind"):
        witness.status(directory, pin, minimum_receipt=current["receipt_sha256"])


@pytest.mark.parametrize("field", ["signature", "stream_id", "head", "number", "previous_receipt"])
def test_forged_receipt_cannot_be_resealed_by_only_rehashing(tmp_path, field):
    source, directory, pin, observed = ready(tmp_path)
    forged = copy.deepcopy(observed)
    if field == "signature":
        sig = forged["receipt"]["signature"]
        forged["receipt"]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    elif field == "head":
        forged["receipt"]["body"]["head"]["digest"] = "a" * 64
    else:
        forged["receipt"]["body"][field] = {
            "stream_id": "another-stream",
            "number": 2,
            "previous_receipt": "b" * 64,
        }[field]
    forged["receipt_sha256"] = sha(canonical(forged["receipt"]))
    with pytest.raises(AuditTransferError):
        check(source, directory, pin, forged)


def test_explicit_receipt_pin_and_public_key_pin_cannot_be_changed(tmp_path):
    source, directory, pin, observed = ready(tmp_path)
    bad = dict(observed, receipt_sha256="c" * 64)
    with pytest.raises(AuditTransferError, match="pin"):
        check(source, directory, pin, bad)
    with pytest.raises(AuditTransferError, match="pin"):
        witness.status(directory, "d" * 64, minimum_receipt=observed["receipt_sha256"])


def test_same_expected_receipt_allows_only_one_writer_and_status_can_inspect(tmp_path):
    source, directory, pin, first = ready(tmp_path)

    def write(_):
        try:
            return witness.observe(
                directory, source.path, pin, expected_receipt=first["receipt_sha256"]
            )
        except AuditTransferError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(write, range(4)))
    winners = [item for item in results if item]
    assert len(winners) == 1
    current = witness.status(directory, pin, minimum_receipt=first["receipt_sha256"])
    assert current["receipt"]["body"]["number"] == 2
    assert current["receipt_sha256"] == winners[0]["receipt_sha256"]
    with pytest.raises(AuditTransferError, match="history changed"):
        witness.observe(directory, source.path, pin, expected_receipt=witness.GENESIS)


def test_witness_journal_tampering_and_source_retargeting_are_rejected(tmp_path):
    _source, directory, pin, observed = ready(tmp_path)
    other = SQLiteAuditStore(tmp_path / "another.sqlite3")
    asyncio.run(other.save(initial(1)))
    with pytest.raises(AuditTransferError, match="locator"):
        witness.observe(directory, other.path, pin, expected_receipt=observed["receipt_sha256"])
    with sqlite3.connect(directory / "journal.sqlite3") as con:
        receipt = copy.deepcopy(observed["receipt"])
        receipt["body"]["head"]["digest"] = "e" * 64
        con.execute("UPDATE witness_receipts SET receipt=?", (canonical(receipt).decode(),))
    with pytest.raises(AuditTransferError, match="signature"):
        witness.status(directory, pin, minimum_receipt=observed["receipt_sha256"])


def test_wrong_signing_key_cannot_append_or_reinitialize(tmp_path):
    source, directory, pin, observed = ready(tmp_path)
    (directory / "private.key").write_bytes(os.urandom(32))
    with pytest.raises(AuditTransferError, match="signer"):
        witness.observe(directory, source.path, pin, expected_receipt=observed["receipt_sha256"])
    with pytest.raises(FileExistsError):
        witness.initialize(directory, source.path, "local-audit")
    assert (
        witness.status(directory, pin, minimum_receipt=observed["receipt_sha256"])["receipt_sha256"]
        == observed["receipt_sha256"]
    )


def test_equal_length_fork_and_encrypted_restored_old_candidate_are_rejected(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    older = source.path.read_bytes()
    key = os.urandom(32)
    package = tmp_path / "old.enc"
    backup = backup_sqlite(source, package, key)
    asyncio.run(source.save(initial(2)))
    latest = witness.observe(directory, source.path, pin, expected_receipt=first["receipt_sha256"])
    target = tmp_path / "restore-candidate.sqlite3"
    restore_sqlite(package, target, backup["backup_sha256"], key)
    candidate = SQLiteAuditStore.open_existing(target)
    with pytest.raises(AuditTransferError, match="older"):
        check(candidate, directory, pin, latest)
    assert check(candidate, directory, pin, first)["source_locator_matches"] is False
    source.path.write_bytes(older)
    asyncio.run(source.save(initial(3)))
    assert source.integrity()["verified_lines"] == latest["receipt"]["body"]["head"]["seq"]
    with pytest.raises(AuditTransferError, match="conflict"):
        witness.observe(directory, source.path, pin, expected_receipt=latest["receipt_sha256"])


@pytest.mark.parametrize("damage", ["truncated", "metadata", "duplicate_json"])
def test_damaged_journal_never_repairs_or_reissues_receipt(tmp_path, damage):
    source, directory, pin, first = ready(tmp_path)
    latest = witness.observe(directory, source.path, pin, expected_receipt=first["receipt_sha256"])
    path = directory / "journal.sqlite3"
    with sqlite3.connect(path) as con:
        if damage == "truncated":
            con.execute("DELETE FROM witness_receipts WHERE number=2")
        elif damage == "metadata":
            con.execute("UPDATE witness_meta SET stream_id='different-stream'")
        else:
            con.execute(
                "UPDATE witness_receipts SET receipt=? WHERE number=2",
                ('{"body":{},"body":{},"signature":"bad"}',),
            )
    before = path.read_bytes()
    with pytest.raises(AuditTransferError):
        witness.observe(directory, source.path, pin, expected_receipt=latest["receipt_sha256"])
    assert path.read_bytes() == before


def test_capacity_fails_without_automatic_retention_or_history_deletion(tmp_path, monkeypatch):
    source, directory, pin, first = ready(tmp_path)
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 1)
    before = (directory / "journal.sqlite3").read_bytes()
    with pytest.raises(AuditTransferError, match="capacity"):
        witness.observe(directory, source.path, pin, expected_receipt=first["receipt_sha256"])
    assert (directory / "journal.sqlite3").read_bytes() == before


def test_source_inside_witness_directory_is_rejected_after_path_normalization(tmp_path):
    directory = tmp_path / "witness"
    directory.mkdir(mode=0o700)
    source = SQLiteAuditStore(directory / "audit.sqlite3")
    asyncio.run(source.save(initial(1)))
    aliased = directory / ".." / "witness" / "audit.sqlite3"
    with pytest.raises(AuditTransferError, match="outside"):
        witness.initialize(directory, aliased, "local-audit")
    assert not (directory / "private.key").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_world_readable_signer_and_linked_journal_are_rejected(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    private = directory / "private.key"
    private.chmod(0o644)
    with pytest.raises(AuditTransferError, match="permission"):
        witness.observe(directory, source.path, pin, expected_receipt=first["receipt_sha256"])
    private.chmod(0o600)
    path = directory / "journal.sqlite3"
    held = directory / "held.sqlite3"
    path.rename(held)
    path.symlink_to(held)
    with pytest.raises(AuditTransferError, match="link"):
        witness.status(directory, pin, minimum_receipt=first["receipt_sha256"])


def test_real_separate_signer_process_and_read_only_candidate_check(tmp_path):
    source = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    asyncio.run(source.save(initial(1)))
    directory = tmp_path / "process-witness"
    executable, environment = direct_python(dict(os.environ))
    environment["AWS_EC2_METADATA_DISABLED"] = "true"

    def run(*arguments):
        result = subprocess.run(
            [executable, "-m", "scripts.audit_witness", *arguments],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return result

    initialized = run(
        "init",
        "--state-dir",
        str(directory),
        "--database",
        str(source.path),
        "--stream-id",
        "local-audit",
    )
    assert initialized.returncode == 0, initialized.stderr
    pin = json.loads(initialized.stdout)["public_key_sha256"]
    observed_process = run(
        "observe",
        "--state-dir",
        str(directory),
        "--database",
        str(source.path),
        "--public-key-sha256",
        pin,
        "--expected-receipt",
        witness.GENESIS,
    )
    assert observed_process.returncode == 0, observed_process.stderr
    observed = json.loads(observed_process.stdout)
    receipt = tmp_path / "selected-receipt.json"
    receipt.write_bytes(canonical(observed["receipt"]))
    verified = run(
        "inspect",
        "--database",
        str(source.path),
        "--receipt-file",
        str(receipt),
        "--expected-receipt",
        observed["receipt_sha256"],
        "--public-key-file",
        str(directory / "public.key"),
        "--public-key-sha256",
        pin,
        "--stream-id",
        "local-audit",
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["minimum_head_verified"]
    refused = run(
        "observe",
        "--state-dir",
        str(directory),
        "--database",
        str(source.path),
        "--public-key-sha256",
        pin,
        "--expected-receipt",
        witness.GENESIS,
    )
    assert refused.returncode == 1 and not refused.stdout
    assert "no automatic retry" in refused.stderr
