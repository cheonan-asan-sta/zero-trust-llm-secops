"""Typed encrypted control snapshots preserve external minima and pending IDs."""

import base64
import copy
import json
import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_audit_witness_observer import ready

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import AuditTransferError, canonical, sha
from scripts.local_process_runtime import direct_python

KEY = bytes(range(32))  # Public fixed test key; never a deployment secret.


def fixture(tmp_path):
    source, signer, key_pin, first, directory, profile_pin = ready(tmp_path)
    result = observer.cycle(directory, profile_pin, minimum_receipt=first["receipt_sha256"])
    package = tmp_path / "control.aesgcm"
    report = backup.backup(directory, profile_pin, result["receipt_sha256"], package, KEY)
    return source, signer, key_pin, directory, profile_pin, result, package, report


def restore(tmp_path, profile, minimum, package, report, *, name="restored", key=KEY):
    return backup.restore(package, tmp_path / name, report["backup_sha256"], profile,
                          minimum["receipt_sha256"], key)


def test_snapshot_restores_only_public_control_state_and_never_activates(tmp_path):
    source, signer, key_pin, directory, pin, last, package, report = fixture(tmp_path)
    before = {p: p.read_bytes() for p in (source.path, signer / "journal.sqlite3",
                                        directory / "observer.sqlite3")}
    result = restore(tmp_path, pin, last, package, report)
    target = tmp_path / "restored"
    assert not result["automatic_activation_allowed"] and not result["private_signing_key_included"]
    assert set(os.listdir(target)) == {*backup.NAMES, "lease.sqlite3", "restore.receipt.json"}
    assert not (target / "restore.pending").exists()
    for path, raw in before.items():
        assert path.read_bytes() == raw
    state = observer.status(target, pin, minimum_receipt=last["receipt_sha256"])
    assert state["healthy"] and state["anchor_count"] == 1
    receipt = (target / "restore.receipt.json").read_bytes()
    assert sha(receipt) == result["restore_receipt_sha256"]
    assert json.loads(receipt)["source_locators_preserved"] is True
    encrypted = package.read_bytes()
    assert (signer / "private.key").read_bytes() not in encrypted
    assert (directory / "profile.json").read_bytes() not in encrypted
    assert (target / "public.key").read_bytes() == (signer / "public.key").read_bytes()
    # Candidate use is a separate explicit operation; no service was changed.
    observer.cycle(target, pin, minimum_receipt=last["receipt_sha256"])
    assert witness.status(signer, key_pin, minimum_receipt=last["receipt_sha256"])["receipt"]["body"]["number"] == 3


@pytest.mark.parametrize("after_commit", [False, True])
def test_pending_snapshot_recovers_only_original_operation_not_a_new_signing_request(tmp_path, monkeypatch, after_commit):
    _, signer, key_pin, first, directory, pin = ready(tmp_path)
    actual = witness.observe

    def lost(*args, **kwargs):
        if after_commit:
            actual(*args, **kwargs)
        raise OSError("test response loss")

    monkeypatch.setattr(witness, "observe", lost)
    with pytest.raises(OSError):
        observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    with sqlite3.connect(directory / "observer.sqlite3") as con:
        pending = con.execute("SELECT payload FROM pending").fetchone()[0]
    package = tmp_path / "pending.aesgcm"
    report = backup.backup(directory, pin, first["receipt_sha256"], package, KEY)
    restore(tmp_path, pin, first, package, report)
    with sqlite3.connect(tmp_path / "restored/observer.sqlite3") as con:
        assert con.execute("SELECT payload FROM pending").fetchone()[0] == pending
    monkeypatch.setattr(witness, "observe", actual)
    result = observer.cycle(tmp_path / "restored", pin, minimum_receipt=first["receipt_sha256"])
    assert result["recovered"] is after_commit
    current = witness.status(signer, key_pin, minimum_receipt=result["receipt_sha256"])
    assert current["receipt"]["body"]["observation_id"] == json.loads(pending)["observation_id"]
    assert current["receipt"]["body"]["number"] == 2


def test_old_backup_cannot_meet_a_new_external_minimum_and_never_rebases(tmp_path):
    _, _, _, directory, pin, last, package, report = fixture(tmp_path)
    newer = observer.cycle(directory, pin, minimum_receipt=last["receipt_sha256"])
    with pytest.raises(AuditTransferError, match="behind required external minimum"):
        restore(tmp_path, pin, newer, package, report)
    assert not (tmp_path / "restored").exists()
    # An explicitly older minimum permits forensic review, not live head adoption.
    restore(tmp_path, pin, last, package, report)
    state = observer.status(tmp_path / "restored", pin, minimum_receipt=last["receipt_sha256"])
    assert state["state"] == "witness_advanced" and not state["healthy"]
    with pytest.raises(AuditTransferError):
        observer.cycle(tmp_path / "restored", pin, minimum_receipt=last["receipt_sha256"])


@pytest.mark.parametrize("corruption", ["package", "key", "profile_pin", "trailing", "truncated"])
def test_corruption_or_wrong_key_pin_is_rejected_before_creating_candidate(tmp_path, corruption):
    _, _, _, _, pin, last, package, report = fixture(tmp_path)
    key = KEY
    if corruption == "key":
        key = b"z" * 32
    elif corruption == "profile_pin":
        pin = "f" * 64
    else:
        raw = bytearray(package.read_bytes())
        if corruption == "package":
            raw[-1] ^= 1
        elif corruption == "trailing":
            raw += b"extra"
        else:
            raw = raw[:16]
        package.write_bytes(raw)
        if corruption != "package":
            report["backup_sha256"] = sha(raw)  # held pin alone cannot authenticate bad AEAD bytes
    with pytest.raises(AuditTransferError):
        restore(tmp_path, pin, last, package, report, key=key)
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize("change", ["unknown_file", "scope", "payload", "extra_field", "algorithm", "future_time"])
def test_even_authenticated_manifest_cannot_bypass_typed_signed_history(tmp_path, change):
    _, _, _, _, pin, last, package, report = fixture(tmp_path)
    raw = package.read_bytes()
    length = int.from_bytes(raw[8:12], "big")
    header = json.loads(raw[12:12 + length])
    nonce = base64.urlsafe_b64decode(header["nonce"])
    payload = AESGCM(KEY).decrypt(nonce, raw[12 + length:], backup.MAGIC + raw[12:12 + length])
    if change == "unknown_file":
        header["files"][-1]["name"] = "private.key"
    elif change == "scope":
        header["scope"]["receipt_sha256"] = "f" * 64
    elif change == "payload":
        payload = payload[:-1] + bytes([payload[-1] ^ 1])
    elif change == "extra_field":
        header["admin_override"] = True
    elif change == "algorithm":
        header["algorithm"] = "none"
    else:
        header["created_at"] = "2099-01-01T00:00:00+00:00"
    new_header = canonical(header)
    encoded = backup.MAGIC + len(new_header).to_bytes(4, "big") + new_header
    encoded += AESGCM(KEY).encrypt(nonce, payload, backup.MAGIC + new_header)
    package.write_bytes(encoded)
    report["backup_sha256"] = sha(encoded)
    with pytest.raises(AuditTransferError):
        restore(tmp_path, pin, last, package, report)
    assert not (tmp_path / "restored").exists()


def test_live_collector_lease_prevents_racing_snapshot_and_existing_destination_is_safe(tmp_path):
    _, _, _, directory, pin, last, package, report = fixture(tmp_path)
    with observer._database(directory, lease=True, profile_pin=pin), pytest.raises(observer.ObserverBusy):
        backup.backup(directory, pin, last["receipt_sha256"], tmp_path / "busy.aesgcm", KEY)
    assert not (tmp_path / "busy.aesgcm").exists()
    before = package.read_bytes()
    with pytest.raises(AuditTransferError, match="must be fresh"):
        backup.backup(directory, pin, last["receipt_sha256"], package, KEY)
    assert package.read_bytes() == before
    restore(tmp_path, pin, last, package, report)
    with pytest.raises(AuditTransferError, match="must be fresh"):
        restore(tmp_path, pin, last, package, report)


def test_mutation_during_encryption_denies_publication(tmp_path, monkeypatch):
    _, _, _, directory, pin, last, _, _ = fixture(tmp_path)
    actual = backup.AESGCM

    class Changed:
        def __init__(self, key):
            self.inner = actual(key)

        def encrypt(self, *args):
            result = self.inner.encrypt(*args)
            (directory / "profile.json").write_bytes(b"changed")
            return result

    monkeypatch.setattr(backup, "AESGCM", Changed)
    with pytest.raises(AuditTransferError, match="pin mismatch"):
        backup.backup(directory, pin, last["receipt_sha256"], tmp_path / "denied.aesgcm", KEY)
    assert not (tmp_path / "denied.aesgcm").exists()


def test_interrupted_restore_cannot_be_used_as_a_running_observer(tmp_path, monkeypatch):
    _, _, _, _, pin, last, package, report = fixture(tmp_path)
    actual = observer._write
    target = tmp_path / "restored"

    def interrupted(path, raw):
        if path == target / "lease.sqlite3":
            raise OSError("test interruption before candidate completes")
        return actual(path, raw)

    monkeypatch.setattr(observer, "_write", interrupted)
    with pytest.raises(OSError):
        restore(tmp_path, pin, last, package, report)
    assert (target / "restore.pending").is_file()
    for method in (observer.cycle, observer.status):
        with pytest.raises(AuditTransferError, match="restore is incomplete"):
            method(target, pin, minimum_receipt=last["receipt_sha256"])


def test_cli_backup_and_restore_use_external_key_pin_and_redact_errors(tmp_path):
    _, _, _, directory, pin, last, _, _ = fixture(tmp_path)
    key = tmp_path / "recovery.key"
    key.write_bytes(KEY)
    key.chmod(0o600)
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    common = ["--profile-sha256", pin, "--minimum-receipt", last["receipt_sha256"],
              "--key-file", str(key), "--key-sha256", sha(KEY)]
    base = [binary, "-m", "scripts.audit_witness_observer_backup"]
    package = tmp_path / "cli.aesgcm"
    result = subprocess.run([*base, "backup", *common, "--directory", str(directory),
                             "--destination", str(package)], capture_output=True, text=True,
                            timeout=30, env=env, check=False)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    restored = subprocess.run([*base, "restore", *common, "--package", str(package),
                               "--backup-sha256", report["backup_sha256"],
                               "--destination", str(tmp_path / "cli-restored")],
                              capture_output=True, text=True, timeout=30, env=env, check=False)
    assert restored.returncode == 0, restored.stderr
    assert not json.loads(restored.stdout)["automatic_activation_allowed"]
    wrong = copy.copy(common)
    wrong[-1] = "0" * 64
    rejected = subprocess.run([*base, "restore", *wrong, "--package", str(package),
                               "--backup-sha256", report["backup_sha256"],
                               "--destination", str(tmp_path / "denied")],
                              capture_output=True, text=True, timeout=30, env=env, check=False)
    assert rejected.returncode == 1 and "refused" in rejected.stderr
    assert KEY.hex() not in rejected.stderr and str(key) not in rejected.stderr
    assert not (tmp_path / "denied").exists()


def test_concurrent_restore_candidates_have_one_fresh_destination_winner(tmp_path):
    _, _, _, _, pin, last, package, report = fixture(tmp_path)

    def attempt(_index):
        try:
            restore(tmp_path, pin, last, package, report)
            return True
        except (AuditTransferError, FileExistsError):
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(attempt, range(2))) == 1
    assert observer.status(tmp_path / "restored", pin, minimum_receipt=last["receipt_sha256"])["healthy"]


def test_backup_rejects_clock_regression_and_storage_overlap_before_publication(tmp_path, monkeypatch):
    _, _, _, directory, pin, last, _, _ = fixture(tmp_path)
    with pytest.raises(AuditTransferError, match="overlaps"):
        backup.backup(directory, pin, last["receipt_sha256"], directory / "leak.aesgcm", KEY)

    class Past(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2000, 1, 1, tzinfo=UTC)

    monkeypatch.setattr(backup, "datetime", Past)
    with pytest.raises(AuditTransferError, match="clock regressed"):
        backup.backup(directory, pin, last["receipt_sha256"], tmp_path / "past.aesgcm", KEY)
    assert not (tmp_path / "past.aesgcm").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file ownership and nofollow contract")
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public_mode", "fifo"])
def test_restore_refuses_unsafe_package_objects_before_candidate_creation(tmp_path, kind):
    _, _, _, _, pin, last, package, report = fixture(tmp_path)
    if kind == "symlink":
        alias = tmp_path / "linked.aesgcm"
        alias.symlink_to(package)
        package = alias
    elif kind == "hardlink":
        os.link(package, tmp_path / "alias.aesgcm")
    elif kind == "public_mode":
        package.chmod(0o644)
    else:
        package.unlink()
        os.mkfifo(package, mode=0o600)
    with pytest.raises(AuditTransferError):
        restore(tmp_path, pin, last, package, report)
    assert not (tmp_path / "restored").exists()


def test_package_size_bound_is_enforced_by_open_file_not_just_path_stat(tmp_path):
    path = tmp_path / "bounded"
    path.write_bytes(b"0123456789")
    path.chmod(0o600)
    with pytest.raises(AuditTransferError, match="type/size"):
        backup._bytes(path, 9)
    assert backup._bytes(path, 10) == b"0123456789"


@pytest.mark.parametrize("change", ["drop_anchor", "signature", "unexpected_view", "pending_predecessor"])
def test_authenticated_sqlite_payload_still_requires_signed_history_and_exact_schema(tmp_path, change):
    _, _, _, _, pin, last, package, report = fixture(tmp_path)
    raw = package.read_bytes()
    length = int.from_bytes(raw[8:12], "big")
    header = json.loads(raw[12:12 + length])
    nonce = base64.urlsafe_b64decode(header["nonce"])
    payload = AESGCM(KEY).decrypt(nonce, raw[12 + length:], backup.MAGIC + raw[12:12 + length])
    offset = 0
    files = {}
    for item in header["files"]:
        files[item["name"]] = payload[offset:offset + item["bytes"]]
        offset += item["bytes"]
    tampered = tmp_path / "tampered.sqlite3"
    tampered.write_bytes(files["observer.sqlite3"])
    with sqlite3.connect(tampered) as con:
        if change == "drop_anchor":
            con.execute("DELETE FROM anchors")
        elif change == "signature":
            value = json.loads(con.execute("SELECT receipt FROM anchors").fetchone()[0])
            value["body"]["observation_id"] = "f" * 32
            con.execute("UPDATE anchors SET receipt=?", (json.dumps(value),))
        elif change == "unexpected_view":
            con.execute("CREATE VIEW shadow AS SELECT receipt FROM anchors")
        else:
            pending = canonical({"observation_id": "a" * 32, "predecessor": "f" * 64,
                                 "started_at": datetime.now(UTC).isoformat()}).decode()
            con.execute("INSERT INTO pending VALUES (1,?,?)", (pending, sha(pending.encode())))
    files["observer.sqlite3"] = tampered.read_bytes()
    chunks = []
    for item in header["files"]:
        content = files[item["name"]]
        item.update(bytes=len(content), sha256=sha(content))
        chunks.append(content)
    payload = b"".join(chunks)
    header.update(payload_bytes=len(payload), payload_sha256=sha(payload))
    raw_header = canonical(header)
    encoded = backup.MAGIC + len(raw_header).to_bytes(4, "big") + raw_header
    encoded += AESGCM(KEY).encrypt(nonce, payload, backup.MAGIC + raw_header)
    package.write_bytes(encoded)
    report["backup_sha256"] = sha(encoded)
    with pytest.raises(AuditTransferError):
        restore(tmp_path, pin, last, package, report)
    assert not (tmp_path / "restored").exists()
