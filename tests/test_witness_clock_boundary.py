"""Clock changes between durable intent and signing must not poison recovery."""

import json
import os
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from test_audit_witness_observer import ready

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services.audit_transfer import AuditTransferError
from scripts.local_process_runtime import direct_python


def clock(instant):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant
    return Clock


def test_clock_regression_after_pending_commit_does_not_persist_unacknowledgeable_receipt(tmp_path, monkeypatch):
    _, signer, _, first, directory, pin = ready(tmp_path)
    prepared_at = datetime.now(UTC) + timedelta(seconds=10)
    before = (signer / "journal.sqlite3").read_bytes()
    monkeypatch.setattr(observer, "datetime", clock(prepared_at))
    monkeypatch.setattr(witness, "datetime", clock(prepared_at - timedelta(seconds=5)))
    with pytest.raises(AuditTransferError):
        observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    # A refusal at the consumer is too late: the signer must not commit a
    # receipt whose time precedes the already-durable pending intent.
    assert (signer / "journal.sqlite3").read_bytes() == before
    with sqlite3.connect(directory / "observer.sqlite3") as con:
        pending = json.loads(con.execute("SELECT payload FROM pending").fetchone()[0])
    later = prepared_at + timedelta(seconds=1)
    monkeypatch.setattr(observer, "datetime", clock(later))
    monkeypatch.setattr(witness, "datetime", clock(later))
    recovered = observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    assert recovered["recovered"] is False
    result = witness.status(signer, first["receipt"]["body"]["public_key_sha256"],
                            minimum_receipt=recovered["receipt_sha256"])
    assert result["receipt"]["body"]["observation_id"] == pending["observation_id"]
    assert result["receipt"]["body"]["number"] == 2


def test_clock_change_after_signing_remains_replayable_when_clock_recovers(tmp_path, monkeypatch):
    _, signer, key_pin, first, directory, pin = ready(tmp_path)
    prepared = datetime.now(UTC) + timedelta(seconds=10)
    observed = prepared + timedelta(seconds=5)
    monkeypatch.setattr(observer, "datetime", clock(prepared))
    monkeypatch.setattr(witness, "datetime", clock(observed))
    with pytest.raises(AuditTransferError):
        observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    committed = (signer / "journal.sqlite3").read_bytes()
    later = observed + timedelta(seconds=5)
    monkeypatch.setattr(observer, "datetime", clock(later))
    monkeypatch.setattr(witness, "datetime", clock(later))
    result = observer.cycle(directory, pin, minimum_receipt=first["receipt_sha256"])
    assert result["recovered"] is True
    assert (signer / "journal.sqlite3").read_bytes() == committed
    current = witness.status(signer, key_pin, minimum_receipt=result["receipt_sha256"])
    assert datetime.fromisoformat(current["receipt"]["body"]["observed_at"]) == observed
    monkeypatch.setattr(observer, "datetime", datetime)
    state = observer.status(directory, pin, minimum_receipt=result["receipt_sha256"], now=later)
    assert state["age_seconds"] == 5


@pytest.mark.parametrize("bound", [True, 1, "", "broken", "2026-01-01", "a" * 65])
def test_invalid_or_naive_minimum_time_never_mutates_witness(tmp_path, bound):
    source, signer, key_pin, first, _, _ = ready(tmp_path)
    before = (signer / "journal.sqlite3").read_bytes()
    with pytest.raises(AuditTransferError):
        witness.observe(signer, source.path, key_pin, expected_receipt=first["receipt_sha256"],
                        observation_id="a" * 32, minimum_observed_at=bound)
    assert (signer / "journal.sqlite3").read_bytes() == before


def test_time_bound_is_opt_in_only_for_explicit_v2_operation(tmp_path):
    source, signer, key_pin, first, _, _ = ready(tmp_path)
    before = (signer / "journal.sqlite3").read_bytes()
    with pytest.raises(AuditTransferError, match="minimum time rejected"):
        witness.observe(signer, source.path, key_pin, expected_receipt=first["receipt_sha256"],
                        minimum_observed_at=datetime.now(UTC).isoformat())
    assert (signer / "journal.sqlite3").read_bytes() == before


def test_real_cli_replay_cannot_evade_a_later_time_bound_by_resigning(tmp_path):
    source, signer, key_pin, first, _, _ = ready(tmp_path)
    minimum = datetime.now(UTC).isoformat()
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    argv = [binary, "-m", "scripts.audit_witness", "observe", "--state-dir", str(signer),
            "--database", str(source.path), "--public-key-sha256", key_pin,
            "--expected-receipt", first["receipt_sha256"], "--observation-id", "a" * 32,
            "--minimum-observed-at", minimum]
    initial = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert initial.returncode == 0, initial.stderr
    receipt = json.loads(initial.stdout)
    before = (signer / "journal.sqlite3").read_bytes()
    replay = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert replay.returncode == 0 and json.loads(replay.stdout)["replayed"] is True
    assert json.loads(replay.stdout)["receipt"] == receipt["receipt"]
    argv[-1] = (datetime.fromisoformat(receipt["receipt"]["body"]["observed_at"])
                + timedelta(seconds=1)).isoformat()
    denied = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert denied.returncode == 1 and "refused" in denied.stderr
    assert (signer / "journal.sqlite3").read_bytes() == before
