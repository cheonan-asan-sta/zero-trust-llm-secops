"""Recover the exact signed observation without adopting another writer's head."""

import asyncio
import copy
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from test_audit_witness import check, ready
from test_sqlite_audit import initial

from app.services import audit_witness as witness
from app.services.audit_transfer import AuditTransferError, canonical, sha
from scripts.local_process_runtime import direct_python

ID = "1" * 32


def observe(source, directory, pin, previous, ident=ID):
    return witness.observe(
        directory,
        source.path,
        pin,
        expected_receipt=previous["receipt_sha256"],
        observation_id=ident,
    )


def test_v1_then_v2_exact_replay_keeps_signed_time_bytes_and_journal(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    result = observe(source, directory, pin, first)
    assert first["receipt"]["body"]["schema"] == witness.SCHEMA
    assert result["receipt"]["body"]["schema"] == witness.OPERATION_SCHEMA
    assert result["receipt"]["body"]["observation_id"] == ID
    assert result["replayed"] is False
    assert check(source, directory, pin, result)["minimum_head_verified"]
    before = (directory / "journal.sqlite3").read_bytes()
    replay = observe(source, directory, pin, first)
    assert replay["replayed"] is True
    assert replay["receipt"] == result["receipt"]
    assert replay["receipt_sha256"] == result["receipt_sha256"]
    assert (directory / "journal.sqlite3").read_bytes() == before
    # Manual callers still require the exact current head, without idempotence.
    with pytest.raises(AuditTransferError, match="history changed"):
        witness.observe(directory, source.path, pin, expected_receipt=first["receipt_sha256"])


def test_reused_id_cannot_jump_over_another_writer_or_change_predecessor(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    second = observe(source, directory, pin, first)
    with pytest.raises(AuditTransferError, match="exact operation"):
        observe(source, directory, pin, second)
    with pytest.raises(AuditTransferError, match="predecessor changed"):
        observe(source, directory, pin, first, "2" * 32)
    third = observe(source, directory, pin, second, "2" * 32)
    before = (directory / "journal.sqlite3").read_bytes()
    with pytest.raises(AuditTransferError, match="exact operation"):
        observe(source, directory, pin, first)
    with pytest.raises(AuditTransferError, match="exact operation"):
        observe(source, directory, pin, third)
    assert (directory / "journal.sqlite3").read_bytes() == before


def test_exact_replay_still_rejects_current_audit_rollback(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    old = source.path.read_bytes()
    asyncio.run(source.save(initial(2)))
    result = observe(source, directory, pin, first)
    source.path.write_bytes(old)
    with pytest.raises(AuditTransferError, match="older"):
        observe(source, directory, pin, first)
    assert (
        witness.status(directory, pin, minimum_receipt=result["receipt_sha256"])["receipt_sha256"]
        == result["receipt_sha256"]
    )


@pytest.mark.parametrize("value", ["", "A" * 32, "f" * 31, "f" * 33, 1, [], True])
def test_invalid_operation_is_rejected_before_any_file_access(value):
    with pytest.raises(AuditTransferError, match="observation ID rejected"):
        witness.observe(
            "must-not-open",
            "must-not-open",
            "a" * 64,
            expected_receipt=witness.GENESIS,
            observation_id=value,
        )


def test_mixed_receipts_do_not_allow_stripping_or_resealing_operation_fields(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    result = observe(source, directory, pin, first)
    for change in ("strip", "schema", "replace"):
        value = copy.deepcopy(result)
        if change == "strip":
            value["receipt"]["body"].pop("observation_id")
        elif change == "schema":
            value["receipt"]["body"]["schema"] = witness.SCHEMA
        else:
            value["receipt"]["body"]["observation_id"] = "2" * 32
        value["receipt_sha256"] = sha(canonical(value["receipt"]))
        with pytest.raises(AuditTransferError):
            check(source, directory, pin, value)


def test_same_operation_concurrency_signs_only_once(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: observe(source, directory, pin, first), range(4)))
    assert sum(not item["replayed"] for item in results) == 1
    assert len({item["receipt_sha256"] for item in results}) == 1
    last = witness.status(directory, pin, minimum_receipt=first["receipt_sha256"])
    assert last["receipt"]["body"]["number"] == 2


def test_operational_clock_cannot_move_backwards_before_signing(tmp_path, monkeypatch):
    source, directory, pin, first = ready(tmp_path)
    fixed = datetime.fromisoformat(first["receipt"]["body"]["observed_at"]) - timedelta(seconds=1)

    class BackwardsClock(datetime):
        @classmethod
        def now(cls, tz=UTC):
            return fixed.astimezone(tz)

    monkeypatch.setattr(witness, "datetime", BackwardsClock)
    before = (directory / "journal.sqlite3").read_bytes()
    with pytest.raises(AuditTransferError, match="clock regressed"):
        observe(source, directory, pin, first)
    assert (directory / "journal.sqlite3").read_bytes() == before


def test_replay_survives_full_capacity_without_an_extra_receipt(tmp_path, monkeypatch):
    source, directory, pin, first = ready(tmp_path)
    second = observe(source, directory, pin, first)
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 2)
    assert observe(source, directory, pin, first)["receipt_sha256"] == second["receipt_sha256"]
    with pytest.raises(AuditTransferError, match="capacity"):
        observe(source, directory, pin, second, "2" * 32)


def test_separate_cli_process_recovers_the_same_operation_after_lost_response(tmp_path):
    source, directory, pin, first = ready(tmp_path)
    executable, environment = direct_python(dict(os.environ))
    environment["AWS_EC2_METADATA_DISABLED"] = "true"
    command = [
        executable,
        "-m",
        "scripts.audit_witness",
        "observe",
        "--state-dir",
        str(directory),
        "--database",
        str(source.path),
        "--public-key-sha256",
        pin,
        "--expected-receipt",
        first["receipt_sha256"],
        "--observation-id",
        ID,
    ]
    before_source = source.path.read_bytes()
    first_run = subprocess.run(
        command, env=environment, capture_output=True, text=True, timeout=30, check=False
    )
    assert first_run.returncode == 0, first_run.stderr
    # The caller may lose this output; its persistent request ID is unchanged.
    after_commit = (directory / "journal.sqlite3").read_bytes()
    recovered = subprocess.run(
        command, env=environment, capture_output=True, text=True, timeout=30, check=False
    )
    assert recovered.returncode == 0, recovered.stderr
    one, two = json.loads(first_run.stdout), json.loads(recovered.stdout)
    assert one["replayed"] is False and two["replayed"] is True
    assert one["receipt"] == two["receipt"]
    assert one["receipt_sha256"] == two["receipt_sha256"]
    assert (directory / "journal.sqlite3").read_bytes() == after_commit
    assert source.path.read_bytes() == before_source
