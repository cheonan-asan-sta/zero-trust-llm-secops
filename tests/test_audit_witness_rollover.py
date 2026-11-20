"""Local generation handoff through the operator CLI and pinned watch."""

import asyncio
import base64
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_audit_witness_observer import ready
from test_sqlite_audit import initial

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services import audit_witness_rollover as rollover
from app.services.audit_transfer import AuditTransferError, canonical, sha


def target(root, source, control, profile, terminal, label):
    signer = root / f"signer-{label}"
    key = witness.initialize(signer, source.path, "local-audit")["public_key_sha256"]
    return control, profile, terminal, signer, key, root / f"generation-{label}.json"


def full_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 2)
    source, signer, _, first, control, profile = ready(tmp_path)
    before = source.path.read_bytes()
    asyncio.run(source.save(initial(2)))
    terminal = observer.cycle(control, profile, minimum_receipt=first["receipt_sha256"])
    args = target(tmp_path, source, control, profile, terminal["receipt_sha256"], "two")
    return source, signer, before, args


def test_rejects_pending_or_nonterminal_old_head(tmp_path, monkeypatch):
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 2)
    source, _, _, first, control, profile = ready(tmp_path)
    args = target(tmp_path, source, control, profile, first["receipt_sha256"], "early")
    with pytest.raises(AuditTransferError, match="settled observer"):
        rollover.plan(*args)
    terminal = observer.cycle(control, profile, minimum_receipt=first["receipt_sha256"])
    args = (*args[:2], terminal["receipt_sha256"], *args[3:])
    # Preserve a previously stored unfinished intent; approval may not clear it.
    with observer._database(control, write=True) as con:
        pending = canonical({"observation_id": "a" * 32, "predecessor": args[2],
                             "started_at": first["receipt"]["body"]["observed_at"]})
        con.execute("INSERT INTO pending VALUES (1,?,?)", (pending.decode(), sha(pending)))
    with pytest.raises(AuditTransferError, match="settled observer"):
        rollover.plan(*args)
    assert not args[-1].exists()


def test_approval_rejects_source_behind_terminal_before_signing(tmp_path, monkeypatch):
    source, _, before, args = full_fixture(tmp_path, monkeypatch)
    approval = rollover.plan(*args)["approval_sha256"]
    journal = args[3] / "journal.sqlite3"
    original = journal.read_bytes()
    with pytest.raises(AuditTransferError, match="operator approval"):
        rollover.approve(*args, "a" * 64)
    source.path.write_bytes(before)
    with pytest.raises(AuditTransferError, match="older than required checkpoint"):
        rollover.approve(*args, approval)
    assert journal.read_bytes() == original
    assert not args[-1].exists()


def test_response_loss_reuses_first_signature_and_supports_next_generation(tmp_path, monkeypatch):
    source, old_signer, _, args = full_fixture(tmp_path, monkeypatch)
    approval = rollover.plan(*args)["approval_sha256"]
    archived = [(old_signer / "journal.sqlite3"), (args[0] / "observer.sqlite3"), source.path]
    old_bytes = [path.read_bytes() for path in archived]
    observe = witness.observe

    def lost_reply(*parameters, **options):
        observe(*parameters, **options)
        raise OSError("simulated lost reply")

    with monkeypatch.context() as fault:
        fault.setattr(witness, "observe", lost_reply)
        with pytest.raises(OSError, match="lost reply"):
            rollover.approve(*args, approval)
    assert not args[-1].exists()
    journal = args[3] / "journal.sqlite3"
    initial_bytes = journal.read_bytes()
    result = rollover.approve(*args, approval)
    assert journal.read_bytes() == initial_bytes
    assert [path.read_bytes() for path in archived] == old_bytes
    assert rollover.approve(*args, approval) == result
    with pytest.raises(AuditTransferError, match="record pin"):
        rollover.verify(args[-1], "a" * 64)
    terminal = observer.cycle(result["directory"], result["profile_sha256"],
                              minimum_receipt=result["minimum_receipt"])
    assert rollover.approve(*args, approval) == result
    following = target(tmp_path, source, result["directory"], result["profile_sha256"],
                       terminal["receipt_sha256"], "three")
    third = rollover.approve(*following, rollover.plan(*following)["approval_sha256"])
    assert rollover.verify(following[-1], third["record_sha256"]) == third
    assert rollover.verify(args[-1], result["record_sha256"]) == result


def test_concurrent_distinct_approvals_publish_only_one_successor(tmp_path, monkeypatch):
    source, _, _, args = full_fixture(tmp_path, monkeypatch)
    clone = tmp_path / "previous-control-copy"
    shutil.copytree(args[0], clone)
    other = target(tmp_path, source, clone, *args[1:3], "competing")
    approvals = [(item, rollover.plan(*item)["approval_sha256"]) for item in (args, other)]

    def approve(pair):
        parameters, approval = pair
        try:
            return rollover.approve(*parameters, approval)
        except AuditTransferError as error:
            assert "reserved" in str(error)
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, approvals))
    assert sum(result is not None for result in results) == 1
    loser = (args, other)[results.index(None)]
    assert not loser[-1].exists()
    assert witness.status(loser[3], loser[4], minimum_receipt=witness.GENESIS)["receipt"] is None


def test_real_capacity_cli_approval_and_watch(tmp_path):
    source, signer, _, first, control, profile = ready(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes((signer / "private.key").read_bytes())
    receipts = []
    previous = first["receipt_sha256"]
    for number in range(2, witness.MAX_RECEIPTS + 1):
        body = dict(first["receipt"]["body"], schema=witness.OPERATION_SCHEMA,
                    previous_receipt=previous, number=number, observation_id=f"{number:032x}")
        signature = key.sign(witness._signature_prefix(body["schema"]) + canonical(body))
        receipt = {"body": body, "signature": base64.b64encode(signature).decode()}
        receipts.append((number, canonical(receipt).decode()))
        previous = sha(canonical(receipt))
    with witness._journal(signer, write=True) as con:
        con.executemany("INSERT INTO witness_receipts VALUES (?,?)", receipts)
    with observer._database(control, write=True) as con:
        con.executemany("INSERT INTO anchors VALUES (?,?)",
                        ((number - 1, receipt) for number, receipt in receipts))
    args = target(tmp_path, source, control, profile, previous, "real")
    command = [sys.executable, "-m", "scripts.audit_witness_rollover"]
    flags = [part for flag, value in zip(
        ("--old-control", "--old-profile-sha256", "--old-terminal-sha256",
         "--new-signer", "--new-key-sha256", "--record"), args, strict=True,
    ) for part in (flag, str(value))]

    def run(*options):
        result = subprocess.run(command + list(options), capture_output=True,
                                text=True, encoding="utf-8", timeout=180, check=True)
        return json.loads(result.stdout)

    plan = run("plan", *flags)
    assert plan["proposal"]["old_terminal_receipt"]["body"]["number"] == 4096
    approved = run("approve", *flags, "--approval-sha256", plan["approval_sha256"])
    record_flags = ("--record", str(args[-1]), "--record-sha256", approved["record_sha256"])
    assert run("verify", *record_flags) == approved
    watched = run("watch", *record_flags, "--minimum-receipt", approved["minimum_receipt"],
                  "--cycles", "1")
    assert watched["cycle_success"] is True and watched["anchor_count"] == 1
    assert witness.status(args[3], args[4], minimum_receipt=approved["minimum_receipt"])[
        "receipt"
    ]["body"]["number"] == 2
