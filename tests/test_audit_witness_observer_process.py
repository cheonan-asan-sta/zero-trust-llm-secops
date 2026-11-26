"""Actual owned process loss, SQLite lease release and exact receipt recovery."""

import json
import os
import sqlite3
import subprocess

import pytest
from test_audit_witness_observer import ready

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from scripts.local_process_runtime import direct_python


def run_process(args, *, timeout=30):
    executable, environment = direct_python(dict(os.environ))
    environment["AWS_EC2_METADATA_DISABLED"] = "true"
    return subprocess.run(
        [executable, *args],
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.mark.parametrize("stage", ["before_witness", "after_witness", "after_ack"])
def test_process_loss_recovers_committed_pending_and_never_rebases(tmp_path, stage):
    source, signer, key_pin, first, directory, pin = ready(tmp_path)
    # Test-owned wrapper only. Production CLI has no crash/debug environment switch.
    program = """
import os,sys
from app.services import audit_witness as w
from app.services import audit_witness_observer as o
stage=sys.argv[1]
actual=w.observe
ack=o._acknowledge
def observe(*a,**kw):
    if stage=='before_witness':os._exit(71)
    result=actual(*a,**kw)
    if stage=='after_witness':os._exit(72)
    return result
def acknowledged(*a,**kw):
    ack(*a,**kw)
    if stage=='after_ack':os._exit(73)
w.observe=observe
o._acknowledge=acknowledged
o.cycle(sys.argv[2],sys.argv[3],minimum_receipt=sys.argv[4])
"""
    stopped = run_process(["-c", program, stage, str(directory), pin, first["receipt_sha256"]])
    assert (
        stopped.returncode == {"before_witness": 71, "after_witness": 72, "after_ack": 73}[stage]
    ), stopped.stderr
    initial_state = observer.status(directory, pin, minimum_receipt=first["receipt_sha256"])
    assert initial_state["pending"] is (stage != "after_ack")
    witness_before = witness.status(signer, key_pin, minimum_receipt=first["receipt_sha256"])
    before = (signer / "journal.sqlite3").read_bytes()
    base = ["-m", "scripts.audit_witness_observer"]
    common = [
        "--directory",
        str(directory),
        "--profile-sha256",
        pin,
        "--minimum-receipt",
        first["receipt_sha256"],
    ]
    if stage == "after_ack":
        recovered = run_process([*base, "status", *common])
        assert recovered.returncode == 0, recovered.stderr
        assert json.loads(recovered.stdout)["healthy"]
    else:
        recovered = run_process([*base, "cycle", *common])
        assert recovered.returncode == 0, recovered.stderr
        assert json.loads(recovered.stdout)["recovered"] is (stage == "after_witness")
    if stage != "before_witness":
        assert (signer / "journal.sqlite3").read_bytes() == before
    current = witness.status(signer, key_pin, minimum_receipt=first["receipt_sha256"])
    assert current["receipt"]["body"]["number"] == 2
    if stage == "after_witness":
        assert current["receipt"] == witness_before["receipt"]
    with sqlite3.connect(directory / "observer.sqlite3") as con:
        assert con.execute("SELECT count(*) FROM anchors").fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM pending").fetchone()[0] == 0
    assert source.integrity()["verified_lines"] == 1


def test_bounded_watch_uses_pinned_profile_and_owned_process_only(tmp_path):
    _source, signer, key_pin, first, directory, pin = ready(tmp_path)
    watched = run_process(
        [
            "-m",
            "scripts.audit_witness_observer",
            "watch",
            "--directory",
            str(directory),
            "--profile-sha256",
            pin,
            "--minimum-receipt",
            first["receipt_sha256"],
            "--cycles",
            "2",
        ]
    )
    assert watched.returncode == 0, watched.stderr
    rows = [json.loads(line) for line in watched.stdout.splitlines()]
    assert len(rows) == 2 and all(row["healthy"] for row in rows)
    assert [row["anchor_count"] for row in rows] == [1, 2]
    assert all(row["independent_storage_verified"] is False for row in rows)
    assert (
        witness.status(signer, key_pin, minimum_receipt=first["receipt_sha256"])["receipt"]["body"][
            "number"
        ]
        == 3
    )
    private = (signer / "private.key").read_bytes().hex()
    assert private not in watched.stdout + watched.stderr
