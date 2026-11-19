"""Pinned local collection never adopts an unknown head or refreshes a replay."""

import asyncio
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from test_audit_witness import ready as witness_ready
from test_sqlite_audit import initial

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services.audit_transfer import AuditTransferError


def ready(tmp_path):
    source, signer, key_pin, first = witness_ready(tmp_path)
    directory = tmp_path / "observer"
    profile = observer.initialize(
        directory,
        signer,
        source.path,
        key_pin,
        expected_receipt=first["receipt_sha256"],
        interval_seconds=1,
        max_age_seconds=30,
        capacity_warning=0,
    )
    return source, signer, key_pin, first, directory, profile["profile_sha256"]


def read(directory, pin, minimum, **kwargs):
    return observer.status(directory, pin, minimum_receipt=minimum["receipt_sha256"], **kwargs)


def cycle(directory, pin, minimum):
    return observer.cycle(directory, pin, minimum_receipt=minimum["receipt_sha256"])


def test_initial_profile_copies_only_public_key_and_collects_exact_next_heads(tmp_path):
    source, signer, key_pin, first, directory, pin = ready(tmp_path)
    assert not (directory / "private.key").exists()
    assert (directory / "public.key").read_bytes() == (signer / "public.key").read_bytes()
    before = source.path.read_bytes()
    result = cycle(directory, pin, first)
    assert result["recovered"] is False
    status = read(directory, pin, first)
    assert status["healthy"] and status["audit_minimum_verified"]
    assert status["anchor_count"] == 1 and not status["pending"]
    cycle(directory, pin, first)
    assert read(directory, pin, first)["anchor_count"] == 2
    assert (
        witness.status(signer, key_pin, minimum_receipt=first["receipt_sha256"])["receipt"]["body"][
            "number"
        ]
        == 3
    )
    assert source.path.read_bytes() == before


@pytest.mark.parametrize("after_commit", [False, True])
def test_pending_operation_recovers_without_adopting_or_resigning(
    tmp_path, monkeypatch, after_commit
):
    _source, signer, key_pin, first, directory, pin = ready(tmp_path)
    actual = witness.observe

    def interrupted(*args, **kwargs):
        if after_commit:
            actual(*args, **kwargs)
        raise OSError("controlled local response loss")

    monkeypatch.setattr(witness, "observe", interrupted)
    with pytest.raises(OSError):
        cycle(directory, pin, first)
    pending_state = read(directory, pin, first)
    assert pending_state["pending"] and not pending_state["healthy"]
    with sqlite3.connect(directory / "observer.sqlite3") as con:
        original_id = json.loads(con.execute("SELECT payload FROM pending").fetchone()[0])[
            "observation_id"
        ]
    committed = (signer / "journal.sqlite3").read_bytes()
    monkeypatch.setattr(witness, "observe", actual)
    recovered = cycle(directory, pin, first)
    assert recovered["recovered"] is after_commit
    if after_commit:
        assert (signer / "journal.sqlite3").read_bytes() == committed
    current = witness.status(signer, key_pin, minimum_receipt=first["receipt_sha256"])
    assert current["receipt"]["body"]["observation_id"] == original_id
    assert current["receipt"]["body"]["number"] == 2
    assert read(directory, pin, first)["healthy"]
    future = datetime.fromisoformat(current["receipt"]["body"]["observed_at"]) + timedelta(
        seconds=31
    )
    assert read(directory, pin, first, now=future)["state"] == "stale"


def test_other_writer_is_never_automatically_adopted(tmp_path):
    source, signer, key_pin, first, directory, pin = ready(tmp_path)
    unknown = witness.observe(
        signer, source.path, key_pin, expected_receipt=first["receipt_sha256"]
    )
    assert read(directory, pin, first)["state"] == "witness_advanced"
    with pytest.raises(AuditTransferError, match="predecessor changed"):
        cycle(directory, pin, first)
    current = read(directory, pin, first)
    assert current["pending"] and current["receipt_sha256"] == first["receipt_sha256"]
    assert not current["healthy"]
    with pytest.raises(AuditTransferError, match="external minimum"):
        read(directory, pin, unknown)


def test_audit_rollback_blocks_status_and_new_collection_without_changing_anchor(tmp_path):
    source, signer, key_pin, first, directory, pin = ready(tmp_path)
    old = source.path.read_bytes()
    asyncio.run(source.save(initial(2)))
    last = cycle(directory, pin, first)
    live = source.path.read_bytes()
    source.path.write_bytes(old)
    assert read(directory, pin, first)["state"] == "unavailable"
    with pytest.raises(AuditTransferError):
        cycle(directory, pin, first)
    assert read(directory, pin, first)["receipt_sha256"] == last["receipt_sha256"]
    source.path.write_bytes(live)
    assert cycle(directory, pin, first)["recovered"] is False
    assert read(directory, pin, first)["healthy"]
    assert witness.status(signer, key_pin, minimum_receipt=last["receipt_sha256"])[
        "minimum_receipt_present"
    ]


def test_control_rollback_cannot_cross_external_minimum_or_silently_follow_signer(tmp_path):
    _source, _signer, _key_pin, first, directory, pin = ready(tmp_path)
    cycle(directory, pin, first)
    old = (directory / "observer.sqlite3").read_bytes()
    latest = cycle(directory, pin, first)
    (directory / "observer.sqlite3").write_bytes(old)
    with pytest.raises(AuditTransferError, match="external minimum"):
        read(directory, pin, latest)
    assert read(directory, pin, first)["state"] == "witness_advanced"
    with pytest.raises(AuditTransferError, match="predecessor changed"):
        cycle(directory, pin, first)


def test_freshness_unobserved_rows_and_clock_regression_are_explicit(tmp_path):
    source, _signer, _key_pin, first, directory, pin = ready(tmp_path)
    cycle(directory, pin, first)
    profile = json.loads((directory / "profile.json").read_bytes())
    with sqlite3.connect(directory / "observer.sqlite3") as con:
        receipt = json.loads(con.execute("SELECT receipt FROM anchors").fetchone()[0])
    instant = datetime.fromisoformat(receipt["body"]["observed_at"])
    assert (
        read(directory, pin, first, now=instant - timedelta(seconds=1))["state"]
        == "clock_regression"
    )
    assert (
        read(
            directory, pin, first, now=instant + timedelta(seconds=profile["max_age_seconds"] + 1)
        )["state"]
        == "stale"
    )
    asyncio.run(source.save(initial(2)))
    current = read(directory, pin, first)
    assert current["state"] == "unobserved" and current["unobserved_rows"] == 1
    assert not current["healthy"] and current["audit_minimum_verified"]


def test_offline_verification_never_claims_live_health_and_does_not_need_signing_key(tmp_path):
    _source, signer, _key_pin, first, directory, pin = ready(tmp_path)
    cycle(directory, pin, first)
    (signer / "private.key").unlink()
    offline = read(directory, pin, first, offline=True)
    assert offline["anchor_verified"] and not offline["healthy"] and not offline["live_checked"]
    assert offline["state"] == "offline"
    with pytest.raises(FileNotFoundError):
        cycle(directory, pin, first)
    assert read(directory, pin, first)["pending"]


def test_full_signer_never_rotates_or_deletes_history_to_keep_collecting(tmp_path, monkeypatch):
    _source, signer, _key_pin, first, directory, pin = ready(tmp_path)
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 2)
    cycle(directory, pin, first)
    before = (signer / "journal.sqlite3").read_bytes()
    assert read(directory, pin, first)["state"] == "capacity_exhausted"
    with pytest.raises(AuditTransferError, match="capacity"):
        cycle(directory, pin, first)
    assert (signer / "journal.sqlite3").read_bytes() == before
    after = read(directory, pin, first)
    assert after["state"] == "capacity_exhausted" and after["pending"] is False


def test_lost_final_capacity_receipt_recovers_before_rejecting_further_work(tmp_path, monkeypatch):
    _source, signer, _key_pin, first, directory, pin = ready(tmp_path)
    monkeypatch.setattr(witness, "MAX_RECEIPTS", 2)
    actual = witness.observe

    def lost(*args, **kwargs):
        actual(*args, **kwargs)
        raise OSError("test-owned lost final-capacity response")

    monkeypatch.setattr(witness, "observe", lost)
    with pytest.raises(OSError, match="final-capacity"):
        cycle(directory, pin, first)
    before = (signer / "journal.sqlite3").read_bytes()
    assert read(directory, pin, first)["pending"] is True
    monkeypatch.setattr(witness, "observe", actual)
    result = cycle(directory, pin, first)
    assert result["recovered"] and (signer / "journal.sqlite3").read_bytes() == before
    assert read(directory, pin, first)["state"] == "capacity_exhausted"
    with pytest.raises(AuditTransferError, match="capacity"):
        cycle(directory, pin, first)
    after = read(directory, pin, first)
    assert after["state"] == "capacity_exhausted" and after["pending"] is False


def test_lease_prevents_another_collector_from_mutating_pending_state(tmp_path, monkeypatch):
    _source, _signer, _key_pin, first, directory, pin = ready(tmp_path)
    actual = witness.observe
    entered, release = threading.Event(), threading.Event()

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return actual(*args, **kwargs)

    monkeypatch.setattr(witness, "observe", blocked)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(cycle, directory, pin, first)
        try:
            assert entered.wait(10)
            before = (directory / "observer.sqlite3").read_bytes()
            with pytest.raises(observer.ObserverBusy):
                cycle(directory, pin, first)
            assert (directory / "observer.sqlite3").read_bytes() == before
        finally:
            release.set()
        assert future.result(timeout=10)["recovered"] is False


@pytest.mark.parametrize(
    "policy",
    [
        {"interval_seconds": 0},
        {"interval_seconds": True},
        {"max_age_seconds": 1},
        {"max_age_seconds": float("inf")},
        {"capacity_warning": -1},
    ],
)
def test_invalid_policy_does_not_create_observer_state(tmp_path, policy):
    source, signer, key_pin, first = witness_ready(tmp_path)
    directory = tmp_path / "rejected-observer"
    with pytest.raises(AuditTransferError, match="policy"):
        observer.initialize(
            directory,
            signer,
            source.path,
            key_pin,
            expected_receipt=first["receipt_sha256"],
            **policy,
        )
    assert not directory.exists()


def test_profile_pin_and_corrupt_pending_cannot_reset_trust(tmp_path):
    _source, _signer, _key_pin, first, directory, pin = ready(tmp_path)
    with pytest.raises(AuditTransferError, match="profile pin"):
        read(directory, "f" * 64, first)
    with sqlite3.connect(directory / "observer.sqlite3") as con:
        con.execute("INSERT INTO pending VALUES (1,'{}','bad')")
    with pytest.raises(AuditTransferError, match="checksum"):
        cycle(directory, pin, first)


def test_initializer_does_not_discover_a_newer_unconfirmed_bootstrap(tmp_path):
    source, signer, key_pin, first = witness_ready(tmp_path)
    witness.observe(signer, source.path, key_pin, expected_receipt=first["receipt_sha256"])
    directory = tmp_path / "unconfirmed-observer"
    with pytest.raises(AuditTransferError, match="history changed"):
        observer.initialize(
            directory, signer, source.path, key_pin, expected_receipt=first["receipt_sha256"]
        )
    assert not directory.exists()


def test_signed_but_lost_witness_commit_cannot_be_acknowledged(tmp_path, monkeypatch):
    _source, signer, _key_pin, first, directory, pin = ready(tmp_path)
    actual = witness.observe
    before = (signer / "journal.sqlite3").read_bytes()
    saved = {}

    def lost_commit(*args, **kwargs):
        result = actual(*args, **kwargs)
        saved["committed"] = (signer / "journal.sqlite3").read_bytes()
        (signer / "journal.sqlite3").write_bytes(before)
        return result

    monkeypatch.setattr(witness, "observe", lost_commit)
    with pytest.raises(AuditTransferError, match="history changed"):
        cycle(directory, pin, first)
    assert read(directory, pin, first)["pending"]
    with sqlite3.connect(directory / "observer.sqlite3") as con:
        assert con.execute("SELECT count(*) FROM anchors").fetchone()[0] == 0
    (signer / "journal.sqlite3").write_bytes(saved["committed"])
    monkeypatch.setattr(witness, "observe", actual)
    assert cycle(directory, pin, first)["recovered"]
    assert read(directory, pin, first)["healthy"]
