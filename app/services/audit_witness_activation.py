"""Explicit local activation of a restored witness observer."""

import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import (
    AuditTransferError,
    canonical,
    decode,
    fresh_stage,
    publish,
    require,
    sha,
)
from app.services.federated_audit import AuditQueryUnavailable

ERRORS = (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError,
          KeyError, RecursionError, sqlite3.Error)
MAX_EVENTS = 10000


def initialize(path):
    with fresh_stage(path) as (stage, target):
        observer._write(stage, b"")
        con = sqlite3.connect(stage)
        try:
            con.execute("CREATE TABLE events (number INTEGER PRIMARY KEY, payload TEXT NOT NULL, "
                        "digest TEXT NOT NULL)")
            con.commit()
        finally:
            con.close()
        publish(stage, target)


@contextmanager
def _journal(path, *, write=False):
    path = Path(path).absolute()
    witness._file(path, 128 * 1024 * 1024)
    con = sqlite3.connect(path.as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True)
    try:
        con.execute("PRAGMA trusted_schema=OFF")
        if write:
            con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        require(con.execute(
            "SELECT type,name FROM sqlite_master WHERE type IN ('table','view','trigger')"
        ).fetchall() == [("table", "events")], "activation journal schema mismatch")
        yield con
        if write:
            con.commit()
    finally:
        con.close()


def _history(con):
    events = []
    head, active = witness.GENESIS, None
    for number, raw, digest in con.execute(
        "SELECT number,payload,digest FROM events ORDER BY number LIMIT ?", (MAX_EVENTS + 1,),
    ):
        require(number == len(events) + 1 <= MAX_EVENTS and isinstance(raw, str)
                and len(raw.encode()) <= 32768 and sha(raw.encode()) == digest,
                "activation journal integrity failure")
        event = decode(raw)
        require(event["previous"] == head, "activation journal head mismatch")
        head = digest
        if event["kind"] == "activated":
            active = {"sha256": digest, "proposal": event["proposal"]}
        events.append({"sha256": digest, **event})
    return head, active, events


def _append(con, head, count, kind, **fields):
    require(count < MAX_EVENTS, "activation journal capacity exhausted")
    raw = canonical({"kind": kind, "previous": head, "time": datetime.now(UTC).isoformat(),
                     **fields})
    require(len(raw) <= 32768, "activation record too large")
    digest = sha(raw)
    con.execute("INSERT INTO events VALUES (?,?,?)", (count + 1, raw.decode(), digest))
    return digest


def _active_pin(active):
    return witness.GENESIS if active is None else active["sha256"]


def history(path, expected_head=None):
    with _journal(path) as con:
        head, active, events = _history(con)
    require(expected_head is None or head == expected_head
            or any(event["sha256"] == expected_head for event in events),
            "external activation history pin missing")
    return {"head_sha256": head, "active_sha256": _active_pin(active), "events": events}


def _evidence(directory, package, backup_pin, receipt_pin, profile_pin, minimum):
    proof = backup.inspect_restore(package, directory, backup_pin, receipt_pin, profile_pin, minimum)
    current = proof["current_scope"]
    directory, profile, public = observer._load(directory, profile_pin)
    require(not current["pending"] and current["receipt_sha256"] != witness.GENESIS,
            "restore candidate requires a settled signed head")
    status = observer.status(directory, profile_pin, minimum_receipt=minimum)
    require(status["receipt_sha256"] == current["receipt_sha256"]
            and status["audit_minimum_verified"] and status["live_checked"]
            and status["state"] in {"healthy", "stale", "capacity_pressure", "unobserved"}
            and status["remaining_receipts"] > 0, "restore candidate disagrees with live witness")
    witness._signing_key(Path(profile["witness_directory"]), public)
    return directory, profile, public, current["receipt_sha256"]


def _review(journal, directory, package, backup_pin, receipt_pin, profile_pin, minimum,
            expected_active, active):
    journal = Path(journal).absolute()
    require(_active_pin(active) == expected_active, "activation target changed")
    directory, profile, _, current = _evidence(
        directory, package, backup_pin, receipt_pin, profile_pin, minimum,
    )
    require(not any(journal.resolve().is_relative_to(Path(path).resolve()) for path in (
        directory, profile["witness_directory"], profile["database"],
    )), "activation journal overlaps runtime storage")
    if active is not None:
        require(active["proposal"]["directory"] != str(directory.resolve()),
                "activation requires a different candidate")
        require(profile_pin == active["proposal"]["profile_sha256"],
                "activation cannot change the active witness profile")
    proposal = {
        "journal": str(journal.resolve()), "directory": str(directory.resolve()),
        "package": str(Path(package).resolve()), "backup_sha256": backup_pin,
        "restore_receipt_sha256": receipt_pin, "profile_sha256": profile_pin,
        "minimum_receipt": minimum, "candidate_head": current, "previous_active": expected_active,
    }
    return {"proposal": proposal, "approval_sha256": sha(canonical(proposal))}


def plan(journal, directory, package, backup_pin, receipt_pin, profile_pin, minimum, expected_active):
    with _journal(journal) as con:
        _, active, _ = _history(con)
    return _review(journal, directory, package, backup_pin, receipt_pin, profile_pin, minimum,
                   expected_active, active)


def activate(journal, directory, package, backup_pin, receipt_pin, profile_pin, minimum,
             expected_active, approval_pin, operator):
    require(isinstance(operator, str) and re.fullmatch(r"[A-Za-z0-9_.@-]{1,100}", operator)
            and witness._hex(approval_pin), "activation operator and approval pin required")
    attempt = uuid.uuid4().hex
    with _journal(journal, write=True) as con:
        head, _, events = _history(con)
        require(len(events) <= MAX_EVENTS - 3, "activation journal capacity exhausted")
        _append(con, head, len(events), "approval_submitted", attempt=attempt, operator=operator,
                approval_sha256=approval_pin)
    try:
        candidate = witness._directory(directory)
        with (_journal(journal, write=True) as con,
              observer._database(candidate, lease=True, profile_pin=profile_pin)):
            head, active, events = _history(con)
            reviewed = _review(journal, candidate, package, backup_pin, receipt_pin,
                               profile_pin, minimum, expected_active, active)
            require(reviewed["approval_sha256"] == approval_pin, "activation approval mismatch")
            approved = _append(con, head, len(events), "approved", attempt=attempt,
                               operator=operator, approval_sha256=approval_pin)
            selected = _append(con, approved, len(events) + 1, "activated", attempt=attempt,
                               operator=operator, proposal=reviewed["proposal"])
    except ERRORS as error:
        with _journal(journal, write=True) as con:
            head, _, events = _history(con)
            _append(con, head, len(events), "activation_failed", attempt=attempt, operator=operator,
                    error_type=type(error).__name__)
        raise
    return {"activation_sha256": selected, "attempt": attempt}


def _selected(journal, active, activation_pin):
    require(active is not None and witness._hex(activation_pin)
            and active["sha256"] == activation_pin, "approved active restore required")
    proposal = active["proposal"]
    require(proposal["journal"] == str(Path(journal).resolve()), "activation journal path mismatch")
    return proposal


def _target(proposal, minimum):
    directory, profile, public = observer._load(proposal["directory"], proposal["profile_sha256"])
    receipt = backup._bytes(directory / "restore.receipt.json", 16384)
    require(sha(receipt) == proposal["restore_receipt_sha256"], "active restore receipt changed")
    with observer._database(directory) as con:
        observer._read(con, profile, public, proposal["candidate_head"])
        observer._read(con, profile, public, minimum)
    return directory, proposal["profile_sha256"], profile


def target(journal, activation_pin, minimum):
    with _journal(journal) as con:
        _, active, _ = _history(con)
    return _target(_selected(journal, active, activation_pin), minimum)


def record_failure(journal, activation_pin, error, *, kind):
    with _journal(journal, write=True) as con:
        head, _, events = _history(con)
        _append(con, head, len(events), kind, activation_sha256=activation_pin,
                error_type=type(error).__name__)


def cycle(journal, activation_pin, minimum):
    try:
        # Hold the registry lock until this collection completes. A concurrent
        # selection cannot commit while the old managed process is signing.
        with _journal(journal, write=True) as con:
            _, active, _ = _history(con)
            proposal = _selected(journal, active, activation_pin)
            directory, profile_pin, _ = _target(proposal, minimum)
            return observer.cycle(directory, profile_pin, minimum_receipt=minimum)
    except ERRORS as error:
        record_failure(journal, activation_pin, error, kind="collection_failed")
        raise
