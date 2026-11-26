"""Portable evidence for a closed witness generation, with no signing secrets."""

import base64
import sqlite3
from contextlib import closing
from pathlib import Path

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services.audit_backup import restore_sqlite
from app.services.audit_transfer import canonical, decode, fresh_stage, publish, require, sha
from app.services.audit_witness_observer_backup import _bytes

SCHEMA = "local-witness-generation-archive-1"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


def read(path):
    return _bytes(path, MAX_ARCHIVE_BYTES)


def write(raw, destination):
    with fresh_stage(destination) as (stage, target):
        observer._write(stage, raw)
        publish(stage, target)


def inspect(raw, archive_pin, key_pin, terminal_pin):
    """Verify the entire chain using independently retained pins."""
    require(all(witness._hex(pin) for pin in (archive_pin, key_pin, terminal_pin)),
            "archive, public key and terminal pins required")
    require(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE_BYTES
            and sha(raw) == archive_pin, "generation archive bytes or pin rejected")
    document = decode(raw)
    require(type(document) is dict and set(document) == {
        "schema", "stream_id", "source_locator_sha256", "public_key", "receipts",
    } and document["schema"] == SCHEMA, "generation archive shape rejected")
    encoded_key = document["public_key"]
    require(type(encoded_key) is str and len(encoded_key) == 44, "archive public key rejected")
    public = base64.b64decode(encoded_key, validate=True)
    require(len(public) == 32 and sha(public) == key_pin, "archive public key pin mismatch")
    receipts = document["receipts"]
    require(type(receipts) is list and len(receipts) == witness.MAX_RECEIPTS,
            "archive requires a complete closed generation")

    # Load only the explicit evidence fields into a fresh in-memory schema.
    # The existing verifier checks every signature, sequence, predecessor and operation ID.
    with closing(sqlite3.connect(":memory:")) as con:
        con.execute("CREATE TABLE witness_meta (stream_id, source_locator_sha256, public_key_sha256)")
        con.execute("CREATE TABLE witness_receipts (number INTEGER PRIMARY KEY, receipt TEXT)")
        con.execute("INSERT INTO witness_meta VALUES (?,?,?)",
                    (document["stream_id"], document["source_locator_sha256"], key_pin))
        con.executemany("INSERT INTO witness_receipts VALUES (?,?)",
                        ((number, canonical(receipt).decode())
                         for number, receipt in enumerate(receipts, 1)))
        stream, locator, terminal, _, _ = witness._history(
            con, public, expected_receipt=terminal_pin, exact=True,
        )
    return {
        "archive_sha256": archive_pin, "public_key_sha256": key_pin,
        "terminal_receipt_sha256": terminal_pin, "receipt_count": len(receipts),
        "stream_id": stream, "source_locator_sha256": locator,
        "audit_minimum_head": terminal["body"]["head"],
    }


def export(control, profile_pin, terminal_pin, destination):
    directory, profile, public = observer._load(control, profile_pin)
    signer = Path(profile["witness_directory"])
    output = Path(destination).resolve()
    require(not any(output.is_relative_to(location.resolve()) for location in (
        directory, signer, Path(profile["database"]),
    )), "archive output overlaps witness storage")
    with observer._database(directory) as con:
        state = observer._read(con, profile, public, terminal_pin)
    require(state["pending"] is None and state["receipt_sha256"] == terminal_pin
            and state["receipt"] is not None
            and state["receipt"]["body"]["number"] == witness.MAX_RECEIPTS,
            "archive requires the exact full, settled observer head")
    key_pin = profile["public_key_sha256"]
    _, signer_public = witness._public(signer, key_pin)
    require(public == signer_public, "archive signer public key mismatch")
    with witness._journal(signer) as con:
        stream, locator, last, _, _ = witness._history(
            con, public, expected_receipt=terminal_pin, exact=True,
        )
        require(last == state["receipt"], "archive signer and observer disagree")
        receipts = [decode(row[0]) for row in con.execute(
            "SELECT receipt FROM witness_receipts ORDER BY number"
        )]
    raw = canonical({
        "schema": SCHEMA, "stream_id": stream, "source_locator_sha256": locator,
        "public_key": base64.b64encode(public).decode("ascii"), "receipts": receipts,
    }) + b"\n"
    result = inspect(raw, sha(raw), key_pin, terminal_pin)
    write(raw, destination)
    return result


def restore_audit(raw, archive_pin, key_pin, terminal_pin, package, backup_pin, key, destination):
    evidence = inspect(raw, archive_pin, key_pin, terminal_pin)
    with fresh_stage(destination) as (stage, target):
        restored = restore_sqlite(package, stage, backup_pin, key,
                                  minimum_head=evidence["audit_minimum_head"])
        stage.chmod(0o600)
        publish(stage, target)
    return {"generation": evidence, "restored_audit": restored}
