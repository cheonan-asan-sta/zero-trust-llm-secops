"""Explicit local signing witness; not a remote trust boundary or a WORM store.

The witness independently reads and verifies SQLite audit history. Its separately
held journal and caller-pinned receipt detect source rollback. A host admin who
controls the signer, journal and external pins remains outside this guarantee.
"""

import base64
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.services.audit_backup import read_key
from app.services.audit_checkpoint import _locator, _verified_head
from app.services.audit_transfer import canonical, decode, require, sha
from app.services.sqlite_audit import SQLiteAuditStore

SCHEMA = "local-sqlite-audit-witness-1"
OPERATION_SCHEMA = "local-sqlite-audit-witness-2"
GENESIS = "0" * 64
MAX_RECEIPTS = 4096
HEX = re.compile(r"[a-f0-9]{64}")
STREAM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
OPERATION = re.compile(r"[a-f0-9]{32}")


def _signature_prefix(schema):
    return (
        b"zero-trust-audit-witness-v2\x00"
        if schema == OPERATION_SCHEMA
        else b"zero-trust-audit-witness-v1\x00"
    )


def _operation(value):
    return isinstance(value, str) and OPERATION.fullmatch(value) is not None


def _hex(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _file(path, limit):
    require(not path.is_symlink(), "witness file link rejected")
    info = path.stat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
        "witness file type/size rejected",
    )
    if os.name == "posix":
        require(
            info.st_mode & 0o077 == 0 and info.st_uid == os.geteuid(),
            "witness file ownership/permission rejected",
        )


def _directory(directory):
    directory = Path(directory).absolute()
    require(
        directory.is_dir() and not directory.is_symlink(), "existing witness directory required"
    )
    if os.name == "posix":
        info = directory.stat()
        require(
            info.st_mode & 0o077 == 0 and info.st_uid == os.geteuid(),
            "witness directory ownership/permission rejected",
        )
    return directory


@contextmanager
def _journal(directory, *, write=False):
    path = directory / "journal.sqlite3"
    _file(path, 128 * 1024 * 1024)
    con = sqlite3.connect(
        path.as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True, timeout=5
    )
    try:
        con.execute("PRAGMA trusted_schema=OFF")
        con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        tables = {
            row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        require(tables == {"witness_meta", "witness_receipts"}, "witness schema rejected")
        yield con
        if write:
            con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def _public(directory, pin):
    require(_hex(pin), "explicit public key pin required")
    path = directory / "public.key"
    _file(path, 32)
    raw = path.read_bytes()
    require(len(raw) == 32 and sha(raw) == pin, "witness public key pin mismatch")
    return Ed25519PublicKey.from_public_bytes(raw), raw


def verify_receipt(receipt, public_raw, *, stream_id, expected_receipt):
    """Authenticate an explicitly pinned exported receipt, without a private key."""
    require(
        type(receipt) is dict
        and set(receipt) == {"body", "signature"}
        and _hex(expected_receipt)
        and sha(canonical(receipt)) == expected_receipt,
        "witness receipt fields/pin rejected",
    )
    body = receipt["body"]
    require(type(body) is dict, "witness receipt body rejected")
    require(isinstance(body.get("schema"), str), "witness receipt schema rejected")
    operational = body.get("schema") == OPERATION_SCHEMA
    require(
        set(body)
        == (
            {
                "schema",
                "stream_id",
                "source_locator_sha256",
                "public_key_sha256",
                "number",
                "previous_receipt",
                "observed_at",
                "head",
            }
            | ({"observation_id"} if operational else set())
        ),
        "witness receipt body rejected",
    )
    require(
        body["schema"] in {SCHEMA, OPERATION_SCHEMA}
        and (not operational or _operation(body["observation_id"]))
        and body["stream_id"] == stream_id
        and isinstance(stream_id, str)
        and STREAM.fullmatch(stream_id)
        and _hex(body["source_locator_sha256"])
        and body["public_key_sha256"] == sha(public_raw)
        and type(body["number"]) is int
        and 1 <= body["number"] <= MAX_RECEIPTS
        and _hex(body["previous_receipt"]),
        "witness receipt scope rejected",
    )
    head = body["head"]
    require(
        type(head) is dict
        and set(head) == {"seq", "digest"}
        and type(head["seq"]) is int
        and 0 <= head["seq"] <= SQLiteAuditStore.MAX_ROWS
        and _hex(head["digest"])
        and (head["seq"] != 0 or head["digest"] == GENESIS),
        "witness audit head rejected",
    )
    require(
        isinstance(body["observed_at"], str)
        and datetime.fromisoformat(body["observed_at"]).utcoffset() is not None,
        "witness observation time rejected",
    )
    require(
        isinstance(receipt["signature"], str) and len(receipt["signature"]) == 88,
        "witness signature encoding rejected",
    )
    signature = base64.b64decode(receipt["signature"], validate=True)
    require(len(signature) == 64, "witness signature size rejected")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature, _signature_prefix(body["schema"]) + canonical(body)
        )
    except InvalidSignature:
        require(False, "witness signature rejected")
    return body


def _history(con, public_raw, *, expected_receipt, exact):
    require(_hex(expected_receipt), "explicit witness receipt pin required")
    metadata = con.execute(
        "SELECT stream_id, source_locator_sha256, public_key_sha256 FROM witness_meta"
    ).fetchall()
    require(len(metadata) == 1, "witness metadata rejected")
    stream_id, locator, public_pin = metadata[0]
    require(
        isinstance(stream_id, str)
        and STREAM.fullmatch(stream_id)
        and _hex(locator)
        and public_pin == sha(public_raw),
        "witness metadata scope rejected",
    )
    rows = con.execute(
        "SELECT number, receipt FROM witness_receipts ORDER BY number LIMIT ?", (MAX_RECEIPTS + 1,)
    ).fetchall()
    require(len(rows) <= MAX_RECEIPTS, "witness receipt capacity exceeded")
    previous, last, seen = GENESIS, None, expected_receipt == GENESIS
    operations = {}
    for number, raw in rows:
        require(
            isinstance(raw, str) and len(raw.encode()) <= 16384, "witness receipt size rejected"
        )
        receipt = decode(raw)
        digest = sha(canonical(receipt))
        body = verify_receipt(receipt, public_raw, stream_id=stream_id, expected_receipt=digest)
        if body["schema"] == OPERATION_SCHEMA:
            ident = body["observation_id"]
            require(ident not in operations, "witness observation ID reused")
            operations[ident] = receipt
        require(
            body["number"] == number == (1 if last is None else last["body"]["number"] + 1)
            and body["previous_receipt"] == previous
            and body["source_locator_sha256"] == locator,
            "witness history chain rejected",
        )
        if last is not None:
            older = last["body"]["head"]
            require(
                body["head"]["seq"] >= older["seq"]
                and (body["head"]["seq"] != older["seq"] or body["head"] == older),
                "witness head regressed",
            )
            if body["schema"] == OPERATION_SCHEMA:
                require(
                    datetime.fromisoformat(body["observed_at"])
                    >= datetime.fromisoformat(last["body"]["observed_at"]),
                    "witness observation clock regressed",
                )
        previous, last = digest, receipt
        seen = seen or digest == expected_receipt
    require(
        seen and (not exact or previous == expected_receipt),
        "witness history changed/behind required receipt; inspect without retrying write",
    )
    return stream_id, locator, last, previous, operations


def initialize(directory, database, stream_id):
    require(isinstance(stream_id, str) and STREAM.fullmatch(stream_id), "witness stream rejected")
    store = SQLiteAuditStore.open_existing(database)
    directory = Path(directory).absolute()
    require(
        not store.path.resolve().is_relative_to(directory.resolve()),
        "audit must be outside witness directory",
    )
    directory.mkdir(mode=0o700, exist_ok=False)
    private = Ed25519PrivateKey.generate()
    secret = private.private_bytes_raw()
    public = private.public_key().public_bytes_raw()
    for name, raw in (("private.key", secret), ("public.key", public)):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    db = directory / "journal.sqlite3"
    fd = os.open(db, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    con = sqlite3.connect(db)
    try:
        con.execute(
            "CREATE TABLE witness_meta (stream_id TEXT NOT NULL, source_locator_sha256 TEXT NOT NULL, public_key_sha256 TEXT NOT NULL)"
        )
        con.execute(
            "CREATE TABLE witness_receipts (number INTEGER PRIMARY KEY, receipt TEXT NOT NULL)"
        )
        con.execute(
            "INSERT INTO witness_meta VALUES (?,?,?)", (stream_id, _locator(store), sha(public))
        )
        con.commit()
    finally:
        con.close()
    return {
        "public_key_sha256": sha(public),
        "receipt_sha256": GENESIS,
        "stream_id": stream_id,
        "independent_storage_verified": False,
    }


def status(directory, public_key_sha256, *, minimum_receipt):
    directory = _directory(directory)
    _key, raw = _public(directory, public_key_sha256)
    with _journal(directory) as con:
        stream, _locator_hash, receipt, digest, _operations = _history(
            con, raw, expected_receipt=minimum_receipt, exact=False
        )
    return {
        "stream_id": stream,
        "receipt": receipt,
        "receipt_sha256": digest,
        "minimum_receipt_present": True,
        "independent_storage_verified": False,
    }


def observe(directory, database, public_key_sha256, *, expected_receipt, observation_id=None):
    require(observation_id is None or _operation(observation_id), "witness observation ID rejected")
    directory = _directory(directory)
    _key, public = _public(directory, public_key_sha256)
    private_path = directory / "private.key"
    _file(private_path, 32)
    secret = private_path.read_bytes()
    require(len(secret) == 32, "witness private key size rejected")
    # read_key also enforces the existing platform-specific key-file contract.
    private = Ed25519PrivateKey.from_private_bytes(read_key(private_path, sha(secret)))
    require(private.public_key().public_bytes_raw() == public, "witness signer key mismatch")
    store = SQLiteAuditStore.open_existing(database)
    require(
        not store.path.resolve().is_relative_to(directory.resolve()),
        "audit must be outside witness directory",
    )
    with _journal(directory, write=True) as con:
        stream, locator, last, previous, operations = _history(
            con, public, expected_receipt=expected_receipt, exact=observation_id is None
        )
        require(_locator(store) == locator, "witness source locator changed")
        replayed = observation_id is not None and observation_id in operations
        if replayed:
            require(
                operations[observation_id] == last
                and last["body"]["previous_receipt"] == expected_receipt,
                "witness observation is not the current exact operation",
            )
            # A committed response may be recovered, never refreshed or resigned.
            # The current DB still has to contain the already witnessed history.
            with store._transaction() as audit:
                _verified_head(store, audit, last["body"]["head"])
            return {
                "receipt": last,
                "receipt_sha256": previous,
                "replayed": True,
                "automatic_activation_allowed": False,
                "independent_storage_verified": False,
            }
        require(previous == expected_receipt, "witness observation predecessor changed")
        number = 1 if last is None else last["body"]["number"] + 1
        require(number <= MAX_RECEIPTS, "witness receipt capacity exceeded")
        minimum = last["body"]["head"] if last else None
        with store._transaction() as audit:
            seq, digest = _verified_head(store, audit, minimum)
        observed_at = datetime.now(UTC)
        if observation_id is not None and last is not None:
            require(
                observed_at >= datetime.fromisoformat(last["body"]["observed_at"]),
                "witness observation clock regressed",
            )
        body = {
            "schema": SCHEMA if observation_id is None else OPERATION_SCHEMA,
            "stream_id": stream,
            "source_locator_sha256": locator,
            "public_key_sha256": public_key_sha256,
            "number": number,
            "previous_receipt": previous,
            "observed_at": observed_at.isoformat(),
            "head": {"seq": seq, "digest": digest},
        }
        if observation_id is not None:
            body["observation_id"] = observation_id
        signature = private.sign(_signature_prefix(body["schema"]) + canonical(body))
        receipt = {"body": body, "signature": base64.b64encode(signature).decode("ascii")}
        con.execute(
            "INSERT INTO witness_receipts VALUES (?,?)", (number, canonical(receipt).decode())
        )
    result = {
        "receipt": receipt,
        "receipt_sha256": sha(canonical(receipt)),
        "automatic_activation_allowed": False,
        "independent_storage_verified": False,
    }
    if observation_id is not None:
        result["replayed"] = False
    return result


def inspect(database, receipt, public_raw, *, public_key_sha256, stream_id, expected_receipt):
    """Verify a candidate DB against an explicitly selected witness minimum."""
    require(
        type(public_raw) is bytes
        and len(public_raw) == 32
        and _hex(public_key_sha256)
        and sha(public_raw) == public_key_sha256,
        "witness public key pin mismatch",
    )
    body = verify_receipt(
        receipt, public_raw, stream_id=stream_id, expected_receipt=expected_receipt
    )
    store = SQLiteAuditStore.open_existing(database)
    with store._transaction() as con:
        seq, digest = _verified_head(store, con, body["head"])
    return {
        "minimum_head_verified": True,
        "observed_head": {"seq": seq, "digest": digest},
        "witness_head": body["head"],
        "receipt_sha256": expected_receipt,
        "source_locator_matches": _locator(store) == body["source_locator_sha256"],
        "automatic_activation_allowed": False,
        "independent_storage_verified": False,
        "latest_live_state_verified": False,
    }
