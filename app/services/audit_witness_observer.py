"""Local witness collection with a separately persisted, pinned acknowledgement.

No remote trust boundary, grant issuer, restore activator or automatic rebase.
The runner may recover only its own durable pending observation. A local admin
controlling the signing key, both journals and external pins remains trusted.
"""

import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.services import audit_witness as witness
from app.services.audit_transfer import AuditTransferError, canonical, decode, require, sha
from app.services.federated_audit import AuditQueryUnavailable
from app.services.sqlite_audit import SQLiteAuditStore

SCHEMA = "local-audit-witness-observer-1"
PROFILE_LIMIT = 65536


class ObserverBusy(AuditTransferError):
    pass


def _time(value):
    require(isinstance(value, str) and len(value) <= 64, "observer time rejected")
    result = datetime.fromisoformat(value)
    require(result.utcoffset() is not None, "observer aware time required")
    return result


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _separate(directory, witness_directory, database):
    control, signer, source = (p.resolve() for p in (directory, witness_directory, database))
    require(
        not control.is_relative_to(signer)
        and not signer.is_relative_to(control)
        and not source.is_relative_to(control)
        and not source.is_relative_to(signer),
        "observer, witness and audit storage must be separate",
    )


@contextmanager
def _database(directory, *, write=False, lease=False, profile_pin=None):
    path = directory / ("lease.sqlite3" if lease else "observer.sqlite3")
    witness._file(path, 128 * 1024 * 1024)
    require(path.stat().st_size > 0, "observer database must already be initialized")
    con = sqlite3.connect(
        path.as_uri() + ("?mode=rw" if write or lease else "?mode=ro"),
        uri=True,
        timeout=0 if lease else 5,
    )
    try:
        con.execute("PRAGMA trusted_schema=OFF")
        try:
            con.execute("BEGIN IMMEDIATE" if write or lease else "BEGIN")
        except sqlite3.OperationalError as error:
            if lease and getattr(error, "sqlite_errorcode", 0) & 255 in {5, 6}:
                raise ObserverBusy("witness observer already running") from None
            raise
        objects = con.execute(
            "SELECT type,name FROM sqlite_master WHERE type IN ('table','view','trigger')"
        ).fetchall()
        required = {("table", "lease")} if lease else {("table", "anchors"), ("table", "pending")}
        require(set(objects) == required, "observer database schema rejected")
        if lease:
            require(
                con.execute("SELECT profile_sha256 FROM lease").fetchall() == [(profile_pin,)],
                "observer lease profile rejected",
            )
        yield con
        if write:
            con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def _load(directory, profile_pin, *, restoring=False):
    directory = witness._directory(directory)
    require(restoring or not ((directory / "restore.pending").exists()
                             or (directory / "restore.pending").is_symlink()),
            "observer restore is incomplete; candidate must not run")
    path = directory / "profile.json"
    witness._file(path, PROFILE_LIMIT)
    raw = path.read_bytes()
    require(witness._hex(profile_pin) and sha(raw) == profile_pin, "observer profile pin mismatch")
    value = decode(raw)
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "witness_directory",
            "database",
            "stream_id",
            "public_key_sha256",
            "source_locator_sha256",
            "bootstrap_receipt",
            "bootstrap_sha256",
            "interval_seconds",
            "max_age_seconds",
            "capacity_warning",
        },
        "observer profile fields rejected",
    )
    require(
        value["schema"] == SCHEMA
        and isinstance(value["stream_id"], str)
        and witness.STREAM.fullmatch(value["stream_id"])
        and witness._hex(value["public_key_sha256"])
        and witness._hex(value["source_locator_sha256"])
        and witness._hex(value["bootstrap_sha256"]),
        "observer profile scope rejected",
    )
    require(
        all(
            isinstance(value[k], str) and 0 < len(value[k]) <= 4096 and Path(value[k]).is_absolute()
            for k in ("witness_directory", "database")
        ),
        "observer absolute source paths required",
    )
    _separate(directory, Path(value["witness_directory"]), Path(value["database"]))
    require(
        type(value["interval_seconds"]) is int
        and 1 <= value["interval_seconds"] <= 3600
        and type(value["max_age_seconds"]) is int
        and 2 * value["interval_seconds"] <= value["max_age_seconds"] <= 86400
        and type(value["capacity_warning"]) is int
        and 0 <= value["capacity_warning"] <= witness.MAX_RECEIPTS,
        "observer interval/age/capacity policy rejected",
    )
    _key, public = witness._public(directory, value["public_key_sha256"])
    baseline = value["bootstrap_receipt"]
    if baseline is None:
        require(value["bootstrap_sha256"] == witness.GENESIS, "observer bootstrap pin rejected")
    else:
        body = witness.verify_receipt(
            baseline,
            public,
            stream_id=value["stream_id"],
            expected_receipt=value["bootstrap_sha256"],
        )
        require(
            body["source_locator_sha256"] == value["source_locator_sha256"],
            "observer bootstrap source mismatch",
        )
    return directory, value, public


def initialize(
    directory,
    witness_directory,
    database,
    public_key_sha256,
    *,
    expected_receipt,
    interval_seconds=60,
    max_age_seconds=180,
    capacity_warning=16,
):
    directory = Path(directory).absolute()
    signer = witness._directory(witness_directory)
    store = SQLiteAuditStore.open_existing(database)
    _separate(directory, signer, store.path.absolute())
    _key, public = witness._public(signer, public_key_sha256)
    with witness._journal(signer) as con:
        stream, locator, baseline, current, _operations = witness._history(
            con, public, expected_receipt=expected_receipt, exact=True
        )
    require(locator == witness._locator(store), "observer source locator mismatch")
    # Validate all policy fields before creating state. Never discover and adopt
    # an unacknowledged latest receipt instead of the supplied operator pin.
    require(
        type(interval_seconds) is int
        and 1 <= interval_seconds <= 3600
        and type(max_age_seconds) is int
        and 2 * interval_seconds <= max_age_seconds <= 86400
        and type(capacity_warning) is int
        and 0 <= capacity_warning <= witness.MAX_RECEIPTS,
        "observer interval/age/capacity policy rejected",
    )
    profile = {
        "schema": SCHEMA,
        "witness_directory": str(signer),
        "database": str(store.path.absolute()),
        "stream_id": stream,
        "public_key_sha256": public_key_sha256,
        "source_locator_sha256": locator,
        "bootstrap_receipt": baseline,
        "bootstrap_sha256": current,
        "interval_seconds": interval_seconds,
        "max_age_seconds": max_age_seconds,
        "capacity_warning": capacity_warning,
    }
    raw = canonical(profile) + b"\n"
    require(len(raw) <= PROFILE_LIMIT, "observer profile too large")
    directory.mkdir(mode=0o700, exist_ok=False)
    _write(directory / "profile.json", raw)
    _write(directory / "public.key", public)
    for name in ("observer.sqlite3", "lease.sqlite3"):
        _write(directory / name, b"")
        con = sqlite3.connect(directory / name)
        try:
            if name == "observer.sqlite3":
                con.execute(
                    "CREATE TABLE anchors (number INTEGER PRIMARY KEY, receipt TEXT NOT NULL)"
                )
                con.execute(
                    "CREATE TABLE pending (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, digest TEXT NOT NULL)"
                )
            else:
                con.execute("CREATE TABLE lease (profile_sha256 TEXT NOT NULL)")
                con.execute("INSERT INTO lease VALUES (?)", (sha(raw),))
            con.commit()
        finally:
            con.close()
    return {
        "profile_sha256": sha(raw),
        "minimum_receipt": current,
        "stream_id": stream,
        "independent_storage_verified": False,
        "automatic_activation_allowed": False,
    }


def _read(con, profile, public, minimum_receipt):
    require(witness._hex(minimum_receipt), "observer explicit minimum receipt required")
    last = profile["bootstrap_receipt"]
    digest = profile["bootstrap_sha256"]
    number = 0 if last is None else last["body"]["number"]
    seen = {digest}
    operations = set()
    if last is not None and last["body"]["schema"] == witness.OPERATION_SCHEMA:
        operations.add(last["body"]["observation_id"])
    rows = con.execute(
        "SELECT number,receipt FROM anchors ORDER BY number LIMIT ?", (witness.MAX_RECEIPTS + 1,)
    ).fetchall()
    require(len(rows) <= witness.MAX_RECEIPTS, "observer anchor capacity exceeded")
    for offset, (ordinal, raw) in enumerate(rows, 1):
        require(
            type(ordinal) is int
            and ordinal == offset
            and isinstance(raw, str)
            and len(raw.encode()) <= 16384,
            "observer anchor row rejected",
        )
        receipt = decode(raw)
        receipt_hash = sha(canonical(receipt))
        body = witness.verify_receipt(
            receipt, public, stream_id=profile["stream_id"], expected_receipt=receipt_hash
        )
        require(
            body["schema"] == witness.OPERATION_SCHEMA
            and body["source_locator_sha256"] == profile["source_locator_sha256"]
            and body["previous_receipt"] == digest
            and body["number"] == number + 1
            and body["observation_id"] not in operations,
            "observer anchor progression rejected",
        )
        if last is not None:
            require(
                body["head"]["seq"] >= last["body"]["head"]["seq"]
                and (
                    body["head"]["seq"] != last["body"]["head"]["seq"]
                    or body["head"] == last["body"]["head"]
                )
                and _time(body["observed_at"]) >= _time(last["body"]["observed_at"]),
                "observer anchor head/time regressed",
            )
        operations.add(body["observation_id"])
        seen.add(receipt_hash)
        last, digest, number = receipt, receipt_hash, body["number"]
    require(minimum_receipt in seen, "observer history behind required external minimum")
    pending_rows = con.execute("SELECT id,payload,digest FROM pending").fetchall()
    require(len(pending_rows) <= 1, "observer pending row count rejected")
    pending = None
    if pending_rows:
        ident, raw, expected = pending_rows[0]
        require(
            ident == 1
            and isinstance(raw, str)
            and len(raw.encode()) <= 4096
            and sha(raw.encode()) == expected,
            "observer pending checksum rejected",
        )
        pending = decode(raw)
        require(
            type(pending) is dict
            and set(pending) == {"observation_id", "predecessor", "started_at"}
            and witness._operation(pending["observation_id"])
            and pending["predecessor"] == digest
            and pending["observation_id"] not in operations,
            "observer pending scope rejected",
        )
        _time(pending["started_at"])
    return {"receipt": last, "receipt_sha256": digest, "anchors": len(rows), "pending": pending}


def _prepare(directory, profile, public, minimum_receipt):
    with _database(directory, write=True) as con:
        state = _read(con, profile, public, minimum_receipt)
        now = datetime.now(UTC)
        if state["receipt"] is not None:
            require(
                _time(state["receipt"]["body"]["observed_at"]) <= now, "observer clock regressed"
            )
        if state["pending"] is None:
            pending = {
                "observation_id": uuid.uuid4().hex,
                "predecessor": state["receipt_sha256"],
                "started_at": now.isoformat(),
            }
            raw = canonical(pending).decode()
            con.execute("INSERT INTO pending VALUES (1,?,?)", (raw, sha(raw.encode())))
            state["pending"] = pending
        require(_time(state["pending"]["started_at"]) <= now, "observer pending clock regressed")
    return state


def _verify_audit_heads(profile, previous_receipt, body):
    store = SQLiteAuditStore.open_existing(profile["database"])
    require(
        witness._locator(store) == profile["source_locator_sha256"],
        "observer audit locator changed",
    )
    minimum = None if previous_receipt is None else previous_receipt["body"]["head"]
    with store._transaction() as con:
        seq, _digest = witness._verified_head(store, con, minimum)
        expected = body["head"]
        require(expected["seq"] <= seq, "observer audit behind returned observation")
        actual = (
            witness.GENESIS
            if expected["seq"] == 0
            else con.execute(
                "SELECT digest FROM audit_entries WHERE seq=?", (expected["seq"],)
            ).fetchone()[0]
        )
        require(actual == expected["digest"], "observer returned audit prefix mismatch")


def _acknowledge(directory, profile, public, minimum_receipt, pending, result):
    require(
        type(result) is dict
        and set(result)
        == {
            "receipt",
            "receipt_sha256",
            "replayed",
            "automatic_activation_allowed",
            "independent_storage_verified",
        }
        and type(result["replayed"]) is bool
        and result["automatic_activation_allowed"] is False
        and result["independent_storage_verified"] is False,
        "observer witness response rejected",
    )
    receipt = result["receipt"]
    body = witness.verify_receipt(
        receipt, public, stream_id=profile["stream_id"], expected_receipt=result["receipt_sha256"]
    )
    require(
        body["schema"] == witness.OPERATION_SCHEMA
        and body["observation_id"] == pending["observation_id"]
        and body["previous_receipt"] == pending["predecessor"]
        and body["source_locator_sha256"] == profile["source_locator_sha256"]
        and _time(pending["started_at"]) <= _time(body["observed_at"]) <= datetime.now(UTC),
        "observer observation response scope/time rejected",
    )
    committed = witness.status(
        profile["witness_directory"],
        profile["public_key_sha256"],
        minimum_receipt=result["receipt_sha256"],
    )
    require(
        committed["receipt_sha256"] == result["receipt_sha256"],
        "observer signer changed before acknowledgement",
    )
    with _database(directory, write=True) as con:
        state = _read(con, profile, public, minimum_receipt)
        require(
            state["pending"] == pending and state["receipt_sha256"] == pending["predecessor"],
            "observer pending changed before acknowledgement",
        )
        number = 0 if state["receipt"] is None else state["receipt"]["body"]["number"]
        require(body["number"] == number + 1, "observer observation number changed")
        _verify_audit_heads(profile, state["receipt"], body)
        if state["receipt"] is not None:
            previous_head = state["receipt"]["body"]["head"]
            require(
                body["head"]["seq"] >= previous_head["seq"]
                and (body["head"]["seq"] != previous_head["seq"] or body["head"] == previous_head),
                "observer observation head regressed",
            )
        con.execute(
            "INSERT INTO anchors VALUES (?,?)", (state["anchors"] + 1, canonical(receipt).decode())
        )
        con.execute("DELETE FROM pending WHERE id=1")


def cycle(directory, profile_sha256, *, minimum_receipt):
    directory, profile, public = _load(directory, profile_sha256)
    # A separate SQLite lease can remain reserved while the pending state commits.
    # Kernel file locks are released on process loss; no stale PID is trusted.
    with _database(directory, lease=True, profile_pin=profile_sha256):
        state = _prepare(directory, profile, public, minimum_receipt)
        pending = state["pending"]
        result = witness.observe(
            profile["witness_directory"],
            profile["database"],
            profile["public_key_sha256"],
            expected_receipt=pending["predecessor"],
            observation_id=pending["observation_id"],
        )
        _acknowledge(directory, profile, public, minimum_receipt, pending, result)
    return {
        "receipt_sha256": result["receipt_sha256"],
        "recovered": result["replayed"],
        "independent_storage_verified": False,
        "automatic_activation_allowed": False,
    }


def status(directory, profile_sha256, *, minimum_receipt, now=None, offline=False):
    directory, profile, public = _load(directory, profile_sha256)
    with _database(directory) as con:
        state = _read(con, profile, public, minimum_receipt)
    now = datetime.now(UTC) if now is None else now
    require(
        isinstance(now, datetime) and now.utcoffset() is not None,
        "observer aware status time required",
    )
    receipt = state["receipt"]
    age = None if receipt is None else (now - _time(receipt["body"]["observed_at"])).total_seconds()
    result = {
        "schema": SCHEMA,
        "state": "offline" if offline else "uninitialized",
        "healthy": False,
        "anchor_verified": True,
        "live_checked": False,
        "audit_minimum_verified": False,
        "signing_capability_checked": False,
        "receipt_sha256": state["receipt_sha256"],
        "age_seconds": age,
        "observed_at": None if receipt is None else receipt["body"]["observed_at"],
        "pending_started_at": None if state["pending"] is None else state["pending"]["started_at"],
        "max_age_seconds": profile["max_age_seconds"],
        "capacity_warning": profile["capacity_warning"],
        "pending": state["pending"] is not None,
        "anchor_count": state["anchors"],
        "independent_storage_verified": False,
        "automatic_activation_allowed": False,
    }
    if offline:
        return result
    if (age is not None and age < 0) or (
        state["pending"] is not None and _time(state["pending"]["started_at"]) > now
    ):
        result["state"] = "clock_regression"
        return result
    try:
        current = witness.status(
            profile["witness_directory"],
            profile["public_key_sha256"],
            minimum_receipt=state["receipt_sha256"],
        )
        result["live_checked"] = True
        if current["receipt_sha256"] != state["receipt_sha256"]:
            result["state"] = "pending" if state["pending"] else "witness_advanced"
            return result
        if receipt is not None:
            audit = witness.inspect(
                profile["database"],
                receipt,
                public,
                public_key_sha256=profile["public_key_sha256"],
                stream_id=profile["stream_id"],
                expected_receipt=state["receipt_sha256"],
            )
            result["unobserved_rows"] = (
                audit["observed_head"]["seq"] - receipt["body"]["head"]["seq"]
            )
            result["audit_minimum_verified"] = True
        else:
            store = SQLiteAuditStore.open_existing(profile["database"])
            with store._transaction() as con:
                result["unobserved_rows"] = witness._verified_head(store, con)[0]
    except (
        AuditTransferError,
        AuditQueryUnavailable,
        OSError,
        ValueError,
        TypeError,
        sqlite3.Error,
    ):
        result["state"] = "unavailable"
        return result
    number = 0 if receipt is None else receipt["body"]["number"]
    result["remaining_receipts"] = witness.MAX_RECEIPTS - number
    if state["pending"]:
        result["state"] = "pending"
    elif receipt is None:
        result["state"] = "uninitialized"
    elif age > profile["max_age_seconds"]:
        result["state"] = "stale"
    elif result["unobserved_rows"]:
        result["state"] = "unobserved"
    elif result["remaining_receipts"] == 0:
        result["state"] = "capacity_exhausted"
    elif result["remaining_receipts"] <= profile["capacity_warning"]:
        result["state"] = "capacity_pressure"
    else:
        result["state"], result["healthy"] = "healthy", True
    return result
