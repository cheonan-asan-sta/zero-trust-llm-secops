"""Durable append-only collector capture and immutable signed delivery variants.

Capture and its input byte checkpoint commit together. Acknowledgement is a
separate transaction and means remote durable receipt, not policy completion.
The caller holds the single-producer OS lock across network operations. Confirmed
rows may be compacted into bounded duplicate history; unconfirmed rows never move.
"""

import hashlib
import hmac
import json
import math
import re
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import TypeAdapter

from app.continuous_signal_models import Observation, SignedContinuousSignal


class SpoolUnavailable(RuntimeError):
    pass


class SpoolConflict(ValueError):
    pass


class SpoolFull(RuntimeError):
    pass


class SpoolBindingMismatch(RuntimeError):
    pass


class SpoolVariantLimit(RuntimeError):
    pass


_HEX = re.compile(r"[a-f0-9]{64}\Z")
_EVENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ERROR = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
_OBSERVATION = TypeAdapter(Observation)


def _canonical(value) -> str:
    result = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                        allow_nan=False)
    if len(result.encode("utf-8")) > 1_048_576:
        raise ValueError("collector record too large")
    return result


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _time(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("collector timestamps require timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _stored_time(value: str) -> None:
    if not isinstance(value, str) or _time(datetime.fromisoformat(value)) != value:
        raise ValueError("invalid stored collector timestamp")


def _event(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"event_id", "observed_at", "observation"}:
        raise ValueError("collector event fields rejected")
    if not isinstance(value["event_id"], str) or not _EVENT_ID.fullmatch(value["event_id"]):
        raise ValueError("collector event identifier rejected")
    observed = value["observed_at"]
    if isinstance(observed, str):
        observed = datetime.fromisoformat(observed)
    observation = _OBSERVATION.validate_python(value["observation"])
    return {"event_id": value["event_id"], "observed_at": _time(observed),
            "observation": observation.model_dump(mode="json")}


class CollectorSpool:
    """Bounded single-host SQLite spool; validation scans all retained records."""

    def __init__(self, path: Path, binding: dict, *, max_pending=1000,
                 max_records=10000, max_variants=16, max_history=100000, max_rotations=100000):
        self.path = Path(path)
        self.max_pending = max_pending
        self.max_records = max_records
        self.max_variants = max_variants
        self.max_history = max_history
        self.max_rotations = max_rotations
        for value in (max_pending, max_records, max_variants, max_history, max_rotations):
            if type(value) is not int or value < 1:
                raise ValueError("collector limits must be positive integers")
        if not isinstance(binding, dict) or any(
            not isinstance(binding.get(field), str) or not binding[field].strip()
            for field in ("tenant_id", "source_id", "key_id")
        ):
            raise ValueError("collector binding requires tenant, source and key")
        # Detach mutable caller data and bind every supplied path/security setting.
        self.binding_json = _canonical(binding)
        self.binding = json.loads(self.binding_json)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._transaction() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS collector_spool_metadata ("
                    "id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, "
                    "binding_digest TEXT NOT NULL, checkpoint TEXT NOT NULL, "
                    "checkpoint_digest TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS collector_spool_records ("
                    "seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, "
                    "record_json TEXT NOT NULL, record_digest TEXT NOT NULL)"
                )
                if not connection.execute("SELECT 1 FROM collector_spool_metadata").fetchone():
                    checkpoint = _canonical({"offset": 0, "prefix_sha256": _digest(""), "records": 0})
                    connection.execute(
                        "INSERT INTO collector_spool_metadata "
                        "(id,binding,binding_digest,checkpoint,checkpoint_digest) VALUES (1,?,?,?,?)",
                        (self.binding_json, _digest(self.binding_json), checkpoint,
                         _digest(checkpoint)),
                    )
                self._migrate(connection)
                self._read(connection)
            # POSIX permissions supplement the protected runtime directory. Windows
            # ACLs remain the caller's responsibility; unsupported chmod is harmless.
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        except OSError as exc:
            raise SpoolUnavailable("collector spool unavailable") from exc

    @staticmethod
    def _migrate(connection):
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(collector_spool_metadata)")}
        if "storage_version" in columns:
            return  # Missing version-2 tables/rows are corruption, never reinitialized.
        connection.execute("ALTER TABLE collector_spool_metadata "
                           "ADD COLUMN storage_version INTEGER NOT NULL DEFAULT 1")
        connection.execute(
            "CREATE TABLE collector_spool_history (seq INTEGER PRIMARY KEY, "
            "event_id TEXT NOT NULL UNIQUE,event_sha256 TEXT NOT NULL, "
            "acknowledged_at TEXT NOT NULL,tombstone_digest TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE collector_spool_rotation (id INTEGER PRIMARY KEY CHECK(id=1), "
            "rotation_json TEXT NOT NULL,rotation_digest TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE collector_spool_rotations (generation INTEGER PRIMARY KEY, "
            "rotation_id TEXT NOT NULL UNIQUE,entry_json TEXT NOT NULL,entry_digest TEXT NOT NULL)"
        )
        serialized = _canonical({"generation": 0, "rotation_id": None})
        connection.execute("INSERT INTO collector_spool_rotation VALUES (1,?,?)",
                           (serialized, _digest(serialized)))
        connection.execute("UPDATE collector_spool_metadata SET storage_version=2")

    @staticmethod
    def _input_checkpoint(value):
        if (not isinstance(value, dict) or set(value) != {"offset", "prefix_sha256"}
                or type(value["offset"]) is not int or value["offset"] < 0
                or not isinstance(value["prefix_sha256"], str)
                or not _HEX.fullmatch(value["prefix_sha256"])):
            raise ValueError("collector input checkpoint invalid")
        return value

    def _rotation(self, connection):
        rows = connection.execute("SELECT * FROM collector_spool_rotation").fetchall()
        if len(rows) != 1 or rows[0]["id"] != 1:
            raise ValueError("collector rotation metadata missing")
        row = rows[0]
        serialized = row["rotation_json"]
        if (not isinstance(serialized, str)
                or not hmac.compare_digest(_digest(serialized), row["rotation_digest"])
                or _canonical(json.loads(serialized)) != serialized):
            raise ValueError("collector rotation metadata integrity failed")
        rotation = json.loads(serialized)
        if (not isinstance(rotation, dict) or set(rotation) != {"generation", "rotation_id"}
                or type(rotation["generation"]) is not int or rotation["generation"] < 0):
            raise ValueError("collector rotation metadata invalid")
        entries = connection.execute("SELECT * FROM collector_spool_rotations ORDER BY generation").fetchall()
        if len(entries) != rotation["generation"]:
            raise ValueError("collector rotation history changed")
        last = None
        for generation, entry in enumerate(entries, 1):
            raw = entry["entry_json"]
            if (entry["generation"] != generation or not isinstance(raw, str)
                    or not hmac.compare_digest(_digest(raw), entry["entry_digest"])
                    or _canonical(json.loads(raw)) != raw):
                raise ValueError("collector rotation entry integrity failed")
            value = json.loads(raw)
            if (not isinstance(value, dict)
                    or set(value) != {"generation", "rotation_id", "expected_checkpoint"}
                    or type(value["generation"]) is not int or value["generation"] != generation
                    or not isinstance(value["rotation_id"], str)
                    or not _EVENT_ID.fullmatch(value["rotation_id"])
                    or value["rotation_id"] != entry["rotation_id"]):
                raise ValueError("collector rotation entry invalid")
            self._input_checkpoint(value["expected_checkpoint"])
            last = value["rotation_id"]
        if rotation["rotation_id"] != last:
            raise ValueError("collector rotation generation changed")
        return rotation

    @contextmanager
    def _transaction(self):
        connection = None
        try:
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
            if connection is not None:
                connection.rollback()
            if isinstance(exc, SpoolConflict):
                raise
            raise SpoolUnavailable("collector spool unavailable") from exc
        except BaseException:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()

    def _envelope(self, envelope: dict, event: dict) -> dict:
        model = SignedContinuousSignal.model_validate(envelope)
        if any(getattr(model, field) != self.binding[field]
               for field in ("tenant_id", "source_id", "key_id")):
            raise ValueError("signed envelope binding rejected")
        normalized = _event({"event_id": model.event_id, "observed_at": model.observed_at,
                             "observation": model.observation.model_dump(mode="json")})
        if normalized != event:
            raise ValueError("signed envelope changes captured observation")
        return model.model_dump(mode="json")

    def _read(self, connection) -> tuple[dict, list[dict], list[dict]]:
        metadata = connection.execute("SELECT * FROM collector_spool_metadata").fetchall()
        if len(metadata) != 1 or metadata[0]["id"] != 1:
            raise ValueError("collector metadata missing")
        meta = metadata[0]
        if meta["storage_version"] != 2:
            raise ValueError("collector storage version invalid")
        self._rotation(connection)
        for field in ("binding", "checkpoint"):
            serialized = meta[field]
            if not isinstance(serialized, str) or not hmac.compare_digest(
                _digest(serialized), meta[f"{field}_digest"]
            ) or _canonical(json.loads(serialized)) != serialized:
                raise ValueError("collector metadata integrity failed")
        if meta["binding"] != self.binding_json:
            raise SpoolBindingMismatch("collector spool belongs to another input or destination")
        checkpoint = json.loads(meta["checkpoint"])
        if (
            not isinstance(checkpoint, dict)
            or set(checkpoint) != {"offset", "prefix_sha256", "records"}
            or type(checkpoint["offset"]) is not int or checkpoint["offset"] < 0
            or type(checkpoint["records"]) is not int or checkpoint["records"] < 0
            or not isinstance(checkpoint["prefix_sha256"], str)
            or not _HEX.fullmatch(checkpoint["prefix_sha256"])
        ):
            raise ValueError("collector checkpoint invalid")
        stored = connection.execute("SELECT * FROM collector_spool_records ORDER BY seq").fetchall()
        records = []
        sequences, identifiers = set(), set()
        for row in stored:
            serialized = row["record_json"]
            if type(row["seq"]) is not int or row["seq"] < 1 or not isinstance(serialized, str) or not hmac.compare_digest(
                _digest(serialized), row["record_digest"]
            ) or _canonical(json.loads(serialized)) != serialized:
                raise ValueError("collector record integrity failed")
            record = json.loads(serialized)
            if set(record) != {"event", "envelopes", "state", "attempts", "next_retry_at",
                               "last_error", "acknowledged_at"}:
                raise ValueError("collector record fields invalid")
            if _event(record["event"]) != record["event"] or row["event_id"] != record["event"]["event_id"]:
                raise ValueError("collector event changed")
            if type(record["attempts"]) is not int or record["attempts"] < 0:
                raise ValueError("collector attempts invalid")
            if record["state"] not in {"pending", "acknowledged"}:
                raise ValueError("collector state invalid")
            if not isinstance(record["envelopes"], list):
                raise TypeError("collector variants invalid")
            seen = set()
            for envelope in record["envelopes"]:
                canonical = _canonical(self._envelope(envelope, record["event"]))
                if canonical in seen:
                    raise ValueError("duplicate stored collector envelope")
                seen.add(canonical)
            if record["last_error"] is not None and (
                not isinstance(record["last_error"], str) or not _ERROR.fullmatch(record["last_error"])
            ):
                raise ValueError("collector error code invalid")
            for field in ("next_retry_at", "acknowledged_at"):
                if record[field] is not None:
                    _stored_time(record[field])
            if record["state"] == "acknowledged":
                if record["acknowledged_at"] is None or record["next_retry_at"] is not None or not seen:
                    raise ValueError("collector acknowledgement invalid")
            elif record["acknowledged_at"] is not None:
                raise ValueError("pending collector acknowledgement invalid")
            records.append(record)
            sequences.add(row["seq"])
            identifiers.add(row["event_id"])
        history = []
        for row in connection.execute("SELECT * FROM collector_spool_history ORDER BY seq"):
            entry = {field: row[field] for field in ("seq", "event_id", "event_sha256", "acknowledged_at")}
            if (type(entry["seq"]) is not int or entry["seq"] < 1 or entry["seq"] in sequences
                    or not isinstance(entry["event_id"], str) or not _EVENT_ID.fullmatch(entry["event_id"])
                    or entry["event_id"] in identifiers or not isinstance(entry["event_sha256"], str)
                    or not _HEX.fullmatch(entry["event_sha256"])
                    or not hmac.compare_digest(_digest(_canonical(entry)), row["tombstone_digest"])):
                raise ValueError("collector duplicate history integrity failed")
            _stored_time(entry["acknowledged_at"])
            history.append(entry)
            sequences.add(entry["seq"])
            identifiers.add(entry["event_id"])
        if (len(sequences) != checkpoint["records"] or len(identifiers) != len(sequences)
                or any(seq != expected for expected, seq in enumerate(sorted(sequences), 1))):
            raise ValueError("collector record history changed")
        return checkpoint, records, history

    @staticmethod
    def _find(records, event_id):
        found = next((record for record in records if record["event"]["event_id"] == event_id), None)
        if found is None:
            raise SpoolConflict("collector event has not been captured")
        return found

    @staticmethod
    def _write(connection, record):
        serialized = _canonical(record)
        connection.execute(
            "UPDATE collector_spool_records SET record_json=?,record_digest=? WHERE event_id=?",
            (serialized, _digest(serialized), record["event"]["event_id"]),
        )

    def checkpoint(self) -> dict:
        with self._transaction() as connection:
            checkpoint, _, _ = self._read(connection)
            result = {field: checkpoint[field] for field in ("offset", "prefix_sha256")}
        return result

    def enqueue(self, event: dict, *, offset: int, prefix_sha256: str) -> bool:
        try:
            event = _event(event)
            if type(offset) is not int or offset < 1 or not isinstance(prefix_sha256, str) or not (
                _HEX.fullmatch(prefix_sha256)
            ):
                raise ValueError("collector capture checkpoint invalid")
        except (ValueError, TypeError) as exc:
            raise SpoolConflict("collector input rejected") from exc
        with self._transaction() as connection:
            checkpoint, records, history = self._read(connection)
            previous = next((record for record in records
                             if record["event"]["event_id"] == event["event_id"]), None)
            compacted = next((entry for entry in history if entry["event_id"] == event["event_id"]), None)
            if ((previous is not None and previous["event"] != event)
                    or (compacted is not None and compacted["event_sha256"] != _digest(_canonical(event)))):
                raise SpoolConflict("collector event identifier reused with different input")
            if offset < checkpoint["offset"] or (
                offset == checkpoint["offset"] and (
                    (previous is None and compacted is None) or prefix_sha256 != checkpoint["prefix_sha256"]
                )
            ):
                raise SpoolConflict("collector input checkpoint moved backwards or changed")
            created = previous is None and compacted is None
            if created:
                if len(records) >= self.max_records or sum(
                    record["state"] == "pending" for record in records
                ) >= self.max_pending:
                    raise SpoolFull("collector spool capacity reached")
                record = {"event": event, "envelopes": [], "state": "pending", "attempts": 0,
                          "next_retry_at": None, "last_error": None, "acknowledged_at": None}
                serialized = _canonical(record)
                connection.execute("INSERT INTO collector_spool_records VALUES (?,?,?,?)",
                                   (checkpoint["records"] + 1, event["event_id"], serialized, _digest(serialized)))
            checkpoint = _canonical({"offset": offset, "prefix_sha256": prefix_sha256,
                                     "records": checkpoint["records"] + int(created)})
            connection.execute(
                "UPDATE collector_spool_metadata SET checkpoint=?,checkpoint_digest=? WHERE id=1",
                (checkpoint, _digest(checkpoint)),
            )
        return created

    def next_pending(self, now: datetime) -> dict | None:
        timestamp = _time(now)
        result = None
        with self._transaction() as connection:
            _, records, _ = self._read(connection)
            for record in records:
                if record["state"] != "pending":
                    continue
                if record["next_retry_at"] is None or record["next_retry_at"] <= timestamp:
                    result = {"event_id": record["event"]["event_id"], "event": record["event"],
                              "envelopes": record["envelopes"], "attempts": record["attempts"]}
                # Preserve captured feed order even while the head is deferred.
                break
        return result

    def stage(self, event_id: str, envelope: dict) -> None:
        with self._transaction() as connection:
            _, records, _ = self._read(connection)
            record = self._find(records, event_id)
            try:
                envelope = self._envelope(envelope, record["event"])
            except (ValueError, TypeError) as exc:
                raise SpoolConflict("collector envelope rejected") from exc
            if envelope in record["envelopes"]:
                return
            if record["state"] != "pending":
                raise SpoolConflict("acknowledged collector event is immutable")
            if len(record["envelopes"]) >= self.max_variants:
                raise SpoolVariantLimit("collector envelope variants exhausted; record retained")
            record["envelopes"].append(envelope)
            self._write(connection, record)

    def defer(self, event_id: str, error_code: str, now: datetime, delay_seconds: float) -> None:
        if not isinstance(error_code, str) or not _ERROR.fullmatch(error_code):
            raise SpoolConflict("collector errors must be bounded codes")
        if isinstance(delay_seconds, bool) or not isinstance(delay_seconds, (int, float)) or not (
            math.isfinite(delay_seconds) and 0 <= delay_seconds <= 86400
        ):
            raise SpoolConflict("collector retry delay invalid")
        due = _time(now + timedelta(seconds=delay_seconds))
        with self._transaction() as connection:
            _, records, _ = self._read(connection)
            record = self._find(records, event_id)
            if record["state"] != "pending":
                raise SpoolConflict("acknowledged collector event is immutable")
            record.update(attempts=record["attempts"] + 1, next_retry_at=due, last_error=error_code)
            self._write(connection, record)

    def acknowledge(self, event_id: str, *, now: datetime) -> None:
        timestamp = _time(now)
        with self._transaction() as connection:
            _, records, history = self._read(connection)
            if any(entry["event_id"] == event_id for entry in history):
                return
            record = self._find(records, event_id)
            if record["state"] == "acknowledged":
                return
            if not record["envelopes"]:
                raise SpoolConflict("unsigned collector event cannot be acknowledged")
            record.update(state="acknowledged", acknowledged_at=timestamp,
                          next_retry_at=None, last_error=None)
            self._write(connection, record)

    def summary(self) -> dict:
        with self._transaction() as connection:
            checkpoint, records, history = self._read(connection)
            acknowledged = len(history) + sum(record["state"] == "acknowledged" for record in records)
            errors = [record["last_error"] for record in records if record["last_error"]]
            result = {"captured": checkpoint["records"], "acknowledged": acknowledged,
                      "pending": checkpoint["records"] - acknowledged, "offset": checkpoint["offset"],
                      "last_error": errors[-1] if errors else None}
        return result

    def compact(self, *, limit=256) -> int:
        """Atomically replace confirmed payloads with immutable duplicate history."""
        if type(limit) is not int or limit < 1:
            raise SpoolConflict("collector compaction limit invalid")
        with self._transaction() as connection:
            _, records, history = self._read(connection)
            eligible = [record for record in records if record["state"] == "acknowledged"]
            if not eligible:
                return 0
            available = self.max_history - len(history)
            if available <= 0:
                raise SpoolFull("collector duplicate history capacity reached")
            selected = eligible[:min(limit, available)]
            for record in selected:
                event_id = record["event"]["event_id"]
                seq = connection.execute("SELECT seq FROM collector_spool_records WHERE event_id=?",
                                         (event_id,)).fetchone()[0]
                entry = {"seq": seq, "event_id": event_id,
                         "event_sha256": _digest(_canonical(record["event"])),
                         "acknowledged_at": record["acknowledged_at"]}
                connection.execute("INSERT INTO collector_spool_history VALUES (?,?,?,?,?)",
                                   (seq, event_id, entry["event_sha256"], entry["acknowledged_at"],
                                    _digest(_canonical(entry))))
                connection.execute("DELETE FROM collector_spool_records WHERE event_id=?", (event_id,))
            self._read(connection)
            return len(selected)

    def storage_summary(self) -> dict:
        with self._transaction() as connection:
            _, records, history = self._read(connection)
            return {"retained": len(records), "compacted": len(history),
                    "max_records": self.max_records, "max_history": self.max_history,
                    "max_rotations": self.max_rotations}

    def rotation_checkpoint(self) -> dict:
        with self._transaction() as connection:
            self._read(connection)
            return self._rotation(connection)

    def rotate_input(self, expected_checkpoint: dict, rotation_id: str) -> None:
        try:
            self._input_checkpoint(expected_checkpoint)
            expected_checkpoint = json.loads(_canonical(expected_checkpoint))
            if not isinstance(rotation_id, str) or not _EVENT_ID.fullmatch(rotation_id):
                raise ValueError("collector rotation identifier invalid")
        except (ValueError, TypeError) as exc:
            raise SpoolConflict("collector input rotation rejected") from exc
        with self._transaction() as connection:
            checkpoint, _, _ = self._read(connection)
            rotation = self._rotation(connection)
            previous = connection.execute("SELECT entry_json FROM collector_spool_rotations WHERE rotation_id=?",
                                          (rotation_id,)).fetchone()
            if previous is not None:
                entry = json.loads(previous[0])
                if (rotation["rotation_id"] != rotation_id
                        or entry["expected_checkpoint"] != expected_checkpoint):
                    raise SpoolConflict("collector rotation identifier reused")
                return  # A repeated completion must not rewind a newly captured feed.
            if {field: checkpoint[field] for field in ("offset", "prefix_sha256")} != expected_checkpoint:
                raise SpoolConflict("collector input changed before rotation")
            if rotation["generation"] >= self.max_rotations:
                raise SpoolFull("collector input rotation history capacity reached")
            generation = rotation["generation"] + 1
            entry = _canonical({"generation": generation, "rotation_id": rotation_id,
                                "expected_checkpoint": expected_checkpoint})
            connection.execute("INSERT INTO collector_spool_rotations VALUES (?,?,?,?)",
                               (generation, rotation_id, entry, _digest(entry)))
            serialized = _canonical({"generation": generation, "rotation_id": rotation_id})
            connection.execute("UPDATE collector_spool_rotation SET rotation_json=?,rotation_digest=? WHERE id=1",
                               (serialized, _digest(serialized)))
            reset = _canonical(checkpoint | {"offset": 0, "prefix_sha256": _digest("")})
            connection.execute("UPDATE collector_spool_metadata SET checkpoint=?,checkpoint_digest=? WHERE id=1",
                               (reset, _digest(reset)))
            self._read(connection)
