"""Durable append-only collector capture and immutable signed delivery variants.

Capture and its input byte checkpoint commit together. Acknowledgement is a
separate transaction and means remote durable receipt, not policy completion.
The caller holds the single-producer OS lock across network operations. Retained
rows are bounded and never pruned automatically, preserving duplicate detection.
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
                 max_records=10000, max_variants=16):
        self.path = Path(path)
        self.max_pending = max_pending
        self.max_records = max_records
        self.max_variants = max_variants
        for value in (max_pending, max_records, max_variants):
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
                        "INSERT INTO collector_spool_metadata VALUES (1,?,?,?,?)",
                        (self.binding_json, _digest(self.binding_json), checkpoint,
                         _digest(checkpoint)),
                    )
                self._read(connection)
            # POSIX permissions supplement the protected runtime directory. Windows
            # ACLs remain the caller's responsibility; unsupported chmod is harmless.
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        except OSError as exc:
            raise SpoolUnavailable("collector spool unavailable") from exc

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

    def _read(self, connection) -> tuple[dict, list[dict]]:
        metadata = connection.execute("SELECT * FROM collector_spool_metadata").fetchall()
        if len(metadata) != 1 or metadata[0]["id"] != 1:
            raise ValueError("collector metadata missing")
        meta = metadata[0]
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
        if len(stored) != checkpoint["records"]:
            raise ValueError("collector record count changed")
        records = []
        for expected, row in enumerate(stored, 1):
            serialized = row["record_json"]
            if row["seq"] != expected or not isinstance(serialized, str) or not hmac.compare_digest(
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
        return checkpoint, records

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
            checkpoint, _ = self._read(connection)
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
            checkpoint, records = self._read(connection)
            previous = next((record for record in records
                             if record["event"]["event_id"] == event["event_id"]), None)
            if previous is not None and previous["event"] != event:
                raise SpoolConflict("collector event identifier reused with different input")
            if offset < checkpoint["offset"] or (
                offset == checkpoint["offset"] and (
                    previous is None or prefix_sha256 != checkpoint["prefix_sha256"]
                )
            ):
                raise SpoolConflict("collector input checkpoint moved backwards or changed")
            created = previous is None
            if created:
                if len(records) >= self.max_records or sum(
                    record["state"] == "pending" for record in records
                ) >= self.max_pending:
                    raise SpoolFull("collector spool capacity reached")
                record = {"event": event, "envelopes": [], "state": "pending", "attempts": 0,
                          "next_retry_at": None, "last_error": None, "acknowledged_at": None}
                serialized = _canonical(record)
                connection.execute("INSERT INTO collector_spool_records VALUES (?,?,?,?)",
                                   (len(records) + 1, event["event_id"], serialized, _digest(serialized)))
            checkpoint = _canonical({"offset": offset, "prefix_sha256": prefix_sha256,
                                     "records": len(records) + int(created)})
            connection.execute(
                "UPDATE collector_spool_metadata SET checkpoint=?,checkpoint_digest=? WHERE id=1",
                (checkpoint, _digest(checkpoint)),
            )
        return created

    def next_pending(self, now: datetime) -> dict | None:
        timestamp = _time(now)
        result = None
        with self._transaction() as connection:
            _, records = self._read(connection)
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
            _, records = self._read(connection)
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
            _, records = self._read(connection)
            record = self._find(records, event_id)
            if record["state"] != "pending":
                raise SpoolConflict("acknowledged collector event is immutable")
            record.update(attempts=record["attempts"] + 1, next_retry_at=due, last_error=error_code)
            self._write(connection, record)

    def acknowledge(self, event_id: str, *, now: datetime) -> None:
        timestamp = _time(now)
        with self._transaction() as connection:
            _, records = self._read(connection)
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
            checkpoint, records = self._read(connection)
            acknowledged = sum(record["state"] == "acknowledged" for record in records)
            errors = [record["last_error"] for record in records if record["last_error"]]
            result = {"captured": len(records), "acknowledged": acknowledged,
                      "pending": len(records) - acknowledged, "offset": checkpoint["offset"],
                      "last_error": errors[-1] if errors else None}
        return result
