"""Bounded, durable local signal inbox with leased, fenced delivery.

The inbox and session journal may share a SQLite file, but never a transaction.
Delivery is at least once: consumers must make policy updates idempotent. Terminal
receipts may move to immutable compressed archives in the same database. Reaching
archive limits refuses new signals instead of forgetting deduplication history.
"""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.services import inbox_archive


class InboxConflict(ValueError):
    pass


class InboxFull(RuntimeError):
    pass


class InboxUnavailable(RuntimeError):
    pass


class InboxLeaseLost(RuntimeError):
    pass


class InboxMissing(LookupError):
    pass


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ERROR = re.compile(r"[a-zA-Z0-9_.:-]{1,100}\Z")
_STATES = {"pending", "processing", "completed", "failed"}


def _json(value: dict) -> str:
    if not isinstance(value, dict):
        raise TypeError("inbox payload must be an object")
    result = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )
    if len(result.encode("utf-8")) > 1_048_576:
        raise ValueError("inbox object too large")
    return result


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(value: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("invalid inbox identifier")


def _time(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("inbox requires timezone-aware timestamps")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _read_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if _time(parsed) != value:
        raise ValueError("noncanonical inbox timestamp")
    return parsed


class SignalInbox:
    """Single-host local store; operations verify all bounded retained records.

    Verification and the write lock are O(retained records), including JSON/hash
    work. The default 10,000-row cap is a local safety boundary, not a throughput
    claim or a production queue design.
    """

    def __init__(
        self,
        path: Path,
        max_pending: int = 1000,
        max_records: int = 10000,
        max_attempts: int = 3,
        lease_seconds: float = 30,
        retry_seconds: float = 1,
        *,
        max_pending_per_tenant: int | None = None,
        max_records_per_tenant: int | None = None,
        archive_batch_size: int = 5000,
        max_archive_records: int = 100000,
        max_archive_segments: int = 1000,
        max_archive_records_per_tenant: int | None = None,
    ):
        self.path = Path(path)
        self.max_pending = max_pending
        self.max_records = max_records
        self.max_attempts = max_attempts
        self.lease_seconds = lease_seconds
        self.retry_seconds = retry_seconds
        self.max_pending_per_tenant = (
            max_pending if max_pending_per_tenant is None else max_pending_per_tenant
        )
        self.max_records_per_tenant = (
            max_records if max_records_per_tenant is None else max_records_per_tenant
        )
        self._archive_limits = inbox_archive.ArchiveLimits(
            max_records=max_records, max_records_per_tenant=self.max_records_per_tenant,
            archive_batch_size=archive_batch_size, max_archive_records=max_archive_records,
            max_archive_segments=max_archive_segments,
            max_archive_records_per_tenant=(max_archive_records if max_archive_records_per_tenant is None
                                            else max_archive_records_per_tenant),
        )
        for value in (
            max_pending, max_records, max_attempts,
            self.max_pending_per_tenant, self.max_records_per_tenant,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError("inbox limits must be positive integers")
        if max_attempts > 100 or not 0 < lease_seconds <= 86400 or not 0 < retry_seconds <= 3600:
            raise ValueError("invalid inbox retry or lease limits")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._transaction() as connection:
                inbox_archive.initialize(connection, self._validate, self._archive_limits)
        except OSError as exc:
            raise InboxUnavailable("signal inbox unavailable") from exc

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
            if isinstance(exc, InboxConflict):
                raise
            raise InboxUnavailable("signal inbox unavailable") from exc
        except inbox_archive.ArchiveFull as exc:
            if connection is not None:
                connection.rollback()
            raise InboxFull("signal inbox archive capacity reached") from exc
        except BaseException:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _validate(row: dict) -> dict:
        for field in ("tenant_id", "event_id", "submitted_by"):
            _identity(row[field])
        for field in ("input_digest", "payload_digest"):
            if not isinstance(row[field], str) or not _HEX.fullmatch(row[field]):
                raise ValueError("invalid inbox digest")
        if not isinstance(row["payload"], str) or len(row["payload"].encode()) > 1_048_576:
            raise ValueError("invalid stored inbox payload")
        payload = json.loads(row["payload"])
        if _json(payload) != row["payload"] or not hmac.compare_digest(
            _sha(row["payload"]), row["payload_digest"]
        ):
            raise ValueError("inbox payload integrity failed")
        received = _read_time(row["received_at"])
        if row["state"] not in _STATES or type(row["attempts"]) is not int:
            raise ValueError("invalid inbox state")
        if row["attempts"] < 0 or row["attempts"] > 100:
            raise ValueError("invalid inbox attempts")
        for field in ("next_attempt_at", "lease_expires_at", "completed_at"):
            if row[field] is not None and _read_time(row[field]) < received:
                raise ValueError("inbox state predates acceptance")
        if row["last_error"] is not None and not _ERROR.fullmatch(row["last_error"]):
            raise ValueError("invalid inbox error code")
        state = row["state"]
        if state in {"pending", "processing"}:
            if row["next_attempt_at"] is None or row["completed_at"] is not None:
                raise ValueError("invalid active inbox row")
            if row["result_json"] is not None:
                raise ValueError("active inbox row has result")
        else:
            if row["completed_at"] is None or row["next_attempt_at"] is not None:
                raise ValueError("invalid terminal inbox row")
        if state == "processing":
            if (
                not isinstance(row["lease_token"], str)
                or not _HEX.fullmatch(row["lease_token"])
                or row["lease_expires_at"] is None or row["attempts"] < 1
            ):
                raise ValueError("invalid inbox lease")
        elif row["lease_token"] is not None or row["lease_expires_at"] is not None:
            raise ValueError("inbox lease in wrong state")
        if state == "completed":
            if row["result_json"] is None or _json(json.loads(row["result_json"])) != row["result_json"]:
                raise ValueError("invalid inbox result")
        elif row["result_json"] is not None:
            raise ValueError("inbox result in wrong state")
        if state in {"completed", "failed"} and row["attempts"] < 1:
            raise ValueError("unattempted terminal inbox row")
        if state == "failed" and row["last_error"] is None:
            raise ValueError("failed inbox row without reason")
        return row

    def _rows(self, connection) -> list[dict]:
        # Capacity is bounded; validating every row also detects corrupt rows that
        # otherwise would disappear from a state-filtered claim or metrics query.
        return inbox_archive.read(connection, self._validate, self._archive_limits).rows

    @staticmethod
    def _receipt(row: dict, *, duplicate: bool = False) -> dict:
        return {
            "tenant_id": row["tenant_id"], "event_id": row["event_id"],
            "state": row["state"], "duplicate": duplicate,
            "received_at": row["received_at"], "attempts": row["attempts"],
            "next_attempt_at": row["next_attempt_at"],
            "completed_at": row["completed_at"], "last_error": row["last_error"],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
        }

    @staticmethod
    def _find(rows: list[dict], tenant_id: str, event_id: str) -> dict:
        row = next((row for row in rows
                    if row["tenant_id"] == tenant_id and row["event_id"] == event_id), None)
        if row is None:
            raise InboxMissing("signal receipt not found")
        return row

    def accept(self, tenant_id: str, event_id: str, payload: dict, input_digest: str,
               submitted_by: str, now: datetime) -> dict:
        for value in (tenant_id, event_id, submitted_by):
            _identity(value)
        if not isinstance(input_digest, str) or not _HEX.fullmatch(input_digest):
            raise ValueError("invalid inbox input digest")
        serialized = _json(payload)
        payload_digest = _sha(serialized)
        timestamp = _time(now)
        with self._transaction() as connection:
            rows = self._rows(connection)
            previous = next((row for row in rows
                             if row["tenant_id"] == tenant_id and row["event_id"] == event_id), None)
            if previous is not None:
                if not hmac.compare_digest(previous["input_digest"], input_digest) or not (
                    hmac.compare_digest(previous["payload_digest"], payload_digest)
                ):
                    raise InboxConflict("event identifier already has a different signal")
                receipt = self._receipt(previous, duplicate=True)
            else:
                tenant_rows = [row for row in rows if row["tenant_id"] == tenant_id]
                active = lambda row: row["state"] in {"pending", "processing"}
                if (
                    sum(map(active, rows)) >= self.max_pending
                    or sum(map(active, tenant_rows)) >= self.max_pending_per_tenant
                ):
                    raise InboxFull("signal inbox capacity reached; retained receipts require archiving")
                prospective = dict.fromkeys(inbox_archive.FIELDS)
                prospective.update(tenant_id=tenant_id, event_id=event_id, payload=serialized,
                                   input_digest=input_digest, payload_digest=payload_digest,
                                   submitted_by=submitted_by, received_at=timestamp,
                                   state="pending", attempts=0, next_attempt_at=timestamp)
                incoming_bytes = len(inbox_archive.canonical(prospective).encode("utf-8"))
                inbox_archive.ensure_capacity(connection, self._validate, self._archive_limits, tenant_id, incoming_bytes)
                connection.execute(
                    "INSERT INTO signal_inbox (tenant_id,event_id,payload,input_digest,payload_digest,"
                    "submitted_by,received_at,state,attempts,next_attempt_at) "
                    "VALUES (?,?,?,?,?,?,?,'pending',0,?)",
                    (tenant_id, event_id, serialized, input_digest, payload_digest,
                     submitted_by, timestamp, timestamp),
                )
                inbox_archive.refresh(connection, self._validate, self._archive_limits, added=1)
                receipt = self._receipt(self._find(self._rows(connection), tenant_id, event_id))
        # This line is reached only after SQLite successfully committed.
        return receipt

    def get(self, tenant_id: str, event_id: str) -> dict:
        with self._transaction() as connection:
            receipt = self._receipt(self._find(self._rows(connection), tenant_id, event_id))
        return receipt

    def claim(self, *, now: datetime, reconcile_exhausted: bool = False) -> dict | None:
        """Lease eligible work, optionally reconciling an exhausted delivery's ACK.

        With reconciliation enabled, ``reconcile_only`` requires the consumer to
        read its committed effect marker without applying policy effects again.
        Reconciliation leases do not increase the bounded policy-attempt counter.
        """
        timestamp = _time(now)
        claimed = None
        with self._transaction() as connection:
            mutated = False
            for row in self._rows(connection):
                if row["state"] == "processing":
                    if row["lease_expires_at"] > timestamp:
                        continue
                elif row["state"] != "pending" or row["next_attempt_at"] > timestamp:
                    continue
                if row["received_at"] > timestamp:
                    continue
                exhausted = row["attempts"] >= self.max_attempts
                if exhausted and not reconcile_exhausted:
                    connection.execute(
                        "UPDATE signal_inbox SET state='failed',completed_at=?,next_attempt_at=NULL,"
                        "lease_token=NULL,lease_expires_at=NULL,last_error='lease_expired' "
                        "WHERE tenant_id=? AND event_id=?",
                        (timestamp, row["tenant_id"], row["event_id"]),
                    )
                    mutated = True
                    continue
                token = secrets.token_hex(32)
                lease_until = _time(now + timedelta(seconds=self.lease_seconds))
                connection.execute(
                    "UPDATE signal_inbox SET state='processing',attempts=attempts+?,"
                    "lease_token=?,lease_expires_at=? WHERE tenant_id=? AND event_id=?",
                    (0 if exhausted else 1, token, lease_until, row["tenant_id"], row["event_id"]),
                )
                mutated = True
                row.update(state="processing", attempts=row["attempts"] + (0 if exhausted else 1),
                           lease_token=token, lease_expires_at=lease_until)
                claimed = self._receipt(row) | {
                    "payload": json.loads(row["payload"]), "input_digest": row["input_digest"],
                    "submitted_by": row["submitted_by"], "lease_token": token,
                    "lease_expires_at": lease_until, "reconcile_only": exhausted,
                }
                break
            if mutated:
                inbox_archive.refresh(connection, self._validate, self._archive_limits)
        return claimed

    @staticmethod
    def _check_lease(row: dict, lease_token: str, timestamp: str) -> None:
        if (
            row["state"] != "processing" or not isinstance(lease_token, str)
            or not hmac.compare_digest(row["lease_token"], lease_token)
            or row["lease_expires_at"] <= timestamp or row["received_at"] > timestamp
        ):
            raise InboxLeaseLost("signal inbox delivery lease lost")

    def complete(self, tenant_id: str, event_id: str, lease_token: str,
                 result: dict, now: datetime) -> dict:
        serialized = _json(result)
        timestamp = _time(now)
        with self._transaction() as connection:
            row = self._find(self._rows(connection), tenant_id, event_id)
            self._check_lease(row, lease_token, timestamp)
            connection.execute(
                "UPDATE signal_inbox SET state='completed',completed_at=?,result_json=?,"
                "next_attempt_at=NULL,lease_token=NULL,lease_expires_at=NULL,last_error=NULL "
                "WHERE tenant_id=? AND event_id=?",
                (timestamp, serialized, tenant_id, event_id),
            )
            inbox_archive.refresh(connection, self._validate, self._archive_limits)
            receipt = self._receipt(self._find(self._rows(connection), tenant_id, event_id))
        return receipt

    def fail(self, tenant_id: str, event_id: str, lease_token: str,
             error_code: str, now: datetime) -> dict:
        if not isinstance(error_code, str) or not _ERROR.fullmatch(error_code):
            raise ValueError("inbox errors must be bounded codes, not exception details")
        timestamp = _time(now)
        with self._transaction() as connection:
            row = self._find(self._rows(connection), tenant_id, event_id)
            self._check_lease(row, lease_token, timestamp)
            terminal = row["attempts"] >= self.max_attempts
            delay = min(self.retry_seconds * 2 ** min(row["attempts"] - 1, 20), 3600)
            due = None if terminal else _time(now + timedelta(seconds=delay))
            connection.execute(
                "UPDATE signal_inbox SET state=?,next_attempt_at=?,completed_at=?,last_error=?,"
                "lease_token=NULL,lease_expires_at=NULL WHERE tenant_id=? AND event_id=?",
                ("failed" if terminal else "pending", due, timestamp if terminal else None,
                 error_code, tenant_id, event_id),
            )
            inbox_archive.refresh(connection, self._validate, self._archive_limits)
            receipt = self._receipt(self._find(self._rows(connection), tenant_id, event_id))
        return receipt

    def metrics(self, tenant_id: str, *, now: datetime | None = None) -> dict:
        observed = _read_time(_time(now if now is not None else datetime.now(UTC)))
        with self._transaction() as connection:
            storage = inbox_archive.read(connection, self._validate, self._archive_limits)
            rows = [row for row in storage.rows if row["tenant_id"] == tenant_id]
            result = {state: sum(row["state"] == state for row in rows) for state in sorted(_STATES)}
            result.update(total=len(rows), max_pending=self.max_pending_per_tenant,
                          max_records=self.max_records_per_tenant,
                          active_records=sum(row["tenant_id"] == tenant_id for row in storage.active),
                          archived_records=sum(row["tenant_id"] == tenant_id for row in storage.archived))
            # Ages measure acceptance-to-observation, not worker CPU time. Completion
            # latency includes queueing and retries and is bounded to retained rows.
            for state in ("pending", "processing"):
                ages = [max(0.0, (observed - _read_time(row["received_at"])).total_seconds())
                        for row in rows if row["state"] == state]
                result[f"oldest_{state}_age_seconds"] = max(ages) if ages else None
            latencies = [
                (_read_time(row["completed_at"]) - _read_time(row["received_at"])).total_seconds()
                for row in rows if row["state"] == "completed"
            ]
            result.update(
                completion_latency_samples=len(latencies),
                mean_completion_latency_seconds=(sum(latencies) / len(latencies)
                                                 if latencies else None),
                max_completion_latency_seconds=max(latencies) if latencies else None,
            )
        return result

    def compact(self, *, limit: int | None = None) -> dict:
        with self._transaction() as connection:
            return inbox_archive.compact(connection, self._validate, self._archive_limits, limit=limit)

    def storage_status(self) -> dict:
        with self._transaction() as connection:
            storage = inbox_archive.read(connection, self._validate, self._archive_limits)
            return inbox_archive.status(storage, self._archive_limits)

    def integrity(self) -> dict:
        result = {"backend": "sqlite", "mode": "local"}
        try:
            with self._transaction() as connection:
                count = len(self._rows(connection))
            return result | {"ok": True, "verified_records": count}
        except InboxUnavailable:
            return result | {"ok": False}
