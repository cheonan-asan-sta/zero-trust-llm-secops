import asyncio
import hashlib
import hmac
import json
import math
import os
import stat
import threading
from pathlib import Path
from typing import Protocol

import boto3
from boto3.dynamodb.conditions import Key

from app.config import Settings
from app.models import AnalysisResult, MetricsSummary, ReviewStatus


class AuditRepository(Protocol):
    async def save(self, record: AnalysisResult) -> None: ...

    def get(self, event_id: str, tenant_id: str = "local") -> AnalysisResult | None: ...

    def recent(self, limit: int = 20, tenant_id: str = "local") -> list[AnalysisResult]: ...

    def metrics(self, tenant_id: str = "local") -> MetricsSummary: ...

    def integrity(self) -> dict[str, bool | int | str]: ...


class AuditStore:
    MAX_BYTES = 128 * 1024 * 1024
    MAX_ROWS = 100000
    MAX_ROW_BYTES = 2 * 1024 * 1024
    _local_review_history = True

    def __init__(self, path: Path, *, strict_reads: bool = False) -> None:
        self._strict_reads = strict_reads
        self._path = path
        self._records: dict[tuple[str, str], AnalysisResult] = {}
        self._history: list[AnalysisResult] = []
        self._history_positions: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._disk_lock = threading.RLock()
        self._prefix_hasher = hashlib.sha256()
        self._last_hash = "0" * 64
        self._integrity_ok = True
        self._verified_lines = 0
        self._legacy_lines = 0
        self._page_seen_file = path.exists()
        self._load_existing()

    async def save(self, record: AnalysisResult) -> None:
        async with self._lock:
            if not self._integrity_ok:
                raise RuntimeError("audit log integrity check failed; refusing to append")
            # Cancellation cannot stop an active filesystem thread. Keep the
            # writer lock until it settles, then publish the same record in
            # memory before propagating cancellation to the disconnected caller.
            write = asyncio.get_running_loop().run_in_executor(None, self._append_jsonl, record)
            cancelled = None
            while True:
                try:
                    await asyncio.shield(write)
                    break
                except asyncio.CancelledError as error:
                    if write.cancelled():
                        self._integrity_ok = False
                        raise
                    cancelled = error
                except BaseException:
                    # A failed append may have left a partial line. Do not add
                    # more records on an unverified chain; preserve it for recovery.
                    self._integrity_ok = False
                    raise
            self._upsert(record)
            if cancelled is not None:
                raise cancelled

    def get(self, event_id: str, tenant_id: str = "local") -> AnalysisResult | None:
        return self._records.get((tenant_id, event_id))

    def recent(self, limit: int = 20, tenant_id: str = "local") -> list[AnalysisResult]:
        records = [record for record in self._history if record.tenant_id == tenant_id]
        return list(reversed(records[-limit:]))

    def metrics(self, tenant_id: str = "local") -> MetricsSummary:
        return _summarize([record for record in self._history if record.tenant_id == tenant_id])

    def integrity(self) -> dict[str, bool | int | str]:
        return {
            "backend": "jsonl_hash_chain",
            "ok": self._integrity_ok,
            "verified_lines": self._verified_lines,
            "legacy_lines": self._legacy_lines,
        }

    def verify_saved(self, expected):
        from app.services.audit_wire import analysis_wire
        from app.services.federated_audit import AuditQueryUnavailable

        expected = AnalysisResult.model_validate_json(expected.model_dump_json())
        expected_wire = analysis_wire(expected)
        found = False

        def observe(record, hashed):
            nonlocal found
            if hashed and record.analysis_id == expected.analysis_id:
                found = found or analysis_wire(record) == expected_wire

        # Reopen bounded disk data, never the writer's cached result objects.
        self._saved_view(observe)
        if not found:
            raise AuditQueryUnavailable("returned analysis is not preserved in its writer shard")

    def _saved_view(self, observe):
        from app.services.audit_paging import _jsonl_view

        return _jsonl_view(
            self,
            row_observer=observe,
            allow_legacy_prefix=True,
            validate_review_transitions=self._local_review_history,
        )

    def _check_writer_view(self):
        from app.services.audit_paging import _jsonl_view
        from app.services.federated_audit import AuditQueryUnavailable

        metadata = {}
        # Ownership is byte/prefix equality, independent of cross-file review state.
        _jsonl_view(
            self,
            allow_legacy_prefix=True,
            metadata=metadata,
            validate_review_transitions=self._local_review_history,
        )
        if (
            metadata["head"] != self._last_hash
            or metadata["verified"] != self._verified_lines
            or metadata["legacy"] != self._legacy_lines
            or metadata["fingerprint"] != self._prefix_hasher.hexdigest()
        ):
            raise AuditQueryUnavailable("owned audit writer differs from its loaded prefix")
        return metadata

    def writer_integrity(self):
        from app.services.federated_audit import AuditQueryUnavailable

        with self._disk_lock:
            result = self.integrity()
            try:
                if result["ok"]:
                    self._check_writer_view()
                verified = result["ok"]
            except AuditQueryUnavailable:
                verified = False
            return {**result, "ok": verified, "writer_head_verified": verified}

    def _load_existing(self) -> None:
        if self._path.is_symlink():
            self._integrity_ok = False
            if self._strict_reads:
                raise OSError("audit bootstrap link rejected")
            return
        if not self._path.exists():
            if self._strict_reads:
                raise OSError("required audit shard missing")
            return

        try:
            if not stat.S_ISREG(self._path.lstat().st_mode):
                self._integrity_ok = False
                if self._strict_reads:
                    raise OSError("audit bootstrap regular file required")
                return
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            with os.fdopen(os.open(self._path, flags), "rb") as stream:
                before = os.fstat(stream.fileno())
                live = self._path.lstat()
                signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or not stat.S_ISREG(live.st_mode)
                    or before.st_size > self.MAX_BYTES
                    or signature(before) != signature(live)
                ):
                    self._integrity_ok = False
                    if self._strict_reads:
                        raise OSError("audit bootstrap file rejected")
                    return
                raw = stream.read(self.MAX_BYTES + 1)
                after = os.fstat(stream.fileno())
                current = self._path.lstat()
            if (
                len(raw) > self.MAX_BYTES
                or len(raw) != before.st_size
                or not stat.S_ISREG(current.st_mode)
                or signature(before) != signature(after)
                or signature(after) != signature(current)
            ):
                self._integrity_ok = False
                if self._strict_reads:
                    raise OSError("audit bootstrap changed during read")
                return
            self._prefix_hasher.update(raw)
            lines = raw.decode("utf-8").splitlines()
        except OSError:
            if self._strict_reads:
                raise
            return

        expected_previous_hash = "0" * 64
        count = 0
        for line in lines:
            if not line.strip():
                continue
            count += 1
            if count > self.MAX_ROWS or len(line.encode("utf-8")) > self.MAX_ROW_BYTES:
                self._integrity_ok = False
                if self._strict_reads:
                    raise OSError("audit bootstrap row capacity exceeded")
                return
            try:
                value = json.loads(line)
            except (TypeError, ValueError):
                self._integrity_ok = False
                continue

            if isinstance(value, dict) and value.get("schema_version") == 1:
                payload = value.get("payload")
                previous_hash = value.get("previous_hash")
                record_hash = value.get("record_hash")
                if not all(isinstance(item, str) for item in (payload, previous_hash, record_hash)):
                    self._integrity_ok = False
                    continue
                calculated = _record_hash(previous_hash, payload)
                if previous_hash != expected_previous_hash or not hmac.compare_digest(
                    calculated, record_hash
                ):
                    self._integrity_ok = False
                    continue
                expected_previous_hash = record_hash
                self._verified_lines += 1
                try:
                    record = AnalysisResult.model_validate_json(payload)
                except ValueError:
                    self._integrity_ok = False
                    continue
            else:
                try:
                    record = AnalysisResult.model_validate(value)
                except ValueError:
                    self._integrity_ok = False
                    continue
                self._legacy_lines += 1
            self._upsert(record)
        self._last_hash = expected_previous_hash

    def _upsert(self, record: AnalysisResult) -> None:
        position = self._history_positions.get(record.analysis_id)
        if position is None:
            self._history_positions[record.analysis_id] = len(self._history)
            self._history.append(record)
        else:
            self._history[position] = record

        record_key = (record.tenant_id, record.event_id)
        latest = self._records.get(record_key)
        if (
            latest is None
            or latest.analysis_id == record.analysis_id
            or record.analyzed_at >= latest.analyzed_at
        ):
            self._records[record_key] = record

    def _append_jsonl(self, record: AnalysisResult) -> None:
        with self._disk_lock:
            self._append_jsonl_locked(record)

    def _append_jsonl_locked(self, record: AnalysisResult) -> None:
        from app.services.audit_paging import _file_signature
        from app.services.federated_audit import AuditQueryUnavailable

        self._path.parent.mkdir(parents=True, exist_ok=True)
        metadata = self._check_writer_view()
        payload = record.model_dump_json()
        record_hash = _record_hash(self._last_hash, payload)
        envelope = {
            "schema_version": 1,
            "previous_hash": self._last_hash,
            "record_hash": record_hash,
            "payload": payload,
        }
        encoded = (json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        if (
            len(encoded) > self.MAX_ROW_BYTES
            or metadata["size"] + len(encoded) > self.MAX_BYTES
            or metadata["verified"] + metadata["legacy"] >= self.MAX_ROWS
        ):
            raise AuditQueryUnavailable("audit append capacity exceeded")
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        if metadata["signature"] is None:
            flags |= os.O_CREAT | os.O_EXCL
        fd = os.open(self._path, flags, 0o600)
        try:
            before = os.fstat(fd)
            live = self._path.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or not stat.S_ISREG(live.st_mode)
                or _file_signature(before) != _file_signature(live)
                or (
                    metadata["signature"] is not None
                    and _file_signature(before) != metadata["signature"]
                )
                or before.st_size != metadata["size"]
            ):
                raise AuditQueryUnavailable("audit append target changed before write")
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("audit append made no progress")
                remaining = remaining[written:]
            os.fsync(fd)
            after = os.fstat(fd)
            current = self._path.lstat()
            if (
                after.st_size != metadata["size"] + len(encoded)
                or not stat.S_ISREG(current.st_mode)
                or _file_signature(after) != _file_signature(current)
            ):
                raise AuditQueryUnavailable("audit append target changed during write")
        finally:
            os.close(fd)
        self._prefix_hasher.update(encoded)
        self._last_hash = record_hash
        self._verified_lines += 1
        self._page_seen_file = True


class DynamoDBAuditStore:
    def __init__(self, table_name: str, region_name: str) -> None:
        resource = boto3.resource("dynamodb", region_name=region_name)
        self._table = resource.Table(table_name)

    async def save(self, record: AnalysisResult) -> None:
        item = {
            "analysis_id": record.analysis_id,
            "event_id": record.event_id,
            "tenant_event_key": f"{record.tenant_id}#{record.event_id}",
            "tenant_id": record.tenant_id,
            "record_type": "analysis",
            "analyzed_at": record.analyzed_at.isoformat(),
            "payload": record.model_dump_json(),
        }
        item["payload_sha256"] = hashlib.sha256(item["payload"].encode("utf-8")).hexdigest()
        await asyncio.to_thread(self._table.put_item, Item=item)

    def get(self, event_id: str, tenant_id: str = "local") -> AnalysisResult | None:
        response = self._table.query(
            IndexName="TenantEventIndex",
            KeyConditionExpression=Key("tenant_event_key").eq(f"{tenant_id}#{event_id}"),
            ScanIndexForward=False,
            Limit=1,
        )
        records = _parse_items(response.get("Items", []), tenant_id)
        return records[0] if records else None

    def recent(self, limit: int = 20, tenant_id: str = "local") -> list[AnalysisResult]:
        response = self._table.query(
            IndexName="TenantRecentIndex",
            KeyConditionExpression=Key("tenant_id").eq(tenant_id),
            ScanIndexForward=False,
            Limit=limit,
        )
        return _parse_items(response.get("Items", []), tenant_id)

    def metrics(self, tenant_id: str = "local") -> MetricsSummary:
        items: list[dict] = []
        response = self._table.query(
            IndexName="TenantRecentIndex",
            KeyConditionExpression=Key("tenant_id").eq(tenant_id),
        )
        items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = self._table.query(
                IndexName="TenantRecentIndex",
                KeyConditionExpression=Key("tenant_id").eq(tenant_id),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))
        records = _parse_items(items, tenant_id)
        records.sort(key=lambda record: record.analyzed_at)
        return _summarize(records)

    def integrity(self) -> dict[str, bool | int | str]:
        return {
            "backend": "dynamodb_payload_digest",
            "ok": True,
            "verified_lines": 0,
            "legacy_lines": 0,
        }


def create_audit_store(settings: Settings) -> AuditRepository:
    if settings.audit_backend == "sqlite":
        from app.services.sqlite_audit import SQLiteAuditStore

        path = settings.audit_db_path or settings.audit_log_path.with_suffix(".sqlite3")
        if path.resolve() in {
            settings.zero_trust_db_path.resolve(),
            settings.audit_log_path.resolve(),
        }:
            raise ValueError("audit database must be separate from policy and JSONL sources")
        if settings.audit_checkpoint_path is not None:
            from app.services.guarded_sqlite_audit import GuardedSQLiteAuditStore

            return GuardedSQLiteAuditStore.open_guarded(
                path, settings.audit_checkpoint_path, settings.audit_checkpoint_sha256
            )
        return SQLiteAuditStore(path)
    if settings.audit_backend == "dynamodb":
        return DynamoDBAuditStore(settings.dynamodb_table_name, settings.aws_region)
    path = settings.audit_log_path
    if (
        settings.native_analysis_shared_config_path is not None
        and settings.app_environment != "production"
    ):
        # Each local worker owns its hash-chain writer. Sharing native references
        # must not make independent JSONL writers fork the same audit chain.
        path = path.with_name(f"{path.stem}.worker-{os.getpid()}{path.suffix}")
        from app.services.federated_audit import FederatedAuditStore

        return FederatedAuditStore(path, settings.audit_log_path)
    return AuditStore(path)


def _parse_items(items: list[dict], tenant_id: str) -> list[AnalysisResult]:
    records: list[AnalysisResult] = []
    for item in items:
        payload = item.get("payload")
        if not isinstance(payload, str):
            continue
        expected_digest = item.get("payload_sha256")
        if isinstance(expected_digest, str) and not hmac.compare_digest(
            hashlib.sha256(payload.encode("utf-8")).hexdigest(), expected_digest
        ):
            continue
        try:
            record = AnalysisResult.model_validate_json(payload)
        except ValueError:
            continue
        if record.tenant_id == tenant_id:
            records.append(record)
    return records


def _record_hash(previous_hash: str, payload: str) -> str:
    return hashlib.sha256(f"{previous_hash}.{payload}".encode()).hexdigest()


def _summarize(records: list[AnalysisResult]) -> MetricsSummary:
    risk_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    analyzer_counts: dict[str, int] = {}
    review_counts: dict[str, int] = {}

    for record in records:
        risk = record.assessment.risk_level.value
        action = record.policy_decision.action.value
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        action_counts[action] = action_counts.get(action, 0) + 1
        analyzer_counts[record.analyzer] = analyzer_counts.get(record.analyzer, 0) + 1
        review = record.review_status.value
        review_counts[review] = review_counts.get(review, 0) + 1

    latest = records[-1].event_id if records else None
    latencies = sorted(record.latency_ms for record in records)
    average_latency = sum(latencies) / len(latencies) if latencies else 0
    p95_index = max(math.ceil(len(latencies) * 0.95) - 1, 0) if latencies else 0
    p95_latency = latencies[p95_index] if latencies else 0
    return MetricsSummary(
        total_analyses=len(records),
        risk_counts=risk_counts,
        action_counts=action_counts,
        analyzer_counts=analyzer_counts,
        review_counts=review_counts,
        pending_review_count=(
            review_counts.get(ReviewStatus.PENDING.value, 0)
            + review_counts.get(ReviewStatus.IN_REVIEW.value, 0)
        ),
        latest_event_id=latest,
        average_latency_ms=round(average_latency, 2),
        p95_latency_ms=round(p95_latency, 2),
    )
