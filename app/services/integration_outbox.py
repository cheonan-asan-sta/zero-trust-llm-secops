import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.config import Settings
from app.models import (
    IncidentCase,
    IncidentCaseCloudEvent,
    IncidentCaseIntegrationData,
    IntegrationDeliveryHistoryEntry,
    IntegrationDeliveryStatus,
    IntegrationDeliveryUpdateRequest,
    IntegrationOutboxMetrics,
    IntegrationOutboxRecord,
)

INTEGRATION_OUTBOX_VERSION = "0.15.0"


class OutboxNotFoundError(LookupError):
    pass


class OutboxConflictError(RuntimeError):
    pass


class OutboxTerminalStateError(ValueError):
    pass


class OutboxNotDueError(ValueError):
    pass


class OutboxRepository(Protocol):
    async def save(self, record: IntegrationOutboxRecord) -> None: ...

    def get(
        self,
        event_id: str,
        tenant_id: str = "local",
    ) -> IntegrationOutboxRecord | None: ...

    def recent(
        self,
        limit: int = 20,
        tenant_id: str = "local",
        status: IntegrationDeliveryStatus | None = None,
    ) -> list[IntegrationOutboxRecord]: ...

    def metrics(self, tenant_id: str = "local") -> IntegrationOutboxMetrics: ...

    def integrity(self) -> dict[str, bool | int | str]: ...


class IntegrationOutboxStore:
    """Append-only local delivery journal with a fail-closed hash chain."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: dict[tuple[str, str], IntegrationOutboxRecord] = {}
        self._lock = asyncio.Lock()
        self._last_hash = "0" * 64
        self._integrity_ok = True
        self._verified_lines = 0
        self._load_existing()

    async def save(self, record: IntegrationOutboxRecord) -> None:
        async with self._lock:
            if not self._integrity_ok:
                raise RuntimeError("outbox log integrity check failed; refusing to append")
            key = (record.event.tenant_id, record.event.id)
            existing = self._records.get(key)
            expected_version = 1 if existing is None else existing.version + 1
            if record.version != expected_version:
                raise OutboxConflictError(
                    f"outbox version conflict: expected {expected_version}, got {record.version}"
                )
            if existing is not None and existing.event != record.event:
                raise OutboxConflictError("immutable integration event payload changed")
            await asyncio.to_thread(self._append_jsonl, record)
            self._records[key] = record

    def get(
        self,
        event_id: str,
        tenant_id: str = "local",
    ) -> IntegrationOutboxRecord | None:
        return self._records.get((tenant_id, event_id))

    def recent(
        self,
        limit: int = 20,
        tenant_id: str = "local",
        status: IntegrationDeliveryStatus | None = None,
    ) -> list[IntegrationOutboxRecord]:
        records = [
            record
            for (record_tenant, _), record in self._records.items()
            if record_tenant == tenant_id and (status is None or record.status == status)
        ]
        records.sort(
            key=lambda record: (record.event.time, record.event.id),
            reverse=True,
        )
        return records[:limit]

    def metrics(self, tenant_id: str = "local") -> IntegrationOutboxMetrics:
        return _summarize(self.recent(10000, tenant_id))

    def integrity(self) -> dict[str, bool | int | str]:
        return {
            "backend": "jsonl_hash_chain",
            "ok": self._integrity_ok,
            "verified_lines": self._verified_lines,
            "version": INTEGRATION_OUTBOX_VERSION,
            "delivery_mode": "simulation",
        }

    def _load_existing(self) -> None:
        if not self._path.exists():
            return
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            self._integrity_ok = False
            return

        expected_previous_hash = "0" * 64
        for line in lines:
            if not line.strip():
                continue
            try:
                envelope = json.loads(line)
                payload = envelope["payload"]
                previous_hash = envelope["previous_hash"]
                record_hash = envelope["record_hash"]
                if envelope.get("schema_version") != 1 or not all(
                    isinstance(value, str)
                    for value in (payload, previous_hash, record_hash)
                ):
                    raise ValueError("invalid outbox envelope")
                calculated = _record_hash(previous_hash, payload)
                if previous_hash != expected_previous_hash or not hmac.compare_digest(
                    calculated, record_hash
                ):
                    raise ValueError("invalid outbox hash chain")
                record = IntegrationOutboxRecord.model_validate_json(payload)
                key = (record.event.tenant_id, record.event.id)
                existing = self._records.get(key)
                expected_version = 1 if existing is None else existing.version + 1
                if record.version != expected_version:
                    raise ValueError("invalid outbox version sequence")
                if existing is not None and existing.event != record.event:
                    raise ValueError("immutable integration event payload changed")
            except (KeyError, TypeError, ValueError):
                self._integrity_ok = False
                continue
            expected_previous_hash = record_hash
            self._last_hash = record_hash
            self._verified_lines += 1
            self._records[key] = record

    def _append_jsonl(self, record: IntegrationOutboxRecord) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = record.model_dump_json()
        record_hash = _record_hash(self._last_hash, payload)
        envelope = {
            "schema_version": 1,
            "previous_hash": self._last_hash,
            "record_hash": record_hash,
            "payload": payload,
        }
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n")
        self._last_hash = record_hash
        self._verified_lines += 1


class DynamoDBIntegrationOutboxStore:
    """DynamoDB projection using the existing tenant-aware audit table."""

    def __init__(self, table_name: str, region_name: str) -> None:
        resource = boto3.resource("dynamodb", region_name=region_name)
        self._table = resource.Table(table_name)

    async def save(self, record: IntegrationOutboxRecord) -> None:
        payload = record.model_dump_json()
        item = {
            "analysis_id": _dynamodb_key(record.event.tenant_id, record.event.id),
            "tenant_event_key": f"outbox#{record.event.tenant_id}#{record.event.id}",
            "tenant_id": record.event.tenant_id,
            "record_type": "integration_outbox",
            "analyzed_at": record.event.time.isoformat(),
            "event_id": record.event.id,
            "version": record.version,
            "payload": payload,
            "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        }
        if record.version == 1:
            condition = "attribute_not_exists(analysis_id)"
            values = None
        else:
            condition = "#version = :expected_version"
            values = {":expected_version": record.version - 1}
        kwargs: dict = {"Item": item, "ConditionExpression": condition}
        if record.version > 1:
            kwargs["ExpressionAttributeNames"] = {"#version": "version"}
        if values is not None:
            kwargs["ExpressionAttributeValues"] = values
        try:
            await asyncio.to_thread(self._table.put_item, **kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise OutboxConflictError("outbox version conflict") from exc
            raise

    def get(
        self,
        event_id: str,
        tenant_id: str = "local",
    ) -> IntegrationOutboxRecord | None:
        response = self._table.get_item(
            Key={"analysis_id": _dynamodb_key(tenant_id, event_id)},
            ConsistentRead=True,
        )
        return _parse_dynamodb_record(response.get("Item"), tenant_id)

    def recent(
        self,
        limit: int = 20,
        tenant_id: str = "local",
        status: IntegrationDeliveryStatus | None = None,
    ) -> list[IntegrationOutboxRecord]:
        items: list[dict] = []
        response = self._table.query(
            IndexName="TenantRecentIndex",
            KeyConditionExpression=Key("tenant_id").eq(tenant_id),
            ScanIndexForward=False,
        )
        items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = self._table.query(
                IndexName="TenantRecentIndex",
                KeyConditionExpression=Key("tenant_id").eq(tenant_id),
                ScanIndexForward=False,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))
        records = [
            record
            for item in items
            if (record := _parse_dynamodb_record(item, tenant_id)) is not None
            and (status is None or record.status == status)
        ]
        records.sort(key=lambda record: (record.event.time, record.event.id), reverse=True)
        return records[:limit]

    def metrics(self, tenant_id: str = "local") -> IntegrationOutboxMetrics:
        return _summarize(self.recent(10000, tenant_id))

    def integrity(self) -> dict[str, bool | int | str]:
        return {
            "backend": "dynamodb_payload_digest",
            "ok": True,
            "verified_lines": 0,
            "version": INTEGRATION_OUTBOX_VERSION,
            "delivery_mode": "simulation",
        }


class IntegrationOutboxService:
    def __init__(self, store: OutboxRepository) -> None:
        self.store = store

    async def reconcile_case(self, record: IncidentCase) -> tuple[int, int]:
        created = 0
        reused = 0
        for history in record.history:
            event = _cloud_event(record, history.sequence)
            existing = self.store.get(event.id, record.tenant_id)
            if existing is not None:
                if existing.event != event:
                    raise OutboxConflictError(
                        "integration event identifier exists with a different payload"
                    )
                reused += 1
                continue
            queued_at = datetime.now(UTC)
            outbox_record = IntegrationOutboxRecord(
                event=event,
                version=1,
                next_attempt_at=queued_at,
                history=[
                    IntegrationDeliveryHistoryEntry(
                        sequence=1,
                        status=IntegrationDeliveryStatus.PENDING,
                        recorded_at=queued_at,
                        actor_id="outbox-reconciler",
                        note="Case event queued for SIEM/ITSM delivery.",
                        attempt_number=0,
                    )
                ],
            )
            try:
                await self.store.save(outbox_record)
            except OutboxConflictError:
                concurrent = self.store.get(event.id, record.tenant_id)
                if concurrent is None or concurrent.event != event:
                    raise
                reused += 1
            else:
                created += 1
        return created, reused

    async def reconcile_cases(self, records: list[IncidentCase]) -> tuple[int, int]:
        created = 0
        reused = 0
        for record in records:
            case_created, case_reused = await self.reconcile_case(record)
            created += case_created
            reused += case_reused
        return created, reused

    async def record_attempt(
        self,
        event_id: str,
        tenant_id: str,
        actor_id: str,
        request: IntegrationDeliveryUpdateRequest,
        *,
        now: datetime | None = None,
    ) -> IntegrationOutboxRecord:
        existing = self.store.get(event_id, tenant_id)
        if existing is None:
            raise OutboxNotFoundError(event_id)
        if existing.status in {
            IntegrationDeliveryStatus.DELIVERED,
            IntegrationDeliveryStatus.DEAD_LETTER,
        }:
            raise OutboxTerminalStateError(
                f"delivery is already terminal: {existing.status.value}"
            )
        if request.expected_version != existing.version:
            raise OutboxConflictError(
                f"outbox version conflict: expected {existing.version}, got {request.expected_version}"
            )

        recorded_at = now or datetime.now(UTC)
        if existing.next_attempt_at is not None and existing.next_attempt_at > recorded_at:
            raise OutboxNotDueError("delivery retry is not due yet")
        attempt_count = existing.attempt_count + 1
        if request.outcome == "delivered":
            status = IntegrationDeliveryStatus.DELIVERED
            next_attempt_at = None
            delivered_at = recorded_at
            last_error_code = None
        elif request.outcome == "permanent_failure" or attempt_count >= existing.max_attempts:
            status = IntegrationDeliveryStatus.DEAD_LETTER
            next_attempt_at = None
            delivered_at = None
            last_error_code = request.error_code
        else:
            status = IntegrationDeliveryStatus.RETRY_SCHEDULED
            delay_seconds = min(30 * (2 ** (attempt_count - 1)), 3600)
            next_attempt_at = recorded_at + timedelta(seconds=delay_seconds)
            delivered_at = None
            last_error_code = request.error_code

        history = [
            *existing.history,
            IntegrationDeliveryHistoryEntry(
                sequence=existing.version + 1,
                status=status,
                recorded_at=recorded_at,
                actor_id=actor_id,
                note=request.note,
                attempt_number=attempt_count,
                error_code=last_error_code,
            ),
        ]
        updated = IntegrationOutboxRecord.model_validate(
            {
                **existing.model_dump(),
                "status": status,
                "version": existing.version + 1,
                "attempt_count": attempt_count,
                "next_attempt_at": next_attempt_at,
                "delivered_at": delivered_at,
                "last_error_code": last_error_code,
                "history": history,
            }
        )
        await self.store.save(updated)
        return updated


def create_integration_outbox_store(settings: Settings) -> OutboxRepository:
    if settings.audit_backend == "dynamodb":
        return DynamoDBIntegrationOutboxStore(
            settings.dynamodb_table_name,
            settings.aws_region,
        )
    return IntegrationOutboxStore(settings.outbox_log_path)


def _cloud_event(record: IncidentCase, sequence: int) -> IncidentCaseCloudEvent:
    history = record.history[sequence - 1]
    data = IncidentCaseIntegrationData(
        case_id=record.case_id,
        incident_uid=record.incident_uid,
        case_version=sequence,
        status=history.to_status,
        previous_status=history.from_status,
        severity_id=record.severity_id,
        title=record.title,
        assignee=history.assignee,
        evidence_sha256=record.evidence_sha256,
        occurred_at=history.changed_at,
    )
    data_sha256 = _data_digest(data)
    event_id = _event_id(record.tenant_id, record.case_id, sequence)
    event_type = (
        "io.blue-semester.secops.incident-case.created"
        if sequence == 1
        else "io.blue-semester.secops.incident-case.status-changed"
    )
    return IncidentCaseCloudEvent(
        id=event_id,
        source=f"/tenants/{record.tenant_id}/cases",
        type=event_type,
        subject=record.case_id,
        time=history.changed_at,
        tenant_id=record.tenant_id,
        data=data,
        data_sha256=data_sha256,
    )


def _event_id(tenant_id: str, case_id: str, case_version: int) -> str:
    digest = hashlib.sha256(f"{tenant_id}:{case_id}:{case_version}".encode()).hexdigest()[:32]
    return f"evt-{digest}"


def _data_digest(data: IncidentCaseIntegrationData) -> str:
    canonical = json.dumps(
        data.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _summarize(records: list[IntegrationOutboxRecord]) -> IntegrationOutboxMetrics:
    now = datetime.now(UTC)
    status_counts: dict[IntegrationDeliveryStatus, int] = {}
    for record in records:
        status_counts[record.status] = status_counts.get(record.status, 0) + 1
    return IntegrationOutboxMetrics(
        total_events=len(records),
        pending_count=status_counts.get(IntegrationDeliveryStatus.PENDING, 0),
        retry_scheduled_count=status_counts.get(
            IntegrationDeliveryStatus.RETRY_SCHEDULED,
            0,
        ),
        due_count=sum(
            record.status
            in {
                IntegrationDeliveryStatus.PENDING,
                IntegrationDeliveryStatus.RETRY_SCHEDULED,
            }
            and record.next_attempt_at is not None
            and record.next_attempt_at <= now
            for record in records
        ),
        delivered_count=status_counts.get(IntegrationDeliveryStatus.DELIVERED, 0),
        dead_letter_count=status_counts.get(IntegrationDeliveryStatus.DEAD_LETTER, 0),
        latest_event_id=records[0].event.id if records else None,
    )


def _record_hash(previous_hash: str, payload: str) -> str:
    return hashlib.sha256(f"{previous_hash}.{payload}".encode()).hexdigest()


def _dynamodb_key(tenant_id: str, event_id: str) -> str:
    return f"outbox#{tenant_id}#{event_id}"


def _parse_dynamodb_record(
    item: object,
    tenant_id: str,
) -> IntegrationOutboxRecord | None:
    if not isinstance(item, dict) or item.get("record_type") != "integration_outbox":
        return None
    payload = item.get("payload")
    expected_digest = item.get("payload_sha256")
    if not isinstance(payload, str) or not isinstance(expected_digest, str):
        return None
    if not hmac.compare_digest(
        hashlib.sha256(payload.encode()).hexdigest(),
        expected_digest,
    ):
        return None
    try:
        record = IntegrationOutboxRecord.model_validate_json(payload)
    except ValueError:
        return None
    return record if record.event.tenant_id == tenant_id else None
