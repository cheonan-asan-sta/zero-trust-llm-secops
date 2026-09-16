import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.config import Settings
from app.models import (
    CorrelationResult,
    IncidentCase,
    IncidentCaseHistoryEntry,
    IncidentCaseMetrics,
    IncidentCaseStatus,
    IncidentCaseUpdateRequest,
    OCSFIncidentFinding,
)

CASE_MANAGEMENT_VERSION = "0.15.0"

ALLOWED_TRANSITIONS: dict[IncidentCaseStatus, set[IncidentCaseStatus]] = {
    IncidentCaseStatus.NEW: {IncidentCaseStatus.TRIAGED},
    IncidentCaseStatus.TRIAGED: {IncidentCaseStatus.INVESTIGATING},
    IncidentCaseStatus.INVESTIGATING: {IncidentCaseStatus.CONTAINED},
    IncidentCaseStatus.CONTAINED: {
        IncidentCaseStatus.INVESTIGATING,
        IncidentCaseStatus.RESOLVED,
    },
    IncidentCaseStatus.RESOLVED: {
        IncidentCaseStatus.INVESTIGATING,
        IncidentCaseStatus.CLOSED,
    },
    IncidentCaseStatus.CLOSED: {IncidentCaseStatus.INVESTIGATING},
}


class CaseNotFoundError(LookupError):
    pass


class CaseConflictError(RuntimeError):
    pass


class InvalidCaseTransitionError(ValueError):
    pass


class CaseRepository(Protocol):
    async def save(self, record: IncidentCase) -> None: ...

    def get(self, case_id: str, tenant_id: str = "local") -> IncidentCase | None: ...

    def recent(
        self,
        limit: int = 20,
        tenant_id: str = "local",
        status: IncidentCaseStatus | None = None,
    ) -> list[IncidentCase]: ...

    def metrics(self, tenant_id: str = "local") -> IncidentCaseMetrics: ...

    def integrity(self) -> dict[str, bool | int | str]: ...


class CaseEventPublisher(Protocol):
    async def reconcile_case(self, record: IncidentCase) -> tuple[int, int]: ...


class CaseStore:
    """Tenant-scoped, append-only case snapshots protected by a hash chain."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: dict[tuple[str, str], IncidentCase] = {}
        self._lock = asyncio.Lock()
        self._last_hash = "0" * 64
        self._integrity_ok = True
        self._verified_lines = 0
        self._load_existing()

    async def save(self, record: IncidentCase) -> None:
        async with self._lock:
            if not self._integrity_ok:
                raise RuntimeError("case log integrity check failed; refusing to append")
            key = (record.tenant_id, record.case_id)
            existing = self._records.get(key)
            expected_version = 1 if existing is None else existing.version + 1
            if record.version != expected_version:
                raise CaseConflictError(
                    f"case version conflict: expected {expected_version}, got {record.version}"
                )
            await asyncio.to_thread(self._append_jsonl, record)
            self._records[key] = record

    def get(self, case_id: str, tenant_id: str = "local") -> IncidentCase | None:
        return self._records.get((tenant_id, case_id))

    def recent(
        self,
        limit: int = 20,
        tenant_id: str = "local",
        status: IncidentCaseStatus | None = None,
    ) -> list[IncidentCase]:
        records = [
            record
            for (record_tenant, _), record in self._records.items()
            if record_tenant == tenant_id and (status is None or record.status == status)
        ]
        records.sort(key=lambda record: (record.updated_at, record.case_id), reverse=True)
        return records[:limit]

    def metrics(self, tenant_id: str = "local") -> IncidentCaseMetrics:
        records = self.recent(10000, tenant_id)
        status_counts: dict[str, int] = {}
        for record in records:
            key = record.status.value
            status_counts[key] = status_counts.get(key, 0) + 1
        return IncidentCaseMetrics(
            total_cases=len(records),
            open_case_count=sum(
                record.status not in {IncidentCaseStatus.RESOLVED, IncidentCaseStatus.CLOSED}
                for record in records
            ),
            unassigned_case_count=sum(record.assignee is None for record in records),
            status_counts=status_counts,
            latest_case_id=records[0].case_id if records else None,
        )

    def integrity(self) -> dict[str, bool | int | str]:
        return {
            "backend": "jsonl_hash_chain",
            "ok": self._integrity_ok,
            "verified_lines": self._verified_lines,
            "version": CASE_MANAGEMENT_VERSION,
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
                    raise ValueError("invalid case envelope")
                calculated = _record_hash(previous_hash, payload)
                if previous_hash != expected_previous_hash or not hmac.compare_digest(
                    calculated, record_hash
                ):
                    raise ValueError("invalid case hash chain")
                record = IncidentCase.model_validate_json(payload)
                key = (record.tenant_id, record.case_id)
                existing = self._records.get(key)
                expected_version = 1 if existing is None else existing.version + 1
                if record.version != expected_version:
                    raise ValueError("invalid case version sequence")
            except (KeyError, TypeError, ValueError):
                self._integrity_ok = False
                continue
            expected_previous_hash = record_hash
            self._last_hash = record_hash
            self._verified_lines += 1
            self._records[key] = record

    def _append_jsonl(self, record: IncidentCase) -> None:
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


class DynamoDBCaseStore:
    """Durable tenant-scoped latest case state with digest and optimistic locking."""

    def __init__(self, table_name: str, region_name: str) -> None:
        resource = boto3.resource("dynamodb", region_name=region_name)
        self._table = resource.Table(table_name)

    async def save(self, record: IncidentCase) -> None:
        payload = record.model_dump_json()
        item = {
            "analysis_id": _dynamodb_key(record.tenant_id, record.case_id),
            "tenant_event_key": f"case#{record.tenant_id}#{record.case_id}",
            "tenant_id": record.tenant_id,
            "record_type": "incident_case",
            "analyzed_at": record.updated_at.isoformat(),
            "case_id": record.case_id,
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
                raise CaseConflictError("case version conflict") from exc
            raise

    def get(self, case_id: str, tenant_id: str = "local") -> IncidentCase | None:
        response = self._table.get_item(
            Key={"analysis_id": _dynamodb_key(tenant_id, case_id)},
            ConsistentRead=True,
        )
        return _parse_dynamodb_case(response.get("Item"), tenant_id)

    def recent(
        self,
        limit: int = 20,
        tenant_id: str = "local",
        status: IncidentCaseStatus | None = None,
    ) -> list[IncidentCase]:
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
            if (record := _parse_dynamodb_case(item, tenant_id)) is not None
            and (status is None or record.status == status)
        ]
        records.sort(key=lambda record: (record.updated_at, record.case_id), reverse=True)
        return records[:limit]

    def metrics(self, tenant_id: str = "local") -> IncidentCaseMetrics:
        records = self.recent(10000, tenant_id)
        status_counts: dict[str, int] = {}
        for record in records:
            key = record.status.value
            status_counts[key] = status_counts.get(key, 0) + 1
        return IncidentCaseMetrics(
            total_cases=len(records),
            open_case_count=sum(
                record.status not in {IncidentCaseStatus.RESOLVED, IncidentCaseStatus.CLOSED}
                for record in records
            ),
            unassigned_case_count=sum(record.assignee is None for record in records),
            status_counts=status_counts,
            latest_case_id=records[0].case_id if records else None,
        )

    def integrity(self) -> dict[str, bool | int | str]:
        return {
            "backend": "dynamodb_payload_digest",
            "ok": True,
            "verified_lines": 0,
            "version": CASE_MANAGEMENT_VERSION,
        }


class IncidentCaseService:
    def __init__(
        self,
        store: CaseRepository,
        event_publisher: CaseEventPublisher | None = None,
    ) -> None:
        self.store = store
        self.event_publisher = event_publisher

    async def create_from_correlation(
        self,
        correlation: CorrelationResult,
        tenant_id: str,
        actor_id: str,
        note: str,
    ) -> tuple[list[IncidentCase], int, int]:
        cases: list[IncidentCase] = []
        created_count = 0
        reused_count = 0
        for incident in correlation.incidents:
            case_id = _case_id(tenant_id, incident.incident_uid)
            evidence_sha256 = _evidence_digest(incident)
            existing = self.store.get(case_id, tenant_id)
            if existing is not None:
                if not hmac.compare_digest(existing.evidence_sha256, evidence_sha256):
                    raise CaseConflictError("case identifier already exists with different evidence")
                cases.append(existing)
                reused_count += 1
                if self.event_publisher is not None:
                    await self.event_publisher.reconcile_case(existing)
                continue

            now = datetime.now(UTC)
            record = IncidentCase(
                case_id=case_id,
                incident_uid=incident.incident_uid,
                title=incident.title,
                severity_id=incident.severity_id,
                tenant_id=tenant_id,
                created_at=now,
                updated_at=now,
                version=1,
                incident=incident,
                evidence_sha256=evidence_sha256,
                history=[
                    IncidentCaseHistoryEntry(
                        sequence=1,
                        from_status=None,
                        to_status=IncidentCaseStatus.NEW,
                        changed_at=now,
                        actor_id=actor_id,
                        note=note,
                        evidence_sha256=evidence_sha256,
                    )
                ],
            )
            try:
                await self.store.save(record)
            except CaseConflictError:
                concurrent = self.store.get(case_id, tenant_id)
                if concurrent is None or not hmac.compare_digest(
                    concurrent.evidence_sha256, evidence_sha256
                ):
                    raise
                record = concurrent
                reused_count += 1
            else:
                created_count += 1
            cases.append(record)
            if self.event_publisher is not None:
                await self.event_publisher.reconcile_case(record)
        return cases, created_count, reused_count

    async def transition(
        self,
        case_id: str,
        tenant_id: str,
        actor_id: str,
        request: IncidentCaseUpdateRequest,
    ) -> IncidentCase:
        existing = self.store.get(case_id, tenant_id)
        if existing is None:
            raise CaseNotFoundError(case_id)
        if self.event_publisher is not None:
            await self.event_publisher.reconcile_case(existing)
        if request.expected_version != existing.version:
            raise CaseConflictError(
                f"case version conflict: expected {existing.version}, got {request.expected_version}"
            )
        if request.status not in ALLOWED_TRANSITIONS[existing.status]:
            raise InvalidCaseTransitionError(
                f"cannot change case from {existing.status.value} to {request.status.value}"
            )

        assignee = request.assignee or existing.assignee or actor_id
        now = datetime.now(UTC)
        history = [
            *existing.history,
            IncidentCaseHistoryEntry(
                sequence=existing.version + 1,
                from_status=existing.status,
                to_status=request.status,
                changed_at=now,
                actor_id=actor_id,
                note=request.note,
                assignee=assignee,
                evidence_sha256=existing.evidence_sha256,
            ),
        ]
        updated = existing.model_copy(
            update={
                "status": request.status,
                "assignee": assignee,
                "updated_at": now,
                "version": existing.version + 1,
                "history": history,
            }
        )
        updated = IncidentCase.model_validate(updated.model_dump())
        await self.store.save(updated)
        if self.event_publisher is not None:
            await self.event_publisher.reconcile_case(updated)
        return updated


def create_case_store(settings: Settings) -> CaseRepository:
    if settings.audit_backend == "dynamodb":
        return DynamoDBCaseStore(settings.dynamodb_table_name, settings.aws_region)
    return CaseStore(settings.case_log_path)


def _case_id(tenant_id: str, incident_uid: str) -> str:
    digest = hashlib.sha256(f"{tenant_id}:{incident_uid}".encode()).hexdigest()[:32]
    return f"case-{digest}"


def _evidence_digest(incident: OCSFIncidentFinding) -> str:
    canonical = json.dumps(
        incident.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _record_hash(previous_hash: str, payload: str) -> str:
    return hashlib.sha256(f"{previous_hash}.{payload}".encode()).hexdigest()


def _dynamodb_key(tenant_id: str, case_id: str) -> str:
    return f"case#{tenant_id}#{case_id}"


def _parse_dynamodb_case(item: object, tenant_id: str) -> IncidentCase | None:
    if not isinstance(item, dict) or item.get("record_type") != "incident_case":
        return None
    payload = item.get("payload")
    expected_digest = item.get("payload_sha256")
    if not isinstance(payload, str) or not isinstance(expected_digest, str):
        return None
    actual_digest = hashlib.sha256(payload.encode()).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        return None
    try:
        record = IncidentCase.model_validate_json(payload)
    except ValueError:
        return None
    return record if record.tenant_id == tenant_id else None
