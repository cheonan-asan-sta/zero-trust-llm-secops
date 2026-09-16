import asyncio
import hashlib
import hmac
import json
import math
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
    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: dict[tuple[str, str], AnalysisResult] = {}
        self._history: list[AnalysisResult] = []
        self._history_positions: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._last_hash = "0" * 64
        self._integrity_ok = True
        self._verified_lines = 0
        self._legacy_lines = 0
        self._load_existing()

    async def save(self, record: AnalysisResult) -> None:
        async with self._lock:
            if not self._integrity_ok:
                raise RuntimeError("audit log integrity check failed; refusing to append")
            await asyncio.to_thread(self._append_jsonl, record)
            self._upsert(record)

    def get(self, event_id: str, tenant_id: str = "local") -> AnalysisResult | None:
        return self._records.get((tenant_id, event_id))

    def recent(self, limit: int = 20, tenant_id: str = "local") -> list[AnalysisResult]:
        records = [record for record in self._history if record.tenant_id == tenant_id]
        return list(reversed(records[-limit:]))

    def metrics(self, tenant_id: str = "local") -> MetricsSummary:
        return _summarize(
            [record for record in self._history if record.tenant_id == tenant_id]
        )

    def integrity(self) -> dict[str, bool | int | str]:
        return {
            "backend": "jsonl_hash_chain",
            "ok": self._integrity_ok,
            "verified_lines": self._verified_lines,
            "legacy_lines": self._legacy_lines,
        }

    def _load_existing(self) -> None:
        if not self._path.exists():
            return

        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return

        expected_previous_hash = "0" * 64
        for line in lines:
            if not line.strip():
                continue
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
    if settings.audit_backend == "dynamodb":
        return DynamoDBAuditStore(settings.dynamodb_table_name, settings.aws_region)
    return AuditStore(settings.audit_log_path)


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
