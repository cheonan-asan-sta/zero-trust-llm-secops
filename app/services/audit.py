import asyncio
import math
from pathlib import Path
from typing import Protocol

import boto3
from boto3.dynamodb.conditions import Key

from app.config import Settings
from app.models import AnalysisResult, MetricsSummary, ReviewStatus


class AuditRepository(Protocol):
    async def save(self, record: AnalysisResult) -> None: ...

    def get(self, event_id: str) -> AnalysisResult | None: ...

    def recent(self, limit: int = 20) -> list[AnalysisResult]: ...

    def metrics(self) -> MetricsSummary: ...


class AuditStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: dict[str, AnalysisResult] = {}
        self._history: list[AnalysisResult] = []
        self._history_positions: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._load_existing()

    async def save(self, record: AnalysisResult) -> None:
        async with self._lock:
            self._upsert(record)
            await asyncio.to_thread(self._append_jsonl, record)

    def get(self, event_id: str) -> AnalysisResult | None:
        return self._records.get(event_id)

    def recent(self, limit: int = 20) -> list[AnalysisResult]:
        return list(reversed(self._history[-limit:]))

    def metrics(self) -> MetricsSummary:
        return _summarize(self._history)

    def _load_existing(self) -> None:
        if not self._path.exists():
            return

        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return

        for line in lines:
            if not line.strip():
                continue
            try:
                record = AnalysisResult.model_validate_json(line)
            except ValueError:
                continue
            self._upsert(record)

    def _upsert(self, record: AnalysisResult) -> None:
        position = self._history_positions.get(record.analysis_id)
        if position is None:
            self._history_positions[record.analysis_id] = len(self._history)
            self._history.append(record)
        else:
            self._history[position] = record

        latest = self._records.get(record.event_id)
        if (
            latest is None
            or latest.analysis_id == record.analysis_id
            or record.analyzed_at >= latest.analyzed_at
        ):
            self._records[record.event_id] = record

    def _append_jsonl(self, record: AnalysisResult) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")


class DynamoDBAuditStore:
    def __init__(self, table_name: str, region_name: str) -> None:
        resource = boto3.resource("dynamodb", region_name=region_name)
        self._table = resource.Table(table_name)

    async def save(self, record: AnalysisResult) -> None:
        item = {
            "analysis_id": record.analysis_id,
            "event_id": record.event_id,
            "record_type": "analysis",
            "analyzed_at": record.analyzed_at.isoformat(),
            "payload": record.model_dump_json(),
        }
        await asyncio.to_thread(self._table.put_item, Item=item)

    def get(self, event_id: str) -> AnalysisResult | None:
        response = self._table.query(
            IndexName="EventIndex",
            KeyConditionExpression=Key("event_id").eq(event_id),
            ScanIndexForward=False,
            Limit=1,
        )
        records = _parse_items(response.get("Items", []))
        return records[0] if records else None

    def recent(self, limit: int = 20) -> list[AnalysisResult]:
        response = self._table.query(
            IndexName="RecentIndex",
            KeyConditionExpression=Key("record_type").eq("analysis"),
            ScanIndexForward=False,
            Limit=limit,
        )
        return _parse_items(response.get("Items", []))

    def metrics(self) -> MetricsSummary:
        items: list[dict] = []
        response = self._table.scan(ProjectionExpression="payload")
        items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = self._table.scan(
                ProjectionExpression="payload",
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))
        records = _parse_items(items)
        records.sort(key=lambda record: record.analyzed_at)
        return _summarize(records)


def create_audit_store(settings: Settings) -> AuditRepository:
    if settings.audit_backend == "dynamodb":
        return DynamoDBAuditStore(settings.dynamodb_table_name, settings.aws_region)
    return AuditStore(settings.audit_log_path)


def _parse_items(items: list[dict]) -> list[AnalysisResult]:
    records: list[AnalysisResult] = []
    for item in items:
        payload = item.get("payload")
        if not isinstance(payload, str):
            continue
        try:
            records.append(AnalysisResult.model_validate_json(payload))
        except ValueError:
            continue
    return records


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
