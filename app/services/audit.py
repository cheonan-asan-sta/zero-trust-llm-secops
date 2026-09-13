import asyncio
from pathlib import Path

from app.models import AnalysisResult, MetricsSummary


class AuditStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: dict[str, AnalysisResult] = {}
        self._history: list[AnalysisResult] = []
        self._lock = asyncio.Lock()
        self._load_existing()

    async def save(self, record: AnalysisResult) -> None:
        async with self._lock:
            self._records[record.event_id] = record
            self._history.append(record)
            await asyncio.to_thread(self._append_jsonl, record)

    def get(self, event_id: str) -> AnalysisResult | None:
        return self._records.get(event_id)

    def recent(self, limit: int = 20) -> list[AnalysisResult]:
        return list(reversed(self._history[-limit:]))

    def metrics(self) -> MetricsSummary:
        risk_counts: dict[str, int] = {}
        action_counts: dict[str, int] = {}
        analyzer_counts: dict[str, int] = {}

        for record in self._history:
            risk = record.assessment.risk_level.value
            action = record.policy_decision.action.value
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            action_counts[action] = action_counts.get(action, 0) + 1
            analyzer_counts[record.analyzer] = analyzer_counts.get(record.analyzer, 0) + 1

        latest = self._history[-1].event_id if self._history else None
        return MetricsSummary(
            total_analyses=len(self._history),
            risk_counts=risk_counts,
            action_counts=action_counts,
            analyzer_counts=analyzer_counts,
            latest_event_id=latest,
        )

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
            self._records[record.event_id] = record
            self._history.append(record)

    def _append_jsonl(self, record: AnalysisResult) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
