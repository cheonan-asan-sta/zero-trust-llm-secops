import asyncio

from fastapi.testclient import TestClient

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.main import app
from app.models import SecurityEvent
from app.services.evaluation import run_evaluation

client = TestClient(app)


def test_rule_evaluation_meets_project_targets() -> None:
    result = asyncio.run(run_evaluation(RuleBasedAnalyzer()))

    assert result.total_cases == 8
    assert result.risk_accuracy == 1
    assert result.action_accuracy == 1
    assert result.json_valid_rate == 1
    assert result.error_rate == 0
    assert result.throughput_per_second > 0
    assert len(result.scenario_breakdown) == 8
    assert all(result.targets_met.values())


def test_evaluation_api_runs_without_openai_key() -> None:
    response = client.post(
        "/evaluation/run",
        json={"analyzer": "rule", "runs_per_scenario": 5, "concurrency": 4},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total_cases"] == 40
    assert payload["error_count"] == 0
    assert payload["risk_confusion_matrix"]["HIGH"]["HIGH"] > 0


class RuntimeFailureAnalyzer:
    name = "rule"

    async def analyze(self, event: SecurityEvent):
        raise RuntimeError(f"simulated failure for {event.event_id}")


def test_evaluation_groups_failures_without_exposing_exception_details() -> None:
    result = asyncio.run(run_evaluation(RuntimeFailureAnalyzer()))

    assert result.error_count == 8
    assert result.error_rate == 1
    assert result.error_categories == {"runtime": 8}
    assert sum(row["ERROR"] for row in result.risk_confusion_matrix.values()) == 8
    assert all(case.error_category == "runtime" for case in result.cases)


class ConcurrencyProbeAnalyzer:
    name = "rule"

    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.delegate = RuleBasedAnalyzer()

    async def analyze(self, event: SecurityEvent):
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0.005)
            return await self.delegate.analyze(event)
        finally:
            self.active -= 1


def test_evaluation_honors_bounded_concurrency() -> None:
    analyzer = ConcurrencyProbeAnalyzer()

    result = asyncio.run(run_evaluation(analyzer, runs_per_scenario=2, concurrency=2))

    assert result.total_cases == 16
    assert analyzer.peak == 2


def test_scenario_evaluation_api_returns_ground_truth_match() -> None:
    event = client.post(
        "/events/simulate",
        json={"scenario_id": "ZT-S04", "count": 1},
    ).json()[0]
    response = client.post("/scenarios/evaluate", json=event)

    assert response.status_code == 200
    assert response.json()["best_match"] == "ZT-S04"
