import asyncio

from fastapi.testclient import TestClient

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.main import app
from app.services.evaluation import run_evaluation

client = TestClient(app)


def test_rule_evaluation_meets_project_targets() -> None:
    result = asyncio.run(run_evaluation(RuleBasedAnalyzer()))

    assert result.total_cases == 8
    assert result.risk_accuracy == 1
    assert result.action_accuracy == 1
    assert result.json_valid_rate == 1
    assert all(result.targets_met.values())


def test_evaluation_api_runs_without_openai_key() -> None:
    response = client.post("/evaluation/run", json={"analyzer": "rule"})

    assert response.status_code == 200
    assert response.json()["total_cases"] == 8


def test_scenario_evaluation_api_returns_ground_truth_match() -> None:
    event = client.post(
        "/events/simulate",
        json={"scenario_id": "ZT-S04", "count": 1},
    ).json()[0]
    response = client.post("/scenarios/evaluate", json=event)

    assert response.status_code == 200
    assert response.json()["best_match"] == "ZT-S04"
