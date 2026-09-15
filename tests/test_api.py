from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["analyzer_mode"] == "rule"


def test_dashboard_is_available() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "천안아산역" in response.text
    assert "Zero Trust SecOps" in response.text
    assert "AI 교차분석" in response.text


def test_default_simulation_returns_eight_events() -> None:
    response = client.post("/events/simulate", json={})
    assert response.status_code == 200
    assert len(response.json()) == 8


def test_scenario_detail_exposes_week3_threat_model() -> None:
    response = client.get("/scenarios/ZT-S04")

    assert response.status_code == 200
    scenario = response.json()
    assert scenario["category"] == "THREAT"
    assert scenario["attack_techniques"][0]["technique_id"] == "T1021"
    assert "behavior.distinct_resources_10m >= 8" in scenario["observable_signals"]
    assert scenario["normal_exceptions"]


def test_unknown_scenario_detail_returns_404() -> None:
    response = client.get("/scenarios/DOES-NOT-EXIST")
    assert response.status_code == 404


def test_analysis_excludes_ground_truth_and_requires_review() -> None:
    event_response = client.post(
        "/events/simulate",
        json={"scenario_id": "ZT-S05", "count": 1},
    )
    event = event_response.json()[0]
    response = client.post("/analysis", json=event)

    assert response.status_code == 200
    result = response.json()
    assert result["assessment"]["risk_level"] in {"HIGH", "CRITICAL"}
    assert result["assessment"]["requires_human_review"] is True
    assert result["policy_decision"]["mode"] == "simulation"


def test_unknown_scenario_returns_404() -> None:
    response = client.post(
        "/events/simulate",
        json={"scenario_id": "DOES-NOT-EXIST", "count": 1},
    )
    assert response.status_code == 404


def test_metrics_and_recent_results_include_completed_analysis() -> None:
    event = client.post(
        "/events/simulate",
        json={"scenario_id": "ZT-S03", "count": 1},
    ).json()[0]
    analysis = client.post("/analysis", json=event)
    assert analysis.status_code == 200

    metrics = client.get("/metrics")
    recent = client.get("/results", params={"limit": 1})

    assert metrics.status_code == 200
    assert metrics.json()["total_analyses"] >= 1
    assert recent.status_code == 200
    assert recent.json()[0]["event_id"] == "evt-zt-s03"
    assert "analyzed_at" in recent.json()[0]


def test_batch_analysis_processes_multiple_events() -> None:
    events = client.post("/events/simulate", json={"count": 3}).json()
    response = client.post("/analysis/batch", json={"events": events})

    assert response.status_code == 200
    payload = response.json()
    assert payload["analyzer"] == "rule"
    assert payload["requested"] == 3
    assert payload["completed"] == 3
    assert len(payload["results"]) == 3
