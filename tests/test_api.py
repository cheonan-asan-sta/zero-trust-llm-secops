from hashlib import sha256

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["analyzer_mode"] == "rule"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_request_id_is_validated_and_returned() -> None:
    accepted = client.get("/health", headers={"X-Request-ID": "request-12345678"})
    replaced = client.get("/health", headers={"X-Request-ID": "bad id"})

    assert accepted.headers["x-request-id"] == "request-12345678"
    assert replaced.headers["x-request-id"] != "bad id"
    assert len(replaced.headers["x-request-id"]) == 32


def test_oversized_request_is_rejected_before_validation() -> None:
    response = client.post(
        "/analysis",
        content="x" * 1_048_577,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413


def test_prometheus_metrics_are_available_to_local_admin() -> None:
    response = client.get("/internal/metrics")

    assert response.status_code == 200
    assert "secops_http_requests_total" in response.text


def test_api_key_authentication_and_role_enforcement(monkeypatch) -> None:
    api_key = "test-enterprise-key"
    protected_settings = Settings(
        auth_mode="api_key",
        api_key_sha256=sha256(api_key.encode()).hexdigest(),
        api_key_roles="viewer",
        api_key_tenant_id="tenant-a",
    )
    monkeypatch.setattr("app.security.get_settings", lambda: protected_settings)

    missing = client.get("/scenarios")
    allowed = client.get("/scenarios", headers={"X-API-Key": api_key})
    forbidden = client.post(
        "/events/simulate",
        headers={"X-API-Key": api_key},
        json={"count": 1},
    )

    assert missing.status_code == 401
    assert allowed.status_code == 200
    assert forbidden.status_code == 403


def test_api_results_are_isolated_by_authenticated_tenant(monkeypatch) -> None:
    key_a = "tenant-a-key"
    settings_a = Settings(
        auth_mode="api_key",
        api_key_sha256=sha256(key_a.encode()).hexdigest(),
        api_key_roles="analyst,responder,viewer",
        api_key_tenant_id="tenant-a",
    )
    monkeypatch.setattr("app.security.get_settings", lambda: settings_a)
    event = client.post(
        "/events/simulate",
        headers={"X-API-Key": key_a},
        json={"scenario_id": "ZT-S05", "count": 1},
    ).json()[0]
    created = client.post("/analysis", headers={"X-API-Key": key_a}, json=event)
    assert created.status_code == 200
    assert created.json()["tenant_id"] == "tenant-a"

    key_b = "tenant-b-key"
    settings_b = Settings(
        auth_mode="api_key",
        api_key_sha256=sha256(key_b.encode()).hexdigest(),
        api_key_roles="viewer",
        api_key_tenant_id="tenant-b",
    )
    monkeypatch.setattr("app.security.get_settings", lambda: settings_b)

    hidden = client.get(f"/results/{event['event_id']}", headers={"X-API-Key": key_b})
    tenant_b_metrics = client.get("/metrics", headers={"X-API-Key": key_b})
    assert hidden.status_code == 404
    assert tenant_b_metrics.json()["total_analyses"] == 0


def test_dashboard_is_available() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "천안아산역" in response.text
    assert "Zero Trust SecOps" in response.text
    assert "AI 교차분석" in response.text
    assert "ANALYST REVIEW" in response.text
    assert "보안 통제 준비도" in response.text
    assert "공개 로그 회귀 검증" in response.text
    assert "탐지 품질 게이트" in response.text
    assert "표준 탐지 근거" in response.text


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
    assert result["review_status"] == "PENDING"


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
    assert "pending_review_count" in metrics.json()


def test_batch_analysis_processes_multiple_events() -> None:
    events = client.post("/events/simulate", json={"count": 3}).json()
    response = client.post("/analysis/batch", json={"events": events})

    assert response.status_code == 200
    payload = response.json()
    assert payload["analyzer"] == "rule"
    assert payload["requested"] == 3
    assert payload["completed"] == 3
    assert len(payload["results"]) == 3


def test_high_risk_result_can_be_reviewed_and_resolved() -> None:
    event = client.post(
        "/events/simulate",
        json={"scenario_id": "ZT-S05", "count": 1},
    ).json()[0]
    analysis = client.post("/analysis", json=event).json()

    started = client.patch(
        f"/results/{analysis['event_id']}/review",
        json={"status": "IN_REVIEW", "reviewer": "김분석"},
    )
    assert started.status_code == 200
    assert started.json()["review_status"] == "IN_REVIEW"
    assert started.json()["reviewer"] == "김분석"

    resolved = client.patch(
        f"/results/{analysis['event_id']}/review",
        json={
            "status": "RESOLVED",
            "reviewer": "김분석",
            "note": "유출 의심 세션을 확인하고 대응 미리보기를 승인했습니다.",
        },
    )
    assert resolved.status_code == 200
    assert resolved.json()["review_status"] == "RESOLVED"
    assert resolved.json()["review_updated_at"] is not None

    filtered = client.get("/results", params={"review_status": "RESOLVED"})
    assert filtered.status_code == 200
    assert any(item["analysis_id"] == analysis["analysis_id"] for item in filtered.json())

    invalid_terminal_change = client.patch(
        f"/results/{analysis['event_id']}/review",
        json={
            "status": "DISMISSED",
            "reviewer": "김분석",
            "note": "해결된 사건을 곧바로 오탐으로 바꾸려는 요청입니다.",
        },
    )
    assert invalid_terminal_change.status_code == 409

    reopened = client.patch(
        f"/results/{analysis['event_id']}/review",
        json={"status": "IN_REVIEW", "reviewer": "김분석", "note": "추가 검토를 시작합니다."},
    )
    assert reopened.status_code == 200
    assert reopened.json()["review_status"] == "IN_REVIEW"


def test_terminal_review_requires_a_note() -> None:
    event = client.post(
        "/events/simulate",
        json={"scenario_id": "ZT-S04", "count": 1},
    ).json()[0]
    analysis = client.post("/analysis", json=event).json()

    response = client.patch(
        f"/results/{analysis['event_id']}/review",
        json={"status": "DISMISSED", "reviewer": "김분석"},
    )
    assert response.status_code == 422


def test_normal_result_cannot_enter_review_workflow() -> None:
    event = client.post(
        "/events/simulate",
        json={"scenario_id": "NORMAL-01", "count": 1},
    ).json()[0]
    analysis = client.post("/analysis", json=event).json()
    assert analysis["review_status"] == "NOT_REQUIRED"

    response = client.patch(
        f"/results/{analysis['event_id']}/review",
        json={"status": "IN_REVIEW", "reviewer": "김분석"},
    )
    assert response.status_code == 409
