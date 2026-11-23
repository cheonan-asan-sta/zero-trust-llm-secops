"""Authenticated dashboard approval uses the private queue and durable analysis receipt."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from app import login_queue_api, main, security
from app.config import Settings
from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.services.sqlite_audit import SQLiteAuditStore
from scripts import login_delivery_spool
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector
from scripts.login_delivery_spool import LoginRetryPolicy

TENANT = "local"
OPERATOR = "operator"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    accounts = tmp_path / "accounts.json"
    accounts.write_text(json.dumps({"schema": "api-key-accounts-1", "accounts": [
        {"sha256": digest("operator-key"), "tenant_id": TENANT, "subject": OPERATOR, "roles": ["responder"]},
        {"sha256": digest("second-key"), "tenant_id": TENANT, "subject": "different-operator", "roles": ["responder"]},
        {"sha256": digest("viewer-key"), "tenant_id": TENANT, "subject": "viewer", "roles": ["viewer"]},
        {"sha256": digest("foreign-key"), "tenant_id": "foreign", "subject": "foreign", "roles": ["responder"]},
    ]}), encoding="utf-8")
    path = tmp_path / "queue.sqlite3"
    profile = tmp_path / "queue-config.json"
    profile.write_text(json.dumps({
        "queue_file": str(path), "analysis_origin": "http://127.0.0.1",
        "tenant_id": TENANT, "collector_subject": "collector",
        "prometheus_origin": "http://127.0.0.1:9090/", "scrape_instance": "127.0.0.1:9101",
    }), encoding="utf-8")
    settings = Settings(
        _env_file=None, app_environment="test", auth_mode="api_key", analyzer_mode="rule",
        api_key_sha256=digest("collector-key"), api_key_subject="collector", api_key_roles="analyst",
        api_key_accounts_path=accounts, audit_backend="sqlite", audit_db_path=tmp_path / "audit.sqlite3",
        dashboard_login_queue_profile=profile,
    )
    monkeypatch.setattr(login_queue_api, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "audit_store", SQLiteAuditStore(settings.audit_db_path))
    state = SimpleNamespace(mode="reject", now=200.0)
    monkeypatch.setattr(login_delivery_spool, "time", lambda: state.now)
    matching = {"job": "zt-signals", "instance": "127.0.0.1:9101"}

    def monitoring(_, origin, path):
        assert origin == "http://127.0.0.1:9090/"
        if path == "/api/v1/targets?state=active":
            return {"activeTargets": [{"labels": matching, "health": "up"}]}
        assert path == "/api/v1/alerts"
        return {"alerts": [
            {"labels": matching | {"alertname": "C01LoginQueueHeld"}, "state": "firing"},
            {"labels": matching | {"alertname": "C01LoginQueueBacklog"}, "state": "pending"},
            {"labels": (matching | {"alertname": "C01LoginQueueStatusUnavailable", "instance": "another"}), "state": "firing"},
        ]}

    monkeypatch.setattr(login_queue_api, "_prometheus_get", monitoring)
    with TestClient(main.app, base_url="http://127.0.0.1") as api:
        def dispatch(request):
            if state.mode == "reject":
                return httpx.Response(403)
            outcome = api.post("/analysis/login-delivery", content=request.content,
                               headers={"Content-Type": "application/json", "X-API-Key": "collector-key"})
            outcome.raise_for_status()
            if state.mode == "lose":
                raise httpx.ReadError("lost test receipt", request=request)
            return outcome

        with httpx.Client(base_url="http://127.0.0.1", transport=httpx.MockTransport(dispatch)) as client:
            state.collector = KeycloakLoginAnalysisCollector(
                client, settings=None, authority=None, registry=None, gateway_id="local", source_id="fixture",
                key_id="fixture", signing_key=None, spool_path=path, tenant_id=TENANT, collector_subject="collector",
                retry_policy=LoginRetryPolicy(success_interval=0), clock=lambda: state.now,
            )
            state.api = api
            yield state


def headers(key="operator-key"):
    return {"X-API-Key": key}


def event_for(threat):
    values = synthetic_events()[0].analysis_payload()
    values.update(action="LOGIN", event_id="fixture-dashboard-login")
    values["network"]["location_anomaly"] = True
    values["auth_context"].update(authentication_result="failure" if threat else "success",
                                  failed_attempts=4 if threat else 0, mfa="unknown" if threat else "success")
    return SecurityEvent.model_validate(values)


def hold(state, event):
    with pytest.raises(httpx.HTTPStatusError) as error:
        state.collector.submit(event, None)
    assert error.value.response.status_code == 403


def review(state, key="operator-key"):
    response = state.api.get("/dashboard/login-queue", headers=headers(key))
    assert response.status_code == 200, response.text
    return response.json()["review"]


def approval(state, item, metadata, *, key="operator-key", note="확인 후 권한 설정 복구"):
    return state.api.post("/dashboard/login-queue/approvals",
                          headers=headers(key) | {"If-Match": item["etag"], "X-Review-Identity": metadata["identity"]},
                          json={"event_id": item["event_id"], "hold_id": item["hold_id"], "note": note})


@pytest.mark.parametrize("threat", [False, True])
def test_duplicate_approval_and_lost_receipt_preserve_detection_and_audit(setup, threat):
    state = setup
    event = event_for(threat)
    original = state.api.post("/analysis", headers=headers("collector-key"), json=event.analysis_payload()).json()
    hold(state, event)
    metadata = review(state)
    item, = metadata["held"]
    assert item["failure_code"] == "http_403"
    assert state.api.post("/dashboard/login-queue/approvals", headers=headers(), json={
        "event_id": item["event_id"], "hold_id": item["hold_id"], "note": "원인 확인 완료",
    }).status_code == 428
    assert approval(state, item, metadata, key="second-key").status_code == 403
    assert approval(state, item, metadata, note="  a  ").status_code == 422

    with ThreadPoolExecutor(max_workers=2) as pool:
        submissions = list(pool.map(lambda _: approval(state, item, metadata), range(2)))
    assert all(response.status_code == 200 for response in submissions)
    assert {response.json()["duplicate"] for response in submissions} == {False, True}
    assert approval(state, item, metadata, note="다른 요청 메모").status_code == 412
    assert state.collector.spool.counts() == {"pending": 1, "held": 0}

    state.mode = "lose"
    assert state.collector.flush_pending() == 0
    assert main.audit_store.integrity()["verified_lines"] == 2
    state.now += 2
    state.mode = "recover"
    assert state.collector.flush_pending() == 1
    assert main.audit_store.integrity()["verified_lines"] == 2
    history = review(state)["history"]
    assert [row["outcome"] for row in history] == ["delivered", "deferred", "approved"]
    assert history[0]["duplicate"] and history[2]["actor"] == OPERATOR
    row = main.audit_store.login_delivery(history[0]["analysis_id"]).model_dump(mode="json")
    assert row["detection"] == original["detection"]
    assert row["assessment"] == original["assessment"]
    assert row["policy_decision"] == original["policy_decision"]
    assert bool(row["detection"]["matches"]) is threat


def test_retry_that_fails_again_requires_a_fresh_review(setup):
    state = setup
    event = event_for(False)
    hold(state, event)
    metadata = review(state)
    initial, = metadata["held"]
    assert approval(state, initial, metadata).status_code == 200
    assert state.collector.flush_pending() == 0
    refreshed = review(state)
    new, = refreshed["held"]
    assert new["hold_id"] != initial["hold_id"]
    assert refreshed["history"][0]["outcome"] == "held_again"
    assert approval(state, initial, metadata).json()["duplicate"]
    assert state.collector.spool.counts() == {"pending": 0, "held": 1}
    assert approval(state, new, refreshed).status_code == 200
    state.mode = "recover"
    assert state.collector.flush_pending() == 1
    assert [row["outcome"] for row in review(state)["history"]] == ["delivered", "approved", "held_again", "approved"]


def test_only_scoped_alerts_survive_queue_unavailability(setup):
    state = setup
    hold(state, event_for(False))
    response = state.api.get("/dashboard/login-queue", headers=headers("viewer-key"))
    data = response.json()
    assert data["review"] is None and data["queue"]["held"] == 1
    assert {entry["name"]: entry["state"] for entry in data["alerts"]["entries"]} == {
        "C01LoginQueueHeld": "firing", "C01LoginQueueBacklog": "pending",
    }
    assert state.api.get("/dashboard/login-queue", headers=headers("foreign-key")).status_code == 403
    state.collector.spool.path.rename(state.collector.spool.path.with_suffix(".offline"))
    unavailable = state.api.get("/dashboard/login-queue", headers=headers()).json()
    assert unavailable["alerts"] == data["alerts"]
    assert unavailable["queue"] is unavailable["review"] is None
    assert not state.collector.spool.path.exists()
