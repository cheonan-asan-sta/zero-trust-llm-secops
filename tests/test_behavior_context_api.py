import sqlite3
from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import main
from app.behavior_context_api import behavior_context_router
from app.services.behavior_context import BehaviorContextService
from app.services.behavior_context_store import BehaviorContextStore


def test_context_unavailable_when_local_operations_disabled():
    application = FastAPI()
    application.include_router(behavior_context_router(None))
    response = TestClient(application).post("/detections/context/evaluate", json={"capture_id": "sample"})
    assert response.status_code == 503


def test_readiness_detects_context_history_damage(tmp_path, monkeypatch):
    store = BehaviorContextStore(tmp_path / "context.sqlite3")
    service = BehaviorContextService(store, SimpleNamespace(path=tmp_path / "policy.sqlite3"))
    monkeypatch.setattr(main, "behavior_context_service", service)
    client = TestClient(main.app)
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json()["behavior_context"]["ok"] is True
    with store.transaction() as tx:
        tx.put("evaluation", "tenant-a", "audit-1", {"test": True}, "analyst", datetime.now(UTC))
    with sqlite3.connect(store.path) as connection:
        connection.execute("DELETE FROM behavior_context_entries")
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["behavior_context"]["ok"] is False
