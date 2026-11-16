"""Integration boundaries for the optional POSIX dashboard runner."""

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.dashboard_jobs_api import router
from app.security import Principal, Role, get_principal
from app.services import dashboard_jobs

ADMIN = Principal("operator", "tenant-a", frozenset({Role.ADMIN}), "api_key")


def test_unsupported_host_keeps_api_available_and_cannot_launch(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_jobs, "fcntl", None)
    settings = Settings(
        _env_file=None, auth_mode="api_key", api_key_sha256="a" * 64,
        app_environment="test", dashboard_operations_tenant="tenant-a",
        dashboard_operations_directory=tmp_path / "never-created",
        dashboard_m7_paired_directory=tmp_path, dashboard_live_max_usd=1,
    )
    monkeypatch.setattr("app.dashboard_jobs_api.get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_principal] = lambda: ADMIN
    client = TestClient(app)
    response = client.get("/dashboard/jobs/capabilities")
    assert response.status_code == 200
    assert not response.json()["enabled"]
    assert all(not action["available"] for action in response.json()["actions"])
    payload = {
        "request_id": "11111111-1111-4111-8111-111111111111",
        "action": "m6-mock", "reason": "Local integration check", "confirmed": True,
    }
    assert client.post("/dashboard/jobs", json=payload,
                       headers={"X-Dashboard-Action": "1"}).status_code == 409
    assert client.get("/dashboard/jobs").status_code == 503
    with pytest.raises(dashboard_jobs.JobUnavailable, match="posix_host_required"):
        dashboard_jobs.JobStore(settings.dashboard_operations_directory)
    assert not settings.dashboard_operations_directory.exists()


def test_integrated_defaults_keep_llm_and_host_operations_opt_in():
    settings = Settings(_env_file=None)
    assert (settings.analyzer_mode, settings.openai_prompt_mode,
            settings.hybrid_review_all) == ("rule", "legacy", False)
    assert settings.dashboard_operations_directory is None
    assert settings.dashboard_live_max_usd == 0


@pytest.mark.skipif(not dashboard_jobs.host_jobs_supported(), reason="POSIX job commands")
@pytest.mark.parametrize("action,entrypoint,mode", [
    ("runtime-status", "scripts.execution_mtls_runtime", "status"),
    ("runtime-up", "scripts.execution_mtls_runtime", "up"),
    ("runtime-down", "scripts.execution_mtls_runtime", "down"),
    ("runtime-recover", "scripts.execution_mtls_runtime", "recover"),
    ("runtime-verify", "scripts.test_execution_mtls_runtime", None),
    ("m6-mock", "scripts.evaluate_m6", None),
    ("m6-plan", "scripts.evaluate_m6", None),
    ("m6-live", "scripts.evaluate_m6", None),
])
def test_dashboard_command_contracts_keep_explicit_live_boundary(tmp_path, action, entrypoint, mode):
    jobs = dashboard_jobs.JobStore(tmp_path / "jobs")
    row = {
        "id": "11111111-1111-4111-8111-111111111111", "action": action,
        "request": json.dumps({"max_usd": 1}),
        "config": json.dumps({"paired": str(tmp_path / "paired"), "max_usd": 1}),
    }
    command, _ = jobs.command(row)
    assert command[1:3] == ["-m", entrypoint]
    if mode:
        assert command[3] == mode
    assert "--purge" not in command
    assert ("--live" in command) == (action == "m6-live")
    if action in {"m6-plan", "m6-live"}:
        assert command[3:5] == ["--m7-paired", str(tmp_path / "paired")]
    if action == "m6-live":
        assert command[-6:] == ["--live-max-usd", "1", "--max-requests", "600",
                                "--wall-seconds", "3600"]
