"""Dashboard access and durable host jobs preserve the original safety boundaries."""

import json
import os
import sqlite3
import subprocess
import sys
import time
from hashlib import sha256
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.dashboard_catalog import OPERATIONS, catalog
from app.dashboard_jobs_api import JobRequest, router
from app.security import Principal, Role
from app.services.dashboard_jobs import JobConflict, JobStore, JobUnavailable


def body(action="m6-mock", **extra):
    return JobRequest(request_id=uuid4(), action=action, reason="Local acceptance run",
                      confirmed=True, **extra)


ADMIN = Principal("operator", "tenant-a", frozenset({Role.ADMIN}), "api_key")


@pytest.fixture
def jobs(tmp_path):
    return JobStore(tmp_path.resolve() / "operations")


def test_catalog_covers_business_writes_and_matches_actual_contracts():
    from app.main import app

    metadata = catalog(app)
    specification = app.openapi()["paths"]
    covered = {(item[3], item[2].lower()) for item in OPERATIONS}
    writes = {(path, method) for path, methods in specification.items()
              for method in methods if method in {"post", "put", "patch", "delete"}
              and not path.startswith("/dashboard/jobs")}
    assert writes <= covered
    assert len(metadata["operations"]) == len(covered)
    assert all(p["in"] in {"query", "path"} for op in metadata["operations"]
               for p in op["parameters"])
    assert not any("internal" in op["path"] for op in metadata["operations"])


@pytest.mark.parametrize("role,status", [("viewer", 403), ("responder", 403), ("admin", 202)])
def test_host_jobs_require_server_bound_admin_and_deduplicate(tmp_path, monkeypatch, role, status):
    key = "synthetic-operations-key"
    settings = Settings(_env_file=None, auth_mode="api_key", app_environment="test",
                        api_key_sha256=sha256(key.encode()).hexdigest(), api_key_subject="operator",
                        api_key_tenant_id="tenant-a", api_key_roles=role,
                        dashboard_operations_tenant="tenant-a",
                        dashboard_operations_directory=tmp_path.resolve() / "jobs")
    monkeypatch.setattr("app.security.get_settings", lambda: settings)
    monkeypatch.setattr("app.dashboard_jobs_api.get_settings", lambda: settings)
    launches = []
    monkeypatch.setattr("app.services.dashboard_jobs.subprocess.Popen",
                        lambda *args, **kwargs: launches.append(args))
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    payload = body().model_dump(mode="json")
    headers = {"X-API-Key": key, "X-Dashboard-Action": "1", "Origin": "http://testserver"}
    assert client.post("/dashboard/jobs", json=payload).status_code == 401
    result = client.post("/dashboard/jobs", json=payload, headers=headers)
    assert result.status_code == status
    if role != "admin":
        assert not launches
        return
    assert client.post("/dashboard/jobs", json=payload, headers=headers).json()["id"] == payload["request_id"]
    assert len(launches) == 1
    assert "config" not in result.json() and "request" not in result.json()
    assert client.post("/dashboard/jobs", json=payload, headers=headers | {
        "Origin": "http://other.example"}).status_code == 403
    assert client.post("/dashboard/jobs", json=payload, headers={"X-API-Key": key}).status_code == 403
    assert client.post("/dashboard/jobs", json=payload | {"command": "arbitrary"}, headers=headers).status_code == 422
    assert client.post("/dashboard/jobs", json=payload | {"action": "runtime-purge"}, headers=headers).status_code == 422
    assert client.post("/dashboard/jobs", json=payload | {"confirmed": False}, headers=headers).status_code == 422
    assert client.post("/dashboard/jobs", json=payload | {"reason": "Changed command"}, headers=headers).status_code == 409
    settings.dashboard_operations_tenant = "other-tenant"
    assert client.get("/dashboard/jobs", headers=headers).status_code == 403
    settings.dashboard_operations_tenant = "tenant-a"
    settings.app_environment = "production"
    assert client.get("/dashboard/jobs", headers=headers).status_code == 403


def test_disabled_host_control_and_live_budget_are_not_browser_overrides(tmp_path, monkeypatch):
    from app.security import get_principal

    settings = Settings(_env_file=None, auth_mode="api_key", app_environment="test",
                        api_key_sha256="a" * 64, dashboard_operations_tenant="tenant-a")
    monkeypatch.setattr("app.dashboard_jobs_api.get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_principal] = lambda: ADMIN
    client = TestClient(app)
    headers = {"X-Dashboard-Action": "1"}
    assert not client.get("/dashboard/jobs/capabilities").json()["enabled"]
    assert client.get("/dashboard/jobs").status_code == 503
    assert client.post("/dashboard/jobs", json=body().model_dump(mode="json"), headers=headers).status_code == 409
    settings.dashboard_operations_directory = tmp_path.resolve() / "jobs"
    settings.dashboard_m7_paired_directory = tmp_path.resolve()
    settings.dashboard_live_max_usd = 1
    for limit in (0, 1.01):
        assert client.post("/dashboard/jobs", json=body("m6-live", max_usd=limit).model_dump(mode="json"),
                           headers=headers).status_code == 422
    settings.auth_mode = "disabled"
    assert client.get("/dashboard/jobs/capabilities").status_code == 403


def test_pending_conflicts_restart_and_tenant_isolation(jobs):
    request = body()
    launches = []
    first = jobs.start(request, ADMIN, {}, launch=launches.append)
    assert first["status"] == "QUEUED"
    assert jobs.start(request, ADMIN, {}, launch=launches.append) == first
    assert len(launches) == 1
    with pytest.raises(JobConflict):
        jobs.start(body(), ADMIN, {}, launch=launches.append)
    assert jobs.get(str(request.request_id), "other-tenant") is None
    assert jobs.recent("other-tenant") == []
    with jobs.connection() as con:
        con.execute("UPDATE jobs SET status='RUNNING'")
    with jobs.lock():
        assert JobStore(jobs.root).get(str(request.request_id), ADMIN.tenant_id)["status"] == "RUNNING"
    restarted = JobStore(jobs.root)
    assert restarted.get(str(request.request_id), ADMIN.tenant_id)["status"] == "INTERRUPTED"
    assert restarted.start(request, ADMIN, {}, launch=launches.append)["status"] == "INTERRUPTED"
    assert len(launches) == 1


def test_real_mock_worker_survives_store_restart_and_does_not_reexecute(jobs):
    request = body()
    jobs.start(request, ADMIN, {})
    deadline = time.monotonic() + 40
    while True:
        record = JobStore(jobs.root).get(str(request.request_id), ADMIN.tenant_id)
        if record["status"] not in {"QUEUED", "RUNNING"}:
            break
        assert time.monotonic() < deadline
        time.sleep(0.1)
    assert record["status"] == "SUCCEEDED", record
    assert record["result"]["mode"] == "offline_mock_pilot"
    assert record["result"]["models"]
    report = jobs.root / str(request.request_id) / "report.json"
    timestamp = report.stat().st_mtime_ns
    assert jobs.start(request, ADMIN, {})["status"] == "SUCCEEDED"
    assert report.stat().st_mtime_ns == timestamp


def test_worker_child_retains_exclusive_lock_after_parent_disappears(jobs):
    with jobs.lock() as fd:
        child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(3)"], pass_fds=(fd,))
    try:
        with pytest.raises(BlockingIOError), jobs.lock():
            pass
    finally:
        child.terminate()
        child.wait(timeout=5)
    with jobs.lock():
        pass


def test_launch_failure_and_process_error_are_not_success(jobs, monkeypatch):
    def fail(identifier):
        raise OSError("Synthetic unavailable worker")
    failed = jobs.start(body(), ADMIN, {}, launch=fail)
    assert failed["status"] == "FAILED" and failed["error"] == "worker_start_failed"
    request = body()
    jobs.start(request, ADMIN, {}, launch=lambda _: None)
    monkeypatch.setattr(jobs, "command", lambda row: (
        [sys.executable, "-c", 'import json;print(json.dumps({"api_key":"private","status":"failed"}));exit(1)'], jobs.root))
    jobs.run(str(request.request_id))
    failed = jobs.get(str(request.request_id), ADMIN.tenant_id)
    assert failed["status"] == "FAILED"
    assert failed["result"]["api_key"] == "[REDACTED]"


def test_private_store_rejects_foreign_directory_and_symlinks(tmp_path, jobs):
    directory = tmp_path.resolve() / "foreign"
    directory.mkdir(mode=0o700)
    (directory / "important.txt").write_text("Keep")
    with pytest.raises(JobUnavailable):
        JobStore(directory)
    link = tmp_path.resolve() / "link"
    link.symlink_to(jobs.root, target_is_directory=True)
    with pytest.raises(JobUnavailable):
        JobStore(link)
    jobs.db.unlink()
    jobs.db.symlink_to(directory / "important.txt")
    with pytest.raises(OSError):
        JobStore(jobs.root)
    assert (directory / "important.txt").read_text() == "Keep"


def test_fixed_runtime_paths_and_budget_in_worker(jobs):
    request = body("runtime-up")
    jobs.start(request, ADMIN, {}, launch=lambda _: None)
    with jobs.connection() as con:
        row = con.execute("SELECT * FROM jobs").fetchone()
    command, _ = jobs.command(row)
    assert "scripts.execution_mtls_runtime" in command and "up" in command
    assert "/runtime/c02/dashboard-" in command[-1]
    assert "--purge" not in command
    altered = dict(row) | {"action": "m6-live", "request": json.dumps({"max_usd": 2}),
                           "config": json.dumps({"paired": "server-owned", "max_usd": 1})}
    with pytest.raises(JobUnavailable):
        jobs.command(altered)


def test_queued_restart_does_not_erase_older_history(jobs):
    request = body()
    jobs.start(request, ADMIN, {}, launch=lambda _: None)
    with sqlite3.connect(jobs.db) as con:
        con.execute("UPDATE jobs SET created=?", (time.time() - 31,))
    old = jobs.get(str(request.request_id), ADMIN.tenant_id)
    assert old["status"] == "INTERRUPTED"
    jobs.start(body(), ADMIN, {}, launch=lambda _: None)
    assert len(jobs.recent(ADMIN.tenant_id)) == 2
    assert os.stat(jobs.root).st_mode & 0o077 == 0


def test_runtime_report_progress_is_redacted_without_replacing_job_state(jobs, monkeypatch):
    report = jobs.root / "verification.json"
    monkeypatch.setattr(jobs, "runtime_directory", lambda identifier=None: jobs.root)
    request = body("runtime-verify")
    jobs.start(request, ADMIN, {}, launch=lambda _: None)
    report.write_text(json.dumps({
        "schema": "execution-mtls-verification-1", "completed": False,
        "checks": [{"label": "actual_access_403", "passed": True, "grant_token": "private"}],
        "release": {"private_key": "not-exported"},
    }))
    row = jobs.get(str(request.request_id), ADMIN.tenant_id)
    assert row["status"] == "QUEUED" and not row["result"]["verification_completed"]
    assert row["result"]["checks"][0]["grant_token"] == "[REDACTED]"
    assert "release" not in row["result"]
    report.write_text("{partial report")
    assert jobs.get(str(request.request_id), ADMIN.tenant_id)["result"] is None
    report.unlink()
    secret = jobs.root / "unrelated-secret"
    secret.write_text("private")
    report.symlink_to(secret)
    assert jobs.get(str(request.request_id), ADMIN.tenant_id)["result"] is None
