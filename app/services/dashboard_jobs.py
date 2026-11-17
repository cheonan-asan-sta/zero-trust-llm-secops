"""Durable, opt-in host jobs. Browsers never choose commands or filesystem paths."""

import hashlib
import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # The application can serve read/analysis APIs on Windows.
    fcntl = None

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = {
    "runtime-status": "실행 환경 상태 조회",
    "runtime-up": "앱과 수집 서비스 시작",
    "runtime-down": "서비스 정지 (자료 보존)",
    "runtime-recover": "기록자 정지 및 백업과 격리 복원",
    "runtime-verify": "별도 환경에서 장애와 복원 검증",
    "m6-mock": "M6 모의 모델 비교",
    "m6-plan": "200세션 모델 비교 모의 실행",
    "m6-live": "200세션 실제 모델 비교",
}


class JobConflict(ValueError):
    pass


class JobUnavailable(ValueError):
    pass


def host_jobs_supported():
    # Do not substitute weaker ACL or process-lock semantics on other platforms.
    return os.name == "posix" and fcntl is not None and hasattr(os, "O_NOFOLLOW")


def private_root(directory):
    if not host_jobs_supported():
        raise JobUnavailable("operations_posix_host_required")
    path = Path(directory).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise JobUnavailable("operations_symlink_forbidden")
    if path.exists():
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise JobUnavailable("operations_private_directory_required")
        if any(path.iterdir()) and not (path / "dashboard-owner.json").is_file():
            raise JobUnavailable("operations_directory_not_owned")
    else:
        path.mkdir(parents=True, mode=0o700)
    marker = path / "dashboard-owner.json"
    expected = {"schema": "dashboard-jobs-1", "root": str(ROOT)}
    if marker.exists():
        if marker.is_symlink() or json.loads(marker.read_text()) != expected:
            raise JobUnavailable("operations_owner_mismatch")
    else:
        with marker.open("x") as stream:
            json.dump(expected, stream)
    return path


def public_result(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if any(s in k.lower() for s in
                ("token", "secret", "password", "credential", "api_key", "signature"))
                else public_result(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [public_result(v) for v in value[:1000]]
    return value


class JobStore:
    def __init__(self, directory):
        self.root = private_root(directory)
        self.db = self.root / "jobs.sqlite3"
        fd = os.open(self.db, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.connection() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, tenant TEXT, actor TEXT, action TEXT,
                reason TEXT, request TEXT, config TEXT, status TEXT,
                created REAL, updated REAL, result TEXT, error TEXT)""")

    @contextmanager
    def connection(self):
        if self.db.is_symlink():
            raise JobUnavailable("operations_store_symlink")
        with sqlite3.connect(self.db, timeout=10) as con:
            con.row_factory = sqlite3.Row
            yield con

    @contextmanager
    def lock(self):
        fd = os.open(self.root / "execution.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)

    def reconcile(self):
        try:
            with self.lock(), self.connection() as con:
                con.execute("""UPDATE jobs SET status='INTERRUPTED', error='worker_interrupted',
                    updated=? WHERE status='RUNNING' OR (status='QUEUED' AND created<?)""",
                            (time.time(), time.time() - 30))
        except BlockingIOError:
            pass

    def runtime_directory(self, verification_id=None):
        scope = hashlib.sha256(str(self.root).encode()).hexdigest()[:16]
        name = "dashboard-" + scope
        if verification_id is not None:
            name += "-verify-" + verification_id
        return ROOT / "runtime" / "c02" / name

    def verification_result(self, identifier):
        path = self.runtime_directory(identifier) / "verification.json"
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(1_048_577)
            if len(raw) > 1_048_576:
                return None
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get("schema") != "execution-mtls-verification-1":
                return None
            return public_result({"verification_completed": value.get("completed", False)} | {
                key: value[key] for key in ("checks", "maintenance", "failure_diagnostics", "cleanup",
                                           "error", "error_code", "started_at", "finished_at") if key in value
            })
        except (OSError, ValueError):
            # A writer may be replacing its report. Keep the persisted job outcome.
            return None

    def view(self, row):
        result = json.loads(row["result"]) if row["result"] else None
        if row["action"] == "runtime-verify":
            result = self.verification_result(row["id"]) or result
        return {key: row[key] for key in
                ("id", "tenant", "actor", "action", "reason", "status", "created", "updated", "error")} | {
                    "result": result,
                }

    def get(self, identifier, tenant):
        self.reconcile()
        with self.connection() as con:
            row = con.execute("SELECT * FROM jobs WHERE id=? AND tenant=?", (identifier, tenant)).fetchone()
        return self.view(row) if row else None

    def recent(self, tenant):
        self.reconcile()
        with self.connection() as con:
            rows = con.execute("SELECT * FROM jobs WHERE tenant=? ORDER BY created DESC LIMIT 50",
                               (tenant,)).fetchall()
        return [self.view(row) for row in rows]

    def start(self, request, principal, config, launch=None):
        self.reconcile()
        body = request.model_dump(mode="json")
        identifier = str(request.request_id)
        encoded = json.dumps(body, sort_keys=True)
        with self.connection() as con:
            con.execute("BEGIN IMMEDIATE")
            old = con.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()
            if old:
                if (old["tenant"], old["actor"], old["request"]) != (
                    principal.tenant_id, principal.subject, encoded,
                ):
                    raise JobConflict("job_identifier_conflict")
                return self.view(old)
            if con.execute("SELECT 1 FROM jobs WHERE status IN ('QUEUED','RUNNING')").fetchone():
                raise JobConflict("another_job_is_running")
            now = time.time()
            con.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                identifier, principal.tenant_id, principal.subject, request.action, request.reason,
                encoded, json.dumps(config), "QUEUED", now, now, None, None,
            ))
        try:
            if launch:
                launch(identifier)
            else:
                subprocess.Popen(
                    [sys.executable, "-m", "scripts.dashboard_job", "--directory", str(self.root),
                     "--job-id", identifier], cwd=ROOT, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
        except OSError:
            with self.connection() as con:
                con.execute("UPDATE jobs SET status='FAILED', error='worker_start_failed' WHERE id=?",
                            (identifier,))
        return self.get(identifier, principal.tenant_id)

    def command(self, row):
        config = json.loads(row["config"])
        request = json.loads(row["request"])
        output = self.root / row["id"]
        output.mkdir(mode=0o700, exist_ok=True)
        # Runtime tools already validate this subtree and their own ownership labels.
        runtime = self.runtime_directory()
        prefix = [sys.executable, "-m"]
        action = row["action"]
        if action == "runtime-verify":
            return [*prefix, "scripts.test_execution_mtls_runtime", "--directory",
                    str(self.runtime_directory(row["id"]))], output
        if action.startswith("runtime-"):
            return [*prefix, "scripts.execution_mtls_runtime", action.removeprefix("runtime-"),
                    "--directory", str(runtime)], output
        if action == "m6-mock":
            return [*prefix, "scripts.evaluate_m6", "--output", str(output / "report.json")], output
        if action in {"m6-plan", "m6-live"} and config.get("paired"):
            command = [*prefix, "scripts.evaluate_m6", "--m7-paired", config["paired"],
                       "--output-dir", str(output / "evaluation")]
            if action == "m6-live":
                budget = request["max_usd"]
                if not 0 < budget <= config["max_usd"]:
                    raise JobUnavailable("live_budget_not_approved")
                command += ["--live", "--live-max-usd", str(budget), "--max-requests", "600",
                            "--wall-seconds", "3600"]
            return command, output
        raise JobUnavailable("job_not_configured")

    def run(self, identifier):
        with self.lock() as lock_fd, self.connection() as con:
            row = con.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()
            if row is None or row["status"] != "QUEUED":
                return
            con.execute("UPDATE jobs SET status='RUNNING',updated=? WHERE id=?", (time.time(), identifier))
            con.commit()
            result, error, status = None, None, "FAILED"
            try:
                command, output = self.command(row)
                # No shell, environment overrides, browser paths, or raw logs in responses.
                with tempfile.TemporaryFile() as log:
                    process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                               stdin=subprocess.DEVNULL, start_new_session=True,
                                               pass_fds=(lock_fd,))
                    try:
                        returncode = process.wait(timeout=5400)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=5)
                        raise
                    log.seek(0, os.SEEK_END)
                    size = log.tell()
                    log.seek(max(0, size - 1_048_576))
                    for line in reversed(log.read().decode("utf-8", errors="replace").splitlines()):
                        try:
                            value = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(value, dict):
                            result = public_result(value)
                            break
                report_path = output / ("report.json" if row["action"] == "m6-mock"
                                        else "evaluation/report.json")
                if row["action"].startswith("m6-") and report_path.is_file():
                    report = json.loads(report_path.read_text())
                    result = public_result({k: report[k] for k in
                                            ("schema", "mode", "models", "summary", "request_count",
                                             "budget", "stop_reason", "wire_verification") if k in report})
                status = "SUCCEEDED" if returncode == 0 else "FAILED"
                error = None if returncode == 0 else "operation_failed_check_runtime_state"
            except subprocess.TimeoutExpired:
                error = "operation_timeout_state_requires_review"
            except (OSError, ValueError, RuntimeError):
                error = "operation_unavailable"
            con.execute("UPDATE jobs SET status=?,updated=?,result=?,error=? WHERE id=?", (
                status, time.time(), json.dumps(result) if result is not None else None, error, identifier,
            ))
