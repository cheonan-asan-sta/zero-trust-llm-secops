"""Real spool lock contention and bounded receipt/exit/cleanup boundaries."""

import errno
import json
import os
import sqlite3
import subprocess
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from scripts import execution_maintenance_probe as probe
from scripts import test_execution_mtls_runtime as driver
from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.continuous_signal_collector import exclusive_collector
from tests import test_execution_retention as retention

PRIVATE = "private-key-token-response-never-publish"


def collector(monkeypatch, *, compacted=5, retired=5, error=None):
    def retire(path):
        if error:
            raise error
        return retired
    value = SimpleNamespace(compact=lambda: {"compacted": compacted}, retire_inputs=retire)
    monkeypatch.setattr(probe, "ExecutionCollector", lambda *a, **k: value)
    return value


def success():
    return probe.Receipt(operation="observer_archive", completed=True, compacted=5,
                         retired_inputs=5).model_dump(mode="json")


@pytest.mark.parametrize("error,category", [
    (BlockingIOError(errno.EAGAIN, PRIVATE), "collector_busy"),
    (PermissionError(PRIVATE), "io"), (ValueError(PRIVATE), "invalid_state"),
    (RuntimeError(PRIVATE), "internal"), (sqlite3.DatabaseError(PRIVATE), "sqlite"),
    (TimeoutError(PRIVATE), "timeout"),
])
def test_later_failure_keeps_valid_compaction_and_no_private_text(monkeypatch, error, category):
    collector(monkeypatch, error=error)
    result = probe.perform("observer_archive")
    assert result["completed"] is False and result["compacted"] == 5
    assert result["retired_inputs"] is None
    assert result["issue"] == {"phase": "observer_retire", "category": category}
    assert PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("value", [True, "5", -1, 1001, float("nan")])
def test_bad_counter_stops_before_retirement(monkeypatch, value):
    obj = collector(monkeypatch, compacted=value)
    obj.retire_inputs = lambda path: pytest.fail("invalid compaction must stop")
    result = probe.perform("observer_archive")
    assert result["completed"] is False and result["compacted"] is None
    assert result["issue"]["phase"] == "observer_compact"


def test_success(monkeypatch):
    collector(monkeypatch)
    assert probe.perform("observer_archive") == success()


@pytest.mark.parametrize("change", [
    {"completed": "true"}, {"retired_inputs": True}, {"stdout": PRIVATE},
    {"compacted": None}, {"archived_records": 1},
    {"completed": False, "issue": {"phase": "server_compact", "category": "io"}},
])
def test_strict_receipt(change):
    with pytest.raises(ValidationError):
        probe.Receipt.model_validate(success() | change)


@pytest.mark.parametrize("output,code,category", [
    (b"", 2, "command_exit"), (PRIVATE.encode(), 2, "invalid_report"),
    (b"x" * 32769, 0, "invalid_report"),
    (b'{"operation":"observer_archive","operation":"server_archive"}', 1, "invalid_report"),
    (json.dumps(success() | {"operation": "server_archive"}).encode(), 0, "invalid_report"),
    (json.dumps(success()).encode(), 2, "command_exit"),
])
def test_parent_checks_exit_scope_and_protocol(monkeypatch, output, code, category):
    def run(argv, **kwargs):
        assert argv == ["docker", "exec", "--interactive", "owned", "python", "-m",
                        "scripts.execution_maintenance_probe"]
        assert kwargs["stderr"] == subprocess.DEVNULL and kwargs["timeout"] == 30
        assert json.loads(kwargs["input"]) == {"operation": "observer_archive"}
        return SimpleNamespace(returncode=code, stdout=output)
    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.execute(SimpleNamespace(container=lambda s: "owned"), "observer_archive")
    assert result["issue"] == {"phase": "command", "category": category}
    assert PRIVATE not in json.dumps(result)


def test_parent_preserves_child_failure_without_retry(monkeypatch):
    collector(monkeypatch, error=BlockingIOError(PRIVATE))
    value = probe.perform("observer_archive")
    calls = []
    def run(*args, **kwargs):
        calls.append(1)
        return SimpleNamespace(returncode=1, stdout=json.dumps(value).encode())
    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.execute(SimpleNamespace(container=lambda s: "owned"), "observer_archive")
    assert result["receipt"] == value and result["issue"] == value["issue"] and len(calls) == 1


def test_driver_saves_failure_before_cleanup_without_retry(tmp_path, monkeypatch):
    checks = object.__new__(driver.Checks)
    checks.report = {"completed": False}
    checks.path = tmp_path / "verification.json"
    checks.runtime = object()
    calls = []
    def execute(*args):
        calls.append(json.loads(checks.path.read_text()))
        return {"exit_code": 1, "receipt": None,
                "issue": {"phase": "command", "category": "command_exit"}}
    monkeypatch.setattr(driver, "execute_maintenance", execute)
    with pytest.raises(RuntimeFailure, match="execution_maintenance_failed"):
        checks.maintenance("observer_archive")
    assert len(calls) == 1 and calls[0]["maintenance"][0]["completed"] is False
    saved = json.loads(checks.path.read_text())["maintenance"][0]
    assert saved["completed"] is False and saved["issue"]["category"] == "command_exit"


@pytest.mark.skipif(os.name != "posix", reason="real POSIX flock requires Linux")
@pytest.mark.parametrize("point", ["init", "compact"])
def test_real_spool_lock_is_classified_without_mutation(tmp_path, monkeypatch, point):
    lab = retention.lab.__wrapped__(tmp_path, monkeypatch)
    obj, feed, path = retention.complete(lab, tmp_path, bundle=True)
    before = path.read_bytes()
    status = obj.status()
    monkeypatch.setattr(probe, "ExecutionCollector",
                        lambda *a, **k: lab.collector() if point == "init" else obj)
    with exclusive_collector(obj.directory):
        result = probe.perform("observer_archive")
    assert result["completed"] is False and result["compacted"] is None
    assert result["issue"] == {"phase": "observer_" + point, "category": "collector_busy"}
    assert obj.status() == status and path.read_bytes() == before
    assert obj.compact() == {"compacted": 1}
    assert obj.retire_inputs(feed) == 1
    assert (feed / ".retired" / path.name).read_bytes() == before


@pytest.mark.parametrize("raw", [PRIVATE.encode(), b"x" * 1025,
    b'{"operation":"observer_archive","operation":"server_archive"}',
    json.dumps({"operation": PRIVATE}).encode()])
def test_input_failure_never_echoes_input(monkeypatch, capsys, raw):
    monkeypatch.setattr(probe.sys, "stdin", SimpleNamespace(buffer=BytesIO(raw)))
    assert probe.main() == 1
    output = capsys.readouterr()
    assert PRIVATE not in output.out and not output.err
    assert json.loads(output.out)["issue"]["phase"] == "input"


@pytest.mark.parametrize("failed_phase", [None, "server_compact", "server_status"])
def test_server_uses_original_existing_database_and_safe_stages(tmp_path, monkeypatch, failed_phase):
    database = tmp_path / "context.sqlite3"
    database.touch()
    monkeypatch.setattr(probe, "Path", lambda p: database if str(p).startswith("/data/") else Path(p))
    monkeypatch.setattr(probe, "get_settings", lambda: SimpleNamespace(app_environment="test"))
    calls = []
    def compact(**kwargs):
        calls.append(kwargs)
        if failed_phase == "server_compact":
            raise PermissionError(PRIVATE)
        return {"compacted": 6}
    def status():
        if failed_phase == "server_status":
            raise probe.ContextStoreUnavailable(PRIVATE)
        return {"archived_records": 6, "private_key": PRIVATE}
    monkeypatch.setattr(probe, "BehaviorContextStore", lambda path: SimpleNamespace(
        compact=compact, storage_status=status))
    result = probe.perform("server_archive")
    assert calls == [{"limit": 1000}] and PRIVATE not in json.dumps(result)
    if failed_phase:
        assert result["completed"] is False and result["issue"]["phase"] == failed_phase
    else:
        assert result["completed"] is True and result["archived_records"] == 6


def test_sqlite_busy_code_not_message_controls_category():
    error = sqlite3.OperationalError(PRIVATE)
    error.sqlite_errorcode = sqlite3.SQLITE_BUSY | 0x100
    assert probe.issue(error, "server_compact")["category"] == "sqlite_busy"
    error.sqlite_errorcode = sqlite3.SQLITE_CORRUPT
    assert probe.issue(error, "server_compact")["category"] == "sqlite"


def test_command_timeout_has_no_exception_text(monkeypatch):
    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired(PRIVATE, 30, output=PRIVATE, stderr=PRIVATE)
    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.execute(SimpleNamespace(container=lambda s: "owned"), "observer_archive")
    assert result["issue"] == {"phase": "command", "category": "timeout"}
    assert PRIVATE not in json.dumps(result)
