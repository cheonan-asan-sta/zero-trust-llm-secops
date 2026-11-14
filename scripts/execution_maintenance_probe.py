"""Fixed local acceptance maintenance with bounded, credential-free receipts."""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from app.config import get_settings
from app.models import StrictModel
from app.services.behavior_context_store import BehaviorContextStore, ContextStoreUnavailable
from app.services.trusted_signals import SignalRegistryUnavailable
from scripts.behavior_execution_collector import ExecutionCollector
from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.infra_probe_diagnostics import report_value

Operation = Literal["observer_archive", "server_archive"]
Phase = Literal["input", "observer_init", "observer_compact", "observer_retire",
                "server_init", "server_compact", "server_status", "complete", "command"]
Category = Literal["collector_busy", "sqlite_busy", "sqlite", "io", "invalid_state",
                   "registry_unavailable", "context_unavailable", "internal", "timeout",
                   "command_exit", "invalid_report", "runtime_control"]


class Issue(StrictModel):
    phase: Phase
    category: Category


class Receipt(StrictModel):
    schema_version: Literal["execution-maintenance-1"] = "execution-maintenance-1"
    operation: Operation
    completed: bool = Field(strict=True)
    compacted: int | None = Field(default=None, strict=True, ge=0, le=1000)
    retired_inputs: int | None = Field(default=None, strict=True, ge=0, le=1000)
    archived_records: int | None = Field(default=None, strict=True, ge=0, le=2_147_483_647)
    issue: Issue | None = None

    @model_validator(mode="after")
    def consistent(self):
        if self.issue is not None and not self.issue.phase.startswith(
            "observer_" if self.operation == "observer_archive" else "server_"
        ):
            raise ValueError("maintenance_failure_scope")
        if self.operation == "observer_archive" and self.archived_records is not None:
            raise ValueError("maintenance_scope")
        if self.operation == "server_archive" and any(
            x is not None for x in (self.compacted, self.retired_inputs)
        ):
            raise ValueError("maintenance_scope")
        if self.completed:
            values = ((self.compacted, self.retired_inputs) if self.operation == "observer_archive"
                      else (self.archived_records,))
            if self.issue is not None or any(v is None for v in values):
                raise ValueError("maintenance_completion")
        elif self.issue is None:
            raise ValueError("maintenance_failure_missing")
        return self


def issue(error, phase):
    """Never include exception strings, class names, paths, stdout or stderr."""
    category = "internal"
    if isinstance(error, BlockingIOError):
        category = "collector_busy"
    elif isinstance(error, sqlite3.Error):
        code = getattr(error, "sqlite_errorcode", None)
        category = "sqlite_busy" if type(code) is int and code & 255 in {
            sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED
        } else "sqlite"
    else:
        for kind, name in (
            ((TimeoutError, subprocess.TimeoutExpired), "timeout"),
            (SignalRegistryUnavailable, "registry_unavailable"),
            (ContextStoreUnavailable, "context_unavailable"),
            (OSError, "io"), (RuntimeFailure, "runtime_control"),
            ((ValueError, TypeError, KeyError, OverflowError), "invalid_state"),
        ):
            if isinstance(error, kind):
                category = name
                break
    return Issue(phase=phase, category=category).model_dump(mode="json")


def count(value, maximum=1000):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("maintenance_counter")
    return value


def perform(operation):
    # Paths and commands are not supplied by callers. This is a local test adapter,
    # with exactly the original maintenance operations and locking behavior.
    if operation not in {"observer_archive", "server_archive"}:
        raise ValueError("maintenance_operation")
    result = {"operation": operation, "completed": False}
    phase = "observer_init" if operation == "observer_archive" else "server_init"
    try:
        if operation == "observer_archive":
            collector = ExecutionCollector(Path("/observer/state"), "https://core:8000",
                                           tls_profile=Path("/tls/core.json"))
            phase = "observer_compact"
            result["compacted"] = count(collector.compact()["compacted"])
            phase = "observer_retire"
            result["retired_inputs"] = count(collector.retire_inputs(Path("/observer/input")))
        else:
            database = Path("/data/app-behavior-context.sqlite3")
            if get_settings().app_environment not in {"local", "test"}:
                raise ValueError("maintenance_local_only")
            if database.is_symlink() or not database.is_file():
                raise ValueError("maintenance_existing_database")
            store = BehaviorContextStore(database)
            phase = "server_compact"
            store.compact(limit=1000)
            phase = "server_status"
            result["archived_records"] = count(store.storage_status()["archived_records"], 2_147_483_647)
        result["completed"] = True
        return Receipt.model_validate(result).model_dump(mode="json")
    except Exception as error:  # noqa: BLE001 -- fixed privacy envelope; no retry or error text.
        result.update(completed=False, issue=issue(error, phase))
        # Retain only previously validated counters if a later operation failed.
        for name in ("compacted", "retired_inputs", "archived_records"):
            value = result.get(name)
            if name in result and (type(value) is not int or not 0 <= value <= (
                2_147_483_647 if name == "archived_records" else 1000
            )):
                result.pop(name)
        return Receipt.model_validate(result).model_dump(mode="json")


def execute(runtime, operation):
    if operation not in {"observer_archive", "server_archive"}:
        raise ValueError("maintenance_operation")
    service = "execution-observer" if operation == "observer_archive" else "app"
    try:
        container = runtime.container(service)  # verifies owned project/service labels
        result = subprocess.run(
            ["docker", "exec", "--interactive", container, "python", "-m",
             "scripts.execution_maintenance_probe"],
            input=json.dumps({"operation": operation}).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False,
        )
    except (OSError, RuntimeFailure, ValueError, subprocess.SubprocessError) as error:
        return {"exit_code": None, "receipt": None, "issue": issue(error, "command")}
    try:
        receipt = Receipt.model_validate(report_value(result.stdout))
        if receipt.operation != operation:
            raise ValueError("maintenance_operation_mismatch")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        category = "command_exit" if result.returncode and not result.stdout else "invalid_report"
        return {"exit_code": result.returncode, "receipt": None,
                "issue": Issue(phase="command", category=category).model_dump(mode="json")}
    failure = receipt.issue.model_dump(mode="json") if receipt.issue else None
    if result.returncode and failure is None:
        failure = Issue(phase="command", category="command_exit").model_dump(mode="json")
    return {"exit_code": result.returncode, "receipt": receipt.model_dump(mode="json"), "issue": failure}


def main():
    try:
        raw = sys.stdin.buffer.read(1025)
        if len(raw) > 1024:
            raise ValueError("maintenance_input_bound")
        value = report_value(raw)
        if type(value) is not dict or set(value) != {"operation"}:
            raise ValueError("maintenance_input_shape")
        result = perform(value["operation"])
    except Exception as error:  # noqa: BLE001 -- no unvalidated input or exception text in output.
        print(json.dumps({"schema_version": "execution-maintenance-input-failure-1",
                          "issue": issue(error, "input")}))
        return 1
    print(json.dumps(result, allow_nan=False))
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
