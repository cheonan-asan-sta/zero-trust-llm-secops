"""Local Docker lab admission gate, before exposing the existing application."""

import argparse
import os
import sqlite3
from pathlib import Path

from app.config import get_settings
from scripts.app_state_recovery import (
    RecoveryError,
    guard_behavior_context,
    local_only,
    read_file,
    require,
    verify_admission,
)
from scripts.app_storage_contract import FILES


def admit(data, public, *, registry_path=None, require_api_key=True):
    local_only()
    settings = get_settings()
    require(settings.analyzer_mode == "rule"
            and (not require_api_key or settings.auth_mode == "api_key"), "lab_authentication_required")
    require(settings.zero_trust_db_path.resolve() == (data / "app.sqlite3").resolve(), "database_path_mismatch")
    context = getattr(settings, "behavior_context_db_path", None)
    expected_context = data / "app-behavior-context.sqlite3"
    require(context is None or Path(context).resolve() == expected_context.resolve(),
            "behavior_context_path_mismatch")
    guard_behavior_context(data, configured_path=context)
    registry = data / "sources.json"
    configured_registry = Path(registry_path) if registry_path is not None else registry
    if registry_path is not None:
        require(read_file(configured_registry, 1024**2) == read_file(registry, 1024**2),
                "registry_witness_mismatch")
    require((settings.trusted_signal_sources_path is not None and
             settings.trusted_signal_sources_path.resolve() == configured_registry.resolve()) if registry.exists()
            else settings.trusted_signal_sources_path is None, "registry_path_mismatch")
    result = verify_admission(data, public)
    if (data / "response-workflow.sqlite3").exists():
        require(settings.response_workflow_db_path.resolve() ==
                (data / "response-workflow.sqlite3").resolve(), "response_path_mismatch")
    if (data / "storage.json").exists():
        require(settings.audit_backend == "jsonl", "jsonl_backend_required")
        for setting, kind in (("audit_log_path", "audit"), ("case_log_path", "cases"),
                              ("outbox_log_path", "outbox")):
            require(getattr(settings, setting).resolve() == (data / FILES[kind]).resolve(),
                    "storage_path_mismatch")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--public", required=True, type=Path)
    args = parser.parse_args()
    try:
        admit(args.data, args.public)
    except (RecoveryError, OSError, ValueError, TypeError, LookupError, RuntimeError, sqlite3.Error):
        raise SystemExit("RECOVERY_ADMISSION_DENIED") from None
    os.execvp("uvicorn", ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000",
                          "--no-access-log"])


if __name__ == "__main__":
    main()
