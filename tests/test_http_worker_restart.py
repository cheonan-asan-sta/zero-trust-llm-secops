import secrets
from types import SimpleNamespace

import pytest
from test_service_analysis_evidence import executed as executed  # noqa: PLC0414

from scripts.f1_lab.http_worker_controls import owned_worker, run
from scripts.f1_lab.shared_native_controls import configure


def test_actual_http_worker_kill_restart_revalidates_reference_and_audit(executed, tmp_path):
    lab, args, _ = executed
    path, pin, _ = configure(lab, tmp_path / "shared")
    passed = []
    result = run(
        lab,
        args["request"],
        SimpleNamespace(session_id=args["signal"].session_id),
        args["receipt"],
        args["event"],
        args["proofs"],
        (path, pin),
        tmp_path,
        passed.append,
    )
    assert result["independent_http_processes"] == 2
    assert result["verified_audit_rows"] == 2
    assert result["provider_stub_calls"] == 2 and result["paid_api_calls"] == 0
    assert result["owned_processes_stopped"] is True and len(passed) == 6
    assert result["first_exit_code"] != 0 and result["second_exit_code"] != 0


def test_bad_bootstrap_pin_does_not_start_or_retry_http_worker(executed, tmp_path):
    lab, _, _ = executed
    path, _, _ = configure(lab, tmp_path / "shared")
    with (
        pytest.raises(ValueError, match="exited_during_startup"),
        owned_worker(
            lab,
            (path, "e" * 64),
            tmp_path / "audit.sqlite3",
            tmp_path / "worker",
            secrets.token_urlsafe(32),
        ),
    ):
        pytest.fail("worker must not serve with a mismatched startup pin")
