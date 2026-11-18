import json
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


def test_actual_http_worker_cursor_resume_and_current_key_readiness(executed, tmp_path):
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
        paging=True,
    )
    assert result["independent_http_processes"] == 3
    assert result["verified_audit_rows"] == 3 and result["provider_stub_calls"] == 2
    assert result["paid_api_calls"] == result["aws_calls"] == 0
    assert len(passed) == 14 and result["new_access_grants_issued"] == 0
    assert result["paging"]["cursor_resumed_over_tcp"]
    assert result["paging"]["original_scope_and_expiry_preserved"]
    assert result["paging"]["key_failure_blocks_pages_and_readiness"]
    assert result["paging"]["provider_stub_calls_third"] == 0
    assert result["paging"]["third_exit_code"] != 0
    assert result["paging"]["owned_cursor_key_removed"]
    assert result["paging"]["runtime_checkpoint_rejects_valid_database_rollback"]
    assert result["paging"]["runtime_checkpoint_pin_failure_blocks_reads"]
    assert result["paging"]["runtime_checkpoint_exact_state_recovery"]
    assert not list(tmp_path.glob("owned-cursor-*.key"))


def test_wrong_cursor_key_pin_never_falls_back_or_starts_worker(executed, tmp_path):
    lab, _, _ = executed
    path, pin, _ = configure(lab, tmp_path / "shared")
    key = tmp_path / "cursor.key"
    key.write_bytes(secrets.token_bytes(32))
    key.chmod(0o600)
    with (
        pytest.raises(ValueError, match="exited_during_startup"),
        owned_worker(
            lab,
            (path, pin),
            tmp_path / "audit.sqlite3",
            tmp_path / "worker",
            secrets.token_urlsafe(32),
            cursor_config=(key, "e" * 64),
        ),
    ):
        pytest.fail("worker must not use an ephemeral fallback key")
    assert not list((tmp_path / "worker").glob("*.ready.json"))


def test_worker_does_not_inherit_parent_app_storage_or_cursor_settings(
    executed, tmp_path, monkeypatch
):
    lab, _, _ = executed
    path, pin, _ = configure(lab, tmp_path / "shared")
    unexpected = tmp_path / "must-not-create.sqlite3"
    monkeypatch.setenv("BEHAVIOR_CONTEXT_DB_PATH", str(unexpected))
    monkeypatch.setenv("AUDIT_CURSOR_KEY_PATH", str(tmp_path / "must-not-read.key"))
    monkeypatch.setenv("AUDIT_CURSOR_KEY_SHA256", "e" * 64)
    key = secrets.token_urlsafe(32)
    with owned_worker(lab, (path, pin), tmp_path / "audit.sqlite3", tmp_path / "worker", key) as (
        _,
        client,
        stats,
    ):
        response = client.get("/audit/results", headers={"X-API-Key": key})
        assert response.status_code == 200 and response.json()["total_matches"] == 0
        assert not unexpected.exists()
        assert json.loads(stats.read_text(encoding="utf-8"))["provider_stub_calls"] == 0


def test_worker_rejects_a_dotenv_file_in_its_owned_directory(executed, tmp_path):
    lab, _, _ = executed
    path, pin, _ = configure(lab, tmp_path / "shared")
    directory = tmp_path / "worker"
    directory.mkdir()
    (directory / ".env.local").write_text("AUDIT_BACKEND=dynamodb\n", encoding="utf-8")
    with (
        pytest.raises(ValueError, match="must_not_supply_dotenv"),
        owned_worker(
            lab, (path, pin), tmp_path / "audit.sqlite3", directory, secrets.token_urlsafe(32)
        ),
    ):
        pytest.fail("test worker must not load a local dotenv file")
    assert not list(directory.glob("*.control.json"))
