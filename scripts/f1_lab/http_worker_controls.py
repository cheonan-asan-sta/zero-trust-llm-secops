"""Owned HTTP processes are killed/reopened; no existing app process is touched."""

import hashlib
import json
import os
import secrets
import subprocess
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx

from app.config import Settings
from app.services.audit_checkpoint import capture_checkpoint
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.service_analysis_evidence import publish_service_analysis
from scripts.f1_lab.shared_service_analysis import open_shared_service_registry
from scripts.local_process_runtime import direct_python


@contextmanager
def owned_worker(
    lab,
    shared_config,
    audit_path,
    directory,
    api_key,
    *,
    cursor_config=None,
    checkpoint_config=None,
):
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(
        not (directory / ".env.local").exists() and not (directory / ".env.local").is_symlink(),
        "owned_http_worker_directory_must_not_supply_dotenv",
    )
    token = secrets.token_hex(16)
    control = directory / (token + ".control.json")
    ready, stats = directory / (token + ".ready.json"), directory / (token + ".stats.json")
    value = {
        "token": token,
        "ready": str(ready),
        "stats": str(stats),
        "operations_db": str(lab.operations.path.absolute()),
        "signal_sources": str(lab.operations.signal_verifier.registry_path.absolute()),
        "shared_config": str(Path(shared_config[0]).absolute()),
        "shared_pin": shared_config[1],
        "audit_db": str(Path(audit_path).absolute()),
        "api_key_sha256": hashlib.sha256(api_key.encode()).hexdigest(),
        "subject": lab.principal.subject,
        "tenant_id": lab.principal.tenant_id,
        "cursor_key_path": str(Path(cursor_config[0]).absolute()) if cursor_config else None,
        "cursor_key_pin": cursor_config[1] if cursor_config else None,
        "checkpoint_path": str(Path(checkpoint_config[0]).absolute())
        if checkpoint_config
        else None,
        "checkpoint_pin": checkpoint_config[1] if checkpoint_config else None,
    }
    control.write_text(json.dumps(value), encoding="utf-8")
    app_settings = {name.upper() for name in Settings.model_fields}
    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() not in app_settings
        and not k.startswith(
            ("OPENAI_", "AWS_", "OIDC_", "API_KEY_", "NATIVE_ANALYSIS_", "DASHBOARD_")
        )
    }
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    source_root = str(Path(__file__).resolve().parents[2])
    executable, env = direct_python(env)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (source_root, env.get("PYTHONPATH", "")) if p)
    with (directory / (token + ".stderr.log")).open("wb") as log:
        process = subprocess.Popen(
            [executable, "-m", "scripts.native_http_worker", "--control", str(control)],
            stdout=subprocess.DEVNULL,
            stderr=log,
            env=env,
            cwd=directory,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            deadline = time.monotonic() + 15
            while not ready.exists():
                require(process.poll() is None, "owned_http_worker_exited_during_startup")
                require(time.monotonic() < deadline, "owned_http_worker_startup_timeout")
                time.sleep(0.05)
            info = json.loads(ready.read_text(encoding="utf-8"))
            require(
                info["token"] == token
                and info["pid"] == process.pid
                and info["provider_stubbed"] is True
                and 0 < info["port"] < 65536,
                "owned_http_worker_ready_binding",
            )
            with httpx.Client(
                base_url=f"http://127.0.0.1:{info['port']}", timeout=5, trust_env=False
            ) as client:
                while True:
                    try:
                        if client.get("/health/live").status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    require(
                        process.poll() is None and time.monotonic() < deadline,
                        "owned_http_worker_not_listening",
                    )
                    time.sleep(0.05)
                yield process, client, stats
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)


def run(
    lab, request, access, receipt, event, proofs, shared_config, directory, passed, *, paging=False
):
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not paging:
        return _run(lab, request, access, receipt, event, proofs, shared_config, directory, passed)
    key = secrets.token_bytes(32)
    key_path = directory / ("owned-cursor-" + secrets.token_hex(16) + ".key")
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        config = key_path, hashlib.sha256(key).hexdigest()
        result = _run(
            lab,
            request,
            access,
            receipt,
            event,
            proofs,
            shared_config,
            directory,
            passed,
            cursor_config=config,
        )
    finally:
        key_path.unlink()
    result["paging"]["owned_cursor_key_removed"] = not key_path.exists()
    return result


def _run(
    lab,
    request,
    access,
    receipt,
    event,
    proofs,
    shared_config,
    directory,
    passed,
    *,
    cursor_config=None,
):
    directory = Path(directory)
    audit_path = directory / "worker-restart-audit.sqlite3"
    registry = open_shared_service_registry(lab.operations, *shared_config)
    ref = publish_service_analysis(
        registry,
        lab.operations,
        lab.signals[access.session_id],
        lab.principal,
        lab.broker.joiner,
        lab.broker.registry,
        request,
        event,
        proofs,
        receipt,
    )
    journal = lab.operations.journal_status()
    evidence_hash = hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest()
    api_key = secrets.token_urlsafe(32)
    headers = {"X-API-Key": api_key}
    with owned_worker(
        lab, shared_config, audit_path, directory / "worker-1", api_key, cursor_config=cursor_config
    ) as (
        first,
        client,
        stats,
    ):
        first_pid = first.pid
        require(
            client.post("/analysis/native-service", json={"execution_ref": ref}).status_code == 401,
            "owned_worker_real_auth",
        )
        require(
            client.post(
                "/analysis/native-service",
                headers=headers,
                json={"execution_ref": ref, "verification_context": {}},
            ).status_code
            == 422,
            "owned_worker_no_client_evidence",
        )
        passed("http_worker_process_uses_real_auth_and_strict_reference_request")
        response = client.post(
            "/analysis/native-service", headers=headers, json={"execution_ref": ref}
        )
        require(response.status_code == 200, "owned_first_worker_analysis")
        payload = response.json()
        require(
            payload["verification_context"]["native_execution"]["event_sha256"] == event.sha256
            and payload["assessment"]["recommended_action"] == "HOLD_FOR_REVIEW",
            "owned_worker_grounded_guard",
        )
        require(
            json.loads(stats.read_text())["provider_stub_calls"] == 1,
            "owned_first_worker_stub_count",
        )
        first.kill()
        first_exit = first.wait(timeout=10)
    persisted = SQLiteAuditStore.open_existing(audit_path)
    require(
        persisted.get(payload["event_id"], lab.principal.tenant_id).model_dump(mode="json")
        == payload,
        "owned_worker_commit_survives_kill",
    )
    passed("committed_native_analysis_survives_actual_http_process_kill")
    with owned_worker(
        lab, shared_config, audit_path, directory / "worker-2", api_key, cursor_config=cursor_config
    ) as (
        second,
        client,
        stats,
    ):
        require(second.pid != first_pid, "owned_worker_new_process")
        fetched = client.get(f"/results/{payload['event_id']}", headers=headers)
        require(
            fetched.status_code == 200 and fetched.json() == payload, "owned_worker_restart_history"
        )
        passed("new_http_process_bootstrap_reopens_same_verified_sqlite_audit")
        require(
            datetime.now(UTC) < min(p.expires_at for p in proofs),
            "owned_worker_native_proof_expired",
        )
        response = client.post(
            "/analysis/native-service", headers=headers, json={"execution_ref": ref}
        )
        require(
            response.status_code == 200
            and response.json()["assessment"]["recommended_action"] == "HOLD_FOR_REVIEW",
            "owned_restarted_worker_revalidates_reference",
        )
        passed("restarted_http_process_revalidates_shared_execution_reference")
        registry.revoke(ref)
        require(
            client.post(
                "/analysis/native-service", headers=headers, json={"execution_ref": ref}
            ).status_code
            == 404,
            "owned_restarted_worker_withdrawal",
        )
        require(
            json.loads(stats.read_text())["provider_stub_calls"] == 1,
            "owned_restarted_worker_stub_count",
        )
        require(
            datetime.now(UTC) < min(p.expires_at for p in proofs),
            "owned_worker_withdrawal_must_not_be_confused_with_expiry",
        )
        passed("withdrawn_reference_blocks_restarted_worker_without_model_call")
        if cursor_config is not None:
            query = {"limit": 1, "review_status": "PENDING"}
            page_response = client.get("/audit/results", headers=headers, params=query)
            require(page_response.status_code == 200, "owned_http_cursor_first_page")
            page = page_response.json()
            previous_audit_bytes = audit_path.read_bytes()
            require(
                page["total_matches"] == 2
                and page["next_cursor"] is not None
                and page["items"][0]["review_status"] == "PENDING",
                "owned_http_cursor_initial_snapshot",
            )
            reviewed = client.patch(
                f"/results/{payload['event_id']}/review",
                headers=headers,
                json={"status": "RESOLVED", "note": "Owned worker cursor acceptance"},
            )
            require(
                reviewed.status_code == 200 and reviewed.json()["review_status"] == "RESOLVED",
                "owned_http_cursor_post_snapshot_review",
            )
            passed("http_cursor_pins_pending_audit_before_review")
        second.kill()
        second_exit = second.wait(timeout=10)
    paging_report = None
    if cursor_config is not None:
        paging_report = _resume_page(
            lab,
            shared_config,
            audit_path,
            directory,
            api_key,
            headers,
            page,
            payload,
            {first_pid, second.pid},
            cursor_config,
            previous_audit_bytes,
            passed,
        )
    require(
        journal == lab.operations.journal_status()
        and evidence_hash == hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest(),
        "owned_worker_restart_source_history_unchanged",
    )
    expected_rows = 3 if cursor_config else 2
    require(
        persisted.integrity()["verified_lines"] == expected_rows, "owned_worker_restart_audit_rows"
    )
    passed("http_worker_kill_restart_does_not_reissue_grant_or_modify_execution_evidence")
    if paging_report is not None:
        passed("http_cursor_recovery_reads_issue_no_model_call_or_access_grant")
    report = {
        "independent_http_processes": 3 if cursor_config else 2,
        "first_exit_code": first_exit,
        "second_exit_code": second_exit,
        "verified_audit_rows": expected_rows,
        "provider_stub_calls": 2,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "new_access_grants_issued": 0,
        "owned_processes_stopped": True,
        "withdrawal_checked_before_original_proof_expiry": True,
    }
    if paging_report is not None:
        report["paging"] = paging_report
    return report


def _resume_page(
    lab,
    shared_config,
    audit_path,
    directory,
    api_key,
    headers,
    page,
    payload,
    previous_pids,
    cursor_config,
    previous_audit_bytes,
    passed,
):
    checkpoint_path = directory / "worker-minimum-checkpoint.json"
    checkpoint_receipt = capture_checkpoint(audit_path, checkpoint_path)
    with owned_worker(
        lab,
        shared_config,
        audit_path,
        directory / "worker-3",
        api_key,
        cursor_config=cursor_config,
        checkpoint_config=(checkpoint_path, checkpoint_receipt["checkpoint_sha256"]),
    ) as (third, client, stats):
        require(third.pid not in previous_pids, "owned_cursor_recovery_new_process")
        resumed = client.get(
            "/audit/results",
            headers=headers,
            params={"limit": 1, "review_status": "PENDING", "cursor": page["next_cursor"]},
        )
        require(resumed.status_code == 200, "owned_cursor_resume_http_status")
        body = resumed.json()
        require(
            body["total_matches"] == 2
            and len(body["items"]) == 1
            and body["items"][0]["analysis_id"] == payload["analysis_id"]
            and body["items"][0]["review_status"] == "PENDING"
            and body["next_cursor"] is None,
            "owned_cursor_resume_exact_pending_snapshot",
        )
        passed("http_cursor_survives_owned_worker_kill_restart")
        require(
            all(
                body[name] == page[name]
                for name in (
                    "snapshot_id",
                    "snapshot_created_at",
                    "snapshot_expires_at",
                    "snapshot_mode",
                )
            ),
            "owned_cursor_resume_original_scope_expiry",
        )
        passed("http_cursor_preserves_snapshot_scope_expiry_after_restart")
        current = client.get("/audit/results", headers=headers, params={"review_status": "PENDING"})
        require(
            current.status_code == 200 and current.json()["total_matches"] == 1,
            "owned_cursor_current_pending_view",
        )
        latest = client.get(f"/results/{payload['event_id']}", headers=headers)
        require(
            latest.status_code == 200 and latest.json()["review_status"] == "RESOLVED",
            "owned_cursor_current_review_view",
        )
        passed("http_cursor_current_view_reflects_post_snapshot_review")
        ready = client.get("/health/ready")
        require(ready.json()["audit_paging"]["ok"] is True, "owned_cursor_key_ready")
        require(
            ready.json()["audit"]["checkpoint_guard"]["minimum_head_verified"] is True,
            "owned_runtime_checkpoint_ready",
        )
        current_audit_bytes = audit_path.read_bytes()
        try:
            audit_path.write_bytes(previous_audit_bytes)
            require(
                SQLiteAuditStore.open_existing(audit_path).integrity()["ok"], "owned_valid_old_db"
            )
            old_page = client.get(
                "/audit/results",
                headers=headers,
                params={"review_status": "PENDING", "cursor": page["next_cursor"]},
            )
            old_ready = client.get("/health/ready")
            require(
                old_page.status_code == 503
                and old_ready.status_code == 503
                and old_ready.json()["audit"]["checkpoint_guard"]["minimum_head_verified"] is False
                and client.get("/health/live").status_code == 200,
                "owned_runtime_checkpoint_blocks_valid_rollback",
            )
        finally:
            audit_path.write_bytes(current_audit_bytes)
        passed("http_runtime_checkpoint_rejects_valid_old_db_even_for_matching_historical_cursor")
        checkpoint_bytes = checkpoint_path.read_bytes()
        try:
            checkpoint_path.write_bytes(checkpoint_bytes + b" ")
            changed = client.get("/results", headers=headers)
            changed_ready = client.get("/health/ready")
            require(
                changed.status_code == 503
                and changed_ready.status_code == 503
                and changed_ready.json()["audit"]["ok"] is False,
                "owned_runtime_checkpoint_pin_failure_blocks_reads",
            )
        finally:
            checkpoint_path.write_bytes(checkpoint_bytes)
        require(
            client.get("/results", headers=headers).status_code == 200,
            "owned_runtime_checkpoint_exact_state_recovery",
        )
        passed("http_runtime_checkpoint_pin_failure_has_no_fallback_and_exact_state_recovers")
        cursor_config[0].write_bytes(secrets.token_bytes(32))
        blocked = client.get(
            "/audit/results",
            headers=headers,
            params={"review_status": "PENDING", "cursor": page["next_cursor"]},
        )
        degraded = client.get("/health/ready")
        require(
            blocked.status_code == 503
            and degraded.status_code == 503
            and degraded.json()["audit_paging"]["ok"] is False
            and client.get("/health/live").status_code == 200,
            "owned_cursor_key_failure_has_no_fallback",
        )
        passed("http_cursor_key_failure_blocks_pages_and_readiness")
        require(
            json.loads(stats.read_text())["provider_stub_calls"] == 0,
            "owned_cursor_reader_never_calls_model",
        )
        third.kill()
        exit_code = third.wait(timeout=10)
    return {
        "cursor_resumed_over_tcp": True,
        "snapshot_pending_analyses": 2,
        "current_pending_analyses": 1,
        "current_audit_rows": 3,
        "third_exit_code": exit_code,
        "provider_stub_calls_third": 0,
        "original_scope_and_expiry_preserved": True,
        "key_failure_blocks_pages_and_readiness": True,
        "runtime_checkpoint_rejects_valid_database_rollback": True,
        "runtime_checkpoint_pin_failure_blocks_reads": True,
        "runtime_checkpoint_exact_state_recovery": True,
    }
