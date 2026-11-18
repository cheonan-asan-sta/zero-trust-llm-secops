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

from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.service_analysis_evidence import publish_service_analysis
from scripts.f1_lab.shared_service_analysis import open_shared_service_registry
from scripts.local_process_runtime import direct_python


@contextmanager
def owned_worker(lab, shared_config, audit_path, directory, api_key):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(16)
    control = directory / (token + ".control.json")
    ready, stats = directory / (token + ".ready.json"), directory / (token + ".stats.json")
    value = {
        "token": token,
        "ready": str(ready),
        "stats": str(stats),
        "operations_db": str(lab.operations.path),
        "signal_sources": str(lab.operations.signal_verifier.registry_path),
        "shared_config": str(shared_config[0]),
        "shared_pin": shared_config[1],
        "audit_db": str(audit_path),
        "api_key_sha256": hashlib.sha256(api_key.encode()).hexdigest(),
        "subject": lab.principal.subject,
        "tenant_id": lab.principal.tenant_id,
    }
    control.write_text(json.dumps(value), encoding="utf-8")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(
            ("OPENAI_", "AWS_", "OIDC_", "API_KEY_", "NATIVE_ANALYSIS_", "DASHBOARD_")
        )
    }
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    executable, env = direct_python(env)
    with (directory / (token + ".stderr.log")).open("wb") as log:
        process = subprocess.Popen(
            [executable, "-m", "scripts.native_http_worker", "--control", str(control)],
            stdout=subprocess.DEVNULL,
            stderr=log,
            env=env,
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


def run(lab, request, access, receipt, event, proofs, shared_config, directory, passed):
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
    with owned_worker(lab, shared_config, audit_path, directory / "worker-1", api_key) as (
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
    with owned_worker(lab, shared_config, audit_path, directory / "worker-2", api_key) as (
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
        second.kill()
        second_exit = second.wait(timeout=10)
    require(
        journal == lab.operations.journal_status()
        and evidence_hash == hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest(),
        "owned_worker_restart_source_history_unchanged",
    )
    require(persisted.integrity()["verified_lines"] == 2, "owned_worker_restart_two_analyses")
    passed("http_worker_kill_restart_does_not_reissue_grant_or_modify_execution_evidence")
    return {
        "independent_http_processes": 2,
        "first_exit_code": first_exit,
        "second_exit_code": second_exit,
        "verified_audit_rows": 2,
        "provider_stub_calls": 2,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "new_access_grants_issued": 0,
        "owned_processes_stopped": True,
        "withdrawal_checked_before_original_proof_expiry": True,
    }
