"""Free loopback TCP HTTP/audit acceptance for trusted native execution evidence.

The real OpenAI adapter is used with its structured provider boundary stubbed.
Only this test harness replaces server configuration; it is not an HTTP publisher.
"""

import asyncio
import hashlib
import json
import os
import secrets
import socket
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import uvicorn

from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.models import SecurityAssessment
from app.services.audit import AuditStore, create_audit_store
from app.services.native_analysis_registry import (
    NativeAnalysisRegistry,
    create_native_analysis_registry,
)
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.service_analysis_evidence import publish_service_analysis


def preload(directory):
    """Import the serving app before the native execution's short proof window starts."""
    directory = Path(directory)
    with patch.dict(
        os.environ,
        {
            "APP_ENVIRONMENT": "test",
            "AUTH_MODE": "disabled",
            "ANALYZER_MODE": "rule",
            "AUDIT_BACKEND": "jsonl",
            "AUDIT_LOG_PATH": str(directory / "bootstrap-audit.jsonl"),
            "ZERO_TRUST_DB_PATH": str(directory / "bootstrap-app.sqlite3"),
            "CASE_LOG_PATH": str(directory / "bootstrap-cases.jsonl"),
            "OUTBOX_LOG_PATH": str(directory / "bootstrap-outbox.jsonl"),
        },
    ):
        from app import main

    return main


def run(lab, request, access, receipt, event, proofs, directory, passed, *, shared_config=None):
    from app import main, security

    before = hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest()
    journal_before = lab.operations.journal_status()
    signal = lab.signals[access.session_id]
    served_operations = lab.operations
    registry = NativeAnalysisRegistry(lab.operations)
    if shared_config is not None:
        from scripts.f1_lab.shared_native_controls import new_operations
        from scripts.f1_lab.shared_service_analysis import open_shared_service_registry

        registry = open_shared_service_registry(lab.operations, *shared_config)
        served_operations = new_operations(lab)
    ref = publish_service_analysis(
        registry,
        lab.operations,
        signal,
        lab.principal,
        lab.broker.joiner,
        lab.broker.registry,
        request,
        event,
        proofs,
        receipt,
    )
    key = secrets.token_urlsafe(32)
    config = Settings(
        _env_file=None,
        app_environment="test",
        analyzer_mode="openai",
        auth_mode="api_key",
        api_key_sha256=hashlib.sha256(key.encode()).hexdigest(),
        api_key_subject=lab.principal.subject,
        api_key_tenant_id=lab.principal.tenant_id,
        api_key_roles="responder",
        openai_prompt_mode="grounded",
        openai_api_key="local-stub-not-a-real-api-key",
        audit_backend="jsonl",
        audit_log_path=Path(directory) / "native-http-audit.jsonl",
        native_analysis_shared_config_path=shared_config[0] if shared_config else None,
        native_analysis_shared_config_sha256=shared_config[1] if shared_config else None,
    )
    if shared_config is not None:
        registry = create_native_analysis_registry(served_operations, config)
    audit = create_audit_store(config)
    reply = SecurityAssessment(
        risk_score=10,
        risk_level="LOW",
        violation_type="NORMAL",
        confidence=0.8,
        rationale="실제 실행 관측과 사용된 권한 연결을 확인한 로컬 HTTP 시험입니다.",
        evidence=["verified_session.native_execution.process.executable_sha256"],
        recommended_action="ALLOW",
        requires_human_review=False,
    )
    adapter = OpenAIAnalyzer(config)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    server = uvicorn.Server(
        uvicorn.Config(
            main.app,
            host="127.0.0.1",
            log_level="critical",
            access_log=False,
            lifespan="off",
        )
    )
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    try:
        with ExitStack() as stack:
            for name, value in {
                "get_settings": lambda: config,
                "settings": config,
                "zero_trust_operations": served_operations,
                "native_analysis_registry": registry,
                "audit_store": audit,
                "get_analyzer": lambda: adapter,
                "analysis_capacity": asyncio.Semaphore(2),
            }.items():
                stack.enter_context(patch.object(main, name, value))
            stack.enter_context(patch.object(security, "get_settings", lambda: config))
            parse = stack.enter_context(
                patch(
                    "app.analyzers.openai_analyzer.parse_structured_response",
                    new_callable=AsyncMock,
                )
            )
            parse.return_value = (SimpleNamespace(output_parsed=reply), None)
            worker.start()
            deadline = time.monotonic() + 10
            while not server.started and worker.is_alive() and time.monotonic() < deadline:
                worker.join(0.02)
            require(server.started, "native_http_server_start")
            base = f"http://127.0.0.1:{listener.getsockname()[1]}"
            headers = {"X-API-Key": key, "X-Request-ID": "native-systemd-http-local-control"}
            with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
                require(
                    client.post("/analysis/native-service", json={"execution_ref": ref}).status_code
                    == 401,
                    "native_http_requires_authentication",
                )
                passed("native_http_loopback_requires_actual_api_key")
                require(
                    client.post(
                        "/analysis/native-service",
                        headers=headers,
                        json={"execution_ref": "e" * 64},
                    ).status_code
                    == 404,
                    "native_http_unknown_reference",
                )
                passed("native_http_unknown_reference_rejected_before_model")
                require(
                    client.post(
                        "/analysis/native-service",
                        headers=headers,
                        json={"execution_ref": ref, "verification_context": {}},
                    ).status_code
                    == 422,
                    "native_http_no_client_facts",
                )
                passed("native_http_client_trusted_facts_rejected")
                response = client.post(
                    "/analysis/native-service", headers=headers, json={"execution_ref": ref}
                )
                require(response.status_code == 200, "native_http_analysis_response")
                payload = response.json()
                native = payload["verification_context"]["native_execution"]
                require(
                    native["event_sha256"] == event.sha256
                    and native["invocation_id"] == event.invocation_id
                    and native["analysis_ref_sha256"] == hashlib.sha256(ref.encode()).hexdigest(),
                    "native_http_exact_execution",
                )
                passed("native_http_tcp_response_binds_actual_exec_and_reference_digest")
                require(
                    payload["assessment"]["recommended_action"] == "HOLD_FOR_REVIEW"
                    and payload["assessment"]["requires_human_review"] is True
                    and payload["assessment"]["violation_type"] == "NORMAL",
                    "native_http_advisory_only",
                )
                passed("native_http_consumed_grant_cannot_be_reissued_by_model")
                require(
                    client.get(f"/results/{payload['event_id']}", headers=headers).json()
                    == payload,
                    "native_http_audit_query",
                )
            reloaded = AuditStore(audit._path)
            require(
                reloaded.integrity()["ok"]
                and reloaded.integrity()["verified_lines"] == 1
                and reloaded.get(payload["event_id"], lab.principal.tenant_id).model_dump(
                    mode="json"
                )
                == payload,
                "native_http_persisted_audit",
            )
            passed("native_http_hash_chain_audit_reload_equals_response")
            raw = json.dumps(payload) + audit._path.read_text(encoding="utf-8")
            require(
                all(
                    secret not in raw
                    for secret in (key, ref, request.nonce, receipt.signature, signal.signature)
                )
                and parse.await_count == 1,
                "native_http_private_values",
            )
            passed("native_http_audit_and_response_exclude_raw_credentials_and_reference")
            require(
                before == hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest()
                and journal_before == lab.operations.journal_status(),
                "native_http_read_only",
            )
            passed("native_http_analysis_preserves_execution_ledger_and_app_grant_history")
            return {
                "transport": "tcp_loopback",
                "reference_backend": "encrypted_sqlite" if shared_config else "process_memory",
                "audit_writer_scope": "per_process_file" if shared_config else "single_process",
                "http_status": response.status_code,
                "model_provider_stubbed": True,
                "paid_api_calls": 0,
                "aws_calls": 0,
                "provider_stub_invocations": parse.await_count,
                "analysis_id": payload["analysis_id"],
                "request_id": payload["request_id"],
                "event_sha256": event.sha256,
                "analysis_ref_sha256": native["analysis_ref_sha256"],
                "audit_verified_lines": reloaded.integrity()["verified_lines"],
                "persisted_audit_equals_response": True,
                "historical_audit_is_not_delivery_or_access_receipt": True,
            }
    finally:
        server.should_exit = True
        if worker.ident is not None:
            worker.join(10)
        listener.close()
        asyncio.run(adapter._client.close())
        require(not worker.is_alive(), "native_http_server_cleanup")
        passed("native_http_loopback_server_stopped")
