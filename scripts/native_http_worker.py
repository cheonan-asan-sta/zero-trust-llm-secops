"""Private loopback acceptance worker with an explicit no-paid-provider stub.

This entrypoint is for owned test processes only; never a production launch mode.
It loads the normal app/PDP/registry/audit factories from fixed test settings.
"""

import argparse
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", required=True)
    args = parser.parse_args()
    path = Path(args.control)
    if path.is_symlink() or path.stat().st_size > 16384:
        raise ValueError("worker control file rejected")
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != {
        "token",
        "ready",
        "stats",
        "operations_db",
        "signal_sources",
        "shared_config",
        "shared_pin",
        "audit_db",
        "api_key_sha256",
        "subject",
        "tenant_id",
        "cursor_key_path",
        "cursor_key_pin",
    }:
        raise ValueError("worker control fields rejected")
    if (data["cursor_key_path"] is None) != (data["cursor_key_pin"] is None):
        raise ValueError("worker cursor key configuration rejected")
    for name in ("AUDIT_CURSOR_KEY_PATH", "AUDIT_CURSOR_KEY_SHA256"):
        os.environ.pop(name, None)
    if data["cursor_key_path"] is not None:
        os.environ["AUDIT_CURSOR_KEY_PATH"] = data["cursor_key_path"]
        os.environ["AUDIT_CURSOR_KEY_SHA256"] = data["cursor_key_pin"]
    os.environ.update(
        {
            "APP_ENVIRONMENT": "test",
            "AUTH_MODE": "api_key",
            "ANALYZER_MODE": "openai",
            "OPENAI_PROMPT_MODE": "grounded",
            "OPENAI_API_KEY": "local-worker-stub-not-a-real-key",
            "API_KEY_SHA256": data["api_key_sha256"],
            "API_KEY_SUBJECT": data["subject"],
            "API_KEY_TENANT_ID": data["tenant_id"],
            "API_KEY_ROLES": "responder",
            "AUDIT_BACKEND": "sqlite",
            "AUDIT_DB_PATH": data["audit_db"],
            "AUDIT_LOG_PATH": str(path.parent / "unused-audit.jsonl"),
            "CASE_LOG_PATH": str(path.parent / "worker-cases.jsonl"),
            "OUTBOX_LOG_PATH": str(path.parent / "worker-outbox.jsonl"),
            "ZERO_TRUST_DB_PATH": data["operations_db"],
            "TRUSTED_SIGNAL_SOURCES_PATH": data["signal_sources"],
            "NATIVE_ANALYSIS_SHARED_CONFIG_PATH": data["shared_config"],
            "NATIVE_ANALYSIS_SHARED_CONFIG_SHA256": data["shared_pin"],
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    from app import main as application
    from app.analyzers import openai_analyzer
    from app.models import SecurityAssessment

    calls = 0
    atomic_json(data["stats"], {"provider_stub_calls": calls, "paid_api_calls": 0})

    async def parse(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        atomic_json(data["stats"], {"provider_stub_calls": calls, "paid_api_calls": 0})
        assessment = SecurityAssessment(
            risk_score=10,
            risk_level="LOW",
            violation_type="NORMAL",
            confidence=0.8,
            rationale="독립 테스트 worker가 현재 실행 근거를 읽은 모의 분석입니다.",
            evidence=["verified_session.native_execution.process.executable_sha256"],
            recommended_action="ALLOW",
            requires_human_review=False,
        )
        return SimpleNamespace(output_parsed=assessment), None

    openai_analyzer.parse_structured_response = AsyncMock(side_effect=parse)
    import uvicorn

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    atomic_json(
        data["ready"],
        {
            "token": data["token"],
            "pid": os.getpid(),
            "port": listener.getsockname()[1],
            "provider_stubbed": True,
        },
    )
    server = uvicorn.Server(
        uvicorn.Config(application.app, log_level="critical", access_log=False, lifespan="off")
    )
    server.run(sockets=[listener])


if __name__ == "__main__":
    main()
