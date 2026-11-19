"""Private loopback acceptance worker with an explicit no-paid-provider stub.

This entrypoint is for owned test processes only; never a production launch mode.
It loads the normal app/PDP/registry/audit factories from fixed test settings.
"""

import argparse
import asyncio
import json
import os
import socket
import traceback
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
    if set(data) - {"review_policy"} != {
        "token",
        "ready",
        "stats",
        "operations_db",
        "signal_sources",
        "shared_config",
        "shared_pin",
        "audit_db",
        "audit_mode",
        "accounts_path",
        "provider_gate",
        "api_key_sha256",
        "subject",
        "tenant_id",
        "cursor_key_path",
        "cursor_key_pin",
        "checkpoint_path",
        "checkpoint_pin",
    }:
        raise ValueError("worker control fields rejected")
    if data["audit_mode"] not in {"sqlite", "jsonl", "federated_jsonl"}:
        raise ValueError("worker audit mode rejected")
    review_policy = data.get("review_policy", "optional")
    if review_policy not in {"optional", "caller_bound"} or (
        review_policy == "caller_bound" and data["audit_mode"] != "sqlite"
    ):
        raise ValueError("worker review policy rejected")
    os.environ.pop("API_KEY_ACCOUNTS_PATH", None)
    if data["accounts_path"] is not None:
        os.environ["API_KEY_ACCOUNTS_PATH"] = data["accounts_path"]
    gate = Path(data["provider_gate"]).absolute() if data["provider_gate"] is not None else None
    if gate is not None:
        if not gate.is_relative_to(path.parent.absolute()) or gate.is_symlink():
            raise ValueError("worker provider gate must be inside its owned directory")
        gate.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (data["cursor_key_path"] is None) != (data["cursor_key_pin"] is None):
        raise ValueError("worker cursor key configuration rejected")
    if (data["checkpoint_path"] is None) != (data["checkpoint_pin"] is None):
        raise ValueError("worker checkpoint configuration rejected")
    for name in ("AUDIT_CHECKPOINT_PATH", "AUDIT_CHECKPOINT_SHA256"):
        os.environ.pop(name, None)
    if data["checkpoint_path"] is not None:
        os.environ["AUDIT_CHECKPOINT_PATH"] = data["checkpoint_path"]
        os.environ["AUDIT_CHECKPOINT_SHA256"] = data["checkpoint_pin"]
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
            "AUDIT_BACKEND": "sqlite" if data["audit_mode"] == "sqlite" else "jsonl",
            "AUDIT_REVIEW_REQUIRE_IF_MATCH": str(review_policy == "caller_bound").lower(),
            "AUDIT_REVIEW_REQUIRE_IDENTITY": str(review_policy == "caller_bound").lower(),
            "AUDIT_DB_PATH": data["audit_db"],
            "AUDIT_LOG_PATH": str(path.parent / "unused-audit.jsonl")
            if data["audit_mode"] == "sqlite"
            else data["audit_db"],
            "CASE_LOG_PATH": str(path.parent / "worker-cases.jsonl"),
            "OUTBOX_LOG_PATH": str(path.parent / "worker-outbox.jsonl"),
            "ZERO_TRUST_DB_PATH": data["operations_db"],
            "TRUSTED_SIGNAL_SOURCES_PATH": data["signal_sources"],
            "NATIVE_ANALYSIS_SHARED_CONFIG_PATH": data["shared_config"],
            "NATIVE_ANALYSIS_SHARED_CONFIG_SHA256": data["shared_pin"],
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    if data["audit_mode"] == "jsonl":
        # Explicit ordinary-analysis-only fixture. Shared native bootstrap would
        # select federation in the normal factory, so disable it for plain JSONL.
        os.environ.pop("NATIVE_ANALYSIS_SHARED_CONFIG_PATH", None)
        os.environ.pop("NATIVE_ANALYSIS_SHARED_CONFIG_SHA256", None)
    from app import main as application
    from app.analyzers import openai_analyzer
    from app.models import SecurityAssessment

    calls = 0
    atomic_json(data["stats"], {"provider_stub_calls": calls, "paid_api_calls": 0})

    async def parse(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        atomic_json(data["stats"], {"provider_stub_calls": calls, "paid_api_calls": 0})
        if gate is not None:
            atomic_json(gate / "entered.json", {"pid": os.getpid(), "calls": calls})
            deadline = asyncio.get_running_loop().time() + 8
            while not (gate / "release").is_file():
                if asyncio.get_running_loop().time() >= deadline:
                    raise TimeoutError("owned provider gate was not released")
                await asyncio.sleep(0.02)
        prompt = next(item for item in reversed(_kwargs["input"]) if item["role"] == "user")
        catalog = json.loads(prompt["content"])["evidence_catalog"]
        native_path = "verified_session.native_execution.process.executable_sha256"
        citation = native_path if catalog.get(native_path) is not None else "device.managed"
        if catalog.get(citation) is None:
            raise ValueError("owned provider stub has no supported citation")
        assessment = SecurityAssessment(
            risk_score=10,
            risk_level="LOW",
            violation_type="NORMAL",
            confidence=0.8,
            rationale="독립 테스트 worker가 현재 실행 근거를 읽은 모의 분석입니다.",
            evidence=[citation],
            recommended_action="ALLOW",
            requires_human_review=False,
        )
        return SimpleNamespace(output_parsed=assessment), None

    openai_analyzer.parse_structured_response = AsyncMock(side_effect=parse)
    original_pipeline = application._analyze_event

    async def diagnosed_pipeline(*args, **kwargs):
        try:
            return await original_pipeline(*args, **kwargs)
        except Exception as error:
            # Test-owned failure evidence, never raw exception/request values.
            atomic_json(
                data["stats"],
                {
                    "provider_stub_calls": calls,
                    "paid_api_calls": 0,
                    "failure": {
                        "type": type(error).__name__,
                        "frames": [
                            {
                                "name": frame.name,
                                "file": Path(frame.filename).name,
                                "line": frame.lineno,
                            }
                            for frame in traceback.extract_tb(error.__traceback__)[-5:]
                        ],
                    },
                },
            )
            raise

    application._analyze_event = diagnosed_pipeline
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
