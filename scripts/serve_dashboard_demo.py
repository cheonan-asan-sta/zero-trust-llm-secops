"""Serve an isolated, loopback-only dashboard with optional synthetic API records.

Run as a module. This process ignores dotenv and inherited application settings.
No cloud backend, API key, model call, trusted source or external response is used.
"""

import argparse
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

SCHEMA = "dashboard-demo-1"
DEMO_SCENARIOS = (
    "NORMAL-01", "NORMAL-02", "NORMAL-03", "ZT-S01", "ZT-S02", "ZT-S03", "ZT-S04", "ZT-S05",
)


def isolated_app(directory: Path):
    from app import config

    # This launcher owns its child process; do not mutate an already running app.
    for name in list(os.environ):
        if name.lower() in config.Settings.model_fields:
            os.environ.pop(name)
    config.Settings.model_config["env_file"] = None
    settings = config.Settings(
        _env_file=None,
        app_environment="local",
        analyzer_mode="rule",
        auth_mode="disabled",
        audit_backend="jsonl",
        audit_log_path=directory / "audit.jsonl",
        case_log_path=directory / "cases.jsonl",
        outbox_log_path=directory / "integration-outbox.jsonl",
        zero_trust_db_path=directory / "zero-trust.sqlite3",
        behavior_context_db_path=directory / "behavior-context.sqlite3",
        trusted_signal_sources_path=None,
        openai_api_key=None,
        openai_api_key_secret_arn=None,
        allowed_hosts="127.0.0.1,localhost,testserver",
    )
    config.get_settings = lambda: settings
    from app.main import app

    @app.middleware("http")
    async def synthetic_scope(request, call_next):
        response = await call_next(request)
        response.headers["X-Secops-Data-Scope"] = "synthetic-dashboard-demo"
        return response

    return app


def seed(app):
    from fastapi.testclient import TestClient

    def post(client, path, body, expected=200):
        response = client.post(path, json=body)
        if response.status_code != expected:
            raise RuntimeError(f"Synthetic seed failed: {path}, HTTP {response.status_code}")
        return response.json()

    with TestClient(app) as client:
        for scenario_id in DEMO_SCENARIOS:
            events = post(client, "/events/simulate", {"scenario_id": scenario_id, "count": 3})
            for event in events:
                event.pop("ground_truth", None)
                event["event_id"] = "demo-log-" + uuid4().hex
                post(client, "/analysis", event)
        for index, posture in enumerate(("healthy", "healthy", "healthy", "compromised")):
            event = post(client, "/events/simulate", {"scenario_id": "NORMAL-01", "count": 1})[0]
            event.pop("ground_truth", None)
            event["event_id"] = "demo-signal-" + uuid4().hex
            event["timestamp"] = datetime.now(UTC).isoformat()
            event["user"]["role"] = "employee"
            event["device"]["security_posture"] = posture
            event["resource"] = {
                "resource_id": "zt-demo-documents", "resource_type": "document",
                "sensitivity": "internal",
            }
            event["auth_context"].update(authentication_result="success", mfa="success")
            if index == 2:
                event["auth_context"]["mfa"] = "unknown"
            session_id = "demo-session-" + uuid4().hex
            decision = post(client, "/zero-trust/sessions/evaluate", {
                "session_id": session_id, "expected_version": 0, "event": event,
            })
            if index == 3:
                post(client, "/response/requests", {
                    "request_id": "demo-response-" + uuid4().hex,
                    "session_id": session_id,
                    "expected_session_version": decision["session"]["version"],
                    "action": "isolate_device",
                    "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                    "reason": "합성 시연: 침해 신호 이후 기기 격리 제안. 실제 승인과 외부 격리는 수행하지 않음.",
                }, expected=201)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("runtime/dashboard-demo"))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--seed", action="store_true", help="Seed synthetic records once via actual APIs")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    directory = args.data_dir.resolve()
    marker = directory / "dashboard-demo.json"
    if directory.exists() and any(directory.iterdir()) and not marker.is_file():
        parser.error("data directory is not owned by this demo; choose a new empty directory")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = json.loads(marker.read_text()) if marker.exists() else {
        "schema": SCHEMA, "synthetic": True, "seed_state": "empty",
    }
    if metadata.get("schema") != SCHEMA or metadata.get("synthetic") is not True:
        parser.error("unexpected demo marker; choose a new empty directory")
    if metadata["seed_state"] == "started":
        parser.error("previous seeding was interrupted; preserve it and choose a new data directory")
    marker.write_text(json.dumps(metadata, indent=2) + "\n")
    app = isolated_app(directory)
    if args.seed and metadata["seed_state"] != "complete":
        metadata["seed_state"] = "started"
        marker.write_text(json.dumps(metadata, indent=2) + "\n")
        seed(app)
        metadata["seed_state"] = "complete"
        marker.write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Synthetic local dashboard: http://127.0.0.1:{args.port}", flush=True)
    print(f"Isolated records: {directory}", flush=True)
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
