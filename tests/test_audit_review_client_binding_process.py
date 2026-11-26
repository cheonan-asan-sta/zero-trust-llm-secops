"""Actual CLI subprocess over TCP, with an identity change after its final read.

The HTTP bridge forwards to the real authenticated ASGI application and SQLite
store. Existing native worker tests cover the separate application process too.
"""

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from scripts.local_process_runtime import direct_python


@pytest.mark.parametrize("remap_after_who", [False, True])
@pytest.mark.parametrize("required_policy", [False, True])
def test_real_cli_sends_bound_intent_and_server_rejects_post_check_remap(
    api, tmp_path, remap_after_who, required_policy
):
    main.settings.audit_review_require_if_match = required_policy
    main.settings.audit_review_require_identity = required_policy
    control = {"remap": False, "patches": []}

    class Handler(BaseHTTPRequestHandler):
        def forward(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            headers = {
                key: self.headers[key]
                for key in (
                    "X-API-Key",
                    "Authorization",
                    "Content-Type",
                    "If-Match",
                    "X-Review-Identity",
                )
                if key in self.headers
            }
            response = api.client.request(
                self.command, self.path, headers=headers, content=body or None
            )
            if self.command == "PATCH":
                control["patches"].append(
                    (self.headers.get("If-Match"), self.headers.get("X-Review-Identity"))
                )
            if self.path == "/auth/me" and control["remap"]:
                main.settings.api_key_subject = "changed-after-real-cli-who"
                control["remap"] = False
            self.send_response(response.status_code)
            for key, value in response.headers.multi_items():
                if key.lower() not in {"content-length", "transfer-encoding", "connection"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)

        do_GET = forward
        do_PATCH = forward

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("OPENAI_", "AWS_", "API_KEY_", "OIDC_"))
        }
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        environment["ZT_CLI_FIXTURE_KEY"] = api.headers["X-API-Key"]
        executable, environment = direct_python(environment)
        command = [
            executable,
            *(["-S"] if os.name == "nt" else []),
            "-m",
            "scripts.audit_review_client",
            "--base-url",
            f"http://127.0.0.1:{server.server_port}",
            "--credential-env",
            "ZT_CLI_FIXTURE_KEY",
        ]

        def run(arguments):
            return subprocess.run(
                command + arguments,
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )

        path = tmp_path / "observed.json"
        prepared = run(["prepare", "--event-id", "audit-cancel-1", "--snapshot", str(path)])
        assert prepared.returncode == 0, prepared.stderr
        observed = json.loads(path.read_text(encoding="utf-8"))
        assert observed["schema"] == "operator-audit-review-snapshot-2"
        assert observed["review_mode"] == "conditional"
        assert api.headers["X-API-Key"] not in path.read_text(encoding="utf-8")
        control["remap"] = remap_after_who
        reviewed = run(
            [
                "review",
                "--snapshot",
                str(path),
                "--status",
                "IN_REVIEW",
                "--note",
                "Actual TCP CLI observed intent",
            ]
        )
        assert control["patches"] == [(observed["etag"], observed["review_identity"])]
        if remap_after_who:
            assert reviewed.returncode == 1 and "HTTP 403" in reviewed.stderr
            assert api.store.integrity()["verified_lines"] == 2
            assert api.store.get("audit-cancel-1", "local").reviewer is None
        else:
            assert reviewed.returncode == 0, reviewed.stderr
            assert json.loads(reviewed.stdout)["reviewer"] == "local-auditor"
            assert api.store.integrity()["verified_lines"] == 3
        assert (
            api.headers["X-API-Key"]
            not in prepared.stdout + prepared.stderr + reviewed.stdout + reviewed.stderr
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        assert not thread.is_alive()
