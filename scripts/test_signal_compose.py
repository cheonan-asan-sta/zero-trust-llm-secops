"""Exercise the real local app/worker stack with isolated data and in-memory private keys.

Run: python -m scripts.test_signal_compose --report runtime/m3-validation/compose-report.json
Docker context/host environment is inherited. No AWS, paid model, or external log input is used.
"""

import argparse
import base64
import json
import os
import socket
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.continuous_signal_models import SignedContinuousSignal
from app.scenarios import synthetic_events
from app.services.trusted_signals import canonical_observation, canonical_signal
from app.zero_trust_models import SignedSessionSignal

ROOT = Path(__file__).resolve().parents[1]
TENANT = "local"
RESOURCE = "zt-demo-documents"
USERS = ["m3-related-first", "m3-related-second", "m3-unrelated", "m3-probe"]
DEVICES = ["m3-device-first-a", "m3-device-first-b", "m3-device-second-a",
           "m3-device-second-b", "m3-device-unrelated", "m3-device-probe"]


class CheckFailed(RuntimeError):
    """Messages contain fixed check labels only, never server payloads or credentials."""


def timestamp():
    return datetime.now(UTC).isoformat()


def require(condition, label):
    if not condition:
        raise CheckFailed(label)


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def initialize_assets(directory: Path, registry_directory: Path | None = None, project: str | None = None):
    """Keep signing keys in memory; mount only the public registry into containers.

    POSIX chmod bits do not provide private-file protection on Windows. This
    short-lived driver does not need to persist private keys on either platform.
    """
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(directory, 0o700)
    now = datetime.now(UTC)
    keys = {kind: Ed25519PrivateKey.generate() for kind in ("session", "identity")}
    sources = []
    for kind, key in keys.items():
        sources.append({
            "source_id": f"m3check-{kind}", "tenant_id": TENANT,
            "user_ids": USERS, "device_ids": DEVICES, "roles": ["employee"],
            "observation_kinds": ["identity"] if kind == "identity" else [],
            "keys": [{"key_id": f"{kind}-key", "public_key_pem": key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(), "not_before": (now - timedelta(seconds=30)).isoformat(),
                "not_after": (now + timedelta(days=1)).isoformat()}],
        })
    registry = directory / "public-sources.json"
    registry.write_text(json.dumps({"sources": sources}, indent=2), encoding="utf-8")
    os.chmod(registry, 0o644)
    if registry_directory is not None:
        # Colima may need a short ASCII host share. Copy this one public file,
        # never the host-only directory containing the two private keys.
        public_directory = registry_directory / (project or directory.name)
        public_directory.mkdir(parents=True, exist_ok=False, mode=0o755)
        os.chmod(public_directory, 0o755)
        shared_registry = public_directory / "public-sources.json"
        shared_registry.write_bytes(registry.read_bytes())
        os.chmod(shared_registry, 0o644)
        registry = shared_registry
    override = directory / "override.yaml"
    override.write_text(
        "services:\n"
        "  app:\n"
        "    environment:\n"
        "      SIGNAL_INBOX_LEASE_SECONDS: '2'\n"
        "      SIGNAL_INBOX_RETRY_SECONDS: '0.2'\n"
        "  signal-worker:\n"
        "    restart: 'no'\n"
        "    command: ['python', '-m', 'scripts.signal_worker', '--poll-seconds', '0.05']\n"
        "    environment:\n"
        "      SIGNAL_INBOX_LEASE_SECONDS: '2'\n"
        "      SIGNAL_INBOX_RETRY_SECONDS: '0.2'\n",
        encoding="utf-8",
    )
    return {"directory": directory, "registry": registry, "override": override, "keys": keys}


def sign(model, key):
    canonical = canonical_observation if isinstance(model, SignedContinuousSignal) else canonical_signal
    signature = base64.urlsafe_b64encode(key.sign(canonical(model))).decode().rstrip("=")
    return model.model_copy(update={"signature": signature})


def signed_session(label, user, device, key):
    # Small host/VM clock skew must not turn a valid proof into a future signal.
    now = datetime.now(UTC) - timedelta(seconds=5)
    event = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    event.update(event_id=f"{label}-event", timestamp=now.isoformat())
    event["user"].update(user_id=user, role="employee", active=True)
    event["device"].update(device_id=device, managed=True, security_posture="healthy")
    event["resource"].update(resource_id=RESOURCE, required_role=None)
    event["auth_context"].update(authentication_result="success", mfa="success")
    return sign(SignedSessionSignal(
        session_id=label, expected_version=0, event=event, tenant_id=TENANT,
        source_id="m3check-session", key_id="session-key", issued_at=now,
        expires_at=now + timedelta(seconds=120), signature="A" * 86,
    ), key).model_dump(mode="json")


def signed_observation(event_id, user, key):
    now = datetime.now(UTC) - timedelta(seconds=1)
    return sign(SignedContinuousSignal(
        tenant_id=TENANT, event_id=event_id, source_id="m3check-identity", key_id="identity-key",
        issued_at=now, observed_at=now, expires_at=now + timedelta(seconds=120),
        observation={"kind": "identity", "subject_id": user, "active": False,
                     "authentication_result": "failure"}, signature="A" * 86,
    ), key)


def detect_compose():
    for command in (["docker", "compose"], ["docker-compose"]):
        try:
            result = subprocess.run([*command, "version"], capture_output=True, timeout=15, check=False)
            if result.returncode == 0:
                return command
        except (OSError, subprocess.TimeoutExpired):
            continue
    raise CheckFailed("compose_cli_unavailable")


class Compose:
    def __init__(self, command, project, port, assets):
        require(project.startswith("secops-m3check-"), "isolated_project_required")
        self.command = [*command, "--project-name", project,
                        "--file", str(ROOT / "compose.yaml"),
                        "--file", str(ROOT / "compose.signals.yaml"),
                        "--file", str(assets["override"])]
        self.env = {**os.environ, "SECOPS_PORT": str(port),
                    "SIGNAL_REGISTRY_PATH": str(assets["registry"])}
        self.log_directory = assets["directory"] / "compose-logs"
        self.log_directory.mkdir()
        self.log_paths = []

    def save_log(self, args, stdout, stderr, returncode):
        path = self.log_directory / f"{len(self.log_paths) + 1:03d}-{args[0]}.log"
        # These are Docker build/lifecycle/probe commands only. Signed HTTP
        # payloads, private keys and grant tokens never enter their arguments.
        record = {"command": [*self.command, *args], "returncode": returncode,
                  "stdout": stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout,
                  "stderr": stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr}
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.log_paths.append(path)

    def run(self, *args, timeout=120):
        try:
            result = subprocess.run([*self.command, *args], cwd=ROOT, env=self.env,
                                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            self.save_log(args, exc.stdout, exc.stderr, None)
            raise CheckFailed("compose_" + args[0] + "_timeout") from exc
        except OSError as exc:
            self.save_log(args, None, type(exc).__name__, None)
            raise CheckFailed("compose_" + args[0] + "_unavailable") from exc
        self.save_log(args, result.stdout, result.stderr, result.returncode)
        if result.returncode:
            # Preserve CLI details in task-local log files, not report/stdout.
            raise CheckFailed("compose_" + args[0] + "_exit_" + str(result.returncode))
        return result.stdout

    def cleanup(self, preserve_data=False):
        args = ["down", "--remove-orphans"]
        if not preserve_data:
            args.append("--volumes")
        self.run(*args)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CheckFailed("loopback_api_redirect_rejected")


class Api:
    def __init__(self, port, report):
        self.base_url = f"http://127.0.0.1:{port}"
        self.report = report
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method, path, payload=None, *, label="request", expected=None, record=True):
        request = Request(self.base_url + path, method=method,
                          data=json.dumps(payload).encode() if payload is not None else None,
                          headers={"Content-Type": "application/json"})
        started = time.monotonic()
        try:
            response = self.opener.open(request, timeout=5)
        except HTTPError as exc:
            response = exc
        with response:
            status = response.code
            raw = response.read(1_000_001)
        require(len(raw) <= 1_000_000, "loopback_response_too_large")
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CheckFailed("loopback_response_not_json") from exc
        if record:
            self.report["http"].append({"label": label, "method": method, "path": path,
                "status": status, "at": timestamp(),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2)})
        if expected is not None:
            require(status == expected, label + "_http_" + str(status))
        return status, body

    def wait_ready(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                status, _ = self.request("GET", "/health/live", record=False)
                if status == 200:
                    return
            except (OSError, URLError, CheckFailed):
                pass
            time.sleep(0.2)
        raise CheckFailed("app_startup_timeout")

    def receipt(self, event_id, *, expected=None):
        _, result = self.request("GET", f"/zero-trust/signals/inbox/{event_id}",
                                 label="receipt", expected=200)
        if expected is not None:
            require(result["state"] == expected, "receipt_expected_" + expected)
        return result

    def wait_completed(self, event_id, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.receipt(event_id)
            if result["state"] == "completed":
                return result
            require(result["state"] != "failed", "worker_delivery_failed")
            time.sleep(0.1)
        raise CheckFailed("worker_completion_timeout")


def safe_receipt(receipt):
    result = {field: receipt.get(field) for field in (
        "event_id", "state", "received_at", "completed_at", "attempts", "last_error",
    )}
    result["result"] = None if receipt.get("result") is None else {
        field: receipt["result"].get(field) for field in (
            "matched_sessions", "changed_sessions", "stale", "duplicate",
        )
    }
    return result


def session_snapshot(api, session_id):
    _, history = api.request("GET", f"/zero-trust/sessions/{session_id}",
                             label="session_history", expected=200)
    current = history[-1]
    return {**{field: current[field] for field in (
        "session_id", "version", "decision", "status", "signal_trust", "signal_source_id",
    )}, "history_count": len(history)}


def run_checks(api, compose, assets, report, timeout):
    def passed(label):
        report["checks"].append({"label": label, "status": "passed", "at": timestamp()})

    def create(label, user, device):
        _, result = api.request("POST", "/zero-trust/signals/evaluate",
            signed_session(label, user, device, assets["keys"]["session"]),
            label="create_" + label, expected=200)
        require(result["session"]["decision"] == "ALLOW" and result.get("grant_token"),
                "normal_session_not_allowed")
        report["sessions"][label] = session_snapshot(api, label)
        return result["grant_token"]

    def access(label, token, expected):
        _, result = api.request("POST", "/zero-trust/protected-access", {
            "session_id": label, "resource_id": RESOURCE, "action": "READ", "grant_token": token,
        }, label="access_" + label, expected=expected)
        if expected == 403:
            # A denied expired or previously consumed grant is not evidence of revocation.
            require(result["reason_code"] == "SESSION_NOT_AUTHORIZED", "wrong_denial_reason")

    probe = create("m3-normal-probe", USERS[3], DEVICES[5])
    access("m3-normal-probe", probe, 200)
    passed("normal_probe")
    first = create("m3-first-a", USERS[0], DEVICES[0])
    second = create("m3-first-b", USERS[0], DEVICES[1])
    unrelated = create("m3-unrelated", USERS[2], DEVICES[4])
    observation = signed_observation("m3-risk-first", USERS[0], assets["keys"]["identity"])
    payload = observation.model_dump(mode="json")
    api.request("POST", "/zero-trust/signals/inbox", payload, label="risk_intake", expected=202)
    completed = api.wait_completed(observation.event_id, timeout)
    require(completed["result"]["matched_sessions"] == 2
            and completed["result"]["changed_sessions"] == 2, "fanout_count")
    report["receipts"]["first_completed"] = safe_receipt(completed)
    access("m3-first-a", first, 403)
    access("m3-first-b", second, 403)
    passed("related_revoked")
    access("m3-unrelated", unrelated, 200)
    passed("unrelated_preserved")
    versions = {label: session_snapshot(api, label) for label in ("m3-first-a", "m3-first-b")}
    require(all(state["status"] == "REVOKED" and state["version"] == 2
                for state in versions.values()), "first_revocation_state")
    _, duplicate = api.request("POST", "/zero-trust/signals/inbox", payload,
                               label="exact_duplicate", expected=202)
    require(duplicate["duplicate"], "duplicate_not_recognized")
    require(all(session_snapshot(api, label) == state for label, state in versions.items()),
            "duplicate_changed_version")
    passed("duplicate_idempotent")
    changed = sign(observation.model_copy(update={"observation": observation.observation.model_copy(
        update={"active": True, "authentication_result": "unknown"},
    )}), assets["keys"]["identity"])
    api.request("POST", "/zero-trust/signals/inbox", changed.model_dump(mode="json"),
                label="changed_payload", expected=409)
    passed("conflicting_payload_rejected")

    compose.run("stop", "signal-worker")
    late_a = create("m3-second-a", USERS[1], DEVICES[2])
    late_unused = create("m3-second-b", USERS[1], DEVICES[3])
    reserved_unrelated = create("m3-unrelated-reserved", USERS[2], DEVICES[4])
    pending_signal = signed_observation("m3-risk-second", USERS[1], assets["keys"]["identity"])
    api.request("POST", "/zero-trust/signals/inbox", pending_signal.model_dump(mode="json"),
                label="risk_while_worker_stopped", expected=202)
    pending = api.receipt(pending_signal.event_id, expected="pending")
    report["receipts"]["before_app_restart"] = safe_receipt(pending)
    compose.run("restart", "app")
    api.wait_ready(timeout)
    restored = api.receipt(pending_signal.event_id, expected="pending")
    require(safe_receipt(restored) == safe_receipt(pending), "pending_receipt_changed_on_restart")
    require(session_snapshot(api, "m3-second-a")["version"] == 1, "stopped_worker_applied_effects")
    passed("pending_survives_app_restart")
    compose.run("start", "signal-worker")
    resumed = api.wait_completed(pending_signal.event_id, timeout)
    require(resumed["result"]["changed_sessions"] == 2, "resumed_fanout_count")
    report["receipts"]["resumed_completed"] = safe_receipt(resumed)
    access("m3-second-a", late_a, 403)
    passed("worker_resumes_pending")
    all_versions = {label: session_snapshot(api, label) for label in (
        "m3-first-a", "m3-first-b", "m3-second-a", "m3-second-b", "m3-unrelated-reserved",
    )}
    require(all(state["status"] == "REVOKED" and state["version"] == 2
                for label, state in all_versions.items() if label != "m3-unrelated-reserved"),
            "second_revocation_state")
    compose.run("restart", "app", "signal-worker")
    api.wait_ready(timeout)
    require(safe_receipt(api.receipt(pending_signal.event_id)) == safe_receipt(resumed),
            "completed_receipt_changed_on_restart")
    require(all(session_snapshot(api, label) == state for label, state in all_versions.items()),
            "session_version_changed_on_restart")
    report["sessions"].update(all_versions)
    report["receipts"]["after_both_restart"] = safe_receipt(api.receipt(pending_signal.event_id))
    passed("restarts_preserve_receipt_and_versions")
    access("m3-second-b", late_unused, 403)
    passed("unused_grant_remains_revoked")
    access("m3-unrelated-reserved", reserved_unrelated, 200)
    passed("unrelated_survives_restarts")


def check_container_boundaries(compose, report):
    app_probe = (
        "import json,os,pathlib; p=pathlib.Path('/data/.m3check-volume'); "
        "p.write_text('app-write'); r=pathlib.Path('/signals/sources.json'); "
        "print(json.dumps({'uid':os.getuid(),'registry_readable':r.is_file(),"
        "'registry_mode':oct(r.stat().st_mode & 511),'shared_write':p.read_text()=='app-write',"
        "'private_keys_absent':not any(pathlib.Path('/signals').glob('private*'))}))"
    )
    worker_probe = (
        "import json,os,pathlib; p=pathlib.Path('/data/.m3check-volume'); "
        "seen=p.read_text()=='app-write'; p.write_text('worker-write'); "
        "print(json.dumps({'uid':os.getuid(),'shared_app_write_seen':seen,"
        "'worker_write':p.read_text()=='worker-write',"
        "'private_keys_absent':not any(pathlib.Path('/signals').glob('private*'))}))"
    )
    app = json.loads(compose.run("exec", "-T", "app", "python", "-c", app_probe))
    worker = json.loads(compose.run("exec", "-T", "signal-worker", "python", "-c", worker_probe))
    require(app["uid"] == worker["uid"] == 10001 and app["registry_readable"]
            and app["shared_write"] and worker["shared_app_write_seen"] and worker["worker_write"]
            and app["private_keys_absent"] and worker["private_keys_absent"], "container_boundaries")
    report["container_probes"] = {"app": app, "signal-worker": worker}
    report["checks"].append({"label": "container_boundaries", "status": "passed", "at": timestamp()})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--registry-directory", type=Path,
                        help="Optional shared host directory for public registry copies only")
    parser.add_argument("--no-build", action="store_true", help="Use an already built local app image")
    parser.add_argument("--keep-running", action="store_true", help="Keep this isolated stack and volume")
    parser.add_argument("--keep-data-on-failure", action="store_true", help="Retain this project's failed volume")
    parser.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args(argv)
    if not 5 <= args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be between 5 and 600")
    suffix = uuid.uuid4().hex[:12]
    project = "secops-m3check-" + suffix
    directory = ROOT / "runtime" / "m3-validation" / ("compose-" + suffix)
    report_path = args.report.resolve() if args.report else directory / "report.json"
    report = {"status": "failed", "started_at": timestamp(), "project": project,
              "checks": [], "http": [], "sessions": {}, "receipts": {},
              "artifacts": str(directory), "no_build": args.no_build}
    compose = None
    try:
        assets = initialize_assets(
            directory, args.registry_directory.resolve() if args.registry_directory else None, project,
        )
        report["public_registry"] = str(assets["registry"])
        port = available_port()
        report.update(port=port, base_url=f"http://127.0.0.1:{port}")
        command = detect_compose()
        report["compose_command"] = command
        compose = Compose(command, project, port, assets)
        compose.run("up", "-d", "--no-build" if args.no_build else "--build",
                    "app", "signal-worker", timeout=1200)
        api = Api(port, report)
        api.wait_ready(args.timeout_seconds)
        check_container_boundaries(compose, report)
        run_checks(api, compose, assets, report, args.timeout_seconds)
        report["status"] = "passed"
    except CheckFailed as exc:
        report["error_code"] = str(exc)
    except Exception as exc:  # noqa: BLE001 -- redact unexpected exception payloads and credentials
        report["error_code"] = "unexpected_" + type(exc).__name__
    finally:
        if compose is not None and not args.keep_running:
            try:
                preserve_data = args.keep_data_on_failure and report["status"] != "passed"
                compose.cleanup(preserve_data=preserve_data)
                report["cleanup"] = {"containers_removed": True, "data_retained": preserve_data}
            except CheckFailed as exc:
                report["cleanup"] = {"containers_removed": False, "error_code": str(exc)}
                report["status"] = "failed"
        else:
            report["cleanup"] = {"resources_preserved": compose is not None,
                                  "keep_running_requested": args.keep_running}
        report["compose_logs"] = [str(path.relative_to(directory))
                                  for path in getattr(compose, "log_paths", [])]
        report["finished_at"] = timestamp()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "project": project, "report": str(report_path),
                      "base_url": report.get("base_url"), "checks_passed": len(report["checks"]),
                      "error_code": report.get("error_code")}, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
