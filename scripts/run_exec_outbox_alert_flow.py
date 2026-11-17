"""Actual outbox reports through cached monitoring in one isolated namespace.

Input reports come from a real native managed-exec run; this is a local file
bridge, not a production multi-host mTLS or independent detection evaluation.
"""

import argparse
import json
import secrets
import socket
import subprocess
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

import yaml

from scripts.f1_lab import exec_outbox_status as status
from scripts.f1_lab.collector_status_bridge import read_public
from scripts.f1_lab.native_jsonl import require
from scripts.observability_lab import receiver
from scripts.run_collector_alert_flow import http, wait_for
from scripts.signal_metrics_exporter import handler


def run(directory, reports):
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    inputs = {
        name: read_public(Path(reports) / ("outbox-" + name + ".json"))
        for name in ("pending", "unavailable", "ready")
    }
    scope = inputs["pending"]["scope_sha256"]
    for name, value in inputs.items():
        status.validate(value, scope)
        require(value["state"] == name, "outbox_flow_input_state")
    require(
        inputs["pending"]["values"]["pending"] == 1 and inputs["ready"]["values"]["pending"] == 0,
        "outbox_flow_input_counts",
    )
    processes, streams, servers, threads, checks, versions = [], [], [], [], [], {}
    token, notify = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    def check(name, condition=True):
        require(condition, "outbox_flow_" + name)
        checks.append({"name": name, "passed": True})

    class Inbox(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            body = json.dumps(
                {
                    "pending": 0,
                    "processing": 0,
                    "completed": 0,
                    "failed": 0,
                    "total": 0,
                    "oldest_pending_age_seconds": None,
                    "oldest_processing_age_seconds": None,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def serve(cls):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cls)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        servers.append(server)
        threads.append(worker)
        return server.server_port

    def free_port():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def spawn(argv, name):
        stream = (output / name).open("wb")
        streams.append(stream)
        child = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT)
        processes.append(child)

    try:
        with tempfile.TemporaryDirectory(prefix="exec-outbox-alert-") as temporary:
            root = Path(temporary)
            profile = {
                "schema": "zt-exec-outbox-metrics-profile-1",
                "scope_sha256": scope,
                "status_file": str(root / "status.json"),
                "max_pending_age_seconds": 5,
                "max_records": 10000,
            }
            status.publish(profile["status_file"], inputs["pending"])
            inbox, sink = serve(Inbox), serve(receiver(notify))
            upstream = f"http://127.0.0.1:{inbox}/zero-trust/signals/inbox"
            primary = serve(handler(upstream, "local-fixture", token, outbox_profile=profile))
            legacy = serve(handler(upstream, "local-fixture", token))
            am_port, prom_port = free_port(), free_port()
            scrape, webhook = root / "scrape.secret", root / "webhook.secret"
            scrape.write_text(token)
            webhook.write_text(notify)
            scrape.chmod(0o600)
            webhook.chmod(0o600)
            am = {
                "route": {
                    "receiver": "local",
                    "group_by": ["alertname"],
                    "group_wait": "0s",
                    "group_interval": "1s",
                    "repeat_interval": "1h",
                },
                "receivers": [
                    {
                        "name": "local",
                        "webhook_configs": [
                            {
                                "url": f"http://127.0.0.1:{sink}/events",
                                "send_resolved": True,
                                "http_config": {
                                    "authorization": {
                                        "type": "Bearer",
                                        "credentials_file": str(webhook),
                                    }
                                },
                            }
                        ],
                    }
                ],
            }
            prom = {
                "global": {
                    "scrape_interval": "500ms",
                    "scrape_timeout": "400ms",
                    "evaluation_interval": "500ms",
                },
                "rule_files": [str(source / "infra/observability/alerts.yaml")],
                "alerting": {
                    "alertmanagers": [{"static_configs": [{"targets": [f"127.0.0.1:{am_port}"]}]}]
                },
                "scrape_configs": [
                    {
                        "job_name": job,
                        "authorization": {"type": "Bearer", "credentials_file": str(scrape)},
                        "static_configs": [{"targets": [f"127.0.0.1:{port}"]}],
                    }
                    for job, port in [("zt-signals", primary), ("zt-signals-legacy", legacy)]
                ],
            }
            for name, value in [("am", am), ("prom", prom)]:
                (root / (name + ".yml")).write_text(yaml.safe_dump(value))
            for name in ("prometheus", "alertmanager"):
                result = subprocess.run(
                    ["/tools/" + name, "--version"], capture_output=True, timeout=5, check=True
                )
                versions[name] = (result.stdout + result.stderr).decode().splitlines()[0]
            subprocess.run(
                [
                    "/tools/promtool",
                    "check",
                    "rules",
                    str(source / "infra/observability/alerts.yaml"),
                ],
                capture_output=True,
                timeout=10,
                check=True,
            )
            spawn(
                [
                    "/tools/alertmanager",
                    "--config.file=" + str(root / "am.yml"),
                    "--storage.path=" + str(root / "am-data"),
                    "--cluster.listen-address=",
                    f"--web.listen-address=127.0.0.1:{am_port}",
                ],
                "alertmanager.log",
            )
            spawn(
                [
                    "/tools/prometheus",
                    "--config.file=" + str(root / "prom.yml"),
                    "--storage.tsdb.path=" + str(root / "prom-data"),
                    "--storage.tsdb.retention.time=1h",
                    f"--web.listen-address=127.0.0.1:{prom_port}",
                ],
                "prometheus.log",
            )

            def query(expression):
                code, raw = http(
                    f"http://127.0.0.1:{prom_port}/api/v1/query?" + urlencode({"query": expression})
                )
                require(code == 200, "outbox_flow_query")
                return json.loads(raw)["data"]["result"]

            def events():
                return json.loads(http(f"http://127.0.0.1:{sink}/events", notify)[1])["events"]

            def notification(name, state, offset, episode=None):
                return next(
                    (
                        v
                        for v in events()[offset:]
                        if v["alertname"] == name
                        and v["status"] == state
                        and (
                            episode is None
                            or (v["fingerprint"], v["starts_at"])
                            == (episode["fingerprint"], episode["starts_at"])
                        )
                    ),
                    None,
                )

            wait_for(
                lambda: (
                    query('up{job="zt-signals"} == 1') and query('up{job="zt-signals-legacy"} == 1')
                )
            )
            check(
                "exporter_and_receiver_require_authentication",
                http(f"http://127.0.0.1:{primary}/metrics")[0] == 401
                and http(f"http://127.0.0.1:{sink}/events")[0] == 401,
            )
            check(
                "default_profile_has_no_outbox_metrics_or_alerts",
                not query('secops_exec_outbox_bridge_enabled{job="zt-signals-legacy"}')
                and not query('ALERTS{job="zt-signals-legacy",alertname=~"C01ExecOutbox.*"}'),
            )
            pending_episode = wait_for(
                lambda: notification("C01ExecOutboxPendingOverdue", "firing", 0)
            )
            check(
                "actual_unpublished_record_age_reaches_real_alertmanager_receiver",
                bool(query("secops_exec_outbox_pending == 1")),
            )
            check(
                "pending_report_preserves_original_observation_and_check_times",
                read_public(profile["status_file"]) == inputs["pending"],
            )
            offset = len(events())
            status.publish(profile["status_file"], inputs["unavailable"])
            failure = wait_for(lambda: notification("C01ExecOutboxUnavailable", "firing", offset))
            wait_for(
                lambda: notification(pending_episode["alertname"], "resolved", 0, pending_episode)
            )
            check("actual_seal_damage_reaches_unavailable_and_resolves_pending_episode")
            offset = len(events())
            profile["max_records"] = 1
            status.publish(profile["status_file"], inputs["ready"])
            wait_for(lambda: notification(failure["alertname"], "resolved", 0, failure))
            pressure = wait_for(
                lambda: notification("C01ExecOutboxCapacityPressure", "firing", offset)
            )
            check(
                "same_bytes_recovery_resolves_unavailable_and_exports_actual_queue_capacity",
                bool(query("secops_exec_outbox_published == 1"))
                and bool(query("secops_exec_outbox_pending == 0")),
            )
            profile["max_records"] = 10000
            wait_for(lambda: notification(pressure["alertname"], "resolved", offset, pressure))
            check("explicit_capacity_policy_change_resolves_same_pressure_episode")
            offset = len(events())
            wait_for(lambda: query("secops_exec_outbox_status_success == 0"), seconds=75)
            wait_for(lambda: notification("C01ExecOutboxUnavailable", "firing", offset))
            check(
                "original_report_expires_after_real_60_seconds_without_cached_queue_values",
                not query("secops_exec_outbox_records")
                and read_public(profile["status_file"]) == inputs["ready"],
            )
            require(all(p.poll() is None for p in processes), "outbox_flow_monitor_survived")
            result = {
                "completed": True,
                "cases": checks,
                "versions": versions,
                "notifications": events(),
                "actual_native_reports": True,
                "oldest_pending_at": inputs["pending"]["oldest_pending_at"],
                "original_ready_checked_at": inputs["ready"]["checked_at"],
                "source_expired_in_real_time": datetime.now(UTC)
                >= datetime.fromisoformat(inputs["ready"]["checked_at"]) + timedelta(seconds=60),
                "production_multi_host_mtls_tested": False,
                "independent_detection_evaluation": False,
                "aws_calls": 0,
                "paid_api_calls": 0,
            }
    finally:
        for child in reversed(processes):
            child.terminate()
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        for server in servers:
            server.shutdown()
            server.server_close()
        for worker in threads:
            worker.join(timeout=2)
        for stream in streams:
            stream.close()
    result["owned_processes_stopped"] = all(child.poll() is not None for child in processes)
    (output / "run.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"completed": True, "cases": len(checks)}))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--reports", required=True, type=Path)
    args = parser.parse_args()
    run(args.directory, args.reports)


if __name__ == "__main__":
    main()
