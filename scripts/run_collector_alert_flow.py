"""Real cached Prometheus/Alertmanager and authenticated loopback receiver.

This functional flow uses controlled aggregate reports, not labeled attacks or
the production mTLS deployment. All peers are in one isolated network namespace.
"""

import argparse
import json
import secrets
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

import yaml

from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.collector_status_bridge import COUNTERS, metrics, publish, report, scope_hash
from scripts.f1_lab.native_jsonl import require
from scripts.observability_lab import receiver
from scripts.signal_metrics_exporter import handler


def http(url, token=None):
    request = Request(url, headers={"Authorization": "Bearer " + token} if token else {})
    try:
        response = build_opener(ProxyHandler({})).open(request, timeout=3)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(1048577)
        require(len(raw) <= 1048576, "alert_flow_http_bound")
        return response.status, raw


def wait_for(fn, seconds=30):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            value = fn()
            if value:
                return value
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.2)
    raise ValueError("collector_alert_flow_timeout")


def run(directory):
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    checks = []
    processes = []
    threads = []
    servers = []
    logs = []
    stopped = threading.Event()
    lock = threading.Lock()
    modes = {"health": "fresh", "archive": "ready"}
    token = secrets.token_urlsafe(32)
    notify = secrets.token_urlsafe(32)
    versions = {}
    source = Path(__file__).resolve().parents[1]

    def check(name, condition=True):
        require(condition, "collector_alert_flow_" + name)
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
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        servers.append(server)
        threads.append(thread)
        thread.start()
        return server.server_port

    def spawn(argv, log):
        stream = (output / log).open("wb")
        logs.append(stream)
        process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    try:
        with (
            tempfile.TemporaryDirectory(prefix="collector-alert-") as temporary,
            ExitStack() as stack,
        ):
            root = Path(temporary)
            scope = ArchiveScope(
                tenant_id="private-tenant",
                server_id="private-host",
                unit="private.service",
                source_id="private-source",
            )
            profile = {
                "schema": "zt-collector-metrics-profile-1",
                "scope_sha256": scope_hash(scope),
                "health_file": str(root / "health.json"),
                "archive_file": str(root / "archive.json"),
            }

            def update():
                now = datetime.now(UTC)
                with lock:
                    if modes["health"] != "stopped":
                        observed = now - timedelta(seconds=31 if modes["health"] == "stale" else 1)
                        value = report(
                            "health",
                            scope,
                            modes["health"],
                            checked_at=now,
                            observed_at=observed,
                            expires_at=observed + timedelta(seconds=11),
                        )
                        publish(profile["health_file"], value)
                    if modes["archive"] != "missing":
                        value = report(
                            "archive",
                            scope,
                            modes["archive"],
                            checked_at=now,
                            values=dict.fromkeys(COUNTERS, 1)
                            if modes["archive"] == "ready"
                            else {},
                        )
                        publish(profile["archive_file"], value)

            update()

            def heartbeat():
                while not stopped.wait(0.3):
                    update()

            heart = threading.Thread(target=heartbeat, daemon=True)
            heart.start()
            stack.callback(heart.join, 3)
            stack.callback(stopped.set)
            inbox = serve(Inbox)
            sink = serve(receiver(notify))
            url = f"http://127.0.0.1:{inbox}/zero-trust/signals/inbox"
            exporter = serve(handler(url, "local-fixture", token, collector_profile=profile))
            legacy = serve(handler(url, "local-fixture", token))
            am_port, prom_port = 19093, 19090
            scrape = root / "scrape.token"
            scrape.write_text(token)
            secret = root / "notify.token"
            secret.write_text(notify)
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
                                        "credentials_file": str(secret),
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
                    for job, port in [("zt-signals", exporter), ("zt-signals-legacy", legacy)]
                ],
            }
            for name, value in [("am", am), ("prom", prom)]:
                (root / (name + ".yml")).write_text(yaml.safe_dump(value))
            for name in ("prometheus", "alertmanager"):
                value = subprocess.run(
                    ["/tools/" + name, "--version"], capture_output=True, timeout=5, check=True
                )
                versions[name] = (value.stdout + value.stderr).decode().splitlines()[0]
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
                    "--web.listen-address=127.0.0.1:" + str(am_port),
                ],
                "alertmanager.log",
            )
            spawn(
                [
                    "/tools/prometheus",
                    "--config.file=" + str(root / "prom.yml"),
                    "--storage.tsdb.path=" + str(root / "prom-data"),
                    "--storage.tsdb.retention.time=1h",
                    "--web.listen-address=127.0.0.1:" + str(prom_port),
                ],
                "prometheus.log",
            )

            def query(expression):
                status, raw = http(
                    f"http://127.0.0.1:{prom_port}/api/v1/query?" + urlencode({"query": expression})
                )
                require(status == 200, "collector_query_status")
                return json.loads(raw)["data"]["result"]

            def events():
                return json.loads(http(f"http://127.0.0.1:{sink}/events", notify)[1])["events"]

            def notification(name, status, after, episode=None):
                return next(
                    (
                        v
                        for v in events()[after:]
                        if v["alertname"] == name
                        and v["status"] == status
                        and (
                            episode is None
                            or (v["fingerprint"], v["starts_at"])
                            == (episode["fingerprint"], episode["starts_at"])
                        )
                    ),
                    None,
                )

            wait_for(lambda: query("secops_collector_observation_fresh == 1"))
            check(
                "real_prometheus_scrapes_authenticated_opt_in_bridge",
                http(f"http://127.0.0.1:{exporter}/metrics")[0] == 401,
            )
            wait_for(lambda: query('up{job="zt-signals-legacy"} == 1'))
            time.sleep(3)
            check(
                "default_exporter_has_no_collector_metrics_or_alerts",
                not query('secops_collector_bridge_enabled{job="zt-signals-legacy"}')
                and not query('ALERTS{job="zt-signals-legacy",alertname=~"C01Collector.*"}'),
            )
            check(
                "normal_bridge_has_no_collector_alert",
                not query('ALERTS{alertstate="firing",alertname=~"C01Collector.*"}'),
            )

            offset = len(events())
            with lock:
                modes["health"] = "stale"
            firing = wait_for(
                lambda: notification("C01CollectorObservationNotFresh", "firing", offset)
            )
            check("stale_observation_reaches_real_alertmanager_receiver")
            count = len(
                [
                    v
                    for v in events()[offset:]
                    if v["alertname"] == firing["alertname"] and v["status"] == "firing"
                ]
            )
            time.sleep(3)
            check(
                "constant_fault_does_not_create_new_alert_identity_or_repeated_notifications",
                count == 1
                and len(
                    [
                        v
                        for v in events()[offset:]
                        if v["alertname"] == firing["alertname"] and v["status"] == "firing"
                    ]
                )
                == 1,
            )
            with lock:
                modes["health"] = "fresh"
            wait_for(lambda: notification(firing["alertname"], "resolved", offset, firing))
            check("recovery_resolves_the_same_health_alert_episode")

            for name, mode in [
                ("C01CollectorArchivePressure", "storage_pressure"),
                ("C01CollectorArchiveUnavailable", "missing"),
            ]:
                offset = len(events())
                with lock:
                    modes["archive"] = mode
                    if mode == "missing":
                        Path(profile["archive_file"]).unlink()
                firing = wait_for(
                    lambda name=name, offset=offset: notification(name, "firing", offset)
                )
                check(
                    mode + "_archive_condition_reaches_receiver_without_changing_health",
                    bool(query("secops_collector_observation_fresh == 1")),
                )
                with lock:
                    modes["archive"] = "ready"
                wait_for(
                    lambda name=name, offset=offset, firing=firing: notification(
                        name, "resolved", offset, firing
                    )
                )
                check(mode + "_archive_recovery_resolves_same_episode")

            offset = len(events())
            with lock:
                modes["health"] = "stopped"
            wait_for(
                lambda: query('secops_collector_status_success{worker="health"} == 0'), seconds=35
            )
            firing = wait_for(
                lambda: notification("C01CollectorObservationNotFresh", "firing", offset)
            )
            check("stopped_reporter_expires_in_real_time_instead_of_reusing_cached_fresh")
            with lock:
                modes["health"] = "fresh"
            wait_for(lambda: notification(firing["alertname"], "resolved", offset, firing))
            check("reporter_restart_recovers_and_resolves_fault")
            text = metrics(profile)
            check(
                "metrics_do_not_expose_keys_or_original_identity",
                all(
                    v not in text
                    for v in [token, notify, scope.tenant_id, scope.server_id, scope.unit]
                ),
            )
            require(all(p.poll() is None for p in processes), "monitoring_processes_survived")
            result = {
                "completed": True,
                "scope": "controlled aggregate fixtures through real cached Prometheus/Alertmanager and local authenticated webhook",
                "cases": checks,
                "versions": versions,
                "notifications": events(),
                "paid_api_calls": 0,
                "aws_calls": 0,
                "independent_detection_evaluation": False,
                "production_mTLS_flow_tested_here": False,
                "network_boundary": "single isolated container network namespace, loopback only",
            }
    finally:
        stopped.set()
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
        for log in logs:
            log.close()
    result["owned_processes_stopped"] = all(p.poll() is not None for p in processes)
    (output / "run.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"completed": True, "cases": len(checks)}))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    run(parser.parse_args().directory)


if __name__ == "__main__":
    main()
