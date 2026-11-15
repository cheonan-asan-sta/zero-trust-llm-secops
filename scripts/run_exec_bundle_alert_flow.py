"""Actual typed bundle reports through cached monitoring in one isolated namespace.

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

from scripts.f1_lab import exec_bundle_status as status
from scripts.f1_lab.collector_status_bridge import read_public
from scripts.f1_lab.native_jsonl import require
from scripts.observability_lab import receiver
from scripts.run_collector_alert_flow import http, wait_for
from scripts.signal_metrics_exporter import handler


def run(directory, reports):
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    names = ('verified', 'unavailable', 'repaired')
    inputs = {name: read_public(Path(reports) / ('bundle-' + name + '.json')) for name in names}
    scope = inputs['verified']['scope_sha256']
    for name, value in inputs.items():
        status.validate(value, scope)
        require(value['state'] == ('unavailable' if name == 'unavailable' else 'verified'),
                'bundle_flow_input_state')
    require(inputs['verified']['values'] == inputs['repaired']['values']
            and inputs['verified']['values']['indeterminate'] == 1
            and inputs['verified']['values']['intents'] == 5
            and inputs['verified']['values']['sealed'] == 4, 'bundle_flow_actual_retained_unknown')
    processes, streams, servers, threads, checks, versions = [], [], [], [], [], {}
    token, notify = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    def check(name, condition=True):
        require(condition, "bundle_flow_" + name)
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
        with tempfile.TemporaryDirectory(prefix="exec-bundle-alert-") as temporary:
            root = Path(temporary)
            profile = {
                "schema": "zt-exec-bundle-metrics-profile-1",
                "scope_sha256": scope,
                "status_file": str(root / "status.json"),
                "max_snapshot_age_seconds": 30,
                "max_restore_age_seconds": 3600,
            }
            status.publish(profile["status_file"], inputs["verified"])
            inbox, sink = serve(Inbox), serve(receiver(notify))
            upstream = f"http://127.0.0.1:{inbox}/zero-trust/signals/inbox"
            primary = serve(handler(upstream, "local-fixture", token, bundle_profile=profile))
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
                require(code == 200, "bundle_flow_query")
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
                "default_profile_has_no_bundle_metrics_or_alerts",
                not query('secops_exec_bundle_bridge_enabled{job="zt-signals-legacy"}')
                and not query('ALERTS{job="zt-signals-legacy",alertname=~"C01ExecBundle.*"}'),
            )
            unknown = wait_for(lambda: notification('C01ExecBundleIndeterminateRetained', 'firing', 0))
            check('verified_backup_retains_actual_unknown_without_claiming_execution_recovery',
                  bool(query('secops_exec_bundle_intents == 5'))
                  and bool(query('secops_exec_bundle_sealed == 4'))
                  and bool(query('secops_exec_bundle_indeterminate == 1'))
                  and bool(query('secops_exec_bundle_recovery_recent == 1')))
            check('original_snapshot_backup_restore_times_are_not_renewed_by_exporter',
                  read_public(profile['status_file']) == inputs['verified'])
            offset = len(events())
            status.publish(profile['status_file'], inputs['unavailable'])
            failure = wait_for(lambda: notification('C01ExecBundleVerificationUnavailable', 'firing', offset))
            wait_for(lambda: notification(unknown['alertname'], 'resolved', 0, unknown))
            check('actual_ciphertext_damage_replaces_counts_with_verification_unavailable',
                  not query('secops_exec_bundle_intents'))
            offset = len(events())
            status.publish(profile['status_file'], inputs['repaired'])
            wait_for(lambda: notification(failure['alertname'], 'resolved', 0, failure))
            retained = wait_for(lambda: notification('C01ExecBundleIndeterminateRetained', 'firing', offset))
            check('exact_ciphertext_repair_restores_same_original_unknown_and_dates',
                  bool(query('secops_exec_bundle_indeterminate == 1'))
                  and inputs['verified']['values'] == inputs['repaired']['values'])
            overdue = wait_for(lambda: notification('C01ExecBundleRecoveryOverdue', 'firing', offset), seconds=35)
            check('original_snapshot_becomes_overdue_after_real_30_seconds',
                  datetime.now(UTC) >= datetime.fromisoformat(inputs['repaired']['values']['snapshot_at'])
                  + timedelta(seconds=30))
            profile['max_snapshot_age_seconds'] = 3600
            wait_for(lambda: notification(overdue['alertname'], 'resolved', offset, overdue))
            check('explicit_age_policy_change_resolves_overdue_without_new_snapshot_or_restore',
                  read_public(profile['status_file']) == inputs['repaired']
                  and not notification(retained['alertname'], 'resolved', offset, retained))
            offset = len(events())
            wait_for(lambda: query('secops_exec_bundle_status_success == 0'), seconds=75)
            wait_for(lambda: notification('C01ExecBundleVerificationUnavailable', 'firing', offset))
            check('real_60_second_report_expiry_omits_stale_counts_and_reports_unavailable',
                  not query('secops_exec_bundle_intents')
                  and read_public(profile['status_file']) == inputs['repaired'])
            require(all(p.poll() is None for p in processes), "bundle_flow_monitor_survived")
            result = {
                "completed": True,
                "cases": checks,
                "versions": versions,
                "notifications": events(),
                "actual_native_reports": True,
                "original_snapshot_at": inputs["verified"]["values"]["snapshot_at"],
                "original_restored_at": inputs["verified"]["values"]["restored_at"],
                "unavailable_alert_resolution_is_not_recovery": True,
                "actual_snapshot_age_crossing_seconds": 30,
                "final_indeterminate": 1,
                "automatic_execution_allowed": False,
                "original_repaired_checked_at": inputs["repaired"]["checked_at"],
                "source_expired_in_real_time": datetime.now(UTC)
                >= datetime.fromisoformat(inputs["repaired"]["checked_at"]) + timedelta(seconds=60),
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
