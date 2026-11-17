"""Actual recovery reports through cached monitoring in one isolated namespace.

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

from scripts.f1_lab import exec_recovery_status as status
from scripts.f1_lab.collector_status_bridge import read_public
from scripts.f1_lab.native_jsonl import require
from scripts.observability_lab import receiver
from scripts.run_collector_alert_flow import http, wait_for
from scripts.signal_metrics_exporter import handler


def run(directory, reports):
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    names = ('indeterminate', 'pending', 'partial', 'publication-complete', 'unavailable', 'repaired')
    inputs = {name: read_public(Path(reports) / ('recovery-' + name + '.json')) for name in names}
    scope = inputs['indeterminate']['scope_sha256']
    for name, value in inputs.items():
        status.validate(value, scope)
        require(value['state'] == ('unavailable' if name == 'unavailable' else 'pending'),
                'recovery_flow_input_state')
    require(all(inputs[k]['values']['indeterminate'] == 1 for k in names if k != 'unavailable')
            and [inputs[k]['values']['unpublished'] for k in names if k != 'unavailable'] == [1, 2, 1, 0, 0],
            'recovery_flow_input_counts')
    require(len({v['oldest_indeterminate_at'] for k, v in inputs.items() if k != 'unavailable'}) == 1,
            'recovery_flow_unknown_origin')
    processes, streams, servers, threads, checks, versions = [], [], [], [], [], {}
    token, notify = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    def check(name, condition=True):
        require(condition, "recovery_flow_" + name)
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
        with tempfile.TemporaryDirectory(prefix="exec-recovery-alert-") as temporary:
            root = Path(temporary)
            profile = {
                "schema": "zt-exec-recovery-metrics-profile-1",
                "scope_sha256": scope,
                "status_file": str(root / "status.json"),
                "max_indeterminate_age_seconds": 5,
                "max_unpublished_age_seconds": 5,
                "max_intents": 10000,
            }
            status.publish(profile["status_file"], inputs["indeterminate"])
            inbox, sink = serve(Inbox), serve(receiver(notify))
            upstream = f"http://127.0.0.1:{inbox}/zero-trust/signals/inbox"
            primary = serve(handler(upstream, "local-fixture", token, recovery_profile=profile))
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
                require(code == 200, "recovery_flow_query")
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
                "default_profile_has_no_recovery_metrics_or_alerts",
                not query('secops_exec_recovery_bridge_enabled{job="zt-signals-legacy"}')
                and not query('ALERTS{job="zt-signals-legacy",alertname=~"C01ExecRecovery.*"}'),
            )
            unknown = wait_for(lambda: notification('C01ExecRecoveryIndeterminateOverdue', 'firing', 0))
            publication = wait_for(lambda: notification('C01ExecRecoveryPublicationOverdue', 'firing', 0))
            check('actual_preseal_and_old_cold_loss_fire_separate_alerts',
                  bool(query('secops_exec_recovery_indeterminate == 1'))
                  and bool(query('secops_exec_recovery_unpublished == 1')))
            status.publish(profile['status_file'], inputs['pending'])
            wait_for(lambda: query('secops_exec_recovery_unpublished == 2'))
            check('durable_original_before_outbox_increases_actual_unpublished_count')
            status.publish(profile['status_file'], inputs['partial'])
            wait_for(lambda: query('secops_exec_recovery_unpublished == 1'))
            check('new_publication_does_not_resolve_older_missing_cold_original',
                  not notification(publication['alertname'], 'resolved', 0, publication)
                  and not notification(unknown['alertname'], 'resolved', 0, unknown))
            status.publish(profile['status_file'], inputs['publication-complete'])
            wait_for(lambda: notification(publication['alertname'], 'resolved', 0, publication))
            check('explicit_old_original_republication_resolves_same_publication_episode',
                  bool(query('secops_exec_recovery_unpublished == 0'))
                  and bool(query('secops_exec_recovery_indeterminate == 1'))
                  and not notification(unknown['alertname'], 'resolved', 0, unknown))
            offset = len(events())
            status.publish(profile['status_file'], inputs['unavailable'])
            failure = wait_for(lambda: notification('C01ExecRecoveryUnavailable', 'firing', offset))
            check('actual_signature_damage_reports_unavailable_without_cached_counts',
                  not query('secops_exec_recovery_intents'))
            # Alert disappearance during unavailable means missing observation,
            # not recovered execution. The public state and result say this.
            wait_for(lambda: notification(unknown['alertname'], 'resolved', 0, unknown))
            offset = len(events())
            profile['max_intents'] = 5
            status.publish(profile['status_file'], inputs['repaired'])
            wait_for(lambda: notification(failure['alertname'], 'resolved', 0, failure))
            pressure = wait_for(lambda: notification('C01ExecRecoveryCapacityPressure', 'firing', offset))
            wait_for(lambda: notification('C01ExecRecoveryIndeterminateOverdue', 'firing', offset))
            check('exact_signature_repair_restores_original_unknown_and_actual_capacity',
                  bool(query('secops_exec_recovery_intents == 5'))
                  and bool(query('secops_exec_recovery_indeterminate == 1'))
                  and bool(query('secops_exec_recovery_unpublished == 0')))
            profile['max_intents'] = 10000
            wait_for(lambda: notification(pressure['alertname'], 'resolved', offset, pressure))
            check('explicit_capacity_threshold_change_does_not_change_original_report',
                  read_public(profile['status_file']) == inputs['repaired'])
            offset = len(events())
            wait_for(lambda: query('secops_exec_recovery_status_success == 0'), seconds=75)
            wait_for(lambda: notification('C01ExecRecoveryUnavailable', 'firing', offset))
            check('real_60_second_expiry_omits_cached_counts_and_reports_unavailable',
                  not query('secops_exec_recovery_intents')
                  and read_public(profile['status_file']) == inputs['repaired'])
            require(all(p.poll() is None for p in processes), "recovery_flow_monitor_survived")
            result = {
                "completed": True,
                "cases": checks,
                "versions": versions,
                "notifications": events(),
                "actual_native_reports": True,
                "oldest_indeterminate_at": inputs["indeterminate"]["oldest_indeterminate_at"],
                "unavailable_alert_resolution_is_not_recovery": True,
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
