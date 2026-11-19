"""Bounded real local collector -> exporter -> Prometheus -> Alertmanager flow.

Uses owned loopback peers and ephemeral keys. No cloud, provider call, Docker,
service installation or independent-host admission. Requires operator-provided
local monitoring binaries; records their digests rather than auto-installing.
"""

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

import yaml

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult
from app.scenarios import synthetic_events
from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as observer_backup
from app.services.audit_transfer import canonical, require
from app.services.policy import response_preview
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab import witness_observer_status as bridge
from scripts.f1_lab import witness_restore_status as restore_bridge
from scripts.observability_lab import receiver
from scripts.run_collector_alert_flow import http, wait_for
from scripts.signal_metrics_exporter import handler


def run(directory, tools_directory, *, cadence_controls=False):
    require(os.name == "posix", "witness_alert_flow_posix_required")
    output = Path(directory).absolute()
    output.mkdir(parents=True, exist_ok=False)
    tools = Path(tools_directory).resolve()
    source = Path(__file__).resolve().parents[1]
    checks, processes, streams, servers, threads = [], [], [], [], []
    stop, pause, paused = threading.Event(), threading.Event(), threading.Event()
    failures = []
    scrape, notify = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    cleaned = False
    binaries = {}
    for name in ("prometheus", "promtool", "alertmanager"):
        path = tools / name
        require(path.is_file() and not path.is_symlink(), "witness_alert_flow_tools")
        binaries[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def check(name, condition):
        require(condition, "witness_alert_flow_" + name)
        checks.append({"name": name, "passed": True})

    def serve(cls):
        server = ThreadingHTTPServer(("127.0.0.1", 0), cls)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
        return server.server_port

    def free_port():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    class Inbox(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            raw = canonical({"pending": 0, "processing": 0, "completed": 0, "failed": 0,
                             "total": 0, "oldest_pending_age_seconds": None,
                             "oldest_processing_age_seconds": None})
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    def spawn(argv, name):
        stream = (output / name).open("wb")
        streams.append(stream)
        processes.append(subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT))

    def cleanup():
        nonlocal cleaned
        if cleaned:
            return
        cleaned = True
        stop.set()
        pause.clear()
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
        for stream in streams:
            stream.close()

    try:
        with tempfile.TemporaryDirectory(prefix="witness-alert-") as temporary, ExitStack() as lifecycle:
            lifecycle.callback(cleanup)
            root = Path(temporary)
            store = SQLiteAuditStore(root / "audit.sqlite3")
            event = synthetic_events()[0]
            assessment = RuleBasedAnalyzer().assess(event)
            record = AnalysisResult(event_id=event.event_id, analyzer="rule", assessment=assessment,
                                    policy_decision=response_preview(assessment, event), latency_ms=1)
            asyncio.run(store.save(record))
            before = store.path.read_bytes()
            with store._transaction() as con:
                first_digest = con.execute("SELECT digest FROM audit_entries WHERE seq=1").fetchone()[0]
            signer, control = root / "witness", root / "control"
            key_pin = witness.initialize(signer, store.path, "witness-alert-lab")["public_key_sha256"]
            initial = witness.observe(signer, store.path, key_pin, expected_receipt=witness.GENESIS)
            minimum = initial["receipt_sha256"]
            pin = observer.initialize(control, signer, store.path, key_pin, expected_receipt=minimum,
                                      interval_seconds=1, max_age_seconds=12 if cadence_controls else 6,
                                      capacity_warning=0)["profile_sha256"]
            public = root / "status.json"
            profile = {"schema": bridge.PROFILE_SCHEMA, "profile_sha256": pin,
                       "minimum_receipt": minimum, "status_file": str(public)}
            observer.cycle(control, pin, minimum_receipt=minimum)
            recovery_key = secrets.token_bytes(32)
            package, reviewed = root / "control.aesgcm", root / "reviewed"
            saved = observer_backup.backup(control, pin, minimum, package, recovery_key)
            restored = observer_backup.restore(package, reviewed, saved["backup_sha256"],
                                               pin, minimum, recovery_key)
            del recovery_key
            restore_public = root / "restore-status.json"
            restore_profile = {"schema": restore_bridge.PROFILE_SCHEMA, "profile_sha256": pin,
                               "minimum_receipt": minimum, "backup_sha256": saved["backup_sha256"],
                               "restore_receipt_sha256": restored["restore_receipt_sha256"],
                               "status_file": str(restore_public), "max_backup_age_seconds": 3600,
                               "max_restore_age_seconds": 3600}

            def collect():
                while not stop.is_set():
                    if pause.is_set():
                        paused.set()
                        stop.wait(0.05)
                        continue
                    paused.clear()
                    success = True
                    try:
                        observer.cycle(control, pin, minimum_receipt=minimum)
                    except bridge.ERRORS:
                        success = False
                    try:
                        bridge.publish(public, bridge.inspect(control, pin, minimum,
                                                              cycle_success=success))
                        restore_bridge.publish(restore_public, restore_bridge.inspect(
                            package, reviewed, restore_profile
                        ))
                    except bridge.ERRORS:
                        failures.append("status_publication_failed")
                    stop.wait(1)

            worker = threading.Thread(target=collect, daemon=True)
            worker.start()
            threads.append(worker)
            wait_for(lambda: public.exists() and restore_public.exists())
            upstream = serve(Inbox)
            sink = serve(receiver(notify))
            url = f"http://127.0.0.1:{upstream}/zero-trust/signals/inbox"
            exporter = serve(handler(url, "local-fixture", scrape, witness_profile=profile,
                                     witness_restore_profile=restore_profile))
            legacy = serve(handler(url, "local-fixture", scrape))
            prom_port, am_port = free_port(), free_port()
            for name, token in (("scrape.secret", scrape), ("notify.secret", notify)):
                (root / name).write_text(token)
                (root / name).chmod(0o600)
            am = {"route": {"receiver": "local", "group_by": ["alertname"], "group_wait": "0s",
                            "group_interval": "1s", "repeat_interval": "1h"},
                  "receivers": [{"name": "local", "webhook_configs": [{
                      "url": f"http://127.0.0.1:{sink}/events", "send_resolved": True,
                      "http_config": {"authorization": {"type": "Bearer",
                                                        "credentials_file": str(root / "notify.secret")}}
                  }]}]}
            prom = {"global": {"scrape_interval": "500ms", "scrape_timeout": "400ms",
                               "evaluation_interval": "500ms"},
                    "rule_files": [str(source / "infra/observability/alerts.yaml")],
                    "alerting": {"alertmanagers": [{"static_configs": [{
                        "targets": [f"127.0.0.1:{am_port}"]}]}]},
                    "scrape_configs": [{"job_name": job, "authorization": {
                        "type": "Bearer", "credentials_file": str(root / "scrape.secret")},
                        "static_configs": [{"targets": [f"127.0.0.1:{port}"]}]}
                        for job, port in (("zt-signals", exporter), ("zt-signals-legacy", legacy))]}
            for name, config in (("prom", prom), ("am", am)):
                (root / (name + ".yaml")).write_text(yaml.safe_dump(config))
            checked = subprocess.run([str(tools / "promtool"), "check", "rules",
                                      str(source / "infra/observability/alerts.yaml")],
                                     capture_output=True, text=True, timeout=15, check=True)
            (output / "promtool.txt").write_text(checked.stdout)
            spawn([str(tools / "alertmanager"), "--config.file=" + str(root / "am.yaml"),
                   "--storage.path=" + str(root / "am-data"), "--cluster.listen-address=",
                   f"--web.listen-address=127.0.0.1:{am_port}"], "alertmanager.log")
            spawn([str(tools / "prometheus"), "--config.file=" + str(root / "prom.yaml"),
                   "--storage.tsdb.path=" + str(root / "prom-data"), "--storage.tsdb.retention.time=1h",
                   f"--web.listen-address=127.0.0.1:{prom_port}"], "prometheus.log")

            def query(expression):
                code, raw = http(f"http://127.0.0.1:{prom_port}/api/v1/query?"
                                 + urlencode({"query": expression}))
                require(code == 200, "witness_alert_query")
                return json.loads(raw)["data"]["result"]

            def events():
                return json.loads(http(f"http://127.0.0.1:{sink}/events", notify)[1])["events"]

            def notification(name, state, offset, original=None):
                return next((e for e in events()[offset:] if e["alertname"] == name
                             and e["status"] == state and e["job"] == "zt-signals"
                             and (original is None or (e["fingerprint"], e["starts_at"])
                                  == (original["fingerprint"], original["starts_at"]))), None)

            wait_for(lambda: query('secops_witness_observation_healthy{job="zt-signals"} == 1'))
            check("exporter_receiver_authentication", http(f"http://127.0.0.1:{exporter}/metrics")[0]
                  == http(f"http://127.0.0.1:{sink}/events")[0] == 401)
            check("legacy_opt_out", not query('secops_witness_bridge_enabled{job="zt-signals-legacy"}'))
            check("legacy_restore_opt_out", not query('secops_witness_restore_bridge_enabled{job="zt-signals-legacy"}'))
            wait_for(lambda: query('secops_witness_restore_status_success{job="zt-signals"} == 1'))
            check("healthy_baseline", not query('ALERTS{alertname=~"C01Witness.*",alertstate="firing"}'))
            episodes = []

            def episode(name, condition, trigger, repair):
                offset = len(events())
                trigger()
                wait_for(lambda: query(condition), seconds=40)
                firing = wait_for(lambda: notification(name, "firing", offset), seconds=40)
                check(name + "_firing_new_episode", bool(firing))
                repair()
                resolved = wait_for(lambda: notification(name, "resolved", offset, firing), seconds=40)
                check(name + "_resolved_same_episode", bool(resolved))
                episodes.append({"alert": name, "fault_expression": condition,
                                 "fault_observed": True, "firing": firing, "resolved": resolved})

            def pause_collector():
                pause.set()
                require(paused.wait(5), "witness_alert_pause")

            if cadence_controls:
                pause_collector()
                appended = event.model_copy(update={"event_id": "witness-cadence-append"})
                assessed = RuleBasedAnalyzer().assess(appended)
                asyncio.run(store.save(AnalysisResult(
                    event_id=appended.event_id, analyzer="rule", assessment=assessed,
                    policy_decision=response_preview(assessed, appended), latency_ms=1
                )))
                # This is the one declared fixture append, not mutation of the
                # immutable evaluation corpus or an original audit prefix.
                before = store.path.read_bytes()
                bridge.publish(public, bridge.inspect(control, pin, minimum))
                wait_for(lambda: query('secops_witness_state{job="zt-signals",state="unobserved"} == 1'))
                check("new_rows_remain_explicitly_unobserved", bool(query(
                    'secops_witness_observation_healthy{job="zt-signals"} == 0')))
                time.sleep(3)
                check("in_budget_lag_does_not_fire_critical_observation_alert", not query(
                    'ALERTS{job="zt-signals",alertname="C01WitnessObservationNotHealthy",alertstate="firing"}'))
                pause.clear()
                wait_for(lambda: query('secops_witness_observation_healthy{job="zt-signals"} == 1'))
                check("next_collection_observes_declared_append", observer.status(
                    control, pin, minimum_receipt=minimum)["unobserved_rows"] == 0)

            episode("C01WitnessObservationNotHealthy",
                    'secops_witness_state{job="zt-signals",state="stale"} == 1',
                    pause_collector, pause.clear)
            wait_for(lambda: query('secops_witness_observation_healthy{job="zt-signals"} == 1'))
            private = (signer / "private.key").read_bytes()

            def remove_key():
                (signer / "private.key").unlink()

            def restore_key():
                observer._write(signer / "private.key", private)

            episode("C01WitnessCollectionFailed",
                    'secops_witness_state{job="zt-signals",state="pending"} == 1',
                    remove_key, restore_key)
            wait_for(lambda: query('secops_witness_observation_healthy{job="zt-signals"} == 1'))
            pause_collector()
            known = public.read_bytes()

            def corrupt_cache():
                public.write_bytes(b"not-json")

            def restore_cache():
                # Explicit operator restoration of the exact held cache bytes,
                # not a producer reset accepting a foreign profile or pin.
                public.write_bytes(known)
                pause.clear()

            episode("C01WitnessStatusUnavailable",
                    'secops_witness_status_success{job="zt-signals"} == 0',
                    corrupt_cache, restore_cache)
            wait_for(lambda: query('secops_witness_observation_healthy{job="zt-signals"} == 1'))
            held_package = package.read_bytes()

            def corrupt_package():
                package.write_bytes(held_package + b"fault")

            def restore_package():
                package.write_bytes(held_package)

            episode("C01WitnessRestoreVerificationUnavailable",
                    'secops_witness_restore_status_success{job="zt-signals"} == 0',
                    corrupt_package, restore_package)
            wait_for(lambda: query('secops_witness_restore_status_success{job="zt-signals"} == 1'))
            check("restore_time_not_refreshed_by_monitoring",
                  json.loads(restore_public.read_bytes())["values"]["restore_started_at"]
                  == json.loads((reviewed / "restore.receipt.json").read_bytes())["started_at"])
            stop.set()
            worker.join(timeout=5)
            check("collector_stopped", not worker.is_alive())
            state = observer.status(control, pin, minimum_receipt=minimum)
            check("no_pending_after_recovery", not state["pending"] and state["healthy"])
            check("audit_matches_declared_test_append" if cadence_controls else "original_audit_unchanged",
                  store.path.read_bytes() == before)
            if cadence_controls:
                with store._transaction() as con:
                    check("original_signed_audit_prefix_preserved", con.execute(
                        "SELECT digest FROM audit_entries WHERE seq=1").fetchone()[0] == first_digest)
            check("no_publication_failures", not failures)
            check("legacy_has_no_witness_alerts", not query(
                'ALERTS{job="zt-signals-legacy",alertname=~"C01Witness.*"}'))
            result = {"schema": "local-witness-alert-flow-1", "checked_at": datetime.now(UTC).isoformat(),
                      "completed": True, "checks": checks, "episodes": episodes,
                      "binary_sha256": binaries, "local_loopback_only": True,
                      "cadence_controls": cadence_controls, "declared_synthetic_audit_appends": int(cadence_controls),
                      "real_8h_soak": False, "paid_api_calls": 0, "detection_metrics_changed": False,
                      "independent_storage_verified": False, "automatic_activation_allowed": False}
            (output / "report.json").write_bytes(canonical(result) + b"\n")
            return result
    finally:
        cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--tools-directory", required=True)
    parser.add_argument("--cadence-controls", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.directory, args.tools_directory, cadence_controls=args.cadence_controls), ensure_ascii=False))


if __name__ == "__main__":
    main()
