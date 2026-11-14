"""Real local C01 monitoring, isolated identities, fault episodes and persistence."""

import copy
import json
import secrets
import subprocess
from datetime import UTC, datetime, timedelta

from scripts.continuous_mtls_runtime import RuntimeFailure, command
from scripts.monitored_mtls_runtime import MonitoredRuntime
from scripts.monitoring_readiness import FRESH_UP, inactive_rule
from scripts.test_continuous_mtls_runtime import Checks


class MonitoredChecks(Checks):
    def __init__(self, directory, runtime_class=MonitoredRuntime):
        super().__init__(directory, runtime_class=runtime_class)
        self.report["schema"] = "monitored-continuous-mtls-verification-1"
        self.scrape = self.notify = None
        self.episode_starts = {}

    def record_monitoring_failure(self, label):
        if 'monitoring_failure_diagnostics' not in self.report:
            from scripts.monitoring_diagnostics import collect
            try:
                self.report['monitoring_failure_diagnostics'] = collect(self.runtime, label)
                self.save()
            except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                self.report['monitoring_failure_diagnostics'] = {'available': False}

    def wait(self, predicate, label):
        try:
            super().wait(predicate, label)
        except RuntimeFailure:
            self.record_monitoring_failure(label)
            raise

    def monitor(self, profile, path=None, **data):
        request = {"profile": profile, **data}
        if path is not None:
            request["path"] = path
        return json.loads(self.runtime.execute("operator", ["python", "-m", "scripts.monitoring_runtime_control", "probe"],
                                                json.dumps(request)))

    def metric(self):
        result = self.monitor("exporter", "/metrics", headers={"Authorization": "Bearer " + self.scrape})
        self.require(result["status"] == 200, "monitoring_metrics_unavailable")
        return result["body"]

    def query(self, expression, **options):
        result = self.monitor("prometheus", query=expression, **options)
        self.require(result["status"] == 200 and result["body"]["status"] == "success", "monitoring_query_failed")
        return result["body"]["data"]["result"]

    def events(self):
        result = self.monitor("sink", "/events", headers={"Authorization": "Bearer " + self.notify})
        self.require(result["status"] == 200, "monitoring_receiver_unavailable")
        return result["body"]["events"]

    def episode(self, name, status, floor, original=None):
        since = getattr(self, "episode_starts", {}).get(floor)
        for event in self.events()[floor:]:
            if (event["alertname"] == name and event["status"] == status and event["job"] == "zt-signals"
                    and event["instance"] == "exporter:9101"
                    and (since is None or datetime.fromisoformat(event["starts_at"]) >= since)
                    and (original is None or (event["fingerprint"], event["starts_at"]) ==
                         (original["fingerprint"], original["starts_at"]))):
                return event
        return None

    def begin_episode(self):
        floor = len(self.events())
        clock = self.runtime.execute("sink", ["python", "-c", "from datetime import UTC,datetime;print(datetime.now(UTC).isoformat())"])
        self.episode_starts[floor] = datetime.fromisoformat(clock.strip())
        return floor

    def clear_baseline(self, alert):
        floor = datetime.now(UTC)
        evidence = {}

        def fresh():
            result = self.monitor('prometheus', '/api/v1/rules?type=alert')
            value = inactive_rule(result.get('body'), alert, floor) if result.get('status') == 200 else None
            if not value:
                return False
            samples = self.query(FRESH_UP)
            if (len(samples) != 1 or samples[0].get('metric', {}).get('job') != 'zt-signals'
                    or samples[0].get('metric', {}).get('instance') != 'exporter:9101'
                    or samples[0].get('value', [None, None])[1] != '1'):
                return False
            evidence.update(value)
            return True

        self.wait(fresh, 'monitoring_fresh_inactive_rule_not_ready')
        self.report.setdefault('monitoring_baselines', []).append(evidence)
        self.add('fresh_healthy_inactive_' + alert + '_evaluation_and_live_scrape_before_fault')

    def await_episode(self, name, status, floor, original=None):
        found = {}

        def seen():
            event = self.episode(name, status, floor, original)
            if event:
                found.update(event)
            return event

        self.wait(seen, "monitoring_episode_" + name + "_" + status)
        return found

    def signed_observation(self, event_id):
        program = """import base64,json,sys
from pathlib import Path
from datetime import UTC,datetime,timedelta
from cryptography.hazmat.primitives import serialization
from app.continuous_signal_models import SignedContinuousSignal
from app.services.trusted_signals import canonical_observation
d=Path('/collector/producer');c=json.loads((d/'config.json').read_bytes())
k=serialization.load_pem_private_key((d/'private.pem').read_bytes(),password=None)
now=datetime.now(UTC)-timedelta(seconds=1)
s=SignedContinuousSignal(tenant_id=c['tenant_id'],source_id=c['source_id'],key_id=c['key_id'],
event_id=json.load(sys.stdin)['event'],issued_at=now,observed_at=now,expires_at=now+timedelta(seconds=90),
observation={'kind':'identity','subject_id':'runtime-other','active':True,'authentication_result':'success'},signature='A'*86)
s.signature=base64.urlsafe_b64encode(k.sign(canonical_observation(s))).decode().rstrip('=')
print(s.model_dump_json())
"""
        return json.loads(self.collector_job(["-c", program], json.dumps({"event": event_id})))

    def submit(self, event_id):
        payload = self.signed_observation(event_id)
        response = self.runtime.probe({"profile": "core", "method": "POST", "path": "/zero-trust/signals/inbox", "body": payload})
        self.require(response["status"] == 202 and not response["body"]["duplicate"], "monitoring_fixture_not_committed")
        return payload

    def reader_request(self, *, method="GET", bad_key=False):
        program = """import json,sys
from pathlib import Path
from scripts import mtls_transport as tls
v=json.load(sys.stdin);key=Path('/auth/api-key.txt').read_text().strip()
status,body=tls.request(Path('/tls/reader.json'),'/zero-trust/signals/inbox',{} if v['method']=='POST' else None,
 {'X-API-Key':'bad-synthetic-key' if v['bad'] else key},method=v['method'])
print(json.dumps({'status':status}))
"""
        return json.loads(self.runtime.execute("exporter", ["python", "-c", program], json.dumps({"method": method, "bad": bad_key})))

    def refused_transport(self, target, mode):
        program = """import json,sys,ssl,http.client,tempfile,shutil
from pathlib import Path
from scripts import mtls_transport as tls
v=json.load(sys.stdin);p=Path('/monitor-tls')/(v['target']+'.json');d=json.loads(p.read_bytes());status=0
try:
 if v['mode']=='plain':
  c=http.client.HTTPConnection(d['host'],d['port'],timeout=2);c.request('GET','/metrics');status=c.getresponse().status;c.close()
 elif v['mode']=='no-cert':
  ctx=ssl.create_default_context(cafile='/monitor-tls/ca.pem');c=http.client.HTTPSConnection(d['host'],d['port'],context=ctx,timeout=2)
  c.request('GET','/metrics');status=c.getresponse().status;c.close()
 else:
  with tempfile.TemporaryDirectory() as t:
   r=Path(t)
   for name in ('ca.pem','core-operator.pem','core-operator.key'):shutil.copyfile(Path('/tls')/name,r/name)
   d.update(cert='core-operator.pem',key='core-operator.key');(r/'profile.json').write_text(json.dumps(d))
   status,_=tls.request(r/'profile.json','/metrics' if v['target']=='exporter' else '/api/v1/query?query=up',None,{},method='GET')
except (OSError,ValueError,http.client.HTTPException):pass
print(json.dumps({'status':status,'denied':status in (0,403)}))
"""
        return json.loads(self.runtime.execute("operator", ["python", "-c", program], json.dumps({"target": target, "mode": mode})))

    def integration_checks(self):
        runtime = self.runtime
        self.report["monitoring"] = {"tools": runtime.state["monitoring_tools"], "image_id": runtime.state["monitoring_image_id"],
            "binary_sha256": runtime.state["monitoring_binary_sha256"], "configuration_sha256": runtime.state["monitoring_config_sha256"]}
        self.scrape = runtime.execute("exporter", ["python", "-c", "from pathlib import Path;print(Path('/auth/scrape.token').read_text())"]).strip()
        self.notify = runtime.execute("sink", ["python", "-c", "from pathlib import Path;print(Path('/tls/notify.token').read_text())"]).strip()
        self.wait(lambda: "secops_signal_collection_success 1" in self.metric(), "monitoring_reader_not_ready")
        self.add("monitoring_exporter_uses_authenticated_mtls_viewer")
        for header, label in (({}, "missing"), ({"Authorization": "Bearer wrong-synthetic-token"}, "wrong")):
            self.require(self.monitor("exporter", "/metrics", headers=header)["status"] == 401, "monitoring_bearer_not_enforced")
            self.add("monitoring_scrape_" + label + "_token_denied")
        for target, mode in (("exporter", "plain"), ("exporter", "no-cert"), ("exporter", "wrong-role"), ("prometheus", "wrong-role")):
            result = self.refused_transport(target, mode)
            self.require(result["denied"] and (mode != "plain" or result["status"] == 0), "monitoring_transport_bypass")
            self.add("monitoring_" + target + "_" + mode + "_denied")
        self.require(self.reader_request(method="POST")["status"] == 403, "monitoring_reader_write_allowed")
        self.add("monitoring_viewer_identity_cannot_submit_signals")
        self.require(self.reader_request(bad_key=True)["status"] == 401, "monitoring_reader_api_auth_missing")
        self.add("monitoring_mtls_does_not_replace_viewer_api_authentication")
        for name in ("exporter", "prometheus", "alertmanager", "sink"):
            detail = self.inspect(name)
            mounted = {row["Name"] for row in detail["Mounts"] if row["Type"] == "volume"}
            forbidden = {runtime.state["volumes"][n] for n in ("data", "core-auth", "operator-auth", "collector-state")}
            self.require(not mounted & forbidden, "monitoring_private_authority_mount")
        self.add("monitoring_services_have_no_security_db_or_responder_keys")
        self.wait(lambda: bool(self.query('up{job="zt-signals"}')) and self.query('up{job="zt-signals"}')[0]["value"][1] == "1",
                  "monitoring_scrape_not_ready")
        self.add("monitoring_prometheus_scrapes_real_exporter")

        worker = runtime.container("worker")
        command(["docker", "stop", "--time", "2", worker])
        floor = self.begin_episode()
        event_id = "monitor-backlog-" + secrets.token_hex(5)
        try:
            self.submit(event_id)
            firing = self.await_episode("C01SignalQueueBacklog", "firing", floor)
            self.add("monitoring_real_committed_backlog_fires_new_episode")
        finally:
            command(["docker", "start", worker])
        self.wait(lambda: self.completed(event_id), "monitoring_backlog_not_processed")
        self.await_episode("C01SignalQueueBacklog", "resolved", floor, firing)
        self.add("monitoring_worker_drain_resolves_same_backlog_episode")

        for service, alert in (("reader", "C01SignalCollectionUnavailable"), ("exporter", "C01ExporterDown")):
            self.clear_baseline(alert)
            floor = self.begin_episode()
            command(["docker", "stop", "--time", "2", runtime.container(service)])
            try:
                firing = self.await_episode(alert, "firing", floor)
                if service == "reader":
                    body = self.metric()
                    self.require("secops_signal_collection_success 0" in body and "secops_signal_inbox_records" not in body,
                                 "monitoring_stale_metrics_reused")
                self.add("monitoring_" + service + "_failure_fires_without_stale_success")
                if service == 'exporter':
                    from scripts.monitoring_diagnostics import collect
                    snapshot = collect(runtime, 'synthetic_exporter_outage')
                    self.report['monitoring_diagnostic_validation'] = snapshot
                    self.save()
                    self.require(any(row['value'] == 0 for row in snapshot['prometheus']['up'].get('samples', []))
                                 and any(row.get('labels', {}).get('alertname') == alert and row['value'] == 1
                                         for row in snapshot['prometheus']['alerts'].get('samples', []))
                                 and any(row['service'] == 'exporter' and row.get('running') is False
                                         for row in snapshot['services']), 'monitoring_diagnostics_missing_live_fault')
                    self.add('monitoring_diagnostics_capture_actual_outage_before_cleanup')
            finally:
                command(["docker", "start", runtime.container(service)])
            self.await_episode(alert, "resolved", floor, firing)
            self.add("monitoring_" + service + "_recovery_resolves_same_episode")

        fixed = (datetime.now(UTC) - timedelta(seconds=2)).timestamp()
        expression = 'count_over_time(up{job="zt-signals"}[1m])'
        history = self.query(expression, time=fixed)
        self.require(bool(history) and float(history[0]["value"][1]) > 0, "monitoring_history_missing")
        command(["docker", "restart", runtime.container("prometheus")])
        self.wait(lambda: self.query(expression, time=fixed) == history, "monitoring_tsdb_restart_lost_fixed_history")
        self.add("monitoring_tsdb_restart_retains_fixed_time_samples")
        now = datetime.now(UTC)
        payload = {"matchers": [{"name": "alertname", "value": "C01UnusedPersistenceControl", "isRegex": False, "isEqual": True}],
            "startsAt": (now - timedelta(seconds=1)).isoformat(), "endsAt": (now + timedelta(minutes=10)).isoformat(),
            "createdBy": "local-monitoring-test", "comment": "Synthetic unrelated silence persistence control"}
        result = self.monitor("alertmanager", "/api/v2/silences", method="POST", body=payload)
        self.require(result["status"] == 200 and "silenceID" in result["body"], "monitoring_silence_not_created")
        silence = result["body"]["silenceID"]
        command(["docker", "restart", runtime.container("alertmanager")])
        self.wait(lambda: self.monitor("alertmanager", "/api/v2/silence/" + silence)["status"] == 200,
                  "monitoring_silence_restart_lost")
        self.require(self.monitor("alertmanager", "/api/v2/silence/" + silence)["body"]["matchers"] == payload["matchers"],
                     "monitoring_silence_changed")
        self.add("monitoring_alertmanager_restart_retains_unrelated_silence")
        self.require(self.monitor("alertmanager", "/api/v2/silence/" + silence, method="DELETE")["status"] == 200,
                     "monitoring_silence_cleanup")
        self.configuration_gate()

    def configuration_gate(self):
        runtime = self.runtime
        runtime.compose("stop", "--timeout", "2")
        from scripts.monitoring_runtime_assets import configurations
        config = configurations()["prometheus-tls"]["config.yml"]
        runtime.write_volume("prometheus-tls", {"config.yml": config + "\n# unapproved synthetic edit\n"})
        try:
            try:
                runtime.up()
            except RuntimeFailure as error:
                self.require(str(error) == "monitoring_configuration_drift", "monitoring_wrong_config_denial")
            else:
                raise RuntimeFailure("monitoring_modified_configuration_accepted")
            self.require(all(not row["running"] for row in runtime.status()["services"].values()), "monitoring_drift_started_services")
            self.add("monitoring_configuration_drift_refuses_all_fourteen_services")
        finally:
            runtime.write_volume("prometheus-tls", {"config.yml": config})
        runtime.up()
        self.wait(lambda: "secops_signal_collection_success 1" in self.metric(), "monitoring_resume_not_ready")
        self.add("monitoring_locked_profile_resumes_without_new_keys")

    def run(self):
        super().run()
        self.report["completed"] = False
        self.clear_baseline('C01SignalProcessingFailed')
        floor = self.begin_episode()
        worker = self.runtime.container("worker")
        command(["docker", "stop", "--time", "2", worker])
        registry = json.loads(self.runtime.execute("app", ["python", "-c", "from pathlib import Path;print(Path('/signals/sources.json').read_text())"]))
        event_id = "monitor-failed-" + secrets.token_hex(5)
        try:
            self.submit(event_id)
            changed = copy.deepcopy(registry)
            next(item for item in changed["sources"] if item["source_id"] == "runtime-identity")["keys"][0]["enabled"] = False
            self.runtime.write_volume("registry", {"sources.json": json.dumps(changed)})
            command(["docker", "start", worker])
            self.wait(lambda: self.receipt(event_id).get("body", {}).get("state") == "failed", "monitoring_invalid_source_not_failed")
            receipt = self.receipt(event_id)["body"]
            self.require(receipt["last_error"] == "SIGNAL_REJECTED", "monitoring_unexpected_processing_failure")
            self.add("monitoring_worker_revalidates_disabled_observation_key", error_code=receipt["last_error"])
            self.await_episode("C01SignalProcessingFailed", "firing", floor)
            self.add("monitoring_failed_processing_reaches_authenticated_receiver")
        finally:
            self.runtime.write_volume("registry", {"sources.json": json.dumps(registry)})
            command(["docker", "start", worker])
        self.report["completed"] = True
