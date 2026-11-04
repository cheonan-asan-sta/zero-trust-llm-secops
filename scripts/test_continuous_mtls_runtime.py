"""Real Docker mTLS continuous-runtime fault tests; only owned test resources are purged."""

import argparse
import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.continuous_mtls_assets import DEVICES, OTHER
from scripts.continuous_mtls_runtime import ROOT, SERVICES, Runtime, RuntimeFailure, command
from scripts.pep_lab import DOCUMENT_HASH


class Checks:
    def __init__(self, directory):
        self.runtime = Runtime(directory)
        if self.runtime.descriptor.exists():
            raise ValueError("validation_requires_fresh_directory")
        self.path = Path(directory) / "verification.json"
        self.report = {"schema": "continuous-mtls-verification-1", "completed": False,
                       "started_at": datetime.now(UTC).isoformat(), "checks": []}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.report, indent=2) + "\n")

    @staticmethod
    def require(condition, label):
        if not condition:
            raise RuntimeFailure(label)

    def add(self, label, **evidence):
        self.report["checks"].append({"label": label, "passed": True, **evidence})
        self.save()
        print(json.dumps({"check": label, "passed": True}), flush=True)

    def wait(self, predicate, label):
        try:
            self.runtime.wait(predicate)
        except RuntimeFailure:
            raise RuntimeFailure(label) from None

    def inspect(self, service):
        return json.loads(command(["docker", "inspect", self.runtime.container(service)]))[0]

    def history(self, session_id):
        result = self.runtime.probe({"profile": "core", "path": "/zero-trust/sessions/" + session_id})
        self.require(result["status"] == 200, "history_unavailable")
        return result["body"]

    def journal(self):
        return json.loads(self.runtime.execute("app", ["python", "-m", "scripts.policy_journal",
            "status", "--database", "/data/zero-trust.sqlite3"]))

    def journal_boundary(self):
        # Generate audit rows inside the real shared SQLite transaction. This is
        # a storage boundary test, not a throughput claim about 10,020 HTTP calls.
        program = """from pathlib import Path
from datetime import UTC,datetime
from app.services.zero_trust import ZeroTrustOperations
s=ZeroTrustOperations(Path('/data/zero-trust.sqlite3'))
with s._transaction() as t:
 for i in range(10020):
  s._append(t,{'kind':'access','tenant_id':'local','operator_id':'journal-boundary',
   'session_id':'boundary-no-session','resource_id':'zt-demo-documents','action':'READ',
   'session_version':None,'allowed':False,'reason_code':'GRANT_INVALID',
   'grant_hash':'0'*64,'recorded_at':datetime.now(UTC).isoformat()})
"""
        self.runtime.execute("app", ["python", "-c", program], timeout=90)
        state = self.journal()
        self.require(state["total_records"] >= 10020 and state["archived_records"] > 0
                     and state["active_records"] <= 10000, "journal_boundary_not_archived")
        self.add("policy_journal_continues_after_ten_thousand_records",
                 total_records=state["total_records"], archived_records=state["archived_records"],
                 active_records=state["active_records"], generated_audit_rows=10020)

    def journal_security(self, spent):
        revoked = self.mint("runtime-journal-revoked", user_id=OTHER, device_id=DEVICES[1])
        result = self.runtime.probe({"profile": "core", "method": "POST",
            "path": "/zero-trust/sessions/" + revoked[0] + "/revoke",
            "body": {"expected_version": 1, "note": "Journal maintenance regression"}})
        self.require(result["status"] == 200 and result["body"]["status"] == "REVOKED",
                     "journal_revoke_failed")
        before = self.journal()
        self.runtime.execute("app", ["python", "-m", "scripts.policy_journal", "compact",
            "--database", "/data/zero-trust.sqlite3", "--limit", "10000"], timeout=90)
        after = self.journal()
        self.require(after["active_records"] == 0 and after["total_records"] == before["total_records"]
                     and after["archived_records"] == after["total_records"], "journal_compaction_lost_history")
        self.access(spent, False, "archived_consumed_token_denies_document")
        replay = self.runtime.probe({"profile": "core", "method": "POST",
            "path": "/zero-trust/protected-access", "body": {
                "session_id": spent[0], "resource_id": "zt-demo-documents",
                "action": "READ", "grant_token": spent[1]}})
        self.require(replay["status"] == 403 and replay["body"]["reason_code"] == "GRANT_ALREADY_USED",
                     "archived_consumption_marker_missing")
        self.access(revoked, False, "archived_revocation_denies_unconsumed_token")
        self.require(len(self.history(spent[0])) == 1 and len(self.history(revoked[0])) == 2,
                     "archive_changed_session_history")
        # This explicit restart checks restored history; the later SIGKILL check
        # separately exercises Docker's automatic restart manager.
        command(["docker", "restart", self.runtime.container("app")])
        self.wait(lambda: self.runtime.probe({"profile": "core", "path": "/health/live"})["status"] == 200,
                  "journal_restart_not_ready")
        self.access(revoked, False, "journal_restart_preserves_revoked_access_denial")
        self.require(len(self.history(revoked[0])) == 2 and self.journal()["archived_records"] == after["archived_records"],
                     "journal_restart_changed_archive")
        self.add("journal_checkpoint_retains_sessions_consumption_and_revocation_after_restart",
                 archived_records=after["archived_records"], consumed_reason="GRANT_ALREADY_USED",
                 revoked_versions=2)

    def mint(self, label, **options):
        result = self.runtime.mint({"session_id": label, **options})
        self.require(result["status"] == 200 and result["body"]["grant_token"], "mint_failed")
        self.require(result["body"]["session"]["status"] == "ACTIVE", "mint_not_active")
        return label, result["body"]["grant_token"]

    def inbox_snapshot(self):
        program = """import hashlib,json
from pathlib import Path
from app.services.signal_inbox import SignalInbox
s=SignalInbox(Path('/data/zero-trust.sqlite3'))
with s._transaction() as c:
 rows=[r for r in s._rows(c) if r['event_id'].startswith('runtime-inbox-')]
print(json.dumps({'storage':s.storage_status(),'live_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'states':sorted(r['state'] for r in rows)}))
"""
        return json.loads(self.runtime.execute("app", ["python", "-c", program]))

    def inbox_security(self, affected):
        # Keep a live lease and a pending delivery while archiving a real receipt.
        # Direct mTLS submissions here do not alter the collector's feed counters.
        event_id = "runtime-outage-observation"
        original_receipt = self.receipt(event_id)["body"]
        original = json.loads(self.runtime.execute("app", ["python", "-c", """from pathlib import Path
from app.services.signal_inbox import SignalInbox
s=SignalInbox(Path('/data/zero-trust.sqlite3'))
with s._transaction() as c:print(next(r['payload'] for r in s._rows(c) if r['event_id']=='runtime-outage-observation'))
"""]))
        program = """import base64,json,sys
from pathlib import Path
from datetime import UTC,datetime,timedelta
from cryptography.hazmat.primitives import serialization
from app.continuous_signal_models import SignedContinuousSignal
from app.services.trusted_signals import canonical_observation
d=Path('/collector/producer')
key=serialization.load_pem_private_key((d/'private.pem').read_bytes(),password=None)
cfg=json.loads((d/'config.json').read_text())
old=json.load(sys.stdin)
def sign(value):
 value['signature']='A'*86
 signal=SignedContinuousSignal.model_validate(value)
 value['signature']=base64.urlsafe_b64encode(key.sign(canonical_observation(signal))).decode().rstrip('=')
 return value
now=datetime.now(UTC)
items={}
for label in ('processing','pending'):
 value={'tenant_id':cfg['tenant_id'],'source_id':cfg['source_id'],'key_id':cfg['key_id'],
 'event_id':'runtime-inbox-'+label,'issued_at':now.isoformat(),'observed_at':now.isoformat(),
 'expires_at':(now+timedelta(seconds=90)).isoformat(),
 'observation':{'kind':'identity','subject_id':SUBJECT,'active':True,'authentication_result':'success'}}
 items[label]=sign(value)
old['observation'].update(active=True,authentication_result='success')
items['conflict']=sign(old)
print(json.dumps(items))
""".replace("SUBJECT", repr(OTHER))
        signed = json.loads(self.runtime.execute("collector", ["python", "-c", program], json.dumps(original)))
        worker_id = self.runtime.container("worker")
        command(["docker", "stop", "--time", "2", worker_id])
        for label in ("processing", "pending"):
            result = self.runtime.probe({"profile": "core", "method": "POST",
                "path": "/zero-trust/signals/inbox", "body": signed[label]})
            self.require(result["status"] == 202 and result["body"]["state"] == "pending",
                         "inbox_live_delivery_not_accepted")
        claimed = json.loads(self.runtime.execute("app", ["python", "-c", """import json
from pathlib import Path
from datetime import UTC,datetime
from app.services.signal_inbox import SignalInbox
s=SignalInbox(Path('/data/zero-trust.sqlite3'),lease_seconds=1)
r=s.claim(now=datetime.now(UTC))
print(json.dumps({'event_id':r['event_id'],'state':r['state']}))
"""]))
        self.require(claimed == {"event_id": "runtime-inbox-processing", "state": "processing"},
                     "inbox_processing_lease_missing")
        before = self.inbox_snapshot()
        compact = json.loads(self.runtime.execute("app", ["python", "-m", "scripts.signal_inbox", "compact",
            "--database", "/data/zero-trust.sqlite3", "--limit", "10000"]))
        after = self.inbox_snapshot()
        self.require(compact["compacted"] == 1 and after["storage"]["archived_records"] == 1
                     and after["storage"]["active_records"] == 2
                     and before["live_sha256"] == after["live_sha256"]
                     and after["states"] == ["pending", "processing"], "inbox_compaction_changed_live_work")
        self.add("server_inbox_archive_preserves_pending_processing_and_lease", archived_records=1, live_records=2)
        duplicate = self.runtime.probe({"profile": "core", "method": "POST",
            "path": "/zero-trust/signals/inbox", "body": original})
        conflict = self.runtime.probe({"profile": "core", "method": "POST",
            "path": "/zero-trust/signals/inbox", "body": signed["conflict"]})
        self.require(duplicate["status"] == 202 and duplicate["body"]["duplicate"]
                     and duplicate["body"]["state"] == "completed" and conflict["status"] == 409,
                     "archived_inbox_identity_contract_changed")
        self.add("archived_inbox_exact_duplicate_and_valid_conflict_over_mtls", duplicate_status=202, conflict_status=409)
        command(["docker", "restart", self.runtime.container("app")])
        self.wait(lambda: self.runtime.probe({"profile": "core", "path": "/health/live"})["status"] == 200,
                  "inbox_restart_not_ready")
        restarted = self.inbox_snapshot()
        self.require(restarted == after and self.receipt(event_id)["body"] == original_receipt,
                     "inbox_restart_lost_receipt_or_lease")
        command(["docker", "start", worker_id])
        self.wait(lambda: self.completed("runtime-inbox-processing") and self.completed("runtime-inbox-pending"),
                  "inbox_live_deliveries_not_recovered")
        self.require(len(self.history(affected[0])) == 2 and self.receipt(event_id)["body"] == original_receipt,
                     "inbox_restart_reapplied_archived_effect")
        self.add("inbox_restart_recovers_pending_and_expired_lease_without_reapplying_archive", recovered=2)
        self.access(affected, False, "server_inbox_maintenance_restart_preserves_revoked_access_denial")

    def served(self):
        result = self.runtime.probe({"profile": "resource", "path": "/_stats"})
        self.require(result["status"] == 200, "resource_stats_unavailable")
        return result["body"]["served"]

    def access(self, pair, allowed, label):
        before = self.served()
        result = self.runtime.probe({"profile": "frontend", "path": "/documents", "headers": {
            "X-Session-ID": pair[0], "X-Grant-Token": pair[1]}})
        self.require(result["status"] == (200 if allowed else 403), label + "_status")
        self.require((result["body_sha256"] == DOCUMENT_HASH) == allowed, label + "_content")
        self.require(self.served() - before == int(allowed), label + "_deliveries")
        self.require(result["tls_version"] in {"TLSv1.2", "TLSv1.3"}, label + "_tls")
        self.add(label, status=result["status"], resource_deliveries=int(allowed), tls_version=result["tls_version"])

    def collector(self):
        return json.loads(self.runtime.execute("collector", ["python", "-m", "scripts.continuous_signal_collector",
            "status", "--directory", "/collector/producer", "--base-url", "https://gateway:8443",
            "--tls-profile", "/tls/profile.json"]))

    def spool(self):
        program = """import hashlib,json,sqlite3
c=sqlite3.connect('/collector/producer/state.sqlite3')
rows=[json.loads(r[0]) for r in c.execute('SELECT record_json FROM collector_spool_records ORDER BY seq')]
print(json.dumps({'envelopes':[[hashlib.sha256(json.dumps(e,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest() for e in r['envelopes']] for r in rows]}))
"""
        return json.loads(self.runtime.execute("collector", ["python", "-c", program]))

    def maintenance(self, operation):
        # The long-lived sender is stopped before these production CLI commands
        # acquire its lock. The one-off shares only the collector's own mounts.
        return json.loads(self.runtime.compose("run", "--rm", "--no-deps", "-T",
            "--entrypoint", "python", "collector", "-m", "scripts.continuous_signal_collector",
            operation, "--directory", "/collector/producer", "--base-url", "https://gateway:8443",
            "--tls-profile", "/tls/profile.json"))

    def append(self, event_id, *, active=False, other=False):
        payload = {"event_id": event_id, "active": active,
                   "authentication_result": "success" if active else "failure",
                   "observed_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
        if other:
            payload["subject"] = OTHER
        self.append_record(payload)

    def append_record(self, payload):
        # A busy input lock is expected backpressure. Preserve the entire source
        # event even if the helper committed its append before losing its reply.
        wire = json.dumps(payload)

        def accepted():
            result = json.loads(self.runtime.execute("collector",
                ["python", "-m", "scripts.continuous_mtls_assets", "append"], wire))
            return isinstance(result, dict) and result.get("appended") is True

        self.wait(accepted, "managed_input_append_not_confirmed")

    def receipt(self, event_id):
        return self.runtime.probe({"profile": "core", "path": "/zero-trust/signals/inbox/" + event_id})

    def completed(self, event_id):
        result = self.receipt(event_id)
        return result["status"] == 200 and result["body"]["state"] == "completed"

    def restart(self, service):
        before = self.inspect(service)
        started = datetime.fromisoformat(before["State"]["StartedAt"])
        age = (datetime.now(UTC) - started).total_seconds()
        if age < 11:
            time.sleep(11 - age)
        # init:true makes Python a child of the namespace init. Killing that child
        # is not Docker's manual stop/kill API and exercises the restart manager.
        program = "import os,signal;from pathlib import Path;p=Path('/proc/1/task/1/children').read_text().split();assert len(p)==1 and int(p[0])>1;os.kill(int(p[0]),signal.SIGKILL)"
        try:
            self.runtime.execute(service, ["python", "-c", program])
        except RuntimeFailure:
            pass  # The exec can be torn down with the dying container namespace.
        self.wait(lambda: (after := self.inspect(service))["Id"] == before["Id"]
                  and after["State"]["Running"] and after["RestartCount"] > before["RestartCount"],
                  "automatic_restart_" + service)
        after = self.inspect(service)
        self.require(after["State"]["StartedAt"] != before["State"]["StartedAt"], "restart_time_unchanged")
        self.add("automatic_restart_" + service, same_container=True, before=before["RestartCount"],
                 after=after["RestartCount"], exit_signal="SIGKILL to Python child, not Docker stop")

    def run(self):
        runtime = self.runtime
        runtime.up()
        self.report["project"] = runtime.state["project"]
        self.report["image_id"] = runtime.state["image_id"]
        self.report["source_commit"] = runtime.state["source_commit"]
        self.report["source_dirty"] = runtime.state["source_dirty"]
        self.report["source_input_sha256"] = runtime.state["source_sha256"]
        self.report["configuration_sha256"] = runtime.state["configuration_sha256"]
        self.report["image_source_verified"] = runtime.state["image_source_verified"]
        hardening = {}
        for service in SERVICES:
            data = self.inspect(service)
            host = data["HostConfig"]
            self.require(data["Config"]["User"] == "10001:10001" and host["ReadonlyRootfs"]
                         and "ALL" in host["CapDrop"] and "no-new-privileges:true" in host["SecurityOpt"]
                         and host["RestartPolicy"]["Name"] == "unless-stopped" and host["Init"]
                         and not host.get("PortBindings"), "runtime_hardening_" + service)
            self.require(all(m["Type"] != "bind" for m in data["Mounts"]), "runtime_host_bind")
            if service in {"worker", "watchdog"}:
                self.require(host["NetworkMode"] == "none", "background_network_scope")
                actual = {m["Name"] for m in data["Mounts"] if m["Type"] == "volume"}
                self.require(actual == {runtime.state["volumes"][n] for n in ("data", "registry")}, "background_key_scope")
            hardening[service] = {"network_mode": host["NetworkMode"], "restart": "unless-stopped",
                                  "init": True, "uid": "10001:10001", "read_only": True, "published_ports": False}
        nets = [json.loads(line) for line in command(["docker", "network", "ls", "--filter",
                "label=secops.runtime=" + runtime.state["project"], "--format", "{{json .}}"]).splitlines()]
        self.require(len(nets) == 6, "runtime_network_count")
        for network in nets:
            self.require(json.loads(command(["docker", "network", "inspect", network["ID"]]))[0]["Internal"], "runtime_external_network")
        self.add("nine_hardened_services_and_six_internal_networks", services=hardening)
        self.journal_boundary()
        normal = self.mint("runtime-normal")
        self.access(normal, True, "normal_mtls_document_delivery")
        self.journal_security(normal)

        affected = self.mint("runtime-outage")
        unrelated = self.mint("runtime-unrelated", user_id=OTHER, device_id=DEVICES[1])
        app_id = runtime.container("app")
        command(["docker", "stop", "--time", "2", app_id])
        self.append("runtime-outage-observation")
        self.wait(lambda: (s := self.collector())["captured"] == 1 and s["pending"] == 1
                  and bool(self.spool()["envelopes"][0]), "outage_spooled")
        first, original = self.collector(), self.spool()["envelopes"][0][0]
        self.restart("collector")
        self.restart("worker")
        self.wait(lambda: self.collector()["pending"] == 1, "pending_after_restart")
        self.require(self.collector()["offset"] == first["offset"]
                     and self.spool()["envelopes"][0][0] == original, "spool_restart_changed_input")
        command(["docker", "start", app_id])
        self.wait(lambda: self.completed("runtime-outage-observation") and self.collector()["acknowledged"] == 1,
                  "outage_recovered")
        self.require(len(self.history(affected[0])) == 2 and self.history(affected[0])[-1]["status"] == "REVOKED",
                     "outage_policy_effect_count")
        self.require(self.spool()["envelopes"][0][0] == original, "outage_envelope_lost")
        self.add("outage_restart_recovers_persisted_envelope_once", original_envelope_sha256=original,
                 captured=1, acknowledged=1, policy_transitions=1)
        self.access(affected, False, "recovered_observation_denies_unconsumed_grant")
        self.access(unrelated, True, "unrelated_subject_still_receives_document")

        # Repeat the exact input line: no new event ID and no second policy effect.
        first_event = runtime.execute("collector", ["python", "-c",
            "from pathlib import Path;print(Path('/collector/producer/input.jsonl').read_text().splitlines()[0])"])
        self.append_record(json.loads(first_event))
        self.wait(lambda: self.collector()["offset"] == 2 * first["offset"], "duplicate_input_captured")
        self.require(self.collector()["captured"] == 1 and len(self.history(affected[0])) == 2, "duplicate_policy_effect")
        self.add("duplicate_feed_preserves_one_receipt_and_policy_effect")
        self.inbox_security(affected)

        # Compact a confirmed receipt while a second exact signed transmission
        # is pending during an API outage, then rotate its fully captured feed.
        command(["docker", "stop", "--time", "2", app_id])
        self.append("runtime-maintenance-pending", active=True, other=True)
        self.wait(lambda: (s := self.collector())["captured"] == 2 and s["pending"] == 1
                  and bool(self.spool()["envelopes"][1]), "maintenance_pending_not_staged")
        pending_digest = self.spool()["envelopes"][1][0]
        command(["docker", "stop", "--time", "2", runtime.container("collector")])
        compacted = self.maintenance("compact")
        self.require(compacted["compacted"] == 1 and compacted["storage"]["retained"] == 1
                     and compacted["pending"] == 1 and compacted["acknowledged"] == 1,
                     "maintenance_changed_pending_or_counters")
        rotated = self.maintenance("rotate")
        self.require(rotated["rotated"] and rotated["input_generation"] == 1
                     and rotated["offset"] == 0 and rotated["pending"] == 1
                     and rotated["captured"] == 2, "maintenance_rotation_failed")
        self.add("compaction_and_rotation_preserve_pending_and_duplicate_history",
                 compacted=1, retained_pending=1, input_generation=1)
        command(["docker", "start", runtime.container("collector")])
        command(["docker", "start", app_id])
        self.wait(lambda: self.completed("runtime-maintenance-pending")
                  and self.collector()["acknowledged"] == 2, "maintenance_delivery_not_recovered")
        self.require(self.spool()["envelopes"][0][0] == pending_digest,
                     "maintenance_changed_persisted_envelope")
        self.add("pending_exact_envelope_recovers_over_mtls_after_maintenance",
                 original_envelope_sha256=pending_digest, acknowledged=2)
        self.append_record(json.loads(first_event))
        self.wait(lambda: self.collector()["offset"] > 0, "compacted_duplicate_not_read")
        self.require(self.collector()["captured"] == 2 and self.collector()["acknowledged"] == 2
                     and len(self.history(affected[0])) == 2, "compacted_duplicate_reapplied")
        self.add("compacted_duplicate_skipped_across_input_generation")
        self.access(affected, False, "maintenance_restart_preserves_revoked_access_denial")

        short = self.mint("runtime-expiry", user_id=OTHER, device_id=DEVICES[1], expires_seconds=8)
        self.restart("watchdog")
        self.wait(lambda: self.history(short[0])[-1]["status"] == "HELD", "expiry_without_input")
        self.require(len(self.history(short[0])) == 2 and "SIGNAL_PROOF_EXPIRED" in self.history(short[0])[-1]["reason_codes"],
                     "expiry_reason")
        self.access(short, False, "expired_proof_denies_unconsumed_grant")
        self.add("watchdog_restart_records_expiry_without_new_input", session_versions=2)

        # A wrong server pin must retain the event, with no cleartext fallback.
        tls_profile = json.loads(runtime.execute("collector", ["python", "-c", "from pathlib import Path;print(Path('/tls/profile.json').read_text())"]))
        runtime.write_volume("collector-tls", {"profile.json": json.dumps(tls_profile | {"server_pins": ["0" * 64]})})
        self.append("runtime-bad-server-pin", active=True, other=True)
        self.wait(lambda: (s := self.collector())["captured"] == 3 and s["pending"] == 1
                  and s["last_error"] == "TRANSPORT_OR_RECEIPT_INVALID", "tls_failure_pending")
        self.require(self.receipt("runtime-bad-server-pin")["status"] == 404, "bad_tls_reached_api")
        runtime.write_volume("collector-tls", {"profile.json": json.dumps(tls_profile)})
        self.wait(lambda: self.completed("runtime-bad-server-pin") and self.collector()["acknowledged"] == 3, "tls_profile_recovered")
        self.add("server_pin_failure_retains_event_and_same_path_profile_recovers")

        revoked = self.mint("runtime-key-revoked", user_id=OTHER, device_id=DEVICES[1])
        registry = json.loads(runtime.execute("app", ["python", "-c", "from pathlib import Path;print(Path('/signals/sources.json').read_text())"]))
        next(s for s in registry["sources"] if s["source_id"] == "runtime-session")["keys"][0]["enabled"] = False
        runtime.write_volume("registry", {"sources.json": json.dumps(registry)})
        self.wait(lambda: self.history(revoked[0])[-1]["status"] == "REVOKED", "key_revocation_without_input")
        self.require(len(self.history(revoked[0])) == 2, "key_revocation_duplicate")
        self.access(revoked, False, "revoked_signing_key_denies_unconsumed_grant")
        self.restart("app")
        self.wait(lambda: runtime.probe({"profile": "core", "path": "/health/live"})["status"] == 200, "app_ready_after_restart")
        self.require(len(self.history(revoked[0])) == 2 and self.history(revoked[0])[-1]["status"] == "REVOKED",
                     "revocation_lost_on_app_restart")
        self.access(revoked, False, "app_restart_preserves_revocation")
        self.add("source_key_revocation_visible_through_atomic_registry_replacement")

        # New observation work continues after all four process restarts.
        self.append("runtime-followup", active=True, other=True)
        self.wait(lambda: self.completed("runtime-followup") and self.collector()["acknowledged"] == 4,
                  "followup_after_restarts")
        self.require(len(self.history(revoked[0])) == 2, "positive_observation_restored_revoked_session")
        self.add("collector_worker_watchdog_app_continue_without_reviving_access")
        self.report["completed"] = True

    def cleanup(self):
        if self.runtime.descriptor.exists():
            self.runtime.down(purge=True)
            project = self.runtime.state["project"]
            remaining = {}
            for label, argv in {"containers": ["ps", "-aq"], "volumes": ["volume", "ls", "-q"],
                                "networks": ["network", "ls", "-q"]}.items():
                remaining[label] = len(command(["docker", *argv, "--filter", "label=secops.runtime=" + project]).splitlines())
            self.report["cleanup"] = remaining
            self.require(not any(remaining.values()), "runtime_cleanup_incomplete")
        self.report["finished_at"] = datetime.now(UTC).isoformat()
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/continuous-mtls-validation")
    args = parser.parse_args()
    checks = Checks(args.directory)
    try:
        checks.run()
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        checks.report["completed"] = False
        checks.report["failure"] = str(exc) if isinstance(exc, RuntimeFailure) else type(exc).__name__
    finally:
        try:
            checks.cleanup()
        except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            checks.report["completed"] = False
            checks.report["cleanup_failed"] = True
            checks.save()
    print(json.dumps({"completed": checks.report["completed"], "checks": len(checks.report["checks"])}))
    return 0 if checks.report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
