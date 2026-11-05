"""Real Docker mTLS continuous-runtime fault tests; only owned test resources are purged."""

import argparse
import copy
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

from scripts.continuous_mtls_assets import DEVICES, OTHER
from scripts.continuous_mtls_runtime import ROOT, Runtime, RuntimeFailure, command
from scripts.pep_lab import DOCUMENT_HASH
from scripts.runtime_release import digest


class Checks:
    def __init__(self, directory, runtime_class=Runtime):
        self.runtime = runtime_class(directory)
        if self.runtime.descriptor.exists():
            raise ValueError("validation_requires_fresh_directory")
        self.path = Path(directory) / "verification.json"
        self.report = {"schema": "continuous-mtls-verification-1", "completed": False,
                       "started_at": datetime.now(UTC).isoformat(), "checks": []}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.report, indent=2) + "\n")

    def release_phase(self):
        runtime = self.runtime
        self.report["release_lock"] = copy.deepcopy(runtime.state["release"])
        self.report["nginx_image_id"] = runtime.state["nginx_image_id"]
        self.report["release_image_payload_verified"] = runtime.state["release_image_payload_verified"]
        self.require(runtime.verify_release() == runtime.state["release"]["sha256"]
                     and runtime.state["release_image_payload_verified"], "release_not_verified")
        self.add("runtime_release_inputs_and_image_payload_locked",
                 inputs=len(runtime.state["release"]["payload"]["files"]))
        original = runtime.descriptor.read_bytes()
        state = copy.deepcopy(runtime.state)
        runtime.compose("stop", "--timeout", "2")

        def stopped():
            self.require(all(not row["running"] for row in runtime.status()["services"].values()),
                         "release_fault_started_workloads")

        def rejected(label, expected):
            try:
                runtime.up()
            except (RuntimeFailure, ValueError) as error:
                self.require(str(error) == expected, "release_wrong_denial")
            else:
                raise RuntimeFailure("release_drift_accepted")
            stopped()
            self.add(label, workloads_stayed_stopped=True, denial=expected)

        try:
            changed = copy.deepcopy(state)
            changed["release"]["payload"]["files"]["Dockerfile"] = "0" * 64
            changed["release"]["sha256"] = digest(changed["release"]["payload"])
            runtime.descriptor.write_text(json.dumps(changed))
            rejected("modified_release_refused_before_start", "runtime_release_changed_or_missing")
            legacy = copy.deepcopy(state)
            legacy.pop("release")
            runtime.descriptor.write_text(json.dumps(legacy))
            rejected("legacy_runtime_not_silently_upgraded", "runtime_release_changed_or_missing")
            runtime.descriptor.write_bytes(original)
            runtime.load()
            command(["docker", "image", "tag", state["nginx_image_id"], state["image"]])
            try:
                rejected("replaced_app_tag_refused", "runtime_image_identity_mismatch")
            finally:
                command(["docker", "image", "tag", state["image_id"], state["image"]])
            configured = (ROOT / "infra/mtls/all-hops-nginx.conf").read_text(encoding="utf-8")
            runtime.write_volume("config", {"all-hops.conf": configured + "\n# synthetic unapproved edit\n"})
            try:
                rejected("modified_proxy_volume_refused", "runtime_public_configuration_changed")
            finally:
                runtime.write_volume("config", {"all-hops.conf": configured})
        finally:
            runtime.descriptor.write_bytes(original)
            runtime.load()
        # Host YAML must not be a second mutable deployment authority.
        runtime.manifest.write_text("services: {unexpected: {image: arbitrary:latest}}\n")
        before = self.credential_fingerprints()
        runtime.up()
        spec = json.loads(runtime.compose("config", "--format", "json"))
        self.require(set(spec["services"]) == set(runtime.services), "release_service_inventory")
        for name, service in spec["services"].items():
            image_id = runtime.expected_image(name)
            self.require(service["image"] == image_id and service["pull_policy"] == "never"
                         and self.inspect(name)["Image"] == image_id, "release_running_image_drift")
        self.add("compose_rebuilt_with_local_image_ids", service_count=len(runtime.services), automatic_pull=False)
        self.require(self.credential_fingerprints() == before, "release_resume_replaced_credentials")
        self.add("clean_resume_preserves_credential_volume_fingerprints", volumes=4)

    def credential_fingerprints(self):
        result = {}
        program = """import hashlib,json
from pathlib import Path
print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/data').iterdir() if p.is_file()}))
"""
        for label in ("core-tls", "operator-auth", "registry", "collector-tls"):
            result[label] = json.loads(command(["docker", "run", "--rm", "--network", "none", "--read-only",
                "--user", "10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                "--mount", f"type=volume,src={self.runtime.state['volumes'][label]},dst=/data,readonly",
                "--entrypoint", "python", self.runtime.state["image_id"], "-c", program]))
        return result

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
        # A slow fault campaign can outlive the 60s grant. Verify the actual
        # archived consumption independently; expiry must never mask lost state.
        program = """import json,sys
from pathlib import Path
from app.services.zero_trust import ZeroTrustOperations
q=json.load(sys.stdin);s=ZeroTrustOperations(Path('/data/zero-trust.sqlite3'))
with s._transaction() as t:
 found=any(e['kind']=='access' and e.get('allowed') is True and
  e.get('session_id')==q['session'] and e.get('grant_hash')==q['hash'] for e in t[1])
print(json.dumps({'consumed':found}))
"""
        marker = json.loads(self.runtime.execute("app", ["python", "-c", program], json.dumps({
            "session": spent[0], "hash": hashlib.sha256(spent[1].encode()).hexdigest()})))
        self.require(marker == {"consumed": True}, "archived_consumption_marker_missing")
        reason = replay.get("body", {}).get("reason_code")
        expired = datetime.fromisoformat(self.history(spent[0])[0]["grant_expires_at"]) <= datetime.now(UTC)
        self.require(replay["status"] == 403 and (reason == "GRANT_ALREADY_USED" or
                     (expired and reason in {"GRANT_EXPIRED", "SIGNAL_PROOF_EXPIRED", "SESSION_NOT_AUTHORIZED"})),
                     "archived_replay_not_denied")
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
                 archived_records=after["archived_records"], consumed_reason=reason, consumed_marker_verified=True,
                 revoked_versions=2, expiry_watchdog_quiesced_for_snapshot=True)

    def journal_phase(self):
        # Keep this storage compatibility snapshot free of concurrent expiry
        # decisions. The watchdog is restarted even on failure, then exercised
        # live by security_versions and the subsequent process-fault campaign.
        watchdog = self.runtime.container("watchdog")
        command(["docker", "stop", "--time", "2", watchdog])
        try:
            normal = self.mint("runtime-normal")
            self.access(normal, True, "normal_mtls_document_delivery")
            self.journal_security(normal)
        finally:
            command(["docker", "start", watchdog])

    def unrelated_after_outage(self, pair, label="unrelated_subject_still_receives_document", *,
                               record_label="outage_control_policy_and_expiry_are_distinct"):
        # Availability after an arbitrarily slow outage requires fresh proof.
        # The old session may legitimately be HELD by the expiry watchdog, but
        # an observation about a different subject must never revoke it.
        history = self.history(pair[0])
        self.unrelated_history(history)
        expired = datetime.fromisoformat(history[0]["grant_expires_at"]) <= datetime.now(UTC)
        reason = None
        post_request_history_verified = False
        if expired:
            result = self.runtime.probe({"profile": "core", "path": "/zero-trust/protected-access",
                "method": "POST", "body": {"session_id": pair[0], "resource_id": "zt-demo-documents",
                                            "action": "READ", "grant_token": pair[1]}})
            reason = result.get("body", {}).get("reason_code")
            permitted = {"GRANT_EXPIRED", "SIGNAL_PROOF_EXPIRED"}
            if reason == "SESSION_NOT_AUTHORIZED":
                # The watchdog can append HELD after the pre-request snapshot.
                # Re-read verified history rather than interpreting that safe
                # denial as revival. Never accept REVOKED/changed history or a
                # successful access, and never retry the consumed request.
                after = self.history(pair[0])
                self.unrelated_history(after)
                self.require(after[:len(history)] == history, "outage_control_history_changed")
                if after[-1]["status"] == "HELD":
                    permitted.add("SESSION_NOT_AUTHORIZED")
                    post_request_history_verified = True
                history = after
            self.require(result["status"] == 403 and reason in permitted, "outage_expired_control_revived")
        fresh = self.mint(pair[0] + "-fresh", user_id=OTHER, device_id=DEVICES[1])
        self.access(fresh, True, label)
        self.add(record_label, original_versions=len(history),
                 expired_original_denied=expired, expired_reason=reason, fresh_proof_used=True,
                 post_request_expiry_history_verified=post_request_history_verified)

    def unrelated_history(self, history):
        self.require(bool(history) and history[0]["version"] == 1 and history[0]["decision"] == "ALLOW",
                     "outage_control_initial_decision")
        for previous, current in pairwise(history):
            self.require(current["version"] == previous["version"] + 1 and current["decision"] == "HOLD"
                         and current["status"] == "HELD" and "SIGNAL_PROOF_EXPIRED" in current["reason_codes"],
                         "outage_changed_unrelated_policy")

    def mint(self, label, **options):
        result = self.runtime.mint({"session_id": label, **options})
        self.require(result["status"] == 200 and result["body"]["grant_token"], "mint_failed")
        self.require(result["body"]["session"]["status"] == "ACTIVE", "mint_not_active")
        return label, result["body"]["grant_token"]

    def security_checkpoint(self, session_id):
        # Explicit synthetic legacy boundary, not 200 live evaluations. Keep the
        # original decision and append a synthetic non-granting v200 checkpoint.
        program = """import json,sys
from pathlib import Path
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import SessionDecision
s=ZeroTrustOperations(Path('/data/zero-trust.sqlite3'))
name=json.load(sys.stdin)
with s._transaction() as t:
 old=s._latest(t[1],'local',name)['session']
 capped=SessionDecision.model_validate({**old,'version':200,'decision':'HOLD','status':'HELD',
  'event_id':'boundary-'+name,'reason_codes':[*old['reason_codes'],'SESSION_HISTORY_CAPACITY'],
  'grant_expires_at':None,'challenge_id':None,'challenge_expires_at':None})
 s._append(t,{'kind':'decision','session':capped.model_dump(mode='json'),'grant_hash':None})
print(json.dumps({'version':200,'synthetic_checkpoint':True}))
"""
        result = json.loads(self.runtime.execute("app", ["python", "-c", program], json.dumps(session_id)))
        self.require(result == {"version": 200, "synthetic_checkpoint": True}, "security_checkpoint_failed")
        return self.history(session_id)

    def security_denial(self, pair, version):
        result = self.runtime.probe({"profile": "core", "path": "/zero-trust/protected-access",
            "method": "POST", "body": {"session_id": pair[0], "resource_id": "zt-demo-documents",
                                        "action": "READ", "grant_token": pair[1]}})
        self.require(result["status"] == 403 and result["body"]["reason_code"] == "SESSION_NOT_AUTHORIZED"
                     and result["body"]["session_version"] == version, "security_tail_denial_reason")

    def security_versions(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Dedicated subjects and registry entries keep these fault tests separate
        # from the existing collector feed counters and the original campaign.
        registry = json.loads(self.runtime.execute("app", ["python", "-c",
            "from pathlib import Path;print(Path('/signals/sources.json').read_text())"]))
        session_source = json.loads(json.dumps(next(s for s in registry["sources"]
                                                    if s["source_id"] == "runtime-session")))
        observation_source = next(s for s in registry["sources"] if s.get("observation_kinds") == ["identity"])
        users = ["runtime-tail-risk", "runtime-tail-expiry"]
        key = Ed25519PrivateKey.generate()
        session_source.update(source_id="runtime-tail-session", user_ids=users, device_ids=["runtime-tail-device"])
        session_source["keys"][0]["public_key_pem"] = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.runtime.write_volume("operator-auth", {"tail-private.pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()})
        observation_source["user_ids"] = list(dict.fromkeys([*observation_source["user_ids"], *users]))
        observation_source["device_ids"] = list(dict.fromkeys([*observation_source["device_ids"], "runtime-tail-device"]))
        registry["sources"].append(session_source)
        self.runtime.write_volume("registry", {"sources.json": json.dumps(registry)})

        options = {"source_id": "runtime-tail-session", "device_id": "runtime-tail-device",
                   "signing_key_file": "tail-private.pem"}
        capped = self.mint("runtime-tail-capped", user_id=users[0], **options)
        related = self.mint("runtime-tail-related", user_id=users[0], **options)
        original = self.security_checkpoint(capped[0])
        program = """import base64,json
from pathlib import Path
from datetime import UTC,datetime,timedelta
from cryptography.hazmat.primitives import serialization
from app.continuous_signal_models import SignedContinuousSignal
from app.services.trusted_signals import canonical_observation
d=Path('/collector/producer');cfg=json.loads((d/'config.json').read_text())
key=serialization.load_pem_private_key((d/'private.pem').read_bytes(),password=None)
now=datetime.now(UTC)-timedelta(seconds=1)
s=SignedContinuousSignal(tenant_id=cfg['tenant_id'],source_id=cfg['source_id'],
 key_id=cfg['key_id'],event_id='runtime-tail-risk-observation',issued_at=now,observed_at=now,
 expires_at=now+timedelta(seconds=90),signature='A'*86,
 observation={'kind':'identity','subject_id':'runtime-tail-risk','active':False,'authentication_result':'failure'})
payload=s.model_dump(mode='json')
payload['signature']=base64.urlsafe_b64encode(key.sign(canonical_observation(s))).decode().rstrip('=')
print(json.dumps(payload))
"""
        payload = json.loads(self.runtime.execute("collector", ["python", "-c", program]))
        accepted = self.runtime.probe({"profile": "core", "path": "/zero-trust/signals/inbox",
                                       "method": "POST", "body": payload})
        self.require(accepted["status"] == 202, "security_tail_observation_not_accepted")
        self.wait(lambda: self.completed(payload["event_id"]), "security_tail_fanout_not_completed")
        history = self.history(capped[0])
        self.require(history[:-1] == original and history[-1]["version"] == 201
                     and history[-1]["status"] == "REVOKED"
                     and self.history(related[0])[-1]["version"] == 2, "security_tail_fanout_lost_history")
        replay = self.runtime.probe({"profile": "core", "path": "/zero-trust/signals/inbox",
                                     "method": "POST", "body": payload})
        self.require(replay["status"] == 202 and replay["body"]["duplicate"]
                     and self.history(capped[0]) == history, "security_tail_duplicate_reapplied")
        self.security_denial(capped, 201)
        self.security_denial(related, 2)
        self.access(related, False, "version200_fanout_denies_related_document")
        control = self.mint("runtime-tail-control", user_id=OTHER, device_id=DEVICES[1])
        self.access(control, True, "version200_fanout_preserves_unrelated_document")
        self.add("version200_observation_fanout_and_duplicate_preserve_history",
                 synthetic_checkpoint=True, capped_version=201, related_version=2)

        self.runtime.execute("app", ["python", "-m", "scripts.policy_journal", "compact",
                                      "--database", "/data/zero-trust.sqlite3", "--limit", "10000"])
        command(["docker", "restart", *(self.runtime.container(s) for s in ("app", "worker", "watchdog"))])
        self.wait(lambda: self.runtime.probe({"profile": "core", "path": "/health/live"})["status"] == 200,
                  "security_tail_restart_not_ready")
        self.require(self.history(capped[0]) == history and self.completed(payload["event_id"]),
                     "security_tail_restart_lost_archive")
        self.access(capped, False, "archived_security_tail_restart_denies_document")
        self.add("archived_security_tail_and_receipt_survive_app_worker_watchdog_restart", version=201)

        watchdog = self.runtime.container("watchdog")
        command(["docker", "stop", "--time", "2", watchdog])
        expiring = self.mint("runtime-tail-expiring", user_id=users[1], expires_seconds=12, **options)
        original = self.security_checkpoint(expiring[0])
        fresh = self.mint("runtime-tail-fresh", user_id=users[1], **options)
        command(["docker", "start", watchdog])
        self.wait(lambda: self.history(expiring[0])[-1]["version"] == 201, "version200_expiry_not_recorded")
        held = self.history(expiring[0])
        self.require(held[:-1] == original and held[-1]["status"] == "HELD"
                     and "SIGNAL_PROOF_EXPIRED" in held[-1]["reason_codes"], "version200_expiry_lost_history")
        self.add("version200_watchdog_records_expiry_without_input", synthetic_checkpoint=True, version=201)
        control = self.mint("runtime-tail-key-control", user_id=OTHER, device_id=DEVICES[1])
        registry = json.loads(self.runtime.execute("app", ["python", "-c",
            "from pathlib import Path;print(Path('/signals/sources.json').read_text())"]))
        next(s for s in registry["sources"] if s["source_id"] == "runtime-tail-session")["keys"][0]["enabled"] = False
        self.runtime.write_volume("registry", {"sources.json": json.dumps(registry)})
        self.wait(lambda: self.history(expiring[0])[-1]["status"] == "REVOKED"
                  and self.history(fresh[0])[-1]["status"] == "REVOKED", "version200_key_revoke_not_recorded")
        final = self.history(expiring[0])
        self.require(final[:-1] == held and final[-1]["version"] == 202
                     and self.history(fresh[0])[-1]["version"] == 2, "version200_key_revoke_changed_history")
        repeated = json.loads(self.runtime.execute("watchdog", ["python", "-m", "scripts.session_watchdog", "--once"]))
        self.require(repeated["watchdog"] == "revalidated" and self.history(expiring[0]) == final
                     and self.history(fresh[0])[-1]["version"] == 2,
                     "security_tail_watchdog_repeated_effect")
        self.security_denial(expiring, 202)
        self.security_denial(fresh, 2)
        self.access(fresh, False, "version200_watchdog_key_revocation_denies_related_document")
        self.unrelated_after_outage(control, "version200_watchdog_preserves_unrelated_document",
                                    record_label="version200_control_policy_and_expiry_are_distinct")
        self.add("version200_watchdog_key_revocation_and_repeat_are_idempotent", version=202)

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
        terminal_count = before["storage"]["active_records"] - len(before["states"])
        self.require(compact["compacted"] == terminal_count and terminal_count >= 1
                     and after["storage"]["archived_records"] == before["storage"]["archived_records"] + terminal_count
                     and after["storage"]["active_records"] == 2
                     and before["live_sha256"] == after["live_sha256"]
                     and after["states"] == ["pending", "processing"], "inbox_compaction_changed_live_work")
        self.add("server_inbox_archive_preserves_pending_processing_and_lease",
                 archived_records=after["storage"]["archived_records"], live_records=2)
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
        self.release_phase()
        hardening = {}
        for service in runtime.services:
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
        network_count = len(runtime.definition(runtime.state["project"], "app", "nginx")["networks"])
        self.require(len(nets) == network_count, "runtime_network_count")
        for network in nets:
            self.require(json.loads(command(["docker", "network", "inspect", network["ID"]]))[0]["Internal"], "runtime_external_network")
        self.add("nine_hardened_services_and_six_internal_networks" if len(runtime.services) == 9
                 else "monitored_hardened_services_and_internal_networks", services=hardening, networks=network_count)
        self.integration_checks()
        self.journal_boundary()
        self.journal_phase()
        self.security_versions()

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
        self.unrelated_after_outage(unrelated)

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

    def integration_checks(self):
        pass

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
    parser.add_argument("--monitoring", action="store_true", help="Include the optional C01 monitored profile")
    args = parser.parse_args()
    if args.monitoring:
        from scripts.test_monitored_mtls_runtime import MonitoredChecks
        checks = MonitoredChecks(args.directory)
    else:
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
