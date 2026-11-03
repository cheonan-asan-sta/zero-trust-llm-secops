"""Real local leaf-key rotation on the existing complete mTLS/CA experiment."""

import argparse
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scripts import test_signal_compose as flow
from scripts.certificate_key_rotation import public_hash
from scripts.compare_pep import ROOT, command
from scripts.compare_supply_chain import sha256
from scripts.test_certificate_automation import SERVERS, CertificateLab


class KeyRotationLab(CertificateLab):
    def __init__(self, directory):
        super().__init__(directory)
        self.report["schema"] = "private-key-rotation-1"

    def graph_authority(self):
        self.signing_keys = {name: ec.generate_private_key(ec.SECP256R1()) for name in SERVERS}
        return super().graph_authority()

    def server_signing_key(self, name):
        return self.signing_keys[name]

    def prepare(self):
        super().prepare()
        for name in ["scripts/certificate_key_rotation.py", "scripts/test_private_key_rotation.py",
                     "infra/mtls/nginx-rekey.sh", "infra/mtls/private-key-rotation-contract.json"]:
            self.report["source_input_sha256"][name] = sha256(ROOT / name)
        self.report["key_rotation_contract"] = json.loads((ROOT / "infra/mtls/private-key-rotation-contract.json").read_text())
        self.save()

    def node(self, label, files):
        if label == "proxy":
            files = files | {"nginx-rekey.conf": (ROOT / "infra/mtls/all-hops-nginx.conf").read_text()}
        return super().node(label, files)

    def start(self, name, network, argv, **kwargs):
        if name == self.prefix + "-proxy":
            kwargs["mounts"] = [*kwargs.get("mounts", []),
                f"type=bind,src={ROOT / 'infra/mtls/nginx-rekey.sh'},dst=/config/nginx-rekey.sh,readonly"]
        return super().start(name, network, argv, **kwargs)

    def service_command(self, label, argv):
        if label == "proxy":
            return ["sh", "/config/nginx-rekey.sh"]
        if label in {"prometheus", "am"}:
            return ["python", "-m", "scripts.certificate_reload_runner", "--ack", "/reload/ack", "--resolve-tls",
                    "--watch", "/service-tls/config.yml", "--watch", "/service-tls/web.yml", "--", *argv]
        return argv

    def setup_controller(self, volumes, policy_files, extras, *, probes=(), reload_groups=(), unmanaged=()):
        groups = [{"root": group["root"], "ack": group["ack"], "resolve_tls": True,
            "files": [group["root"] + "/" + name for name in
                      (["nginx-rekey.conf"] if group["root"].endswith("/proxy") else ["config.yml", "web.yml"])]}
                  for group in reload_groups]
        super().setup_controller(volumes, policy_files, extras, probes=probes, reload_groups=groups, unmanaged=unmanaged)
        # Separate fixed CA delegation keys from the rotating management mTLS keys.
        self.write_assets(volumes["renewal"], {"sign-" + name + ".key": key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode() for name, key in self.signing_keys.items()})
        self.controller_config["server_signers"] = {name: "/managed/renewal/sign-" + name + ".key" for name in SERVERS}
        if getattr(self, "key_smoke", False):
            self.controller_config["key_rotation"] = {"interval_seconds": 8, "cleanup_grace_seconds": 0, "configuration_files": []}
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})

    def private_rpc(self, program, payload=None):
        return json.loads(command(["docker", "exec", "-i", self.controller, "python", "-c", program],
                                  input=json.dumps(payload or {})))

    def audit(self):
        # Only public key digests/file names/permissions leave the private volume.
        return self.private_rpc("""import json,stat
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from scripts.certificate_key_rotation import public_hash
s=json.loads(Path('/state/state.json').read_bytes()); out={}
for uid,c in s['credentials'].items():
 if c.get('key_generation',0):
  assets=c['assets']; keys=[Path(a['key']) for a in assets]
  hashes=[public_hash(serialization.load_pem_private_key(p.read_bytes(),password=None).public_key()) for p in keys]
  out[uid]={'name':c['name'],'key_generation':c['key_generation'],'public_key_sha256':hashes[0],
   'copies_match':all(h==hashes[0] for h in hashes),'private_modes':sorted(set(stat.S_IMODE(p.stat().st_mode) for p in keys)),
   'pairs_match':all(public_hash(x509.load_pem_x509_certificate(Path(a['cert']).read_bytes()).public_key())==h for a,h in zip(assets,hashes)),
   'assets':assets}
print(json.dumps(out))""")

    def certificate_checks(self, record, keys):
        super().certificate_checks(record, keys)
        record["key_rotation_checks"] = checks = []
        def add(label, **details):
            checks.append({"label": label, "passed": True, **details})
            self.save()
        # The baseline deliberately expired/retired two canaries. They stay disabled.
        previous = record["certificate_final_public_status"]
        expired = [uid for uid, c in previous["credentials"].items() if c["name"] == "auto-canary"]
        self.controller_config["disabled"] += expired
        self.controller_config["renew_before"] = {"renew-" + name: 1200 for name in SERVERS}
        self.controller_config["key_rotation"] = {"interval_seconds": 60, "cleanup_grace_seconds": 2,
            "configuration_files": [p for group in self.controller_config["reload_groups"] for p in group["files"]]}
        self.controller_config["paused"] = True
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
        command(["docker", "start", self.controller])
        self.wait(lambda: self.status()["paused"], "rekey_initial_pause")
        before = self.private_rpc("""import json
from pathlib import Path
from cryptography import x509
from scripts.certificate_key_rotation import public_hash
from scripts.certificate_controller import atomic
s=json.loads(Path('/state/state.json').read_bytes()); out={}
for uid,c in s['credentials'].items():
 out[uid]={'name':c['name'],'public_key_sha256':public_hash(x509.load_pem_x509_certificate(c['current'].encode()).public_key()),'assets':c['assets']}
 if c['name']=='core-operator':
  atomic('/state/old-client.pem',c['current']);atomic('/state/old-client.key',Path(c['key']).read_bytes())
print(json.dumps(out))""")
        active = set(before) - set(self.controller_config["disabled"])
        signing_hashes = {name: public_hash(key.public_key()) for name, key in self.signing_keys.items()}
        flow.require(all(signing_hashes[name] != next(c["public_key_sha256"] for c in before.values()
                         if c["name"] == "renew-" + name) for name in SERVERS), "rekey_distinct_delegation_keys")
        def all_rotated(generation):
            snapshot = self.status()
            return snapshot["phase"] is None and all((snapshot["credentials"][uid].get("key_generation") or 0) >= generation for uid in active)
        add("rotation_registration_preserves_retired_and_expired_identities", active_identities=len(active))
        self.paused(False)
        self.wait(lambda: all_rotated(1), "rekey_first_timer", timeout=90)
        self.paused(True)
        first = self.audit()
        record["key_rotation_first_public_audit"] = first
        flow.require(set(first) == active and all(first[uid]["public_key_sha256"] != before[uid]["public_key_sha256"] for uid in active), "rekey_all_changed")
        add("all_active_workload_and_management_tls_keys_changed", identities=len(active))
        flow.require(all(c["copies_match"] and c["pairs_match"] and c["private_modes"] == [384] for c in first.values()), "rekey_all_pairs")
        add("every_key_copy_matches_its_certificate_and_mode_0600")
        self.assert_removed(before, active)
        add("all_retired_key_and_certificate_copies_removed")
        status = self.status()
        flow.require(all(status["server_observations"][c["name"]]["fingerprint"] == c["fingerprint"]
                         for uid, c in status["credentials"].items() if uid in active and c["purpose"] == "serverAuth"), "rekey_wire_servers")
        add("fourteen_native_nginx_go_servers_use_rekeyed_certificates", servers=len(SERVERS))
        self.document_access(record, keys, "after-first-rekey")
        add("protected_document_access_after_first_key_rotation")
        denied = self.request(self.controller, {"tls_profile": "/managed/canaries/revocable.json", "path": "/health/live"})
        flow.require(denied["status"] == 403, "rekey_disabled_still_denied")
        add("previously_retired_identity_is_not_restored")
        proof = self.private_rpc("""import json
from pathlib import Path
from scripts.certificate_controller import ca_post
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
key=ec.generate_private_key(ec.SECP256R1()); old=x509.load_pem_x509_certificate(Path('/state/old-client.pem').read_bytes())
csr=x509.CertificateSigningRequestBuilder().subject_name(old.subject).sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
code,_=ca_post(Path('/state'),'/1.0/rekey',{'csr':csr},identity={'certificates':['/state/old-client.pem'],'key':'/state/old-client.key'})
Path('/state/old-client.key').unlink();Path('/state/old-client.pem').unlink()
print(json.dumps({'status':code}))""")
        flow.require(proof["status"] in {401, 403}, "rekey_old_ca_credential_denied")
        add("retired_client_cannot_rekey_at_ca", status=proof["status"])
        # A new complete round after restart proves the timer remains operational.
        self.controller_config["key_rotation"]["interval_seconds"] = 8
        group = self.controller_config["reload_groups"][0]
        original_ack = group["ack"]
        group["ack"] = original_ack + "-missing"
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
        self.close_probe(self.controller)
        command(["docker", "restart", "--time", "2", self.controller])
        self.wait(lambda: self.status()["paused"], "rekey_restart_paused")
        self.paused(False)
        self.wait(lambda: self.status()["phase"] == "activated" and self.status()["last_error"], "rekey_blocked_reload", timeout=60)
        pending = self.private_rpc("""import json
from pathlib import Path
from scripts.certificate_controller import fingerprint
s=json.loads(Path('/state/state.json').read_bytes());out={}
for uid in s['transaction']['credentials']:
 c=s['credentials'][uid];out[uid]={'public_key_sha256':c['pending_key']['public_key_sha256'],'fingerprint':fingerprint(c['candidate']),
  'old_keys_present':all(Path(a['key']).exists() for a in c['assets'])}
print(json.dumps(out))""")
        flow.require(set(pending) == active and all(c["old_keys_present"] for c in pending.values()), "rekey_reload_retains_old_keys")
        add("reload_unconfirmed_retains_old_keys_before_cleanup")
        self.close_probe(self.controller)
        command(["docker", "stop", "--time", "2", self.controller])
        group["ack"] = original_ack
        self.controller_config["key_rotation"]["interval_seconds"] = 60
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
        command(["docker", "start", self.controller])
        self.wait(lambda: all_rotated(2), "rekey_second_timer", timeout=90)
        self.paused(True)
        add("controller_crash_resumes_activated_key_publication")
        second = self.audit()
        flow.require(all(second[uid]["public_key_sha256"] != first[uid]["public_key_sha256"] for uid in active), "rekey_second_new_keys")
        record["key_rotation_second_public_audit"] = second
        after_restart = self.status()
        flow.require(all(second[uid]["public_key_sha256"] == pending[uid]["public_key_sha256"]
                         and after_restart["credentials"][uid]["fingerprint"] == pending[uid]["fingerprint"] for uid in active), "rekey_pending_keys_reused")
        add("crash_recovery_uses_same_pending_keys_without_reissuance")
        add("controller_restart_and_timer_rotate_all_keys_again", identities=len(active))
        self.assert_removed(first, active)
        add("second_rotation_removes_first_generation_key_files")
        self.document_access(record, keys, "after-second-rekey")
        add("protected_document_access_after_second_key_rotation")
        # CA outage must not replace active keys or interrupt valid business traffic.
        prior = self.audit()
        command(["docker", "pause", self.ca_server])
        self.controller_config["key_rotation"]["interval_seconds"] = 8
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
        self.paused(False)
        try:
            self.wait(lambda: any(c["failures"] for uid, c in self.status()["credentials"].items() if uid in active), "rekey_ca_outage_retry", timeout=35)
            flow.require(self.audit() == prior, "rekey_ca_outage_preserves_keys")
            self.document_access(record, keys, "rekey-ca-outage")
            add("ca_outage_retains_active_keys_and_protected_access")
        finally:
            command(["docker", "unpause", self.ca_server])
        self.wait(lambda: all_rotated(3), "rekey_ca_recovery", timeout=90)
        self.paused(True)
        add("ca_recovery_completes_pending_rotation_without_bootstrap")
        self.document_access(record, keys, "rekey-ca-recovered")
        add("protected_document_access_after_ca_recovery")
        signing_after = self.private_rpc("""import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from scripts.certificate_key_rotation import public_hash
cfg=json.loads(Path('/state/config.json').read_bytes())
print(json.dumps({name:public_hash(serialization.load_pem_private_key(Path(path).read_bytes(),password=None).public_key())
 for name,path in cfg['server_signers'].items()}))""")
        flow.require(signing_after == signing_hashes, "rekey_delegation_registration_unchanged")
        record["delegated_signing_public_key_sha256"] = signing_hashes
        add("delegated_signing_keys_distinct_from_rotating_tls_keys_and_unchanged", signing_keys=len(signing_hashes))
        record["key_rotation_final_public_status"] = self.status()
        # Reuse actual scrape/firing/resolved verification with the new key pins.
        baseline_status = record["certificate_final_public_status"]
        record["certificate_final_public_status"] = self.status()
        try:
            self.monitor_after_renewal(record, lambda label, **detail: add("rekey_" + label, **detail))
        finally:
            record["certificate_final_public_status"] = baseline_status
        self.close_probe(self.controller)
        command(["docker", "stop", "--time", "2", self.controller])
        expected = self.report["key_rotation_contract"]["expected_checks"]
        flow.require(len(checks) == len(expected) and {c["label"] for c in checks} == set(expected), "rekey_check_coverage")

    def assert_removed(self, snapshot, identifiers):
        paths = sorted({path for uid in identifiers for asset in snapshot[uid]["assets"] for path in asset.values()})
        result = self.private_rpc("""import json,sys
from pathlib import Path
paths=json.load(sys.stdin)['paths'];print(json.dumps({'remaining':[p for p in paths if Path(p).exists()]}))""", {"paths": paths})
        flow.require(result["remaining"] == [], "rekey_old_files_removed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/c04/rekey")
    parser.add_argument("--repeats", type=int, choices=range(1, 3), default=2)
    parser.add_argument("--key-smoke", action="store_true")
    args = parser.parse_args()
    lab = KeyRotationLab(args.directory)
    lab.key_smoke = args.key_smoke
    try:
        lab.prepare()
        if args.key_smoke:
            lab.smoke()
            flow.require(all((c.get("key_generation") or 0) >= 1 for c in lab.report["smoke"]["credentials"].values()), "rekey_smoke_changed_keys")
        else:
            for iteration in range(1, args.repeats + 1):
                lab.trial("nginx", iteration)
            flow.require(all(r["completed"] for r in lab.report["runs"]), "rekey_incomplete")
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, flow.CheckFailed) as exc:
        lab.report["failure"] = str(exc) if isinstance(exc, flow.CheckFailed) else type(exc).__name__
        if hasattr(lab, "controller"):
            snapshot = subprocess.run(["docker", "exec", lab.controller, "python", "-c",
                "from pathlib import Path;p=Path('/state/status.json');print(p.read_text() if p.exists() else '{}')"],
                capture_output=True, text=True, check=False)
            if snapshot.returncode == 0:
                lab.report["failure_public_status"] = json.loads(snapshot.stdout)
        raise SystemExit(lab.report["failure"]) from None
    finally:
        lab.report["finished_at"] = flow.timestamp()
        lab.cleanup()


if __name__ == "__main__":
    main()
