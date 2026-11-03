"""Local real step-ca root/intermediate/all-JWK timer rotation and graph regression."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from scripts import certificate_authority as bootstrap
from scripts import test_signal_compose as flow
from scripts.authority_custodian import seed_files
from scripts.authority_rotation_coordinator import DockerBackend
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT, Lab, command
from scripts.compare_supply_chain import sha256
from scripts.mtls_fixtures import leaf
from scripts.test_certificate_automation import SERVERS
from scripts.test_private_key_rotation import KeyRotationLab

AUTHORITY_SOURCES = ["scripts/authority_custodian.py", "scripts/authority_rotation_runtime.py",
    "scripts/authority_rotation_coordinator.py", "scripts/test_authority_key_rotation.py",
    "scripts/certificate_controller.py", "scripts/certificate_key_rotation.py",
    "scripts/test_private_key_rotation.py", "scripts/test_certificate_automation.py"]
IMPORTED_SOURCE_SHA256 = {name: sha256(ROOT / name) for name in AUTHORITY_SOURCES}


class AuthorityLab(KeyRotationLab):
    def prepare(self):
        super().prepare()
        self.report["schema"] = "authority-key-rotation-1"
        self.report["authority_contract"] = json.loads((ROOT / "infra/mtls/authority-rotation-contract.json").read_text())
        for path in ["scripts/authority_custodian.py", "scripts/authority_rotation_runtime.py",
                     "scripts/authority_rotation_coordinator.py", "scripts/test_authority_key_rotation.py",
                     "infra/mtls/authority-rotation-contract.json"]:
            self.report["source_input_sha256"][path] = sha256(ROOT / path)
        actual = json.loads(command(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "python", "-i", self.image,
            "-c", "import hashlib,json,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"], input=json.dumps(AUTHORITY_SOURCES)))
        self.report["authority_image_source_sha256"] = actual
        flow.require(actual == IMPORTED_SOURCE_SHA256 and actual == {name: sha256(ROOT / name) for name in AUTHORITY_SOURCES}, "authority_source_changed_during_build")
        self.save()

    def init_authority(self):
        command(["docker", "start", self.controller])
        cfg = self.private_rpc("import json;from pathlib import Path;print(Path('/state/config.json').read_text())")
        self.controller_config = cfg
        self.controller_config["key_rotation"]["interval_seconds"] = 600
        self.controller_config["paused"] = True
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
        command(["docker", "start", self.controller])
        self.wait(lambda: self.status()["paused"], "authority_leaf_paused")
        self.vault = self.volume(self.prefix + "-authority-vault")
        providers = [p[0] for p in self.provisioners.values()] + [bootstrap.server_renewal_provisioner(name, key.public_key()) for name, key in self.signing_keys.items()]
        private = {name: pair[1] for name, pair in self.provisioners.items()} | {"server-renewal-" + name: key for name, key in self.signing_keys.items()}
        signers = {name: Path(path).name for name, path in self.controller_config["server_signers"].items()}
        policy = {"periods": {"root": 3600, "issuer": 3600, "jwk": 3600}, "root_days": 2, "issuer_days": 2}
        self.write_assets(self.vault, seed_files(self.offline_root, self.issuer, providers, private, signers, policy=policy, last_at=0))
        mounts = json.loads(command(["docker", "inspect", self.controller]))[0]["Mounts"]
        renewal = next(m["Name"] for m in mounts if m["Destination"] == "/managed/renewal")
        directory = self.directory / (self.prefix + "-authority")
        directory.mkdir(parents=True, exist_ok=True)
        self.authority_profile = directory / "profile.json"
        profile = {"project": self.ident, "image": self.report["certificate_execution_image_id"],
            "ca": {"name": self.ca_server, "id": json.loads(command(["docker", "inspect", self.ca_server]))[0]["Id"]},
            "leaf": {"name": self.controller, "id": json.loads(command(["docker", "inspect", self.controller]))[0]["Id"]},
            "volumes": {"vault": self.vault, "ca": self.ca_volume, "leaf": self.controller_volume, "renewal": renewal},
            "initial_root": self.offline_root[1].public_bytes(serialization.Encoding.PEM).decode(),
            "poll_seconds": .3, "policy_refresh_seconds": 1, "transition_timeout_seconds": 300}
        self.authority_profile.write_text(json.dumps(profile), encoding="utf-8")
        self.backend = DockerBackend(profile)
        return providers

    def coordinator_state(self):
        return json.loads((self.authority_profile.parent / "authority-coordinator.json").read_text(encoding="utf-8"))

    def authority_tick(self):
        result = json.loads(command([sys.executable, "-m", "scripts.authority_rotation_coordinator", "tick", "--profile", str(self.authority_profile)], timeout=60))
        return result

    def drive_until(self, predicate, label, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.authority_tick()
            state = self.coordinator_state()
            if predicate(state):
                return state
            time.sleep(.3)
        raise flow.CheckFailed("authority_timeout_" + label)

    def update_authority_periods(self, periods):
        command(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount", f"type=volume,src={self.vault},dst=/vault",
            "--entrypoint", "python", "-i", self.image, "-c",
            "import json,sys;from pathlib import Path;from scripts.certificate_controller import save;p=Path('/vault/state.json');s=json.loads(p.read_bytes());s['policy']['periods']=json.load(sys.stdin);save(p,s)"], input=json.dumps(periods))

    def certificate_checks(self, record, keys):
        super().certificate_checks(record, keys)
        self.authority_checks(record, keys)

    def authority_checks(self, record, keys):
        record["authority_checks"] = checks = []
        def add(label, **details):
            checks.append({"label": label, "passed": True, **details})
            self.save()
        providers = self.init_authority()
        state = self.drive_until(lambda s: s["phase"] == "prepared", "prepare")
        plan = state["plan"]
        custody = state["evidence"]["custody"]
        flow.require(custody == {"uid": 10001, "interfaces": ["lo"], "vault_mode": 384, "docker_socket": False}, "authority_isolated_custody")
        add("root_custodian_is_network_isolated_without_socket", **custody)
        for role in ["ca", "leaf"]:
            mounts = json.loads(command(["docker", "inspect", self.backend.profile[role]["name"]]))[0]["Mounts"]
            flow.require(not any(m.get("Name") == self.vault for m in mounts), "authority_no_online_root_vault")
        add("online_ca_and_leaf_controller_do_not_mount_root_vault")
        bad = json.loads(json.dumps(plan)); bad["root"] = plan["old_root"]
        try:
            self.backend.leaf("stage", bad)
            raise flow.CheckFailed("authority_bad_manifest_accepted")
        except LifecycleError:
            add("tampered_root_rotation_manifest_rejected")
        state = self.drive_until(lambda s: s["phase"] == "trust_staged", "staged")
        try:
            self.backend.leaf("retire", plan)
            raise flow.CheckFailed("authority_early_retirement")
        except LifecycleError:
            add("root_retirement_before_leaf_migration_rejected")
        prepared_again = self.backend.custodian("prepare")
        flow.require(prepared_again["plan"] == plan, "authority_pending_keys_stable")
        add("custodian_restart_reuses_same_prepared_authority_keys")
        # Every tick runs a fresh process: the next process resumes the staged journal.
        self.drive_until(lambda s: s["phase"] == "ca_activated", "new_ca")
        add("coordinator_process_restart_resumes_staged_trust")
        command(["docker", "pause", self.ca_server])
        try:
            result = self.authority_tick()
            flow.require(result["phase"] == "ca_activated" and result["error"] is not None, "authority_outage_phase_held")
            add("ca_outage_holds_rotation_without_retiring_old_trust")
            self.document_access(record, keys, "authority-ca-outage")
            add("valid_protected_access_continues_during_ca_rotation_outage")
        finally:
            command(["docker", "unpause", self.ca_server])
        first = self.drive_until(lambda s: s["phase"] == "idle" and s["epoch"] == 1, "root_complete")
        history = first["history"][0]
        flow.require(all(history["changed"].values()), "authority_all_three_key_classes")
        add("root_intermediate_and_all_jwk_keys_rotate_by_timer", jwk_providers=len(providers))
        flow.require(len(history["evidence"]["migrated_services"]["servers"]) == len(SERVERS), "authority_all_servers_migrated")
        add("all_active_leaf_identities_and_native_servers_migrate", identities=history["evidence"]["final_services"]["identities"], servers=len(SERVERS))
        flow.require(history["evidence"]["old_jwks"]["denied"] == len(providers), "authority_old_all_jwks_denied")
        add("fresh_tokens_signed_by_every_old_jwk_are_rejected", providers=len(providers))
        self.document_access(record, keys, "authority-root-complete")
        add("protected_access_after_root_and_jwk_rotation")
        self.old_root_denied()
        add("retired_root_fails_real_tls_validation")
        self.update_authority_periods({"root": 3600, "issuer": 1, "jwk": 1})
        second = self.drive_until(lambda s: s["phase"] == "idle" and s["epoch"] == 2, "issuer_only")
        h1, h2 = second["history"]
        flow.require(not h2["changed"]["root"] and h2["changed"]["issuer"] and h1["root_public_key_sha256"] == h2["root_public_key_sha256"]
                     and h1["issuer_public_key_sha256"] != h2["issuer_public_key_sha256"], "authority_issuer_independent")
        add("intermediate_timer_changes_issuer_without_replacing_root")
        self.update_authority_periods({"root": 3600, "issuer": 3600, "jwk": 1})
        third = self.drive_until(lambda s: s["phase"] == "idle" and s["epoch"] == 3, "jwk_only")
        h3 = third["history"][-1]
        flow.require(h3["changed"] == {"root": False, "issuer": False, "jwk": True} and
                     h3["issuer_public_key_sha256"] == h2["issuer_public_key_sha256"], "authority_jwk_independent")
        add("jwk_timer_changes_signers_without_replacing_ca_keys")
        flow.require(all(before["key"] != after["key"] for before, after in zip(
            plan["before_ca"]["authority"]["provisioners"], h1["plan"]["final_ca"]["authority"]["provisioners"], strict=True)), "authority_all_jwk_spki_changes")
        add("all_registered_jwk_public_keys_change_with_scopes_preserved")
        self.backend.leaf("pause", value=True)
        self.wait(lambda: self.backend.leaf("status")["paused"], "authority_final_pause")
        self.backend.leaf("verify", h3["plan"])
        add("three_authority_epochs_finish_with_current_leaf_certificates")
        cleaned = command(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount", f"type=volume,src={self.vault},dst=/vault",
            "--entrypoint", "python", self.image, "-c", "from pathlib import Path;print(sorted(p.name for p in Path('/vault').glob('*.sealed')))" ]).strip()
        flow.require(cleaned == "['authority-g3.sealed']", "authority_old_encrypted_bundles_removed")
        add("old_encrypted_root_issuer_jwk_bundles_are_removed")
        online = self.backend.command(["run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount", f"type=volume,src={self.ca_volume},dst=/ca",
            "--mount", f"type=volume,src={self.backend.profile['volumes']['renewal']},dst=/renewal", "--entrypoint", "python", self.image, "-c",
            "import json;from pathlib import Path;print(json.dumps({'issuer_keys':sorted(p.name for p in Path('/ca').glob('*.key')),'signer_keys':sorted(p.name for p in Path('/renewal').glob('sign-*.key'))}))"])
        online = json.loads(online)
        flow.require(online["issuer_keys"] == ["issuer-g2.key"] and online["signer_keys"] == sorted(h3["plan"]["signers"].values()), "authority_old_online_keys_removed")
        add("retired_online_issuer_and_signer_key_files_removed")
        self.document_access(record, keys, "authority-final")
        add("protected_access_after_independent_authority_timers")
        record["authority_history"] = third["history"]
        record["authority_final_public_status"] = self.status()
        baseline = record["certificate_final_public_status"]
        record["certificate_final_public_status"] = self.status()
        try:
            self.monitor_after_renewal(record, lambda label, **detail: add("authority_" + label, **detail))
        finally:
            record["certificate_final_public_status"] = baseline
        self.close_probe(self.controller)
        command(["docker", "stop", "--time", "2", self.controller])
        expected = self.report["authority_contract"]["expected_checks"]
        flow.require(len(checks) == len(expected) and {c["label"] for c in checks} == set(expected), "authority_check_coverage")

    def old_root_denied(self):
        material = self.leaves["core-operator"]
        profile = self.private_rpc("import json;from pathlib import Path;print(Path('/managed/core-a/operator.json').read_text())")
        profile.update(cert="old-authority.pem", key="old-authority.key", ca="root.pem")
        self.write_assets(self.controller_volume, {"old-authority.pem": material["cert"] + self.issuer[1].public_bytes(serialization.Encoding.PEM).decode(),
            "old-authority.key": material["key"], "old-authority.json": json.dumps(profile)})
        profile.update(host="core", port=8000, server_name="core-a")
        self.write_assets(self.controller_volume, {"old-authority.json": json.dumps(profile)})
        response = self.request(self.controller, {"tls_profile": "/state/old-authority.json", "path": "/health/live"})
        flow.require(response["status"] == 0, "authority_retired_root_rejected_at_tls")
        self.private_rpc("from pathlib import Path;import json;[(Path('/state')/n).unlink() for n in ['old-authority.pem','old-authority.key','old-authority.json']];print('{}')")

    def smoke(self):
        self.prefix = self.ident + "-smoke"
        self.graph_authority()
        volume = self.volume(self.prefix + "-collector")
        cert, server, proof = leaf(self.issuer, "collector"), leaf(self.issuer, "gateway", server=True), self.renewal_materials["gateway"]
        self.write_assets(volume, {"collector.pem": cert["cert"], "collector.key": cert["key"], "ca.pem": self.trust_bundle(self.issuer),
            "profile.json": json.dumps({"host": "gateway", "port": 8000, "server_name": "gateway", "ca": "ca.pem",
                                       "cert": "collector.pem", "key": "collector.key", "server_pins": [server["fingerprint"]]})})
        server_volume = self.volume(self.prefix + "-native-server")
        self.write_assets(server_volume, {"ca.pem": self.trust_bundle(self.issuer), "gateway.pem": server["cert"], "gateway.key": server["key"],
            "server.json": json.dumps({"ca": "ca.pem", "cert": "gateway.pem", "key": "gateway.key", "peers": {cert["fingerprint"]: "core-operator"}})})
        proof_volume = self.volume(self.prefix + "-renewal-proof")
        self.write_assets(proof_volume, {"renew-gateway.pem": proof["cert"], "renew-gateway.key": proof["key"],
            "renew-gateway.json": json.dumps({"cert": "renew-gateway.pem", "key": "renew-gateway.key"})})
        Lab.start(self, self.prefix + "-native", self.ca_network, ["python", "-m", "scripts.mtls_native", "api", "--profile", "/service-tls/server.json"],
            alias="gateway", mounts=[f"type=volume,src={server_volume},dst=/service-tls,readonly"],
            env={"AUTH_MODE": "disabled", "ANALYZER_MODE": "rule", "ALLOWED_HOSTS": "gateway,127.0.0.1,localhost"}, memory=256, cpus=.5)
        self.setup_controller({"smoke": volume, "server": server_volume, "renewal": proof_volume},
            ["/managed/smoke/profile.json", "/managed/server/server.json", "/managed/renewal/renew-gateway.json"], [],
            probes=[{"server_name": "gateway", "host": "gateway", "port": 8000, "profile": "/managed/smoke/profile.json"}])
        manifest = json.loads(self.helper(["-m", "scripts.certificate_controller", "init"], network="none"))
        self.start_controller(manifest)
        self.wait(lambda: all(c["generation"] >= 2 for c in self.status()["credentials"].values()), "authority_smoke_leaf_ready", timeout=50)
        self.paused(True)
        providers = self.init_authority()
        state = self.drive_until(lambda s: s["phase"] == "idle" and s["epoch"] == 1, "authority_smoke", timeout=120)
        self.report["smoke"] = {"history": state["history"], "providers": len(providers), "public_status": self.status()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/c04/authority")
    parser.add_argument("--repeats", type=int, choices=range(1, 3), default=2)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    lab = AuthorityLab(args.directory)
    lab.key_smoke = args.smoke
    try:
        lab.prepare()
        if args.smoke:
            lab.smoke()
        else:
            for iteration in range(1, args.repeats + 1):
                lab.trial("nginx", iteration)
            flow.require(all(r["completed"] for r in lab.report["runs"]), "authority_incomplete")
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError, flow.CheckFailed) as exc:
        lab.report["failure"] = str(exc) if isinstance(exc, flow.CheckFailed) else type(exc).__name__
        if hasattr(lab, "authority_profile"):
            lab.report["failure_coordinator_state"] = lab.coordinator_state() if (lab.authority_profile.parent / "authority-coordinator.json").exists() else None
        raise SystemExit(lab.report["failure"]) from None
    finally:
        lab.report["finished_at"] = flow.timestamp()
        lab.cleanup()


if __name__ == "__main__":
    main()
