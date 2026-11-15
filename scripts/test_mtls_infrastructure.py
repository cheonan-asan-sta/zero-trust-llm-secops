"""I2 real mTLS on C02 PEP→core; ephemeral Linux-only keys, no cloud/model calls."""

import argparse
import json
import subprocess
from pathlib import Path

from scripts import test_signal_compose as flow
from scripts.compare_pep import ROOT, Lab, command
from scripts.compare_supply_chain import sha256
from scripts.mtls_fixtures import fixtures

WRITE = """import json,os,pathlib,sys
root=pathlib.Path('/data'); files=json.load(sys.stdin)
for name,body in files.items():
 p=root/name
 if p.parent != root or '/' in name or '\\\\' in name: raise ValueError('asset_scope')
 temp=root/(name+'.new'); temp.write_text(body); os.chmod(temp,0o600); os.replace(temp,p)
"""


class TLSLab(Lab):
    def __init__(self, directory):
        super().__init__(directory)
        self.report["schema"] = "i2-mtls-1"
        self.report["transport_contract"] = json.loads((ROOT / "infra/mtls/contract.json").read_text())
        self.save()

    def prepare(self):
        super().prepare(candidates=("nginx",))
        for name in ["scripts/mtls_transport.py", "scripts/mtls_fixtures.py", "scripts/test_mtls_infrastructure.py", "infra/mtls/contract.json"]:
            self.report["source_input_sha256"][name] = sha256(ROOT / name)
        self.save()

    def write_assets(self, volume, files):
        command(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount", f"type=volume,src={volume},dst=/data",
            "--entrypoint", "python", "--interactive", self.image, "-c", WRITE], input=json.dumps(files))

    def prepare_transport(self, prefix, networks):
        self.ca, self.leaves = self.make_fixtures()
        front = prefix + "-mtls"
        command(["docker", "network", "create", "--internal", "--label", "secops.c02=" + self.ident, front])
        self.networks.append(front)
        networks["mtls"] = front
        self.server_volume = self.volume(prefix + "-tls-server")
        self.bridge_volume = self.volume(prefix + "-tls-bridge")
        self.policy = {"ca": "ca.pem", "cert": "server.pem", "key": "server.key", "peers": {
            self.leaves["bridge"]["fingerprint"]: "pep-bridge", self.leaves["collector"]["fingerprint"]: "collector"}}
        self.write_assets(self.server_volume, {"ca.pem": self.ca, "server.pem": self.leaves["server"]["cert"],
            "server.key": self.leaves["server"]["key"], "profile.json": json.dumps(self.policy)})
        self.bridge_files = self.client_files("bridge")
        self.write_assets(self.bridge_volume, self.bridge_files)
        self.gateway = prefix + "-tls-gateway"
        self.start(self.gateway, networks["core"], ["python", "-m", "scripts.mtls_transport", "serve", "--profile", "/tls/profile.json"],
            alias="gateway", mounts=[f"type=volume,src={self.server_volume},dst=/tls,readonly"],
            additional=[(front, "gateway")], memory=192, cpus=.5)
        self.actors, self.actor_volumes = {}, {}
        for label in ["bridge", "bridge-next", "collector", "unknown", "foreign", "expired", "future", "wrong-eku", "missing", "wrong-host", "wrong-pin"]:
            volume = self.volume(prefix + "-actor-" + label)
            self.actor_volumes[label] = volume
            self.write_assets(volume, self.client_files(label))
            name = prefix + "-actor-" + label
            self.start(name, front, ["python", "-c", "import time; time.sleep(3600)"],
                       mounts=[f"type=volume,src={volume},dst=/tls,readonly"], memory=64, cpus=.25)
            self.actors[label] = name
        self.wait(lambda: self.request(self.gateway, {"port": 8444, "path": "/stats"})["status"] == 200, "tls_gateway_ready")
        return {"network": front, "mounts": [f"type=volume,src={self.bridge_volume},dst=/tls,readonly"],
                "args": ["--core-tls-profile", "/tls/profile.json"]}

    def client_files(self, label, server="server"):
        cert = self.leaves.get(label, self.leaves["bridge"])
        credential = label if label in self.leaves else "bridge"
        data = {"host": "gateway", "port": 8443, "server_name": "wrong.local" if label == "wrong-host" else "gateway",
                "ca": "ca.pem", "cert": credential + ".pem", "key": credential + ".key",
                "server_pins": ["0" * 64 if label == "wrong-pin" else self.leaves[server]["fingerprint"]]}
        if label == "missing":
            data.update(cert=None, key=None)
            return {"ca.pem": self.ca, "profile.json": json.dumps(data)}
        return {"ca.pem": self.ca, credential + ".pem": cert["cert"], credential + ".key": cert["key"], "profile.json": json.dumps(data)}

    def make_fixtures(self):
        return fixtures()

    def transport_checks(self, prefix, record, keys, bridge):
        record["transport_checks"] = []

        def stats():
            return json.loads(self.request(self.gateway, {"port": 8444, "path": "/stats", "private_control": True})["body"])

        payload = {"session_id": "i2-nonexistent", "grant_token": "x" * 43, "resource_id": "zt-demo-documents", "action": "READ"}

        def check(label, actor, *, forwarded=0, status=None, http_seen=None, target="/zero-trust/protected-access", api_key=None, headers=()):
            before = stats()
            data = {"path": target, "payload": payload, "headers": [["X-API-Key", api_key or keys["a"]], *headers]}
            result = json.loads(command(["docker", "exec", "--interactive", self.actors[actor], "python", "-m", "scripts.mtls_transport",
                "probe", "--profile", "/tls/profile.json"], input=json.dumps(data), timeout=10))
            after = stats()
            flow.require(after.get("forwarded", 0) - before.get("forwarded", 0) == forwarded, "i2_forwarding_" + label)
            flow.require(not 200 <= result["status"] < 300, "i2_unexpected_allow_" + label)
            if status is not None:
                flow.require(result["status"] == status, "i2_status_" + label)
            if http_seen is not None:
                flow.require(after.get("http_requests", 0) - before.get("http_requests", 0) == http_seen, "i2_http_" + label)
            if forwarded:
                flow.require(result.get("tls_version") in {"TLSv1.2", "TLSv1.3"}, "i2_tls_version_" + label)
                if status == 403:
                    flow.require(result.get("reason_code") == "GRANT_INVALID", "i2_core_reason_" + label)
            record["transport_checks"].append({"label": label, "passed": True, "status": result["status"],
                "backend_request_attempts": forwarded, "http_requests_seen": after.get("http_requests", 0) - before.get("http_requests", 0),
                "tls_version": result.get("tls_version"), "cipher": result.get("cipher"), "core_reason": result.get("reason_code")})
            self.save()

        for label in ["missing", "foreign", "expired", "future", "wrong-eku", "wrong-host", "wrong-pin"]:
            check(label, label, status=0, http_seen=0)
        check("trusted_ca_unknown_leaf_cannot_spoof_identity", "unknown", status=403,
              headers=[["X-Service-Identity", "pep-bridge"], ["X-User", "administrator"]])
        check("collector_cannot_access_pep_route", "collector", status=403)
        check("bridge_cannot_revoke", "bridge", status=403, target="/zero-trust/sessions/i2-session/revoke")
        check("query_cannot_change_route", "bridge", status=403, target="/zero-trust/protected-access?scope=admin")
        check("encoded_path_rejected", "bridge", status=403, target="/zero-trust/%70rotected-access")
        check("double_slash_wire_target_rejected", "bridge", status=403, target="//zero-trust/protected-access")
        check("mtls_does_not_replace_api_key", "bridge", forwarded=1, status=401, api_key="bad-key")
        check("trusted_bridge_reaches_existing_api", "bridge", forwarded=1, status=403)
        for label in ["server-expired", "server-future", "server-wrong-name", "server-wrong-eku"]:
            self.write_assets(self.server_volume, {label + ".pem": self.leaves[label]["cert"], label + ".key": self.leaves[label]["key"]})
            self.policy.update(cert=label + ".pem", key=label + ".key")
            self.write_assets(self.server_volume, {"profile.json": json.dumps(self.policy)})
            # Pin the bad leaf correctly: time/hostname/EKU validation must still reject it.
            self.write_assets(self.actor_volumes["bridge"], self.client_files("bridge", label))
            check(label, "bridge", status=0, http_seen=0)
        self.policy.update(cert="server.pem", key="server.key")
        self.write_assets(self.server_volume, {"profile.json": json.dumps(self.policy)})
        self.write_assets(self.actor_volumes["bridge"], self.client_files("bridge"))
        check("server_repair_valid_identity", "bridge", forwarded=1, status=403)
        self.policy["peers"][self.leaves["bridge-next"]["fingerprint"]] = "pep-bridge"
        self.write_assets(self.server_volume, {"profile.json": json.dumps(self.policy)})
        check("client_rotation_overlap_old", "bridge", forwarded=1, status=403)
        check("client_rotation_overlap_new", "bridge-next", forwarded=1, status=403)
        del self.policy["peers"][self.leaves["bridge"]["fingerprint"]]
        self.write_assets(self.server_volume, {"profile.json": json.dumps(self.policy)})
        check("client_pin_revoked_next_request", "bridge", status=403)
        check("new_client_after_retirement", "bridge-next", forwarded=1, status=403)
        self.write_assets(self.bridge_volume, self.client_files("bridge-next"))
        # New server cert stays chain/hostname valid; old server pin must fail before any HTTP bytes.
        self.write_assets(self.server_volume, {"server-next.pem": self.leaves["server-next"]["cert"],
            "server-next.key": self.leaves["server-next"]["key"]})
        self.policy.update(cert="server-next.pem", key="server-next.key")
        self.write_assets(self.server_volume, {"profile.json": json.dumps(self.policy)})
        check("server_rotation_stale_pin_no_credentials_sent", "bridge-next", status=0, http_seen=0)
        self.write_assets(self.actor_volumes["bridge-next"], self.client_files("bridge-next", "server-next"))
        self.write_assets(self.bridge_volume, self.client_files("bridge-next", "server-next"))
        check("server_rotation_new_pin", "bridge-next", forwarded=1, status=403)
        self.write_assets(self.server_volume, {"profile.json": "{"})
        check("malformed_policy_fail_closed", "bridge-next", status=0, http_seen=0)
        self.write_assets(self.server_volume, {"profile.json": json.dumps(self.policy)})
        check("policy_repair_requires_still_registered_identity", "bridge-next", forwarded=1, status=403)
        # The old cert remains cryptographically valid but is still retired after configuration repair.
        self.write_assets(self.actor_volumes["bridge"], self.client_files("bridge", "server-next"))
        check("repair_does_not_restore_revoked_client", "bridge", status=403)
        direct = self.request(bridge, {"host": "core", "path": "/health/live"})
        flow.require(direct["status"] == 0, "i2_plaintext_backend_not_reachable")
        record["transport_checks"].append({"label": "bridge_no_direct_plaintext_core_route", "passed": True, "status": 0})
        flow.require(len(record["transport_checks"]) == self.report["transport_contract"]["checks_per_trial"], "i2_check_count")
        flow.require({c["label"] for c in record["transport_checks"]} == set(self.report["transport_contract"]["expected_checks"]), "i2_check_coverage")
        record["tls_public_fingerprints"] = {name: leaf["fingerprint"] for name, leaf in self.leaves.items()}
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/i2")
    parser.add_argument("--repeats", type=int, choices=range(1, 4), default=3)
    args = parser.parse_args()
    lab = TLSLab(args.directory)
    try:
        lab.prepare()
        for iteration in range(1, args.repeats + 1):
            lab.trial("nginx", iteration)
        flow.require(all(r["completed"] for r in lab.report["runs"]), "i2_incomplete_evidence")
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, flow.CheckFailed) as exc:
        lab.report["failure"] = str(exc) if isinstance(exc, flow.CheckFailed) else type(exc).__name__
        raise SystemExit(lab.report["failure"]) from None
    finally:
        lab.report["finished_at"] = flow.timestamp()
        lab.cleanup()


if __name__ == "__main__":
    main()
