"""C04 real local step-ca issuance/renewal and selected mTLS graph regression.

Internal Linux Docker networks/volumes only; no cloud, paid model or OS trust store.
"""

import argparse
import json
import shutil
import subprocess
import tarfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from scripts import certificate_authority as bootstrap
from scripts import pep_lab as pep
from scripts import test_signal_compose as flow
from scripts.certificate_controller import fingerprint, issued_chain, metadata
from scripts.compare_pep import ROOT, Lab, command
from scripts.compare_supply_chain import download, sha256
from scripts.mtls_fixtures import leaf
from scripts.test_all_hops_mtls import AllHopsLab

SERVERS = ["gateway", "core-a", "core-b", "core-c", "reader", "proxy", "bridge-auth", "bridge-consume",
           "resource", "exporter", "sink", "prometheus", "am", "gateway-stats"]
CLIENTS = ["pep-bridge", "collector", "core-operator", "gateway-client", "proxy-auth", "proxy-resource", "frontend", "frontend-next",
           "bridge-probe", "resource-consumer", "resource-auditor", "transport-auditor", "metrics-reader", "scrape-agent",
           "scrape-control", "monitor-query", "monitor-alert", "am-control", "alert-manager", "sink-auditor", "resource-probe",
           "auto-canary", "static-canary", "revocable-canary", *["renew-" + name for name in SERVERS]]


class CertificateLab(AllHopsLab):
    def __init__(self, directory):
        super().__init__(directory)
        self.report["schema"] = "certificate-automation-1"
        self.report["certificate_contract"] = json.loads((ROOT / "infra/mtls/certificate-lifecycle-contract.json").read_text())
        self.reload_volumes = {}

    def prepare(self):
        super().prepare()
        self.graph_image = self.image
        self.ca_tools = json.loads((ROOT / "infra/mtls/ca-tools.lock.json").read_text())
        build = self.directory / "ca-build"
        (build / "bin").mkdir(parents=True, exist_ok=True)
        cache = ROOT / "runtime/c02/c04/cache"
        cache.mkdir(parents=True, exist_ok=True)
        for tool in self.ca_tools["tools"]:
            download(tool, tool["asset"], cache)
            with tarfile.open(cache / tool["asset"]["name"], "r:gz") as archive:
                matches = [m for m in archive if m.isfile() and m.name.rsplit("/", 1)[-1] == tool["binary"]]
                flow.require(len(matches) == 1 and 0 < matches[0].size < 200 * 1024**2, "c04_archive_member")
                with archive.extractfile(matches[0]) as source, (build / "bin" / tool["binary"]).open("wb") as output:
                    shutil.copyfileobj(source, output)
        (build / "Dockerfile").write_text(f"FROM {self.graph_image}\nUSER 0\nCOPY bin /tools\nRUN chmod 0555 /tools/*\nUSER 10001:10001\nHEALTHCHECK NONE\n")
        (build / ".dockerignore").write_text("*\n!Dockerfile\n!bin/\n!bin/*\n")
        self.image = self.ident + "-certificate-tools"
        command(["docker", "build", "--tag", self.image, str(build)], timeout=300)
        self.report["certificate_tools"] = self.ca_tools
        self.report["certificate_execution_image_id"] = command(["docker", "image", "inspect", self.image, "--format", "{{.Id}}"]).strip()
        for name in ["scripts/certificate_authority.py", "scripts/certificate_controller.py", "scripts/certificate_reload_runner.py",
                     "scripts/test_certificate_automation.py", "infra/mtls/ca-tools.lock.json", "infra/mtls/certificate-lifecycle-contract.json",
                     "infra/mtls/nginx-renewal.sh", ".gitattributes"]:
            self.report["source_input_sha256"][name] = sha256(ROOT / name)
        self.save()
        self.report["certificate_tool_versions"] = {tool["name"]: command(["docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--entrypoint", "/tools/" + tool["binary"], self.image, "--version"]).strip()
            for tool in self.ca_tools["tools"]}
        self.save()

    def graph_authority(self):
        self.offline_root, self.issuer = bootstrap.hierarchy()
        self.renewal_materials = {name: leaf(self.issuer, "renew-" + name) for name in SERVERS}
        self.provisioners = {}
        for name, purpose in [(s, "serverAuth") for s in SERVERS] + [(c, "clientAuth") for c in CLIENTS]:
            config, key = bootstrap.provisioner(name, purpose)
            self.provisioners[config["name"]] = (config, key)
        self.ca_network = self.prefix + "-ca"
        command(["docker", "network", "create", "--internal", "--label", "secops.c02=" + self.ident, self.ca_network])
        self.networks.append(self.ca_network)
        self.ca_volume = self.volume(self.prefix + "-ca-state")
        files = bootstrap.ca_files(self.offline_root, self.issuer, [p[0] for p in self.provisioners.values()] +
            [bootstrap.server_renewal_provisioner(name, self.server_signing_key(name).public_key()) for name in SERVERS])
        self.write_assets(self.ca_volume, files)
        self.ca_server = self.prefix + "-ca"
        Lab.start(self, self.ca_server, self.ca_network, ["/tools/step-ca", "/ca/ca.json", "--password-file", "/ca/password.txt"],
                  alias="ca", mounts=[f"type=volume,src={self.ca_volume},dst=/ca"], memory=256, cpus=1)
        return self.issuer

    def server_signing_key(self, name):
        return serialization.load_pem_private_key(self.renewal_materials[name]["key"].encode(), password=None)

    def trust_bundle(self, ca):
        return self.offline_root[1].public_bytes(serialization.Encoding.PEM).decode() + ca[1].public_bytes(serialization.Encoding.PEM).decode()

    def trial(self, candidate, iteration):
        self.prefix = f"{self.ident}-{iteration}-{candidate}"
        self.reload_volumes = {}
        super().trial(candidate, iteration)

    def prepare_transport(self, prefix, networks):
        result = super().prepare_transport(prefix, networks)
        networks["ca"] = self.ca_network
        self.graph_networks = networks
        return result

    def start(self, name, network, argv, **kwargs):
        label = name.removeprefix(self.prefix + "-")
        if label in {"proxy", "prometheus", "am"}:
            if label not in self.reload_volumes:
                self.reload_volumes[label] = self.volume(self.prefix + "-reload-" + label)
                self.write_assets(self.reload_volumes[label], {"ack": "starting"})
            mounts = list(kwargs.pop("mounts", ()))
            mounts.append(f"type=volume,src={self.reload_volumes[label]},dst=/reload")
            if label == "proxy":
                mounts.append(f"type=bind,src={ROOT / 'infra/mtls/nginx-renewal.sh'},dst=/config/nginx-renewal.sh,readonly")
            kwargs["mounts"] = mounts
        return super().start(name, network, argv, **kwargs)

    def reload_files(self, label):
        return {"proxy": ["proxy", "proxy-auth", "proxy-resource"],
                "prometheus": ["prometheus", "scrape-agent", "monitor-alert", "monitor-query"],
                "am": ["am", "alert-manager", "am-control"]}[label]

    def service_command(self, label, argv):
        if label == "proxy":
            return ["sh", "/config/nginx-renewal.sh"]
        if label in {"prometheus", "am"}:
            result = ["python", "-m", "scripts.certificate_reload_runner", "--ack", "/reload/ack"]
            for name in self.reload_files(label):
                result += ["--watch", "/service-tls/" + name + ".pem"]
            return result + ["--", *argv]
        return argv

    def helper(self, argv, payload=None, *, network=None):
        mounts = [f"type=volume,src={self.controller_volume},dst=/state", *self.controller_mounts]
        args = ["docker", "run", "--rm", "-i", "--network", network or self.ca_network, "--read-only", "--user", "10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory", "256m", "--cpus", "1"]
        for mount in mounts:
            args += ["--mount", mount]
        return command(args + ["--entrypoint", "python", self.image, *argv], input=json.dumps(payload) if payload else None)

    def rpc(self, payload):
        return json.loads(command(["docker", "exec", "-i", self.controller, "python", "-m", "scripts.certificate_controller", "rpc"], input=json.dumps(payload)))

    def status(self):
        return self.rpc({"operation": "status"})

    def paused(self, value):
        self.controller_config["paused"] = value
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
        if value:
            self.wait(lambda: self.status()["paused"] and self.status()["phase"] is None, "c04_controller_paused", timeout=35)

    def setup_controller(self, volumes, policy_files, extras, *, probes=(), reload_groups=(), unmanaged=()):
        self.controller_volume = self.volume(self.prefix + "-controller-state")
        self.controller_mounts = [f"type=volume,src={v},dst=/managed/{label}" for label, v in volumes.items()]
        for label, volume in self.reload_volumes.items():
            self.controller_mounts.append(f"type=volume,src={volume},dst=/ack/{label},readonly")
        self.controller_config = {"roots": ["/managed/" + label for label in volumes], "policies": policy_files,
            "extra_certificates": extras, "allowed_provisioners": list(self.provisioners), "probes": list(probes),
            "reload_groups": list(reload_groups), "unmanaged_profiles": list(unmanaged),
            "server_renewal": {name: "renew-" + name for name in SERVERS},
            "renew_before": {name: 3590 if name.startswith("renew-") else 1190 for name in SERVERS + CLIENTS} | {"auto-canary": 22},
            "interval_seconds": .3, "overlap_seconds": 1, "disabled": []}
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config),
            "root.pem": self.offline_root[1].public_bytes(serialization.Encoding.PEM).decode(),
            "issuer.pem": self.issuer[1].public_bytes(serialization.Encoding.PEM).decode()})

    def bootstrap_grants(self, inventory):
        grants = {}
        for uid, c in inventory.items():
            provisioner, key = self.provisioners[c["name"] + "-" + c["purpose"]]
            grants[uid] = {"token": bootstrap.bootstrap_token(provisioner, key, c["csr"], seconds=600),
                           "duration": "30s" if c["name"] == "auto-canary" else "1h" if c["name"].startswith("renew-") else "20m"}
        return grants

    def start_controller(self, inventory, *, additional=()):
        self.bootstrap_inventory = inventory
        self.grants = self.bootstrap_grants(inventory)
        self.write_assets(self.controller_volume, {"bootstrap.json": json.dumps(self.grants)})
        self.controller = self.prefix + "-certificate-controller"
        Lab.start(self, self.controller, self.ca_network, ["python", "-m", "scripts.certificate_controller", "run"],
            mounts=[f"type=volume,src={self.controller_volume},dst=/state", *self.controller_mounts],
            additional=additional, memory=512, cpus=1)

    def smoke(self):
        self.prefix = self.ident + "-smoke"
        self.graph_authority()
        volume = self.volume(self.prefix + "-collector")
        cert = leaf(self.issuer, "collector")
        server = leaf(self.issuer, "gateway", server=True)
        proof = self.renewal_materials["gateway"]
        self.write_assets(volume, {"collector.pem": cert["cert"], "collector.key": cert["key"],
            "ca.pem": self.trust_bundle(self.issuer),
            "profile.json": json.dumps({"cert": "collector.pem", "key": "collector.key", "server_pins": [server["fingerprint"]]})})
        server_volume = self.volume(self.prefix + "-native-server")
        self.write_assets(server_volume, {"ca.pem": self.trust_bundle(self.issuer), "gateway.pem": server["cert"], "gateway.key": server["key"],
            "server.json": json.dumps({"ca": "ca.pem", "cert": "gateway.pem", "key": "gateway.key", "peers": {cert["fingerprint"]: "core-operator"}})})
        proof_volume = self.volume(self.prefix + "-renewal-proof")
        self.write_assets(proof_volume, {"renew-gateway.pem": proof["cert"], "renew-gateway.key": proof["key"],
            "renew-gateway.json": json.dumps({"cert": "renew-gateway.pem", "key": "renew-gateway.key"})})
        Lab.start(self, self.prefix + "-native", self.ca_network, ["python", "-m", "scripts.mtls_native", "api", "--profile", "/service-tls/server.json"],
            alias="gateway", mounts=[f"type=volume,src={server_volume},dst=/service-tls,readonly"],
            env={"AUTH_MODE": "disabled", "ANALYZER_MODE": "rule"}, memory=256, cpus=.5)
        self.setup_controller({"smoke": volume, "server": server_volume, "renewal": proof_volume},
            ["/managed/smoke/profile.json", "/managed/server/server.json", "/managed/renewal/renew-gateway.json"], [],
            probes=[{"server_name": "gateway", "host": "gateway", "port": 8000, "profile": "/managed/smoke/profile.json"}])
        manifest = json.loads(self.helper(["-m", "scripts.certificate_controller", "init"], network="none"))
        self.start_controller(manifest)
        self.wait(lambda: all(c["generation"] >= 2 for c in self.status()["credentials"].values()), "c04_smoke_two_generations", timeout=45)
        self.paused(True)
        state = self.status()
        uid = next(uid for uid, c in state["credentials"].items() if c["name"] == "collector")
        flow.require(self.rpc({"operation": "revoke", "id": uid})["revoked"], "c04_smoke_revoke")
        flow.require(not self.rpc({"operation": "renew_attempt", "id": uid})["allowed"], "c04_smoke_revoked_renewal_denied")
        self.report["smoke"] = {"credentials": state["credentials"], "revoked_renewal_denied": True}

    def transport_checks(self, prefix, record, keys, bridge):
        super().transport_checks(prefix, record, keys, bridge)
        try:
            self.certificate_checks(record, keys)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, flow.CheckFailed):
            if hasattr(self, "controller"):
                snapshot = subprocess.run(["docker", "exec", self.controller, "python", "-c",
                    "from pathlib import Path;p=Path('/state/status.json');print(p.read_text() if p.exists() else '{}')"],
                    capture_output=True, text=True, check=False)
                if snapshot.returncode == 0:
                    record["certificate_failure_public_status"] = json.loads(snapshot.stdout)
                    self.save()
            raise

    def certificate_checks(self, record, keys):
        record["certificate_checks"] = checks = []
        def add(label, **details):
            checks.append({"label": label, "passed": True, **details})
            self.save()
        def public_file(container, path):
            return json.loads(command(["docker", "exec", container, "python", "-c",
                "import json,pathlib,sys; print(json.dumps(json.loads(pathlib.Path(sys.argv[1]).read_bytes())))", path]))
        def probe_canary(label):
            return self.request(self.controller, {"tls_profile": f"/managed/canaries/{label}.json", "path": "/health/live"})
        def current_named(name):
            return next((uid, c) for uid, c in self.status()["credentials"].items() if c["name"] == name)
        def all_at_generation(n):
            state = self.status()
            return state["phase"] is None and bool(state["credentials"]) and all(c["generation"] >= n for c in state["credentials"].values())

        # Two equal-lifetime step-ca certificates compare an unattended client with
        # a static client. Their private keys remain only in RAM/owned Linux volumes.
        self.canary_volume = self.volume(self.prefix + "-canaries")
        canaries = {name: leaf(self.issuer, name + "-canary") for name in ["auto", "static", "revocable"]}
        files = {"ca.pem": self.trust_bundle(self.issuer)}
        for name, cert in canaries.items():
            files.update({name + ".pem": cert["cert"], name + ".key": cert["key"], name + ".json": json.dumps({
                "host": "core", "port": 8000, "server_name": "core-a", "ca": "ca.pem", "cert": name + ".pem", "key": name + ".key",
                "server_pins": [self.leaves["core-a"]["fingerprint"]]})})
        self.write_assets(self.canary_volume, files)
        volumes = {label: v for label, v in self.node_volumes.items() if label != "adversary"}
        volumes.update({"tls-server": self.server_volume, "tls-bridge": self.bridge_volume,
                        "collector": self.actor_volumes["collector"], "canaries": self.canary_volume})
        policies = [f"/managed/{label}/{name}" for label, node in self.node_files.items() if label != "adversary"
                    for name in node if name.endswith(".json") and name != "unknown.json"]
        policies += ["/managed/tls-server/" + name for name in ["profile.json", "backend.json", "stats.json", "audit-client.json"]]
        policies += ["/managed/tls-bridge/profile.json", "/managed/collector/profile.json"]
        policies += ["/managed/canaries/" + name + ".json" for name in canaries]
        renewal_volume = self.volume(self.prefix + "-renewal-identities")
        renewal_files = {}
        for name, material in self.renewal_materials.items():
            credential = "renew-" + name
            renewal_files.update({credential + ".pem": material["cert"], credential + ".key": material["key"],
                credential + ".json": json.dumps({"cert": credential + ".pem", "key": credential + ".key"})})
            policies.append("/managed/renewal/" + credential + ".json")
        self.write_assets(renewal_volume, renewal_files)
        volumes["renewal"] = renewal_volume
        extras, reload_groups = [], []
        for label in ["proxy", "prometheus", "am"]:
            names = self.reload_files(label)
            extras += [(f"/managed/{label}/{name}.pem", f"/managed/{label}/{name}.key") for name in names]
            reload_groups.append({"root": "/managed/" + label, "files": [f"/managed/{label}/{n}.pem" for n in names], "ack": f"/ack/{label}/ack"})
        specs = [("gateway", "gateway", 8443, "collector/profile.json"), ("gateway-stats", "gateway", 8444, "tls-server/audit-client.json"),
            ("core-a", "core", 8000, "core-a/operator.json"), ("core-b", "core-b", 8000, "core-b/operator.json"),
            ("core-c", "core-c", 8000, "core-c/operator.json"), ("reader", "reader", 8000, "exporter/reader.json"),
            ("proxy", "proxy", 8080, "client/frontend.json"), ("bridge-auth", "bridge", 8081, "bridge/probe.json"),
            ("bridge-consume", "bridge", 8082, "resource/consume-client.json"), ("resource", "resource", 8083, "resource/document-probe.json"),
            ("exporter", "exporter", 9101, "exporter/local.json"), ("sink", "sink", 9001, "sink/local.json"),
            ("prometheus", "prometheus", 9090, "prometheus/local.json"), ("am", "am", 9093, "am/local.json")]
        probes = [{"server_name": name, "host": host, "port": port, "profile": "/managed/" + profile} for name, host, port, profile in specs]
        self.setup_controller(volumes, policies, extras, probes=probes, reload_groups=reload_groups,
                              unmanaged=["/managed/canaries/static.json"])
        static_key = serialization.load_pem_private_key(canaries["static"]["key"].encode(), password=None)
        static_csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.load_pem_x509_certificate(canaries["static"]["cert"].encode()).subject)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("static-canary")]), critical=False)
            .sign(static_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
        provisioner, signing_key = self.provisioners["static-canary-clientAuth"]
        static_grant = bootstrap.bootstrap_token(provisioner, signing_key, static_csr)
        result = json.loads(self.helper(["-m", "scripts.certificate_controller", "rpc"], {"operation": "ca_post", "path": "/1.0/sign",
            "payload": {"csr": static_csr, "ott": static_grant, "notAfter": "30s"}}))
        flow.require(result["status"] == 201, "c04_static_issued")
        static_certificate = issued_chain(result["result"])
        self.write_assets(self.canary_volume, {"static.pem": static_certificate})
        policy = public_file(self.prefix + "-core-a", "/service-tls/server.json")
        for name, cert in canaries.items():
            policy["peers"][fingerprint(static_certificate) if name == "static" else cert["fingerprint"]] = "core-operator"
        self.write_assets(self.node_volumes["core-a"], {"server.json": json.dumps(policy)})
        initial_static = json.loads(self.helper(["-m", "scripts.pep_lab", "probe"],
            {"tls_profile": "/managed/canaries/static.json", "path": "/health/live"}, network=self.graph_networks["core"]))
        flow.require(initial_static["status"] == 200, "c04_static_initial_access")
        add("static_client_initially_valid", lifetime_seconds=30)
        manifest = json.loads(self.helper(["-m", "scripts.certificate_controller", "init"], network="none"))
        self.start_controller(manifest, additional=[(n, "certificate-controller") for n in self.graph_networks.values() if n != self.ca_network])
        self.wait(lambda: all_at_generation(1), "c04_all_enrolled", timeout=65)
        flow.require(probe_canary("auto")["status"] == 200, "c04_auto_initial_access")
        first = self.status()
        record["certificate_initial_public_status"] = first
        add("all_active_identities_automatically_enrolled", identities=len(manifest))
        duplicate = subprocess.run(["docker", "exec", self.controller, "python", "-m", "scripts.certificate_controller", "run"],
            capture_output=True, timeout=5, check=False)
        flow.require(duplicate.returncode != 0, "c04_single_publisher")
        add("second_publisher_cannot_acquire_lease")
        erased = command(["docker", "exec", self.controller, "python", "-c", "from pathlib import Path;print(not Path('/state/bootstrap.json').exists())"]).strip()
        flow.require(erased == "True", "c04_bootstrap_erased")
        add("bootstrap_grants_erased_after_use")

        collector_uid = next(uid for uid, c in manifest.items() if c["name"] == "collector")
        original_csr = manifest[collector_uid]["csr"]
        provisioner, signing_key = self.provisioners["collector-clientAuth"]
        def sign(csr, token):
            return self.rpc({"operation": "ca_post", "path": "/1.0/sign", "payload": {"csr": csr, "ott": token, "notAfter": "20m"}})
        def rejected(label, csr, token):
            response = sign(csr, token)
            flow.require(response["status"] in {400, 401, 403, 409}, "c04_" + label)
            add(label, status=response["status"])
        rejected("one_time_bootstrap_replay_denied", original_csr, self.grants[collector_uid]["token"])
        rejected("expired_bootstrap_denied", original_csr, bootstrap.bootstrap_token(provisioner, signing_key, original_csr, now=int(time.time()) - 1000))
        rejected("wrong_audience_bootstrap_denied", original_csr, bootstrap.bootstrap_token(provisioner, signing_key, original_csr, audience="https://other/1.0/sign"))
        bad_key = bootstrap.provisioner("collector", "clientAuth")[1]
        rejected("wrong_signature_bootstrap_denied", original_csr, bootstrap.bootstrap_token(provisioner, bad_key, original_csr))
        fresh_key = bootstrap.provisioner("collector", "clientAuth")[1]
        def csr(san="collector", extra=False):
            builder = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "collector")]))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False))
            if extra:
                builder = (builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
            return builder.sign(fresh_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
        other_csr = csr()
        rejected("bootstrap_is_bound_to_exact_csr", other_csr, bootstrap.bootstrap_token(provisioner, signing_key, original_csr))
        server_csr = next(c["csr"] for c in manifest.values() if c["name"] == "core-a" and c["purpose"] == "serverAuth")
        for label, material in [("ordinary_client_cannot_issue_server_certificate", self.leaves["collector"]),
                                ("other_server_renewal_identity_cannot_issue_target", self.renewal_materials["core-b"])]:
            proof_key = serialization.load_pem_private_key(material["key"].encode(), password=None)
            token = bootstrap.server_renewal_token("core-a", material["cert"] + self.trust_bundle(self.issuer), proof_key, server_csr)
            rejected(label, server_csr, token)
        now = int(time.time())
        collector_key = serialization.load_pem_private_key(self.leaves["collector"]["key"].encode(), password=None)
        registered_key = serialization.load_pem_private_key(self.renewal_materials["core-a"]["key"].encode(), password=None).public_key()
        victim_serial = next(c["serial"] for c in first["credentials"].values() if c["name"] == "revocable-canary")
        bad_management_token = bootstrap.jwt.encode({"iss": "server-renewal-core-a", "sub": victim_serial,
            "aud": "https://ca:9000/1.0/revoke", "iat": now, "nbf": now - 2, "exp": now + 60,
            "jti": self.prefix + "-wrong-management-key"}, collector_key, algorithm="ES256",
            headers={"kid": bootstrap.public_jwk(registered_key)["kid"]})
        management_denied = self.rpc({"operation": "ca_post", "path": "/1.0/revoke",
            "payload": {"serial": victim_serial, "ott": bad_management_token, "passive": True}})
        flow.require(management_denied["status"] in {400, 401, 403}, "c04_no_client_management_escalation")
        add("ordinary_client_cannot_revoke_other_identity", status=management_denied["status"])
        for label, request in [("csr_cannot_change_service_san", csr("core-operator")), ("csr_cannot_add_ca_or_server_purpose", csr(extra=True))]:
            response = sign(request, bootstrap.bootstrap_token(provisioner, signing_key, request))
            if response["status"] == 201:
                constrained = metadata(issued_chain(response["result"]))
                flow.require(constrained["name"] == "collector" and constrained["purpose"] == "clientAuth", "c04_template_scope")
            else:
                flow.require(response["status"] in {400, 401, 403}, "c04_template_rejection")
            add(label, status=response["status"])
        # A valid CA certificate is still not an authorized service pin.
        unknown = sign(other_csr, bootstrap.bootstrap_token(provisioner, signing_key, other_csr))
        flow.require(unknown["status"] == 201, "c04_unknown_leaf_issued")
        unknown_certificate = issued_chain(unknown["result"])
        self.wait(lambda: all_at_generation(2), "c04_all_timer_renewed", timeout=65)
        self.paused(True)
        renewed = self.status()
        record["certificate_renewed_public_status"] = renewed
        add("all_active_identities_renewed_by_timer", identities=len(manifest))
        flow.require(len(renewed["server_observations"]) == len(SERVERS) and all(
            renewed["server_observations"][c["name"]]["fingerprint"] == c["fingerprint"]
            for c in renewed["credentials"].values() if c["purpose"] == "serverAuth"), "c04_live_server_generations")
        add("all_native_nginx_go_servers_present_new_leaf", servers=len(SERVERS))
        profile = public_file(self.controller, "/managed/canaries/auto.json")
        helper_profile = profile | {"cert": "renew-core-a.pem", "key": "renew-core-a.key"}
        self.write_assets(renewal_volume, {"ca.pem": self.trust_bundle(self.issuer), "probe.json": json.dumps(helper_profile)})
        denied = self.request(self.controller, {"tls_profile": "/managed/renewal/probe.json", "path": "/health/live"})
        flow.require(denied["status"] == 403 and denied["transport_denied"], "c04_renewal_identity_not_business")
        add("renewal_identity_has_no_business_role", status=403)
        profile.update(cert="unregistered.pem", key="unregistered.key")
        self.write_assets(self.canary_volume, {"unregistered.pem": unknown_certificate,
            "unregistered.key": fresh_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            "unregistered.json": json.dumps(profile)})
        denied = probe_canary("unregistered")
        flow.require(denied["status"] == 403 and denied["transport_denied"], "c04_ca_not_authorization")
        add("valid_ca_leaf_without_service_registration_denied", status=403)
        profile.update(cert="retired.pem", key="retired.key")
        self.write_assets(self.canary_volume, {"retired.pem": self.leaves["core-operator"]["cert"], "retired.key": self.leaves["core-operator"]["key"], "retired.json": json.dumps(profile)})
        denied = probe_canary("retired")
        flow.require(denied["status"] == 403 and denied["transport_denied"], "c04_old_live_pin_removed")
        add("cryptographically_valid_old_leaf_rejected_after_cutover", status=403)
        self.document_access(record, keys, "after-renewal")
        add("document_access_after_automatic_cutover", resource_deliveries=1)
        self.paused(False)
        # Both comparison credentials were issued for 30 seconds by this same CA.
        self.wait(lambda: time.time() > metadata(static_certificate)["not_after"] + 1, "c04_static_expired", timeout=40)
        flow.require(probe_canary("static")["status"] == 0 and probe_canary("auto")["status"] == 200, "c04_static_vs_automatic")
        add("equal_lifetime_static_expires_automatic_stays_valid", lifetime_seconds=30)
        self.paused(True)
        before_restart = self.status()
        self.close_probe(self.controller)
        command(["docker", "restart", "--time", "2", self.controller])
        self.wait(lambda: self.status()["paused"], "c04_controller_restart")
        self.paused(False)
        self.wait(lambda: any(c["name"] == "auto-canary" and c["generation"] > before_restart["credentials"][uid]["generation"]
                             and c["not_after"] - time.time() > 20 for uid, c in self.status()["credentials"].items()),
                  "c04_restart_no_bootstrap", timeout=35)
        add("controller_restart_renews_without_bootstrap_secret")

        self.paused(True)  # No issuance response may cross the outage phase boundary.
        command(["docker", "pause", self.ca_server])
        self.paused(False)
        try:
            self.document_access(record, keys, "ca-unavailable")
            add("valid_service_credentials_continue_during_ca_outage", resource_deliveries=1)
            self.wait(lambda: current_named("auto-canary")[1]["not_after"] < time.time() - 1, "c04_auto_expires_during_outage", timeout=45)
            flow.require(probe_canary("auto")["status"] == 0, "c04_outage_expired_denied")
            add("expired_client_fails_closed_during_ca_outage")
        finally:
            command(["docker", "unpause", self.ca_server])
        auto_uid, _auto = current_named("auto-canary")
        flow.require(not self.rpc({"operation": "renew_attempt", "id": auto_uid})["allowed"], "c04_after_expiry_ca_denial")
        add("ca_refuses_renewal_after_expiry")
        self.paused(True)
        current = self.status()
        command(["docker", "restart", "--time", "2", self.ca_server])
        self.paused(False)
        self.wait(lambda: any(c["generation"] > current["credentials"][uid]["generation"] for uid, c in self.status()["credentials"].items()
                             if c["name"] != "auto-canary"), "c04_ca_restart_recovery", timeout=55)
        add("valid_credentials_recover_after_ca_restart")
        flow.require(probe_canary("auto")["status"] == 0, "c04_expired_identity_no_reenrollment")
        add("expired_identity_not_silently_reenrolled")
        rejected("bootstrap_replay_still_denied_after_ca_restart", original_csr, self.grants[collector_uid]["token"])

        self.paused(True)
        revoked_uid, revoked = current_named("revocable-canary")
        self.controller_config["disabled"].append(revoked_uid)
        self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
        self.close_probe(self.controller)
        command(["docker", "stop", "--time", "2", self.controller])
        policy = public_file(self.prefix + "-core-a", "/service-tls/server.json")
        del policy["peers"][revoked["fingerprint"]]
        self.write_assets(self.node_volumes["core-a"], {"server.json": json.dumps(policy)})
        command(["docker", "start", self.controller])
        self.wait(lambda: self.status()["paused"], "c04_retirement_controller_restart")
        flow.require(self.rpc({"operation": "revoke", "id": revoked_uid})["revoked"], "c04_revoke_ca_serial")
        flow.require(not self.rpc({"operation": "renew_attempt", "id": revoked_uid})["allowed"], "c04_revoked_no_renew")
        add("ca_revocation_blocks_certificate_renewal")
        command(["docker", "restart", "--time", "2", self.ca_server])
        self.wait(lambda: self.rpc({"operation": "renew_attempt", "id": collector_uid})["allowed"], "c04_ca_online_after_revoke_restart", timeout=25)
        flow.require(not self.rpc({"operation": "renew_attempt", "id": revoked_uid})["allowed"], "c04_revocation_db_persistent")
        add("ca_revocation_survives_ca_restart")
        denied = probe_canary("revocable")
        flow.require(denied["status"] == 403 and denied["transport_denied"], "c04_retired_service_denied")
        add("explicit_service_retirement_denies_next_request", status=403)
        self.paused(False)
        self.wait(lambda: current_named("revocable-canary")[1]["status"] == "disabled", "c04_disabled_ack")
        flow.require(probe_canary("revocable")["status"] == 403, "c04_no_unretirement")
        add("controller_restart_does_not_restore_retired_identity")
        self.paused(True)
        record["certificate_final_public_status"] = self.status()
        self.close_probe(self.controller)
        command(["docker", "stop", "--time", "2", self.controller])
        self.document_access(record, keys, "after-ca-failures")
        add("document_access_after_ca_failure_and_recovery", resource_deliveries=1)
        self.monitor_after_renewal(record, add)
        online_files = command(["docker", "exec", self.ca_server, "python", "-c",
            "from pathlib import Path;print(any(p.name.startswith('root') and p.suffix=='.key' for p in Path('/ca').iterdir()))"]).strip()
        flow.require(online_files == "False", "c04_offline_root_not_mounted")
        add("root_private_key_not_on_online_ca")
        inspected = json.loads(command(["docker", "inspect", self.controller]))[0]
        flow.require(not any(m["Destination"].endswith("docker.sock") for m in inspected["Mounts"]), "c04_controller_no_socket")
        add("controller_has_no_docker_socket")
        expected = self.report["certificate_contract"]["expected_checks"]
        flow.require(len(checks) == len(expected) and {c["label"] for c in checks} == set(expected), "c04_check_coverage")

    def document_access(self, record, keys, label):
        signed = flow.signed_session(self.prefix + "-" + label, flow.USERS[1], flow.DEVICES[2], self.trial_assets["keys"]["session"])
        response = self.request(self.actors["collector"], {"tls_profile": "/tls/profile.json", "collector_transport": True,
            "method": "POST", "path": "/zero-trust/signals/evaluate", "payload": signed,
            "headers": [["X-API-Key", keys["a"]]], "private_control": True})
        flow.require(response["status"] == 200, "c04_document_session")
        result = json.loads(response["body"])
        grant = result["grant_token"]
        flow.require(bool(grant), "c04_document_grant")
        response = self.request(self.prefix + "-client", {"host": "proxy", "port": 8080, "path": "/documents",
            "headers": [["X-API-Key", keys["a"]], ["X-Session-ID", signed["session_id"]], ["X-Grant-Token", grant]]})
        flow.require(response["status"] == 200 and response["body_sha256"] == pep.DOCUMENT_HASH, "c04_document_delivered")

    def monitor_after_renewal(self, record, add):
        def local(label, path, port, token=None):
            response = self.request(self.prefix + "-" + label, {"port": port, "path": path, "private_control": True,
                "headers": [["Authorization", "Bearer " + token]] if token else []})
            flow.require(response["status"] == 200, "c04_monitor_" + label)
            return response["body"]
        def query(expression):
            return json.loads(local("prometheus", "/api/v1/query?" + urlencode({"query": expression}), 9090))["data"]["result"]
        def events():
            return json.loads(local("sink", "/events", 9001, self.notify_token))["events"]
        self.wait(lambda: bool(query('up{job="zt-signals"}')) and query('up{job="zt-signals"}')[0]["value"][1] == "1", "c04_scrape_after_renew")
        self.wait(lambda: "secops_signal_collection_success 1" in local("exporter", "/metrics", 9101, self.scrape_token), "c04_collection_after_renew")
        self.wait(lambda: not query('ALERTS{alertname="C01SignalCollectionUnavailable",alertstate="firing"}'), "c04_no_prior_firing_episode")
        add("prometheus_scrapes_with_renewed_credentials")
        # Agent is deliberately paused/stopped before an operator fault so it cannot
        # race this policy edit. All policy writers must obey this single-writer boundary.
        original = json.loads(command(["docker", "exec", self.prefix + "-reader", "python", "-c",
            "import pathlib;print(pathlib.Path('/service-tls/server.json').read_text())"]))
        retired = json.loads(json.dumps(original))
        fp = next(c["fingerprint"] for c in record["certificate_final_public_status"]["credentials"].values() if c["name"] == "metrics-reader")
        del retired["peers"][fp]
        floor = len(events())
        phase = datetime.fromisoformat(command(["docker", "exec", self.prefix + "-sink", "python", "-c",
            "from datetime import UTC,datetime;print(datetime.now(UTC).isoformat())"]).strip())
        self.write_assets(self.node_volumes["reader"], {"server.json": json.dumps(retired)})
        matching = {}
        def firing():
            for event in events()[floor:]:
                if (event["alertname"] == "C01SignalCollectionUnavailable" and event["status"] == "firing"
                        and event.get("job") == "zt-signals" and event.get("instance") == "exporter:9101"
                        and datetime.fromisoformat(event["starts_at"]) >= phase):
                    matching.update(event)
                    return True
            return False
        self.wait(firing, "c04_firing_with_renewed_certs", timeout=50)
        add("new_alert_episode_delivered_after_renewal", fingerprint=matching["fingerprint"], starts_at=matching["starts_at"])
        self.write_assets(self.node_volumes["reader"], {"server.json": json.dumps(original)})
        self.wait(lambda: any(e["status"] == "resolved" and e["fingerprint"] == matching["fingerprint"] and e["starts_at"] == matching["starts_at"]
                             for e in events()[floor:]), "c04_same_episode_resolved_after_renew", timeout=50)
        add("same_alert_episode_resolved_after_renewal", fingerprint=matching["fingerprint"], starts_at=matching["starts_at"])

    def cleanup(self):
        super().cleanup()
        if hasattr(self, "graph_image"):
            subprocess.run(["docker", "image", "rm", self.graph_image], capture_output=True, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/c04/run")
    parser.add_argument("--repeats", type=int, choices=range(1, 3), default=2)
    parser.add_argument("--ca-smoke", action="store_true")
    args = parser.parse_args()
    lab = CertificateLab(args.directory)
    try:
        lab.prepare()
        if args.ca_smoke:
            lab.smoke()
        else:
            for iteration in range(1, args.repeats + 1):
                lab.trial("nginx", iteration)
            flow.require(all(r["completed"] for r in lab.report["runs"]), "c04_incomplete")
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, NotImplementedError, subprocess.SubprocessError, flow.CheckFailed) as exc:
        lab.report["failure"] = str(exc) if isinstance(exc, flow.CheckFailed) else type(exc).__name__
        if hasattr(lab, "controller"):
            snapshot = subprocess.run(["docker", "exec", lab.controller, "python", "-c",
                "from pathlib import Path;p=Path('/state/status.json');print(p.read_text() if p.exists() else '{}')"],
                capture_output=True, text=True, check=False)
            if snapshot.returncode == 0:
                lab.report["failure_public_status"] = json.loads(snapshot.stdout)
        lab.save()
        raise SystemExit(lab.report["failure"]) from None
    finally:
        lab.report["finished_at"] = flow.timestamp()
        lab.cleanup()


if __name__ == "__main__":
    main()
