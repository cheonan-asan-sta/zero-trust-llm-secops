"""All network hops of the selected local SecOps graph use mTLS; no cloud/model calls.

Reuses the I2 30-case and C02 42-case contracts, then exercises collectors and
Prometheus/Alertmanager notifications. Historical HTTP comparison labs stay separate.
"""

import argparse
import hashlib
import json
import secrets
import shutil
import subprocess
import tarfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlencode

import yaml
from cryptography.hazmat.primitives import serialization

from scripts import pep_lab as pep
from scripts import test_signal_compose as flow
from scripts.compare_pep import ROOT, command
from scripts.compare_supply_chain import download, sha256
from scripts.mtls_fixtures import authority, fixtures, leaf
from scripts.observability_lab import notification_seen
from scripts.test_mtls_infrastructure import TLSLab


class AllHopsLab(TLSLab):
    def __init__(self, directory):
        super().__init__(directory)
        self.report["schema"] = "all-hops-mtls-1"
        self.report["all_hops_contract"] = json.loads((ROOT / "infra/mtls/all-hops-contract.json").read_text())
        self.report["conditions"]["all_service_network_hops"] = "mTLS, including native core and monitoring"
        self.save()

    def prepare(self):
        super().prepare()
        self.base_image = self.image
        build = self.directory / "tools-build"
        (build / "bin").mkdir(parents=True, exist_ok=True)
        (build / "downloads").mkdir(exist_ok=True)
        lock = json.loads((ROOT / "infra/observability/tools.lock.json").read_text())
        selected = [t for t in lock["tools"] if t["name"] in {"prometheus", "alertmanager"}]
        for tool in selected:
            asset = tool["assets"][0]
            cached = ROOT / "runtime/c01/build/downloads" / asset["name"]
            target = build / "downloads" / asset["name"]
            if cached.is_file() and "sha256:" + sha256(cached) == asset["digest"]:
                shutil.copyfile(cached, target)
            download(tool, asset, build / "downloads")
            with tarfile.open(target, "r:gz") as archive:
                for name, member in tool["binaries"].items():
                    entry = archive.getmember(member)
                    flow.require(entry.isfile() and 0 < entry.size < 300 * 1024**2, "all_hops_binary")
                    with archive.extractfile(entry) as source, (build / "bin" / name).open("wb") as output:
                        shutil.copyfileobj(source, output)
        (build / "Dockerfile").write_text(f"FROM {self.base_image}\nUSER 0\nCOPY bin /tools\nRUN chmod 0555 /tools/*\nUSER 10001:10001\nHEALTHCHECK NONE\n")
        (build / ".dockerignore").write_text("*\n!Dockerfile\n!bin/\n!bin/*\n")
        self.image = self.ident + "-all-hops"
        command(["docker", "build", "--tag", self.image, str(build)], timeout=900)
        self.report["execution_image_id"] = command(["docker", "image", "inspect", self.image, "--format", "{{.Id}}"]).strip()
        self.report["monitoring_tools"] = selected
        for name in ["scripts/mtls_native.py", "scripts/test_all_hops_mtls.py", "scripts/signal_metrics_exporter.py",
                     "scripts/local_signal_collector.py",
                     "scripts/observability_lab.py", "infra/mtls/all-hops-nginx.conf", "infra/mtls/all-hops-contract.json",
                     "infra/observability/alerts.yaml", "infra/observability/tools.lock.json"]:
            self.report["source_input_sha256"][name] = sha256(ROOT / name)
        self.save()

    def make_fixtures(self):
        return self.ca, self.leaves

    def graph_authority(self):
        return authority("All-hops ephemeral CA")

    def trust_bundle(self, ca):
        return ca[1].public_bytes(serialization.Encoding.PEM).decode()

    def trial(self, candidate, iteration):
        # The I2 adversarial fixture retains its own CA. Native services share that same CA
        # only when explicitly created here, before the core starts.
        self.ca, self.leaves = fixtures()
        # Generate one CA for the expanded graph (including I2 fixtures) so all expected
        # clients can be checked using the same protected trust registry.
        ca = self.graph_authority()
        self.ca = self.trust_bundle(ca)
        names = {"server": ("gateway", True), "server-next": ("gateway", True),
            "bridge": ("pep-bridge", False), "bridge-next": ("pep-bridge", False), "collector": ("collector", False),
            "unknown": ("pep-bridge", False), "wrong-eku": ("pep-bridge", True)}
        for label, (name, server) in names.items():
            self.leaves[label] = leaf(ca, name, server=server)
        for label, kwargs in {"expired": {"expired": True}, "future": {"future": True}}.items():
            self.leaves[label] = leaf(ca, "pep-bridge", **kwargs)
        for label, name, kwargs in [("server-expired", "gateway", {"server": True, "expired": True}),
            ("server-future", "gateway", {"server": True, "future": True}),
            ("server-wrong-name", "different.local", {"server": True}), ("server-wrong-eku", "gateway", {})]:
            self.leaves[label] = leaf(ca, name, **kwargs)
        for label in ["core-a", "core-b", "core-c", "reader", "proxy", "bridge-auth", "bridge-consume", "resource", "exporter", "sink", "prometheus", "am", "gateway-stats"]:
            self.leaves[label] = leaf(ca, label, server=True)
        for label in ["core-operator", "gateway-client", "proxy-auth", "proxy-resource", "frontend", "frontend-next", "bridge-probe",
                      "resource-consumer", "resource-auditor", "transport-auditor", "metrics-reader", "scrape-agent", "scrape-control",
                      "monitor-query", "monitor-alert", "am-control", "alert-manager", "sink-auditor"]:
            self.leaves[label] = leaf(ca, label)
        self.leaves["resource-probe"] = leaf(ca, "resource-probe")
        self.prefix = f"{self.ident}-{iteration}-{candidate}"
        self.node_volumes, self.node_files = {}, {}
        for label in ["core-a", "core-b", "core-c"]:
            files = self.server_files(label, {"core-operator": "core-operator", "gateway-client": "api-gateway"})
            files.update(self.client_profile("operator.json", "core-operator", label, "127.0.0.1", 8000))
            self.node(label, files)
        self.node("proxy", self.key_files("proxy", "proxy-auth", "proxy-resource"))
        self.node("bridge", self.server_files("bridge-auth", {"proxy-auth": "proxy-auth", "bridge-probe": "bridge-probe"}, "auth.json") |
            self.server_files("bridge-consume", {"resource-consumer": "resource-consumer"}, "consume.json") |
            self.client_profile("probe.json", "bridge-probe", "bridge-auth", "127.0.0.1", 8081))
        self.node_files["bridge"]["front.json"] = json.dumps({"forwarded_peers": [self.leaves[n]["fingerprint"] for n in ["frontend", "frontend-next"]]})
        self.write_assets(self.node_volumes["bridge"], {"front.json": self.node_files["bridge"]["front.json"]})
        self.node("resource", self.server_files("resource", {"proxy-resource": "proxy-resource", "resource-auditor": "resource-auditor", "resource-probe": "proxy-resource"}) |
            self.client_profile("consume-client.json", "resource-consumer", "bridge-consume", "bridge", 8082) |
            self.client_profile("audit.json", "resource-auditor", "resource", "127.0.0.1", 8083) |
            self.client_profile("document-probe.json", "resource-probe", "resource", "127.0.0.1", 8083))
        self.node("client", self.client_profile("frontend.json", "frontend", "proxy", "proxy", 8080) |
            self.client_profile("unknown.json", "unknown", "proxy", "proxy", 8080))
        super().trial(candidate, iteration)

    def key_files(self, *labels):
        files = {"ca.pem": self.ca}
        for label in labels:
            files[label + ".pem"], files[label + ".key"] = self.leaves[label]["cert"], self.leaves[label]["key"]
        return files

    def server_files(self, server, peers, filename="server.json"):
        return self.key_files(server) | {filename: json.dumps({"cert": server + ".pem", "key": server + ".key", "ca": "ca.pem",
            "peers": {self.leaves[label]["fingerprint"]: role for label, role in peers.items()}})}

    def client_profile(self, filename, client, server, host, port):
        return self.key_files(client) | {filename: json.dumps({"host": host, "port": port, "server_name": server,
            "cert": client + ".pem", "key": client + ".key", "ca": "ca.pem", "server_pins": [self.leaves[server]["fingerprint"]]})}

    def node(self, label, files):
        volume = self.volume(self.prefix + "-node-" + label)
        self.node_volumes[label], self.node_files[label] = volume, files
        self.write_assets(volume, files)
        return volume

    def write_assets(self, volume, files):
        if volume == getattr(self, "server_volume", None) and "profile.json" in files:
            files = dict(files)
            files.update(self.server_files("gateway-stats", {"transport-auditor": "transport-auditor"}, "stats.json"))
            files.update(self.client_profile("audit-client.json", "transport-auditor", "gateway-stats", "127.0.0.1", 8444))
            files.update(self.client_profile("backend.json", "gateway-client", "core-a", "core", 8000))
        super().write_assets(volume, files)

    def start(self, name, network, argv, **kwargs):
        label = name.removeprefix(getattr(self, "prefix", "") + "-")
        mounts = list(kwargs.pop("mounts", ()))
        if label in getattr(self, "node_volumes", {}):
            mounts.append(f"type=volume,src={self.node_volumes[label]},dst=/service-tls,readonly")
        if label in {"core-a", "core-b", "core-c"}:
            argv = ["python", "-m", "scripts.mtls_native", "api", "--profile", "/service-tls/server.json"]
            if label == "core-a":
                self.shared_mounts, self.app_env, self.core_network = mounts[:-1], kwargs["env"], network
        elif label == "bridge":
            argv += ["--server-tls-profile", "/service-tls/auth.json", "--consume-server-profile", "/service-tls/consume.json",
                     "--forwarded-profile", "/service-tls/front.json"]
        elif label == "resource":
            argv += ["--server-tls-profile", "/service-tls/server.json", "--consume-tls-profile", "/service-tls/consume-client.json"]
        elif label == "tls-gateway":
            argv += ["--backend-profile", "/tls/backend.json", "--stats-profile", "/tls/stats.json"]
        elif label == "proxy":
            argv = ["nginx", "-c", "/config/all-hops.conf", "-g", "daemon off;"]
            mounts = [m for m in mounts if "dst=/config/nginx.conf" not in m]
            mounts.append(f"type=bind,src={ROOT / 'infra/mtls/all-hops-nginx.conf'},dst=/config/all-hops.conf,readonly")
        return super().start(name, network, self.service_command(label, argv), mounts=mounts, **kwargs)

    def service_command(self, label, argv):
        return argv

    def request(self, container, request):
        if (isinstance(request, dict) and container == self.prefix + "-core-a"
                and request.get("method") == "POST" and request.get("path") == "/zero-trust/signals/inbox"):
            # The existing M3 worker case now receives its observation from the actual
            # collector transport through both TLS hops, rather than an operator shortcut.
            data = request | {"tls_profile": "/tls/profile.json", "collector_transport": True}
            response = super().request(self.actors["collector"], data)
            self.report["runs"][-1]["continuous_collector_transport"] = {
                "status": response["status"], "tls_version": response.get("tls_version"),
                "route": "collector -> gateway -> native core", "client": "local_signal_collector._post"}
            return response
        if isinstance(request, list):
            return super().request(container, [self.tls_probe(container, r) for r in request])
        return super().request(container, self.tls_probe(container, request))

    def tls_probe(self, container, request):
        data = dict(request)
        if data.pop("plain", False) or "tls_profile" in data:
            return data
        label = container.removeprefix(self.prefix + "-")
        port = data.get("port", 8000)
        if label in {"core-a", "core-b", "core-c"}:
            data["tls_profile"] = "/service-tls/operator.json"
        elif label == "client" and data.get("host") == "proxy":
            data["tls_profile"] = "/service-tls/frontend.json"
        elif label == "bridge" and port == 8081:
            data["tls_profile"] = "/service-tls/probe.json"
        elif label == "resource" and port == 8083:
            data["tls_profile"] = "/service-tls/audit.json" if data["path"] == "/_stats" else "/service-tls/document-probe.json"
        elif label == "tls-gateway" and port == 8444:
            data.update(path="/_transport/stats", tls_profile="/tls/audit-client.json")
        elif label in {"exporter", "sink", "prometheus", "am"}:
            data["tls_profile"] = "/service-tls/local.json"
        return data

    def prepare_transport(self, prefix, networks):
        result = super().prepare_transport(prefix, networks)
        self.monitoring(prefix, networks)
        return result

    def monitoring(self, prefix, networks):
        monitor = prefix + "-monitoring"
        command(["docker", "network", "create", "--internal", "--label", "secops.c02=" + self.ident, monitor])
        self.networks.append(monitor)
        networks["monitoring"] = monitor
        self.monitor_network = monitor
        self.scrape_token, self.notify_token, viewer_key = [secrets.token_urlsafe(32) for _ in range(3)]
        self.node("reader", self.server_files("reader", {"metrics-reader": "metrics-reader", "core-operator": "core-operator"}))
        self.viewer_key = viewer_key
        self.start(prefix + "-reader", networks["core"], ["python", "-m", "scripts.mtls_native", "api", "--profile", "/service-tls/server.json"],
            alias="reader", mounts=self.shared_mounts, env=self.app_env | {"API_KEY_SHA256": hashlib.sha256(viewer_key.encode()).hexdigest(),
                "API_KEY_ROLES": "viewer", "API_KEY_SUBJECT": "monitor-reader", "ALLOWED_HOSTS": "reader,127.0.0.1,localhost"}, memory=256, cpus=.5)
        self.node("exporter", self.server_files("exporter", {"scrape-agent": "scrape-agent", "scrape-control": "scrape-agent"}) |
            self.client_profile("reader.json", "metrics-reader", "reader", "reader", 8000) |
            self.client_profile("local.json", "scrape-control", "exporter", "127.0.0.1", 9101) | {"scrape.token": self.scrape_token})
        self.start(prefix + "-exporter", monitor, ["python", "-m", "scripts.signal_metrics_exporter", "--upstream", "https://reader:8000/zero-trust/signals/inbox",
            "--token-file", "/service-tls/scrape.token", "--listen", "0.0.0.0", "--server-tls-profile", "/service-tls/server.json",
            "--upstream-tls-profile", "/service-tls/reader.json"], alias="exporter", env={"C01_UPSTREAM_API_KEY": viewer_key}, additional=[(networks["core"], "exporter")])
        self.node("sink", self.server_files("sink", {"alert-manager": "alert-manager", "sink-auditor": "sink-auditor"}) |
            self.client_profile("local.json", "sink-auditor", "sink", "127.0.0.1", 9001) | {"notify.token": self.notify_token})
        self.start(prefix + "-sink", monitor, ["python", "-m", "scripts.mtls_native", "receiver", "--port", "9001",
            "--profile", "/service-tls/server.json", "--token-file", "/service-tls/notify.token"], alias="sink")
        self.node("prometheus", self.key_files("prometheus", "scrape-agent", "monitor-alert", "monitor-query"))
        self.node("am", self.key_files("am", "alert-manager", "am-control"))
        self.configure_monitoring()
        for label, argv, memory, cpus in [("am", ["/tools/alertmanager", "--config.file=/service-tls/config.yml", "--storage.path=/data/alerts",
            "--cluster.listen-address=", "--web.listen-address=:9093", "--web.config.file=/service-tls/web.yml"], 128, .5),
            ("prometheus", ["/tools/prometheus", "--config.file=/service-tls/config.yml", "--storage.tsdb.path=/data/prometheus",
            "--storage.tsdb.retention.time=1d", "--web.listen-address=:9090", "--web.config.file=/service-tls/web.yml"], 512, 1.5)]:
            storage = self.volume(prefix + "-" + label + "-storage")
            self.start(prefix + "-" + label, monitor, argv, alias=label, mounts=[f"type=volume,src={storage},dst=/data"], memory=memory, cpus=cpus)

    def configure_monitoring(self):
        def outgoing(client, server):
            return {"ca_file": "/service-tls/ca.pem", "cert_file": f"/service-tls/{client}.pem", "key_file": f"/service-tls/{client}.key",
                    "server_name": server, "min_version": "TLS12", "insecure_skip_verify": False}
        for server, clients in [("prometheus", ["monitor-query"]), ("am", ["monitor-alert", "am-control"])]:
            web = {"tls_server_config": {"cert_file": f"/service-tls/{server}.pem", "key_file": f"/service-tls/{server}.key",
                "client_auth_type": "RequireAndVerifyClientCert", "client_ca_file": "/service-tls/ca.pem",
                "client_allowed_sans": clients, "min_version": "TLS12"}, "http_server_config": {"http2": False}}
            self.node_files[server]["web.yml"] = yaml.safe_dump(web)
        prom = {"global": {"scrape_interval": "1s", "scrape_timeout": "800ms", "evaluation_interval": "1s"},
            "scrape_configs": [{"job_name": "zt-signals", "scheme": "https", "metrics_path": "/metrics",
                "authorization": {"type": "Bearer", "credentials_file": "/service-tls/scrape.token"},
                "tls_config": outgoing("scrape-agent", "exporter"), "static_configs": [{"targets": ["exporter:9101"]}]}],
            "rule_files": ["/service-tls/alerts.yaml"], "alerting": {"alertmanagers": [{"scheme": "https",
                "tls_config": outgoing("monitor-alert", "am"), "static_configs": [{"targets": ["am:9093"]}]}]}}
        am = {"route": {"receiver": "local", "group_by": ["alertname"], "group_wait": "0s", "group_interval": "1s", "repeat_interval": "1h"},
            "receivers": [{"name": "local", "webhook_configs": [{"url": "https://sink:9001/events", "send_resolved": True,
                "http_config": {"tls_config": outgoing("alert-manager", "sink"),
                    "authorization": {"type": "Bearer", "credentials_file": "/service-tls/notify.token"}}}]}]}
        self.node_files["prometheus"].update({"config.yml": yaml.safe_dump(prom), "scrape.token": self.scrape_token,
            "alerts.yaml": (ROOT / "infra/observability/alerts.yaml").read_text(), **self.client_profile("local.json", "monitor-query", "prometheus", "127.0.0.1", 9090)})
        self.node_files["am"].update({"config.yml": yaml.safe_dump(am), "notify.token": self.notify_token,
            **self.client_profile("local.json", "am-control", "am", "127.0.0.1", 9093)})
        for name in ["prometheus", "am"]:
            self.write_assets(self.node_volumes[name], self.node_files[name])

    def transport_checks(self, prefix, record, keys, bridge):
        super().transport_checks(prefix, record, keys, bridge)
        # I2 deliberately rotated the gateway leaf; distribute that verified new
        # pin to the collector before its genuine signed-session submission.
        self.write_assets(self.actor_volumes["collector"], self.client_files("collector", "server-next"))
        self.extra_checks(prefix, record, keys, bridge)

    def extra_checks(self, prefix, record, keys, bridge):
        checks = record["all_hops_checks"] = []
        counter = 0

        def add(label, **evidence):
            checks.append({"label": label, "passed": True, **evidence})
            self.save()

        def core(path, payload=None):
            req = {"path": path, "headers": [["X-API-Key", keys["a"]]], "private_control": True}
            if payload is not None:
                req.update(method="POST", payload=payload)
            response = self.request(prefix + "-core-a", req)
            return response["status"], json.loads(response["body"])

        def mint():
            nonlocal counter
            counter += 1
            label = f"all-hops-{record['iteration']}-{counter}"
            payload = flow.signed_session(label, flow.USERS[1], flow.DEVICES[2], self.trial_assets["keys"]["session"])
            status, result = core("/zero-trust/signals/evaluate", payload)
            flow.require(status == 200 and result["grant_token"], "all_hops_mint")
            return label, result["grant_token"]

        def proxy(pair, **extra):
            return self.request(prefix + "-client", {"host": "proxy", "port": 8080, "path": "/documents", "headers": [
                ["X-API-Key", keys["a"]], ["X-Session-ID", pair[0]], ["X-Grant-Token", pair[1]]], **extra})

        def resource_count():
            return json.loads(self.request(prefix + "-resource", {"port": 8083, "path": "/_stats", "private_control": True})["body"])["served"]

        def consume(pair, expected):
            status, body = core("/zero-trust/protected-access", {"session_id": pair[0], "grant_token": pair[1],
                "resource_id": "zt-demo-documents", "action": "READ"})
            flow.require(status == (200 if expected == "ACCESS_GRANTED" else 403) and body["reason_code"] == expected, "all_hops_grant_state")

        # Signed collector traffic is genuine, while continuous observations remain in the
        # existing later M3 worker test so no earlier pending item can change its order.
        signed = flow.signed_session(f"all-collector-{record['iteration']}", flow.USERS[1], flow.DEVICES[2], self.trial_assets["keys"]["session"])
        response = self.request(self.actors["collector"], {"tls_profile": "/tls/profile.json", "path": "/zero-trust/signals/evaluate",
            "collector_transport": True, "method": "POST", "payload": signed,
            "headers": [["X-API-Key", keys["a"]]], "private_control": True})
        record["collector_probe_status"] = {"status": response["status"], "tls_version": response.get("tls_version")}
        flow.require(response["status"] == 200 and json.loads(response["body"])["grant_token"], "all_hops_collector")
        add("signed_collector_through_two_tls_hops", status=200, tls_version=response.get("tls_version"))

        targets = [("proxy", "proxy", 8080, "/documents", "proxy"), ("core", "core", 8000, "/health/live", "core-a"),
            ("gateway", "gateway", 8443, "/zero-trust/protected-access", "server-next"),
            ("gateway-stats", "gateway", 8444, "/_transport/stats", "gateway-stats"),
            ("auth", "bridge", 8081, "/_authorize", "bridge-auth"), ("consume", "bridge", 8082, "/consume", "bridge-consume"),
            ("resource", "resource", 8083, "/documents", "resource"), ("reader", "reader", 8000, "/zero-trust/signals/inbox", "reader"),
            ("exporter", "exporter", 9101, "/metrics", "exporter"), ("sink", "sink", 9001, "/events", "sink"),
            ("prometheus", "prometheus", 9090, "/-/ready", "prometheus"), ("am", "am", 9093, "/-/ready", "am")]
        files = {}
        for label, host, port, path, server in targets:
            files.update(self.client_profile(label + ".json", "unknown", server, host, port))
        self.node("adversary", files)
        all_networks = [n for n in self.networks if n.startswith(prefix + "-")]
        actor = prefix + "-adversary"
        self.start(actor, self.monitor_network, ["python", "-c", "import time; time.sleep(3600)"],
            additional=[(n, "adversary") for n in all_networks if n != self.monitor_network])
        for label, host, port, path, server in targets:
            req = {"host": host, "port": port, "path": path}
            plain = self.request(actor, req | {"plain": True})
            flow.require(not 200 <= plain["status"] < 300 and plain["body_sha256"] != pep.DOCUMENT_HASH, "all_hops_plain_" + label)
            add("plain_" + label, status=plain["status"])
            if label == "proxy":
                pair = mint()
                req["headers"] = [["X-API-Key", keys["a"]], ["X-Session-ID", pair[0]], ["X-Grant-Token", pair[1]],
                    ["X-Verified-Client-Cert", quote(self.leaves["frontend"]["cert"])]]
            denied = self.request(actor, req | {"tls_profile": "/service-tls/" + label + ".json"})
            flow.require(not 200 <= denied["status"] < 300 and denied["body_sha256"] != pep.DOCUMENT_HASH, "all_hops_unknown_" + label)
            if label not in {"proxy", "gateway", "prometheus", "am"}:
                flow.require(denied.get("transport_denied"), "all_hops_identity_guard_" + label)
            if label == "proxy":
                consume(pair, "ACCESS_GRANTED")
            add("unknown_" + label, status=denied["status"], transport_denied=denied.get("transport_denied", False))

        # Exercise actual callers against a current, valid registry with one caller retired.
        for label, node, filename, peer, consumed in [
            ("gateway_backend", "core-a", "server.json", "gateway-client", False),
            ("proxy_auth", "bridge", "auth.json", "proxy-auth", False),
            ("proxy_resource", "resource", "server.json", "proxy-resource", True),
            ("resource_consumer", "bridge", "consume.json", "resource-consumer", True)]:
            original = self.node_files[node][filename]
            policy = json.loads(original)
            # A second audit identity keeps the policy structurally valid during retirement.
            if len(policy["peers"]) == 1:
                policy["peers"][self.leaves["core-operator"]["fingerprint"]] = "core-operator"
            del policy["peers"][self.leaves[peer]["fingerprint"]]
            pair, before = mint(), resource_count()
            self.write_assets(self.node_volumes[node], {filename: json.dumps(policy)})
            denied = proxy(pair)
            flow.require(not 200 <= denied["status"] < 300 and resource_count() == before, "all_hops_retired_" + label)
            self.write_assets(self.node_volumes[node], {filename: original})
            consume(pair, "GRANT_ALREADY_USED" if consumed else "ACCESS_GRANTED")
            add("retired_" + label, status=denied["status"], resource_deliveries=0, consumed_before_failure=consumed)

        original = self.client_profile("backend.json", "gateway-client", "core-a", "core", 8000)["backend.json"]
        damaged = json.loads(original)
        damaged["server_pins"] = ["0" * 64]
        pair, before = mint(), resource_count()
        self.write_assets(self.server_volume, {"backend.json": json.dumps(damaged)})
        denied = proxy(pair)
        flow.require(not 200 <= denied["status"] < 300 and resource_count() == before, "all_hops_backend_pin")
        self.write_assets(self.server_volume, {"backend.json": original})
        consume(pair, "ACCESS_GRANTED")
        add("gateway_backend_wrong_server_pin", resource_deliveries=0)

        pair, before = mint(), resource_count()
        self.write_assets(self.node_volumes["bridge"], {"front.json": json.dumps({"forwarded_peers": [self.leaves["frontend-next"]["fingerprint"]]})})
        denied = proxy(pair)
        flow.require(not 200 <= denied["status"] < 300 and resource_count() == before, "all_hops_frontend_retired")
        self.write_assets(self.node_volumes["client"], self.client_profile("frontend.json", "frontend-next", "proxy", "proxy", 8080))
        accepted = proxy(pair)
        flow.require(accepted["status"] == 200 and accepted["body_sha256"] == pep.DOCUMENT_HASH and resource_count() == before + 1, "all_hops_frontend_rotated")
        add("frontend_retirement_and_replacement", resource_deliveries=1, retired_status=denied["status"], replacement_status=200)
        self.monitor_checks(prefix, record, add)
        # Verify network isolation using actual IPs, independently of name resolution/TLS profiles.
        for label, name, port in [("core", prefix + "-core-a", 8000), ("resource", prefix + "-resource", 8083)]:
            addresses = json.loads(command(["docker", "inspect", name]))[0]["NetworkSettings"]["Networks"]
            for address in addresses.values():
                blocked = command(["docker", "exec", "-i", prefix + "-client", "python", "-c",
                    "import json,socket,sys; h,p=json.load(sys.stdin);\ntry:\n s=socket.create_connection((h,p),timeout=.5);s.close();print('open')\nexcept OSError: print('blocked')"], input=json.dumps([address["IPAddress"], port])).strip()
                flow.require(blocked == "blocked", "all_hops_client_isolation")
            add("client_ip_isolated_" + label, interfaces_checked=len(addresses))
        expected = self.report["all_hops_contract"]["expected_checks"]
        flow.require(len(checks) == len(expected) and {c["label"] for c in checks} == set(expected), "all_hops_coverage")
        record["all_hops_public_fingerprints"] = {k: v["fingerprint"] for k, v in self.leaves.items()}

    def monitor_checks(self, prefix, record, add):
        def local(label, path, port, token=None, payload=None):
            req = {"path": path, "port": port, "private_control": True, "headers": []}
            if token:
                req["headers"] = [["Authorization", "Bearer " + token]]
            if payload is not None:
                req.update(method="POST", payload=payload)
            result = self.request(prefix + "-" + label, req)
            flow.require(result["status"] == 200, "all_hops_monitor_read_" + label)
            return result["body"]
        def metric():
            return local("exporter", "/metrics", 9101, self.scrape_token)
        def query(expression):
            raw = local("prometheus", "/api/v1/query?" + urlencode({"query": expression}), 9090)
            return json.loads(raw)["data"]["result"]
        def events():
            return json.loads(local("sink", "/events", 9001, self.notify_token))["events"]
        self.wait(lambda: "secops_signal_collection_success 1" in metric(), "all_hops_exporter_ready", timeout=40)
        add("exporter_authenticated_native_tls", tls=True)
        denied = self.request(prefix + "-exporter", {"path": "/metrics", "port": 9101})
        flow.require(denied["status"] == 401, "all_hops_metrics_bearer")
        add("mtls_does_not_replace_scrape_bearer", status=401)
        denied = self.request(prefix + "-exporter", {"path": "/zero-trust/signals/inbox", "port": 8000,
            "method": "POST", "payload": {}, "headers": [["X-API-Key", self.viewer_key]], "tls_profile": "/service-tls/reader.json"})
        flow.require(denied["status"] == 403 and denied.get("transport_denied"), "all_hops_reader_write")
        add("metrics_reader_cannot_write", status=403)
        self.wait(lambda: bool(query('up{job="zt-signals"}')) and query('up{job="zt-signals"}')[0]["value"][1] == "1", "all_hops_scrape", timeout=40)
        add("prometheus_scrapes_mtls_exporter")
        export_policy = json.loads(self.node_files["exporter"]["server.json"])
        del export_policy["peers"][self.leaves["scrape-agent"]["fingerprint"]]
        self.write_assets(self.node_volumes["exporter"], {"server.json": json.dumps(export_policy)})
        self.wait(lambda: bool(query('up{job="zt-signals"}')) and query('up{job="zt-signals"}')[0]["value"][1] == "0", "all_hops_scraper_revoked")
        flow.require("secops_signal_collection_success 1" in metric(), "all_hops_exporter_still_healthy")
        self.write_assets(self.node_volumes["exporter"], {"server.json": self.node_files["exporter"]["server.json"]})
        self.wait(lambda: query('up{job="zt-signals"}')[0]["value"][1] == "1", "all_hops_scraper_repaired")
        add("scrape_identity_retirement_and_repair")
        target = "C01SignalCollectionUnavailable"
        self.wait(lambda: not query('ALERTS{alertname="' + target + '",alertstate="firing"}'), "all_hops_initial_no_collection_alert")
        floor = len(events())
        phase_time = command(["docker", "exec", prefix + "-sink", "python", "-c", "from datetime import UTC,datetime;print(datetime.now(UTC).isoformat())"]).strip()
        reader_policy = json.loads(self.node_files["reader"]["server.json"])
        del reader_policy["peers"][self.leaves["metrics-reader"]["fingerprint"]]
        sink_policy = json.loads(self.node_files["sink"]["server.json"])
        del sink_policy["peers"][self.leaves["alert-manager"]["fingerprint"]]
        self.write_assets(self.node_volumes["sink"], {"server.json": json.dumps(sink_policy)})
        self.write_assets(self.node_volumes["reader"], {"server.json": json.dumps(reader_policy)})
        self.wait(lambda: "secops_signal_collection_success 0" in metric(), "all_hops_reader_revoked")
        add("exporter_reader_identity_retired_fail_closed")
        self.wait(lambda: any(a["labels"].get("alertname") == target for a in json.loads(local("am", "/api/v2/alerts", 9093))),
                  "all_hops_prometheus_to_am", timeout=40)
        time.sleep(3)
        flow.require(not notification_seen(events(), target, "firing", floor, {"instance": "exporter:9101", "job": "zt-signals"}), "all_hops_notifier_revoked")
        add("alertmanager_client_identity_retired_blocks_webhook")
        self.write_assets(self.node_volumes["sink"], {"bad.pem": self.leaves["server-wrong-name"]["cert"], "bad.key": self.leaves["server-wrong-name"]["key"]})
        bad_policy = json.loads(self.node_files["sink"]["server.json"])
        bad_policy.update(cert="bad.pem", key="bad.key")
        self.write_assets(self.node_volumes["sink"], {"server.json": json.dumps(bad_policy)})
        # The sink audit client also validates server name/pin, so its management TLS
        # cannot be used while deliberately serving the wrong certificate. Inspect
        # the notifier's bounded diagnostic, then repair and verify a fresh episode.
        # Docker sends diagnostics to stderr; retain only a boolean, never raw messages.
        def notifier_tls_error():
            out = subprocess.run(["docker", "logs", "--tail", "100", prefix + "-am"], capture_output=True, text=True, check=False)
            return "different.local" in out.stdout + out.stderr and "sink" in out.stdout + out.stderr
        self.wait(notifier_tls_error, "all_hops_sink_server_name_rejected", timeout=45)
        add("alertmanager_rejects_wrong_sink_server_identity")
        self.write_assets(self.node_volumes["sink"], {"server.json": self.node_files["sink"]["server.json"]})
        matching = {}
        def firing():
            for event in events()[floor:]:
                if (event["alertname"] == target and event["status"] == "firing" and event.get("job") == "zt-signals"
                        and event.get("instance") == "exporter:9101" and datetime.fromisoformat(event["starts_at"]) >= datetime.fromisoformat(phase_time)):
                    matching.update(event)
                    return True
            return False
        self.wait(firing, "all_hops_firing_delivered", timeout=50)
        add("mtls_alert_firing_exact_episode", fingerprint=matching["fingerprint"], starts_at=matching["starts_at"])
        self.write_assets(self.node_volumes["reader"], {"server.json": self.node_files["reader"]["server.json"]})
        self.wait(lambda: "secops_signal_collection_success 1" in metric(), "all_hops_reader_repaired")
        self.wait(lambda: any(e["alertname"] == target and e["status"] == "resolved" and e["fingerprint"] == matching["fingerprint"]
            and e["starts_at"] == matching["starts_at"] for e in events()[floor:]), "all_hops_resolved_delivered", timeout=50)
        add("mtls_alert_resolved_same_episode", fingerprint=matching["fingerprint"], starts_at=matching["starts_at"])

    def cleanup(self):
        super().cleanup()
        if hasattr(self, "base_image"):
            subprocess.run(["docker", "image", "rm", self.base_image], capture_output=True, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/all-hops")
    parser.add_argument("--repeats", type=int, choices=range(1, 4), default=3)
    args = parser.parse_args()
    lab = AllHopsLab(args.directory)
    try:
        lab.prepare()
        for iteration in range(1, args.repeats + 1):
            lab.trial("nginx", iteration)
        flow.require(all(r["completed"] for r in lab.report["runs"]), "all_hops_incomplete")
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, NotImplementedError, subprocess.SubprocessError, flow.CheckFailed) as exc:
        lab.report["failure"] = str(exc) if isinstance(exc, flow.CheckFailed) else type(exc).__name__
        raise SystemExit(lab.report["failure"]) from None
    finally:
        lab.report["finished_at"] = flow.timestamp()
        lab.cleanup()


if __name__ == "__main__":
    main()
