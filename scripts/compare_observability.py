"""C01 isolated local monitoring comparison; no cloud or model calls.

python -m scripts.compare_observability --repeats 3
Public proof stays in runtime/c01; credentials never enter command logs or reports.
"""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tarfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, build_opener

import yaml

from scripts import test_signal_compose as flow
from scripts.compare_supply_chain import download, sha256
from scripts.measure_signal_infrastructure import Sampler, distribution
from scripts.observability_lab import notification_seen
from scripts.signal_metrics_exporter import NoRedirect, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "infra/observability/alerts.yaml"


def command(args, *, env=None, input=None, timeout=300):
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                            env=env, input=input, timeout=timeout, check=False)
    if result.returncode:
        # CLI errors may contain environment/configuration. Keep public failures fixed.
        raise flow.CheckFailed("c01_command_" + args[0] + "_" + str(result.returncode))
    return result.stdout


def http(base, path, token=None, payload=None, api_key=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-API-Key" if api_key else "Authorization"] = token if api_key else "Bearer " + token
    if base.startswith("exec://"):
        container, port = base.removeprefix("exec://").rsplit(":", 1)
        request = {"port": int(port), "path": path, "headers": headers, "payload": payload}
        raw = command(["docker", "exec", "--interactive", container, "python", "-m",
                       "scripts.observability_lab", "local-http"], input=json.dumps(request), timeout=10)
        response = json.loads(raw)
        return response["status"], response["body"]
    request = Request(base + path, headers=headers,
                      data=json.dumps(payload).encode() if payload is not None else None)
    try:
        response = build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=3)
    except HTTPError as exc:
        response = exc
    with response:
        raw = response.read(1048577)
        flow.require(len(raw) <= 1048576, "c01_response_too_large")
        return response.code, raw.decode()


class Lab:
    def __init__(self, directory):
        self.directory = directory.resolve()
        flow.require(self.directory.is_relative_to((ROOT / "runtime/c01").resolve()), "c01_directory_scope")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ident = "c01-" + uuid.uuid4().hex[:12]
        self.app_image, self.image = self.ident + "-app", self.ident + "-tools"
        self.lock = json.loads((ROOT / "infra/observability/tools.lock.json").read_text(encoding="utf-8"))
        self.report = {"schema": "c01-pilot-1", "started_at": flow.timestamp(),
            "source_commit": command(["git", "rev-parse", "HEAD"]).strip(), "tools": self.lock,
            "conditions": {"scrape_seconds": 1, "evaluation_seconds": 1, "rule_for_seconds": 2,
                "backlog_age_seconds": 3, "retention": "1d", "candidate_cpu_budget": 2,
                "candidate_memory_bytes": 671088640, "network": "Docker internal only",
                "candidate_admin_ports_published": False, "all_host_ports_published": False,
                "probe_transport": "Docker exec; credentials on stdin; observed timing includes probe overhead",
                "uid": 10001}, "runs": []}
        self.containers, self.volumes, self.networks = [], [], []
        # A new preparation must never look like the previous run's completed proof.
        self.report["completed"] = False
        self.save()

    def save(self):
        (self.directory / "summary.json").write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")

    def prepare(self):
        build = self.directory / "build"
        downloads, binaries = build / "downloads", build / "bin"
        downloads.mkdir(parents=True, exist_ok=True)
        binaries.mkdir(exist_ok=True)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda tool: download(tool, tool["assets"][0], downloads), self.lock["tools"]))
        for tool in self.lock["tools"]:
            with tarfile.open(downloads / tool["assets"][0]["name"], "r:gz") as bundle:
                for name, member in tool["binaries"].items():
                    matches = [item for item in bundle.getmembers() if item.name == member]
                    flow.require(len(matches) == 1 and matches[0].isfile()
                                 and 0 < matches[0].size < 300 * 1024**2, "c01_binary_member")
                    with bundle.extractfile(matches[0]) as source, (binaries / name).open("wb") as target:
                        shutil.copyfileobj(source, target)
        command(["docker", "build", "--tag", self.app_image, str(ROOT)], timeout=900)
        (build / "Dockerfile").write_text(
            f"FROM {self.app_image}\nUSER 0\nCOPY bin /tools\n"
            "RUN chmod 0555 /tools/* && mkdir -p /monitor /alerts /tokens "
            "&& chown -R 10001:10001 /monitor /alerts /tokens\nUSER 10001:10001\nHEALTHCHECK NONE\n", encoding="utf-8")
        (build / ".dockerignore").write_text("*\n!bin/\n!bin/*\n!Dockerfile\n", encoding="utf-8")
        command(["docker", "build", "--tag", self.image, str(build)], timeout=900)
        self.report["image_id"] = command(["docker", "image", "inspect", self.image,
                                            "--format", "{{.Id}}"]).strip()
        self.report["source_input_sha256"] = {str(p.relative_to(ROOT)): sha256(p)
            for p in [*sorted((ROOT / "app").rglob("*.py")), ROOT / "pyproject.toml",
                      ROOT / "Dockerfile", ALERTS, ROOT / "scripts/signal_metrics_exporter.py",
                      ROOT / "scripts/observability_lab.py", ROOT / "scripts/compare_observability.py"]}
        self.save()

    def volume(self, prefix, label):
        name = prefix + "-" + label
        command(["docker", "volume", "create", "--label", "secops.c01=" + self.ident, name])
        self.volumes.append(name)
        return name

    def start(self, name, network, argv, *, mounts=(), env=None, memory=128, cpus=.25,
              alias=None):
        self.containers.append(name)
        args = ["docker", "run", "--detach", "--name", name, "--network", network,
                "--no-healthcheck",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                "--user", "10001:10001", "--memory", f"{memory}m", "--memory-swap", f"{memory}m",
                "--cpus", str(cpus), "--pids-limit", "128", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m"]
        if alias:
            args += ["--network-alias", alias]
        for mount in mounts:
            args += ["--mount", mount]
        for key in (env or {}):
            args += ["--env", key]  # Values inherited privately, never in arguments or public reports.
        args += ["--entrypoint", argv[0], self.image, *argv[1:]]
        ident = command(args, env={**os.environ, **(env or {})}).strip()
        return ident

    def base_url(self, name, port):
        flow.require(name.startswith(self.ident + "-") and port in {8000, 9101, 9001}, "c01_probe_scope")
        return f"exec://{name}:{port}"

    def token_volume(self, prefix, label, token):
        volume = self.volume(prefix, label)
        command(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
                 "--user", "10001:10001", "--mount", f"type=volume,src={volume},dst=/tokens",
                 "--entrypoint", "python", "--interactive", self.image, "-c",
                 "import pathlib,sys,os; p=pathlib.Path('/tokens/token'); p.write_text(sys.stdin.read()); os.chmod(p,0o600)"],
                input=token)
        return f"type=volume,src={volume},dst=/tokens,readonly"

    def probe(self, exporter, url):
        raw = command(["docker", "exec", "--interactive", exporter, "python", "-m",
                       "scripts.observability_lab", "probe"], input=json.dumps({"url": url}), timeout=10)
        return json.loads(raw)

    def wait(self, label, predicate, record, timeout=40):
        started, deadline = time.perf_counter(), time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    record["checks"].append({"label": label, "passed": True,
                        "first_observed_ms": (time.perf_counter() - started) * 1000, "at": flow.timestamp()})
                    self.save()
                    return
            except (OSError, ValueError, KeyError, flow.CheckFailed):
                pass
            time.sleep(.4)
        raise flow.CheckFailed("c01_timeout_" + label)

    def trial(self, candidate, iteration):
        print(json.dumps({"candidate": candidate, "iteration": iteration, "stage": "starting"}), flush=True)
        prefix = f"{self.ident}-{iteration}-{candidate}"
        directory = self.directory / prefix
        assets = flow.initialize_assets(directory)
        config = directory / "config"
        config.mkdir()
        networks = {}
        for label in ["core", "reader", "producer"]:
            name = prefix + "-" + label
            command(["docker", "network", "create", "--internal", "--label", "secops.c01=" + self.ident, name])
            self.networks.append(name)
            networks[label] = name
        data = self.volume(prefix, "data")
        scrape_token, notify_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        scrape_mount = self.token_volume(prefix, "scrape-token", scrape_token)
        notify_mount = self.token_volume(prefix, "notify-token", notify_token)
        reader_key, collector_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        shared = [f"type=volume,src={data},dst=/data",
                  f"type=bind,src={assets['registry']},dst=/signals/sources.json,readonly"]
        base_env = {"APP_ENVIRONMENT": "local", "ANALYZER_MODE": "rule", "AUTH_MODE": "api_key",
                    "API_KEY_TENANT_ID": "local", "ZERO_TRUST_DB_PATH": "/data/zero-trust.sqlite3",
                    "TRUSTED_SIGNAL_SOURCES_PATH": "/signals/sources.json", "AUDIT_LOG_PATH": "/tmp/audit.jsonl",
                    "CASE_LOG_PATH": "/tmp/cases.jsonl", "OUTBOX_LOG_PATH": "/tmp/outbox.jsonl",
                    "ALLOWED_HOSTS": "reader,collector,localhost,127.0.0.1",
                    "SIGNAL_INBOX_RETRY_SECONDS": "0.2", "SIGNAL_INBOX_MAX_ATTEMPTS": "2"}
        app_command = ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
        for role, key, roles in [("reader", reader_key, "viewer"), ("collector", collector_key, "analyst")]:
            self.start(prefix + "-" + role, networks["producer" if role == "collector" else "reader"], app_command,
                       mounts=shared, memory=256, cpus=.5, alias=role,
                       env=base_env | {"API_KEY_SHA256": hashlib.sha256(key.encode()).hexdigest(), "API_KEY_ROLES": roles})
        exporter = prefix + "-exporter"
        self.start(exporter, networks["core"], ["python", "-m", "scripts.signal_metrics_exporter",
            "--upstream", "http://reader:8000/zero-trust/signals/inbox", "--token-file", "/tokens/token",
            "--listen", "0.0.0.0", "--port", "9101"], mounts=[scrape_mount], memory=128,
            env={"C01_UPSTREAM_API_KEY": reader_key}, alias="exporter")
        command(["docker", "network", "connect", networks["reader"], exporter])
        sink = prefix + "-sink"
        self.start(sink, networks["core"], ["python", "-m", "scripts.observability_lab", "receiver",
                   "--token-file", "/tokens/token"], mounts=[notify_mount], alias="sink")
        record = {"candidate": candidate, "iteration": iteration, "started_at": flow.timestamp(),
                  "checks": [], "candidate_containers": {}, "events": [], "notification_epochs": [], "alert_bindings": {}}
        self.report["runs"].append(record)
        self.save()
        collector_url = self.base_url(prefix + "-collector", 8000)
        reader_url, export_url, sink_url = self.base_url(prefix + "-reader", 8000), self.base_url(exporter, 9101), self.base_url(sink, 9001)
        self.wait("initial_authenticated_export", lambda: "secops_signal_collection_success 1" in
                  http(export_url, "/metrics", scrape_token)[1], record)
        for label, base, path, key, expected, payload in [
            ("scrape_missing_credential", export_url, "/metrics", None, 401, None),
            ("scrape_wrong_credential", export_url, "/metrics", "incorrect", 401, None),
            ("reader_missing_credential", reader_url, "/zero-trust/signals/inbox", None, 401, None),
            ("reader_rejects_scrape_token", reader_url, "/zero-trust/signals/inbox", scrape_token, 401, None),
            ("collector_rejects_viewer_key", collector_url, "/zero-trust/signals/inbox", reader_key, 401, None),
            ("viewer_cannot_submit", reader_url, "/zero-trust/signals/inbox", reader_key, 403, {}),
        ]:
            status, _ = http(base, path, key, payload, api_key=base in {reader_url, collector_url})
            flow.require(status == expected, label)
            record["checks"].append({"label": label, "passed": True, "status": status})
        producer_ip = command(["docker", "inspect", prefix + "-collector", "--format",
            '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}']).strip()
        blocked = command(["docker", "exec", "--interactive", exporter, "python", "-c",
            ("import socket,sys,json; target=json.loads(sys.stdin.read()); "
            "exec(\"try:\\n s=socket.create_connection((target,8000),timeout=.3); s.close(); print('false')\\n"
            "except OSError: print('true')\")")], input=json.dumps(producer_ip)).strip()
        flow.require(blocked == "true", "c01_exporter_cannot_connect_collector")
        record["checks"].append({"label": "exporter_network_cannot_reach_collector", "passed": True})
        self.configure(config)
        cfg_mount = f"type=bind,src={config},dst=/config,readonly"
        am_data = self.volume(prefix, "alerts")
        am_name = prefix + "-am"
        ident = self.start(am_name, networks["core"], ["/tools/alertmanager", "--config.file=/config/alertmanager.yml",
            "--storage.path=/alerts", "--cluster.listen-address=", "--web.listen-address=:9093"],
            mounts=[cfg_mount, notify_mount, f"type=volume,src={am_data},dst=/alerts"], memory=128, cpus=.5, alias="am")
        record["candidate_containers"][ident] = "alertmanager"
        store_data = self.volume(prefix, "store")
        storage = prefix + "-storage"
        mounts = [cfg_mount, scrape_mount, f"type=volume,src={store_data},dst=/monitor"]
        if candidate == "prometheus":
            args = ["/tools/prometheus", "--config.file=/config/prometheus.yml", "--storage.tsdb.path=/monitor",
                    "--storage.tsdb.retention.time=1d", "--web.listen-address=:9090"]
            ident = self.start(storage, networks["core"], args, mounts=mounts, memory=512, cpus=1.5, alias="storage")
            query_base, restart_names = "http://storage:9090", [storage]
        else:
            args = ["/tools/victoria-metrics-prod", "-storageDataPath=/monitor", "-retentionPeriod=1d",
                    "-promscrape.config=/config/scrape.yml", "-search.latencyOffset=0s", "-httpListenAddr=:8428"]
            ident = self.start(storage, networks["core"], args, mounts=mounts, memory=384, cpus=1, alias="storage")
            evaluator = prefix + "-evaluator"
            eval_id = self.start(evaluator, networks["core"], ["/tools/vmalert-prod", "-rule=/config/alerts.yaml",
                "-datasource.url=http://storage:8428", "-notifier.url=http://am:9093", "-rule.evalDelay=0s",
                "-datasource.queryStep=5m", "-evaluationInterval=1s", "-remoteWrite.url=http://storage:8428",
                "-remoteRead.url=http://storage:8428", "-httpListenAddr=:8880"], mounts=[cfg_mount], memory=128, cpus=.5, alias="evaluator")
            record["candidate_containers"][eval_id] = "vmalert"
            query_base, restart_names = "http://storage:8428", [storage, evaluator]
        record["candidate_containers"][ident] = "storage"

        def query(expression, timestamp=None):
            parameters = {"query": expression}
            if timestamp is not None:
                parameters["time"] = timestamp
            return self.probe(exporter, query_base + "/api/v1/query?" + urlencode(parameters))["data"]["result"]

        event_floor = 0
        binding = {"job": "zt-signals", "instance": "exporter:9101"}

        def alert(name, status):
            code, raw = http(sink_url, "/events", notify_token)
            return code == 200 and notification_seen(json.loads(raw)["events"], name, status, event_floor, binding)

        def new_episode(label, keep_binding=False):
            nonlocal event_floor, binding
            code, raw = http(sink_url, "/events", notify_token)
            flow.require(code == 200, "c01_episode_receiver")
            event_floor = len(json.loads(raw)["events"])
            if not keep_binding:
                binding = {"job": "zt-signals", "instance": "exporter:9101"}
            record["notification_epochs"].append({"episode": label, "first_index": event_floor, "at": flow.timestamp()})

        def bind_firing(name):
            nonlocal binding
            _, raw = http(sink_url, "/events", notify_token)
            matching = [event for event in json.loads(raw)["events"][event_floor:]
                        if event["alertname"] == name and event["status"] == "firing"
                        and all(event.get(k) == v for k, v in binding.items())]
            flow.require(bool(matching), "c01_firing_binding")
            event = matching[0]
            binding = {key: event[key] for key in ["job", "instance", "fingerprint", "starts_at"]}
            record["alert_bindings"][name] = dict(binding)

        sampler = Sampler(record["candidate_containers"], directory / "resources.jsonl", 1)
        sampler.thread.start()
        try:
            self.wait("scraped_real_summary", lambda: bool(query("secops_signal_collection_success == 1")), record)
            self.wait("healthy_alerts_clear", lambda: not self.probe(exporter, "http://am:9093/api/v2/alerts"), record)
            time.sleep(3)
            flow.require(not alert("C01SignalQueueBacklog", "firing"), "unexpected_healthy_backlog_alert")
            new_episode("backlog")
            signal = flow.signed_observation(prefix + "-lag", flow.USERS[0], assets["keys"]["identity"])
            status, _ = http(collector_url, "/zero-trust/signals/inbox", collector_key, signal.model_dump(mode="json"), api_key=True)
            flow.require(status == 202, "c01_signed_intake_202")
            self.wait("backlog_notification", lambda: alert("C01SignalQueueBacklog", "firing"), record)
            bind_firing("C01SignalQueueBacklog")
            new_episode("backlog_recovery", keep_binding=True)
            worker = prefix + "-worker"
            self.start(worker, "none", ["python", "-m", "scripts.signal_worker", "--poll-seconds", "0.05"],
                       mounts=shared, env=base_env | {"AUTH_MODE": "disabled"}, memory=256, cpus=.5)
            self.wait("backlog_resolved_notification", lambda: alert("C01SignalQueueBacklog", "resolved"), record)
            new_episode("upstream_loss")
            command(["docker", "stop", "--timeout", "3", prefix + "-reader"])
            self.wait("collection_failure_notification", lambda: alert("C01SignalCollectionUnavailable", "firing"), record)
            bind_firing("C01SignalCollectionUnavailable")
            status, rendered = http(export_url, "/metrics", scrape_token)
            flow.require(status == 200 and "secops_signal_inbox_records" not in rendered, "c01_no_stale_queue_on_error")
            new_episode("upstream_recovery", keep_binding=True)
            command(["docker", "start", prefix + "-reader"])
            self.wait("collection_recovered_notification", lambda: alert("C01SignalCollectionUnavailable", "resolved"), record)
            new_episode("exporter_loss")
            command(["docker", "stop", "--timeout", "3", exporter])
            # Probe through sink while the exporter is down; the sink shares only the monitoring network.
            def down_seen():
                return alert("C01ExporterDown", "firing")
            self.wait("exporter_down_notification", down_seen, record)
            bind_firing("C01ExporterDown")
            new_episode("exporter_recovery", keep_binding=True)
            command(["docker", "start", exporter])
            self.wait("exporter_recovered_notification", lambda: alert("C01ExporterDown", "resolved"), record)
            historical_time = time.time() - 10
            before = query("count_over_time(secops_signal_collection_success[5m])", historical_time)
            flow.require(before, "c01_history_before_restart")
            historical_count = float(before[0]["value"][1])
            command(["docker", "restart", "--timeout", "3", *restart_names])
            self.wait("storage_restart_history", lambda: (result := query(
                "count_over_time(secops_signal_collection_success[5m])", historical_time))
                and float(result[0]["value"][1]) >= historical_count, record)
            record["history_check"] = {"fixed_pre_restart_query_time": historical_time,
                "samples_before": historical_count,
                "samples_after": float(query("count_over_time(secops_signal_collection_success[5m])",
                                             historical_time)[0]["value"][1])}
            # A previously accepted observation loses its source authority before processing.
            new_episode("source_key_disabled")
            command(["docker", "stop", "--timeout", "3", worker])
            signal = flow.signed_observation(prefix + "-rejected", flow.USERS[0], assets["keys"]["identity"])
            status, _ = http(collector_url, "/zero-trust/signals/inbox", collector_key, signal.model_dump(mode="json"), api_key=True)
            flow.require(status == 202, "c01_second_intake_202")
            registry = json.loads(assets["registry"].read_text(encoding="utf-8"))
            registry["sources"][1]["keys"][0]["enabled"] = False
            assets["registry"].write_text(json.dumps(registry), encoding="utf-8")
            command(["docker", "start", worker])
            self.wait("processing_failed_notification", lambda: alert("C01SignalProcessingFailed", "firing"), record)
            bind_firing("C01SignalProcessingFailed")
            _, raw = http(sink_url, "/events", notify_token)
            record["events"] = json.loads(raw)["events"]
            record["final_summary"] = json.loads(http(reader_url, "/zero-trust/signals/inbox", reader_key, api_key=True)[1])
            disk = command(["docker", "exec", storage, "python", "-c",
                "import pathlib,json; p=pathlib.Path('/monitor'); print(json.dumps({'logical_file_bytes':sum(f.stat().st_size for f in p.rglob('*') if f.is_file())}))"])
            record["storage_files"] = json.loads(disk)
            record["container_guards"] = {}
            for container_id, service in record["candidate_containers"].items():
                host = json.loads(command(["docker", "inspect", container_id, "--format", "{{json .HostConfig}} "]))
                ports = json.loads(command(["docker", "inspect", container_id, "--format", "{{json .NetworkSettings.Ports}}"]))
                flow.require(not any(ports.values()) and host["ReadonlyRootfs"]
                             and "ALL" in host["CapDrop"], "c01_container_guards")
                record["container_guards"][service] = {"memory_bytes": host["Memory"], "nano_cpus": host["NanoCpus"],
                    "read_only_root": host["ReadonlyRootfs"], "cap_drop": host["CapDrop"],
                    "security_options": host["SecurityOpt"], "published_ports": ports}
            record["complete"] = True
        finally:
            sampler.stop()
            try:
                code, raw = http(sink_url, "/events", notify_token)
                if code == 200:
                    record["events"] = json.loads(raw)["events"]
            except (OSError, ValueError, flow.CheckFailed):
                pass
            for service, url in [("storage", query_base + "/api/v1/query?" + urlencode({"query": "secops_signal_inbox_records"})),
                                 ("alertmanager", "http://am:9093/api/v2/alerts")]:
                try:
                    record["diagnostic_" + service] = self.probe(exporter, url)
                except (OSError, ValueError, flow.CheckFailed):
                    record["diagnostic_" + service] = {"unavailable": True}
            record["resource_samples"] = sampler.rows
            record["resource_errors"] = sampler.errors
            record["finished_at"] = flow.timestamp()
            self.save()
            self.cleanup_trial(prefix)

    def configure(self, directory):
        shutil.copyfile(ALERTS, directory / "alerts.yaml")
        scrape = {"global": {"scrape_interval": "1s", "scrape_timeout": "800ms"},
                  "scrape_configs": [{"job_name": "zt-signals", "metrics_path": "/metrics",
                      "authorization": {"type": "Bearer", "credentials_file": "/tokens/token"},
                      "static_configs": [{"targets": ["exporter:9101"]}]}]}
        (directory / "scrape.yml").write_text(yaml.safe_dump(scrape), encoding="utf-8")
        prometheus = json.loads(json.dumps(scrape))
        prometheus["global"]["evaluation_interval"] = "1s"
        prometheus["rule_files"] = ["/config/alerts.yaml"]
        prometheus["alerting"] = {"alertmanagers": [{"static_configs": [{"targets": ["am:9093"]}]}]}
        (directory / "prometheus.yml").write_text(yaml.safe_dump(prometheus), encoding="utf-8")
        manager = {"route": {"receiver": "local", "group_by": ["alertname"], "group_wait": "0s",
                             "group_interval": "1s", "repeat_interval": "1h"},
            "receivers": [{"name": "local", "webhook_configs": [{"url": "http://sink:9001/events", "send_resolved": True,
                "http_config": {"authorization": {"type": "Bearer", "credentials_file": "/tokens/token"}}}]}]}
        (directory / "alertmanager.yml").write_text(yaml.safe_dump(manager), encoding="utf-8")

    def cleanup_trial(self, prefix):
        for name in [n for n in self.containers if n.startswith(prefix + "-")]:
            log = subprocess.run(["docker", "logs", "--tail", "100", name], capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", check=False)
            (self.directory / (name + ".private.log")).write_text(log.stdout + log.stderr, encoding="utf-8")
            subprocess.run(["docker", "rm", "--force", "--volumes", name], capture_output=True, check=False)
            self.containers.remove(name)
        for name in [n for n in self.volumes if n.startswith(prefix + "-")]:
            subprocess.run(["docker", "volume", "rm", name], capture_output=True, check=False)
            self.volumes.remove(name)
        for name in [n for n in self.networks if n.startswith(prefix + "-")]:
            subprocess.run(["docker", "network", "rm", name], capture_output=True, check=False)
            self.networks.remove(name)

    def cleanup(self):
        self.cleanup_trial(self.ident)
        for image in [self.image, self.app_image]:
            subprocess.run(["docker", "image", "rm", image], capture_output=True, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c01")
    parser.add_argument("--repeats", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    lab = Lab(args.directory)
    try:
        lab.prepare()
        for i in range(1, args.repeats + 1):
            for candidate in (["prometheus", "victoriametrics"] if i % 2 else ["victoriametrics", "prometheus"]):
                lab.trial(candidate, i)
        lab.report["completed"] = True
        lab.report["timing"] = {candidate: {label: distribution([
            check["first_observed_ms"] for r in lab.report["runs"] if r["candidate"] == candidate
            for check in r["checks"] if check["label"] == label]) for label in [
                "backlog_notification", "backlog_resolved_notification", "collection_failure_notification",
                "collection_recovered_notification", "exporter_down_notification", "exporter_recovered_notification",
                "storage_restart_history", "processing_failed_notification"]}
            for candidate in ["prometheus", "victoriametrics"]}
    except Exception as exc:
        lab.report["completed"] = False
        lab.report["failure_type"] = type(exc).__name__
        lab.report["failure_check"] = str(exc) if isinstance(exc, flow.CheckFailed) else "internal_lab_error"
        raise
    finally:
        lab.cleanup()
        lab.report["finished_at"] = flow.timestamp()
        lab.save()


if __name__ == "__main__":
    main()
