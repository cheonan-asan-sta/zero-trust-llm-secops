"""Optional persistent Prometheus/Alertmanager profile for the locked mTLS runtime."""

import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

from scripts import runtime_release as release
from scripts.continuous_mtls_runtime import (
    ROOT,
    SERVICES,
    VOLUMES,
    Runtime,
    RuntimeFailure,
    command,
    compose_spec,
)

EXTRA_SERVICES = ("reader", "exporter", "prometheus", "alertmanager", "sink")
EXTRA_VOLUMES = ("reader-tls", "reader-auth", "exporter-tls", "exporter-auth", "prometheus-tls",
                 "prometheus-data", "alertmanager-tls", "alertmanager-data", "sink-tls", "monitor-operator-tls")
INPUTS = ("infra/observability/tools.lock.json", "infra/observability/alerts.yaml")


def definition(project, image, nginx):
    spec = compose_spec(project, image, nginx)

    def node(argv, mounts, networks, memory="192m", cpus=.5):
        value = copy.deepcopy(spec["services"]["operator"])
        value.update(entrypoint=argv, volumes=mounts, networks={name: {} for name in networks},
                     mem_limit=memory, memswap_limit=memory, cpus=cpus)
        if any(mount.split(":")[1] == "/data" for mount in mounts):
            value["tmpfs"] = [v for v in value["tmpfs"] if not v.startswith("/data:")]
        return value

    spec["services"].update({
        "reader": node(["python", "-m", "scripts.monitoring_runtime_control", "service", "reader"],
            ["data:/data", "registry:/signals:ro", "reader-tls:/tls:ro", "reader-auth:/auth:ro"], ["metrics-read"], "384m", 1),
        "exporter": node(["python", "-m", "scripts.monitoring_runtime_control", "service", "exporter"],
            ["exporter-tls:/tls:ro", "exporter-auth:/auth:ro"], ["metrics-read", "monitoring"]),
        "prometheus": node(["/tools/prometheus", "--config.file=/tls/config.yml", "--storage.tsdb.path=/data/prometheus",
            "--storage.tsdb.retention.time=1d", "--web.listen-address=:9090", "--web.config.file=/tls/web.yml"],
            ["prometheus-tls:/tls:ro", "prometheus-data:/data"], ["monitoring"], "512m", 1.5),
        "alertmanager": node(["/tools/alertmanager", "--config.file=/tls/config.yml", "--storage.path=/data/alerts",
            "--cluster.listen-address=", "--web.listen-address=:9093", "--web.config.file=/tls/web.yml"],
            ["alertmanager-tls:/tls:ro", "alertmanager-data:/data"], ["monitoring"], "128m"),
        "sink": node(["python", "-m", "scripts.mtls_native", "receiver", "--profile", "/tls/server.json",
            "--token-file", "/tls/notify.token", "--port", "9001"], ["sink-tls:/tls:ro"], ["monitoring"]),
    })
    spec["services"]["reader"]["environment"] = spec["services"]["app"]["environment"] | {
        "ALLOWED_HOSTS": "reader,localhost,127.0.0.1", "AUDIT_LOG_PATH": "/tmp/audit.jsonl",
        "CASE_LOG_PATH": "/tmp/cases.jsonl", "OUTBOX_LOG_PATH": "/tmp/outbox.jsonl"}
    for name in ("prometheus", "alertmanager"):
        spec["services"][name]["image"] = "sha256:" + "2" * 64
    spec["services"]["operator"]["networks"]["monitoring"] = {}
    spec["services"]["operator"]["volumes"].append("monitor-operator-tls:/monitor-tls:ro")
    for name in ("metrics-read", "monitoring"):
        spec["networks"][name] = {"internal": True, "labels": {"secops.runtime": project}}
    spec["volumes"].update({name: {"external": True, "name": project + "-" + name} for name in EXTRA_VOLUMES})
    return spec


class MonitoredRuntime(Runtime):
    services = SERVICES + EXTRA_SERVICES
    volumes = VOLUMES + EXTRA_VOLUMES

    def load(self):
        state = super().load()
        if state.get("monitoring_image", state["project"] + "-monitoring") != state["project"] + "-monitoring":
            raise ValueError("monitoring_image_scope")
        return state

    def definition(self, project, image, nginx):
        return definition(project, image, nginx)

    def release_inputs(self):
        return release.capture(ROOT, definition("kmtls-000000000000", "sha256:" + "0" * 64,
                                               "sha256:" + "1" * 64), INPUTS)

    def expected_image(self, service):
        if service in {"prometheus", "alertmanager"}:
            return self.state.get("monitoring_image_id", "sha256:" + "2" * 64)
        return super().expected_image(service)

    def prepare_extra_images(self):
        from scripts.compare_supply_chain import download, sha256
        build = self.directory / "monitoring-build"
        downloads, binaries = build / "downloads", build / "bin"
        downloads.mkdir(parents=True)
        binaries.mkdir()
        lock = json.loads((ROOT / INPUTS[0]).read_text(encoding="utf-8"))
        if lock["platform"] != "linux/amd64":
            raise ValueError("monitoring_tool_platform")
        tools = [item for item in lock["tools"] if item["name"] in {"prometheus", "alertmanager"}]
        if len(tools) != 2 or {tool["name"] for tool in tools} != {"prometheus", "alertmanager"}:
            raise ValueError("monitoring_tool_inventory")
        hashes = {}
        for tool in tools:
            expected_names = {"prometheus", "promtool"} if tool["name"] == "prometheus" else {"alertmanager", "amtool"}
            if set(tool["binaries"]) != expected_names:
                raise ValueError("monitoring_binary_inventory")
            asset = tool["assets"][0]
            target = downloads / asset["name"]
            cache = ROOT / "runtime/c01/build/downloads" / asset["name"]
            if cache.is_file() and "sha256:" + sha256(cache) == asset["digest"]:
                shutil.copyfile(cache, target)
            download(tool, asset, downloads)
            with tarfile.open(target, "r:gz") as archive:
                for name, member in tool["binaries"].items():
                    entry = archive.getmember(member)
                    if not entry.isfile() or not 0 < entry.size < 300 * 1024**2:
                        raise ValueError("monitoring_binary_entry")
                    with archive.extractfile(entry) as source, (binaries / name).open("wb") as output:
                        shutil.copyfileobj(source, output)
                    hashes[name] = sha256(binaries / name)
        base_detail = json.loads(command(["docker", "image", "inspect", self.state["image"]]))[0]
        release.image_identity(base_detail, self.state["image_id"])
        # BuildKit interprets FROM sha256:<local-ID> as a repository/tag. Use
        # this owned local tag, then prove the inherited layer prefix instead.
        (build / "Dockerfile").write_text(f"FROM {self.state['image']}\nUSER 0\nCOPY bin /tools\nRUN chmod 0555 /tools/*\nUSER 10001:10001\nHEALTHCHECK NONE\n", encoding="utf-8")
        (build / ".dockerignore").write_text("*\n!Dockerfile\n!bin/\n!bin/*\n", encoding="utf-8")
        tag = self.state["project"] + "-monitoring"
        command(["docker", "build", "--tag", tag, str(build)], timeout=900)
        detail = json.loads(command(["docker", "image", "inspect", tag]))[0]
        layers = base_detail["RootFS"]["Layers"]
        if not layers or detail["RootFS"]["Layers"][:len(layers)] != layers:
            raise RuntimeFailure("monitoring_base_image_layers_changed")
        self.state.update(monitoring_image=tag, monitoring_image_id=release.image_identity(detail),
                          monitoring_binary_sha256=hashes, monitoring_tools=tools,
                          monitoring_base_layers_sha256=release.digest(layers))
        self.save()

    def make_assets(self):
        from scripts.continuous_mtls_assets import assets
        material = assets(monitoring=True)
        self.state["monitoring_config_sha256"] = {volume: {
            name: hashlib.sha256(body.encode().replace(b"\r\n", b"\n")).hexdigest()
            for name, body in material[volume].items() if name.endswith((".yaml", ".yml"))}
            for volume in ("prometheus-tls", "alertmanager-tls")}
        self.save()
        return material

    def verify_extra_images(self):
        detail = json.loads(command(["docker", "image", "inspect", self.state["monitoring_image"]]))[0]
        release.image_identity(detail, self.state["monitoring_image_id"])
        program = "import hashlib,json,sys;from pathlib import Path;print(json.dumps({n:hashlib.sha256((Path('/tools')/n).read_bytes()).hexdigest() for n in json.load(sys.stdin)}))"
        actual = json.loads(command(["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/data:size=1m",
            "--entrypoint", "python", "-i", self.state["monitoring_image_id"], "-c", program],
            payload=json.dumps(list(self.state["monitoring_binary_sha256"]))))
        if actual != self.state["monitoring_binary_sha256"]:
            raise RuntimeFailure("monitoring_binary_drift")
        for volume, expected in self.state["monitoring_config_sha256"].items():
            program = "import hashlib,json,sys;from pathlib import Path;print(json.dumps({n:hashlib.sha256((Path('/data')/n).read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for n in json.load(sys.stdin)}))"
            actual = json.loads(command(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
                "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount",
                f"type=volume,src={self.state['volumes'][volume]},dst=/data,readonly",
                "--entrypoint", "python", "-i", self.state["image_id"], "-c", program], payload=json.dumps(list(expected))))
            if actual != expected:
                raise RuntimeFailure("monitoring_configuration_drift")

    def down(self, *, purge=False):
        result = super().down(purge=purge)
        tag = self.state["project"] + "-monitoring"
        if self.state.get("monitoring_image", tag) != tag:
            raise RuntimeFailure("monitoring_image_scope")
        if purge and command(["docker", "image", "ls", "--quiet", tag]).strip():
            command(["docker", "image", "rm", tag])
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("up", "status", "down"))
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/monitored-mtls")
    parser.add_argument("--purge", action="store_true")
    args = parser.parse_args()
    try:
        runtime = MonitoredRuntime(args.directory)
        if args.mode == "up":
            result = runtime.up()
        elif args.mode == "status":
            runtime.load()
            result = runtime.status()
        else:
            result = runtime.down(purge=args.purge)
        print(json.dumps(result))
        return 0
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"runtime": "unavailable"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
