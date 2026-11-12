"""Persistent local mTLS app, observation collector, worker and session watchdog.

Reuse the selected native TLS/NGINX enforcement code in isolated Docker resources.
Only public configuration is written on the host; secrets travel through stdin into
UID 10001 Linux volumes. Docker context selection is inherited from the caller.
"""

import argparse
import hashlib
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

import yaml

from scripts import runtime_release as release

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ("app", "gateway", "bridge", "resource", "proxy", "collector", "worker", "watchdog", "operator")
VOLUMES = ("data", "registry", "core-tls", "gateway-tls", "bridge-tls", "resource-tls", "proxy-tls",
           "collector-tls", "operator-tls", "core-auth", "collector-auth", "operator-auth", "secret",
           "config", "collector-state")
PROJECT = re.compile(r"kmtls-[a-f0-9]{12}")


class RuntimeFailure(RuntimeError):
    """Fixed public errors, never raw Docker output or service payloads."""


def command(argv, *, payload=None, timeout=120):
    result = subprocess.run(argv, input=payload, capture_output=True, text=True,
                            encoding="utf-8", timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeFailure("runtime_command_failed_" + str(result.returncode))
    return result.stdout


def compose_spec(project: str, image: str, nginx_image: str) -> dict:
    if PROJECT.fullmatch(project) is None:
        raise ValueError("runtime_project_scope")

    def service(argv, mounts, networks=None, *, memory="192m", cpus=.5):
        value = {"image": image, "user": "10001:10001", "read_only": True, "init": True,
                 "restart": "unless-stopped", "cap_drop": ["ALL"],
                 "security_opt": ["no-new-privileges:true"], "pids_limit": 128,
                 "mem_limit": memory, "memswap_limit": memory, "cpus": cpus,
                 "tmpfs": ["/tmp:rw,nosuid,nodev,size=64m"], "healthcheck": {"disable": True},
                 "labels": {"secops.runtime": project}, "entrypoint": argv,
                 "volumes": mounts}
        if networks is None:
            value["network_mode"] = "none"
        else:
            value["networks"] = networks
        if not any(mount.split(":")[1] == "/data" for mount in mounts):
            # Override the image's unused /data VOLUME without leaking anonymous volumes.
            value["tmpfs"].append("/data:rw,nosuid,nodev,size=1m,uid=10001,gid=10001")
        return value

    shared = ["data:/data", "registry:/signals:ro"]
    environment = {"APP_ENVIRONMENT": "local", "ANALYZER_MODE": "rule", "AUTH_MODE": "disabled",
                   "ZERO_TRUST_DB_PATH": "/data/zero-trust.sqlite3",
                   "TRUSTED_SIGNAL_SOURCES_PATH": "/signals/sources.json",
                   "ALLOWED_HOSTS": "core,localhost,127.0.0.1",
                   "SIGNAL_INBOX_LEASE_SECONDS": "2", "SIGNAL_INBOX_RETRY_SECONDS": "0.2"}
    definitions = {
        "app": service(["python", "-m", "scripts.continuous_mtls_assets", "service", "app"],
                       [*shared, "core-tls:/tls:ro", "core-auth:/auth:ro"],
                       {"core": {"aliases": ["core"]}}, memory="384m", cpus=1),
        "gateway": service(["python", "-m", "scripts.mtls_transport", "serve", "--profile", "/tls/profile.json",
                            "--backend-profile", "/tls/backend.json", "--secure-stats"], ["gateway-tls:/tls:ro"],
                           {"intake": {}, "core": {}}),
        "bridge": service(["python", "-m", "scripts.pep_lab", "bridge", "--secret-file", "/secret/secret",
                           "--core-tls-profile", "/tls/core.json", "--server-tls-profile", "/tls/auth.json",
                           "--consume-server-profile", "/tls/consume.json", "--forwarded-profile", "/tls/front.json"],
                          ["secret:/secret:ro", "bridge-tls:/tls:ro"], {"auth": {}, "intake": {}, "consume": {}}),
        "resource": service(["python", "-m", "scripts.pep_lab", "resource", "--secret-file", "/secret/secret",
                             "--server-tls-profile", "/tls/server.json", "--consume-tls-profile", "/tls/consume.json"],
                            ["secret:/secret:ro", "resource-tls:/tls:ro"], {"resource": {}, "consume": {}}),
        "proxy": service(["nginx", "-c", "/config/all-hops.conf", "-g", "daemon off;"],
                         ["proxy-tls:/service-tls:ro", "config:/config:ro"],
                         {"client": {}, "auth": {}, "resource": {}}, memory="128m"),
        "collector": service(["python", "-m", "scripts.continuous_mtls_assets", "service", "collector"],
                             ["collector-state:/collector", "collector-tls:/tls:ro", "collector-auth:/auth:ro"],
                             {"intake": {}}),
        "worker": service(["python", "-m", "scripts.signal_worker", "--poll-seconds", "0.2"], shared),
        "watchdog": service(["python", "-m", "scripts.session_watchdog", "--interval-seconds", "0.2"], shared),
        # Explicit trusted local console; no network listener or published ports.
        "operator": service(["python", "-c", "import time;time.sleep(31536000)"],
                            ["operator-tls:/tls:ro", "operator-auth:/auth:ro"],
                            {"core": {}, "client": {}, "resource": {}}),
    }
    for label in ("app", "worker", "watchdog"):
        definitions[label]["environment"] = environment.copy()
    definitions["proxy"].update(image=nginx_image, platform="linux/amd64")
    return {"name": project, "services": definitions,
            "networks": {name: {"internal": True, "labels": {"secops.runtime": project}}
                         for name in ("core", "intake", "auth", "consume", "resource", "client")},
            "volumes": {name: {"external": True, "name": project + "-" + name} for name in VOLUMES}}


class Runtime:
    services = SERVICES
    volumes = VOLUMES

    def __init__(self, directory: Path):
        self.directory = Path(directory).resolve()
        if not self.directory.is_relative_to((ROOT / "runtime/c02").resolve()):
            raise ValueError("runtime_directory_scope")
        self.descriptor = self.directory / "runtime.json"
        self.manifest = self.directory / "compose.yaml"
        self.empty_env = self.directory / "empty.env"
        self.state = None

    def load(self):
        state = json.loads(self.descriptor.read_text())
        project = state.get("project", "")
        if (state.get("schema") != "continuous-mtls-runtime-1" or PROJECT.fullmatch(project) is None
                or state.get("volumes") != {n: project + "-" + n for n in self.volumes}
                or state.get("image") != project + "-app"):
            raise ValueError("runtime_descriptor_scope")
        self.state = state
        # Rebuild public Compose input from the validated descriptor, not arbitrary YAML.
        self.write_manifest()
        return state

    def release_inputs(self):
        return release.capture(ROOT, self.definition("kmtls-000000000000", "sha256:" + "0" * 64,
                                                    "sha256:" + "1" * 64))

    def definition(self, project, image, nginx):
        return compose_spec(project, image, nginx)

    def active_definition(self, project, image, nginx):
        return self.definition(project, image, nginx)

    def make_assets(self):
        from scripts.continuous_mtls_assets import assets
        return assets()

    def prepare_extra_images(self):
        pass

    def before_start(self):
        pass

    def verify_extra_images(self):
        pass

    def expected_image(self, service):
        return self.state["nginx_image_id"] if service == "proxy" else self.state["image_id"]

    def verify_release(self):
        return release.verify(self.state.get("release"), self.release_inputs())

    def save(self):
        temporary = self.descriptor.with_suffix(".next")
        temporary.write_text(json.dumps(self.state, indent=2) + "\n")
        temporary.replace(self.descriptor)

    def write_manifest(self):
        # Cleanup of old descriptors is allowed, but old descriptors cannot be
        # started or silently upgraded to a newly captured release.
        nginx = self.state.get("nginx_image_id")
        if nginx is None:
            nginx = "nginx@sha256:" + "0" * 64
        spec = self.active_definition(self.state["project"], self.state.get("image_id", self.state["image"]), nginx)
        for name, service in spec["services"].items():
            if "image_id" in self.state and (name != "proxy" or self.state.get("nginx_image_id")):
                service["image"] = self.expected_image(name)
            service.update(pull_policy="never", platform="linux/amd64")
        self.manifest.write_text(yaml.safe_dump(spec))
        self.empty_env.write_text("")

    def compose(self, *args, timeout=120, payload=None):
        return command(["docker", "compose", "--env-file", str(self.empty_env), "--project-name", self.state["project"],
                        "--project-directory", str(ROOT), "--file", str(self.manifest), *args],
                       timeout=timeout, payload=payload)

    def write_volume(self, label, files):
        program = """import json,os,sys
from pathlib import Path
root=Path('/data')
for name,body in json.load(sys.stdin).items():
 if Path(name).name!=name or name in {'.','..'}:raise ValueError('asset_scope')
 target=root/name;temporary=root/(name+'.new')
 temporary.write_text(body);os.chmod(temporary,0o600)
 with temporary.open('rb') as stream:os.fsync(stream.fileno())
 os.replace(temporary,target)
"""
        return command(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
                        "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount",
                        f"type=volume,src={self.state['volumes'][label]},dst=/data", "--entrypoint", "python", "-i",
                        self.state["image"], "-c", program], payload=json.dumps(files))

    def up(self):
        if self.descriptor.exists():
            self.load()
            if not self.state.get("initialized"):
                raise RuntimeFailure("runtime_initialization_incomplete")
            self.verify_release()
        else:
            captured = self.release_inputs()
            self.directory.mkdir(parents=True, exist_ok=True)
            project = "kmtls-" + uuid.uuid4().hex[:12]
            self.state = {"schema": "continuous-mtls-runtime-1", "project": project, "image": project + "-app",
                          "volumes": {n: project + "-" + n for n in self.volumes}, "initialized": False,
                          "release": captured}
            self.save()
            self.write_manifest()
            command(["docker", "build", "--tag", self.state["image"], str(ROOT)], timeout=900)
            self.state["image_id"] = command(["docker", "image", "inspect", self.state["image"], "--format", "{{.Id}}"]).strip()
            detail = json.loads(command(["docker", "image", "inspect", self.state["image"]]))[0]
            release.image_identity(detail, self.state["image_id"])
            nginx_ref = captured["payload"]["nginx_reference"]
            command(["docker", "pull", "--platform", "linux/amd64", nginx_ref], timeout=300)
            detail = json.loads(command(["docker", "image", "inspect", "--platform", "linux/amd64", nginx_ref]))[0]
            self.state["nginx_image_id"] = release.image_identity(detail, reference=nginx_ref)
            self.state["nginx_reference"] = nginx_ref
            self.verify_release()
            self.write_manifest()
            self.state["source_commit"] = command(["git", "rev-parse", "HEAD"]).strip()
            self.state["source_dirty"] = bool(command(["git", "status", "--porcelain"]).strip())
            self.state["source_sha256"] = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                           for folder in ("app", "scripts") for p in sorted((ROOT / folder).rglob("*.py"))}
            image_hashes = json.loads(command(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "python",
                "-i", self.state["image"], "-c", "import hashlib,json,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"],
                payload=json.dumps(list(self.state["source_sha256"]))))
            if image_hashes != self.state["source_sha256"]:
                raise RuntimeFailure("runtime_image_source_mismatch")
            self.state["image_source_verified"] = True
            payload_files = {name: digest for name, digest in captured["payload"]["files"].items()
                             if name.startswith(("app/", "scripts/")) or name == "pyproject.toml"}
            program = """import hashlib,json,sys
from pathlib import Path
print(json.dumps({p:hashlib.sha256(Path(p).read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for p in json.load(sys.stdin)}))
"""
            copied = json.loads(command(["docker", "run", "--rm", "--network", "none", "--read-only",
                "--tmpfs", "/data:rw,nosuid,nodev,size=1m", "--entrypoint", "python", "-i",
                self.state["image_id"], "-c", program], payload=json.dumps(list(payload_files))))
            if copied != payload_files:
                raise RuntimeFailure("runtime_release_image_payload_mismatch")
            self.state["release_image_payload_verified"] = True
            self.prepare_extra_images()
            self.state["configuration_sha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in ("Dockerfile", "pyproject.toml", "infra/pep/tools.lock.json", "infra/mtls/all-hops-nginx.conf")}
            self.state["configuration_sha256"].update({p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted((ROOT / "infra/runtime").rglob("*")) if p.is_file() and "__pycache__" not in p.parts})
            self.save()
            material = self.make_assets()
            for label, volume in self.state["volumes"].items():
                command(["docker", "volume", "create", "--label", "secops.runtime=" + project, volume])
                detail = json.loads(command(["docker", "volume", "inspect", volume]))[0]
                if detail.get("Labels", {}).get("secops.runtime") != project:
                    raise RuntimeFailure("runtime_volume_scope")
                self.write_volume(label, material.get(label, {}))
            init = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount",
                    f"type=volume,src={self.state['volumes']['collector-state']},dst=/data", "--entrypoint", "python", self.state["image"]]
            command([*init, "-m", "scripts.continuous_signal_collector", "init", "--directory", "/data/producer",
                     "--tenant", "local", "--source-id", "runtime-identity", "--kind", "identity",
                     "--subject", "runtime-user", "--subject", "runtime-other"])
            public = json.loads(command([*init, "-c", "from pathlib import Path;print(Path('/data/producer/sources.json').read_text())"]))
            registry = json.loads(material["registry"]["sources.json"])
            registry["sources"].extend(public["sources"])
            self.write_volume("registry", {"sources.json": json.dumps(registry)})
            self.state["initialized"] = True
            self.save()
        self.verify_release()
        for reference, expected in ((self.state["image"], self.state["image_id"]),
                                    (self.state["nginx_image_id"], self.state["nginx_image_id"])):
            release.image_identity(json.loads(command(["docker", "image", "inspect", reference]))[0], expected)
        self.verify_public_configuration()
        self.verify_extra_images()
        self.write_manifest()
        self.before_start()
        self.compose("up", "--detach", timeout=300)
        self.wait(lambda: self.probe({"profile": "core", "path": "/health/live", "method": "GET"})["status"] == 200)
        self.wait(lambda: all(row["running"] for row in self.status()["services"].values()))
        return self.status()

    def verify_public_configuration(self):
        program = "from pathlib import Path;import hashlib;print(hashlib.sha256(Path('/config/all-hops.conf').read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest())"
        actual = command(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--tmpfs", "/data:rw,nosuid,nodev,size=1m",
            "--mount", f"type=volume,src={self.state['volumes']['config']},dst=/config,readonly",
            "--entrypoint", "python", self.state["image_id"], "-c", program]).strip()
        if actual != self.state["release"]["payload"]["files"]["infra/mtls/all-hops-nginx.conf"]:
            raise RuntimeFailure("runtime_public_configuration_changed")

    def container(self, service):
        if service not in self.services:
            raise ValueError("runtime_service_scope")
        ident = self.compose("ps", "--all", "--quiet", service).strip()
        if not re.fullmatch(r"[a-f0-9]{12,64}", ident):
            raise RuntimeFailure("runtime_container_missing")
        data = json.loads(command(["docker", "inspect", ident]))[0]
        if (data["Config"]["Labels"].get("secops.runtime") != self.state["project"]
                or data["Config"]["Labels"].get("com.docker.compose.service") != service):
            raise RuntimeFailure("runtime_container_replaced")
        return ident

    def execute(self, service, argv, payload=None, timeout=30):
        return command(["docker", "exec", "--interactive", self.container(service), *argv],
                       payload=payload, timeout=timeout)

    def probe(self, request):
        return json.loads(self.execute("operator", ["python", "-m", "scripts.continuous_mtls_assets", "probe"],
                                       json.dumps(request)))

    def mint(self, request):
        return json.loads(self.execute("operator", ["python", "-m", "scripts.continuous_mtls_assets", "mint"],
                                       json.dumps(request)))

    @staticmethod
    def wait(predicate, timeout=90):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            try:
                if predicate():
                    return
            except (RuntimeFailure, OSError, ValueError, KeyError):
                pass
            time.sleep(.3)
        raise RuntimeFailure("runtime_wait_timeout")

    def status(self):
        rows = {}
        for name in self.services:
            info = json.loads(command(["docker", "inspect", self.container(name)]))[0]
            rows[name] = {"running": info["State"]["Running"], "restart_count": info["RestartCount"],
                          "restart_policy": info["HostConfig"]["RestartPolicy"]["Name"]}
        return {"project": self.state["project"], "services": rows}

    def down(self, *, purge=False):
        self.load()
        # Only this generated project; never prune the engine or other workloads.
        for name in self.services:
            try:
                self.container(name)
            except RuntimeFailure as exc:
                if str(exc) != "runtime_container_missing":
                    raise
        self.compose("down", "--volumes", "--timeout", "5", timeout=180)
        if purge:
            existing = set(command(["docker", "volume", "ls", "--format", "{{.Name}}"]).splitlines())
            for volume in self.state["volumes"].values():
                if volume not in existing:
                    continue
                detail = json.loads(command(["docker", "volume", "inspect", volume]))[0]
                if detail.get("Labels", {}).get("secops.runtime") != self.state["project"]:
                    raise RuntimeFailure("runtime_volume_scope")
                command(["docker", "volume", "rm", volume])
            if command(["docker", "image", "ls", "--quiet", self.state["image"]]).strip():
                command(["docker", "image", "rm", self.state["image"]])
            self.state["initialized"] = False
            self.state["purged"] = True
            self.save()
        return {"project": self.state["project"], "stopped": True, "purged": purge}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("up", "status", "down"))
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/continuous-mtls")
    parser.add_argument("--purge", action="store_true", help="Delete only this disposable project's volumes and image")
    args = parser.parse_args(argv)
    try:
        runtime = Runtime(args.directory)
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
