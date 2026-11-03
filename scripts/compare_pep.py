"""C02: isolated NGINX/Envoy HTTP enforcement comparison; no AWS/model calls.

python -m scripts.compare_pep --repeats 3
Control credentials/signatures/grants stay in memory and Docker-exec stdin.
"""

import argparse
import hashlib
import json
import os
import queue
import secrets
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.zero_trust_models import SignedSessionSignal
from scripts import pep_lab as pep
from scripts import test_signal_compose as flow
from scripts.compare_observability import command
from scripts.compare_supply_chain import sha256
from scripts.measure_signal_infrastructure import Sampler, distribution

ROOT = Path(__file__).resolve().parents[1]


class Lab:
    def __init__(self, directory):
        self.directory = directory.resolve()
        flow.require(self.directory.is_relative_to((ROOT / "runtime/c02").resolve()), "c02_directory_scope")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ident = "c02-" + uuid.uuid4().hex[:12]
        self.image = self.ident + "-app"
        self.containers, self.volumes, self.networks = [], [], []
        self.probes = {}
        self.lock = json.loads((ROOT / "infra/pep/tools.lock.json").read_text())
        self.contract = json.loads((ROOT / "infra/pep/contract.json").read_text())
        self.report = {"schema": "c02-pilot-1", "started_at": flow.timestamp(), "completed": False,
            "source_commit": command(["git", "rev-parse", "HEAD"]).strip(), "tools": self.lock, "contract": self.contract,
            "protected_fixture_sha256": pep.DOCUMENT_HASH,
            "conditions": {"network": "internal Docker networks; no published ports", "uid": 10001,
                "proxy_cpu_budget": 1, "proxy_memory_bytes": 268435456, "proxy_workers": 1,
                "handoff_ttl_seconds": 3, "grant_ttl_seconds": 60,
                "timing": "client HTTP duration inside container; excludes Docker exec startup",
                "authorization_point": "existing core SQLite grant-consumption transaction"}, "runs": []}
        self.save()

    def save(self):
        (self.directory / "summary.json").write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")

    def prepare(self, candidates=("nginx", "envoy")):
        command(["docker", "build", "--tag", self.image, str(ROOT)], timeout=900)
        self.report["app_image_id"] = command(["docker", "image", "inspect", self.image, "--format", "{{.Id}} "]).strip()
        for tool in [self.lock["tools"][candidate] for candidate in candidates]:
            command(["docker", "pull", "--platform", "linux/amd64", tool["image"]], timeout=600)
        version = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "nginx",
            self.lock["tools"]["nginx"]["image"], "-V"], capture_output=True, text=True, check=True)
        flow.require("--with-http_auth_request_module" in version.stderr, "c02_nginx_auth_module")
        self.report["nginx_auth_request_module_verified"] = True
        paths = [*[p for p in sorted((ROOT / "app").rglob("*")) if p.suffix in {".py", ".json", ".yaml", ".yml"}], ROOT / "Dockerfile", ROOT / "pyproject.toml",
                 ROOT / "scripts/pep_lab.py", ROOT / "scripts/compare_pep.py", *sorted((ROOT / "infra/pep").glob("*"))]
        self.report["source_input_sha256"] = {p.relative_to(ROOT).as_posix(): sha256(p) for p in paths if p.is_file()}
        self.save()

    def start(self, name, network, argv, *, image=None, mounts=(), env=None, alias=None, memory=128, cpus=.25, additional=()):
        self.containers.append(name)
        args = ["docker", "create", "--name", name, "--network", network, "--no-healthcheck",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user", "10001:10001",
            "--memory", f"{memory}m", "--memory-swap", f"{memory}m", "--cpus", str(cpus),
            "--pids-limit", "128", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m"]
        if alias:
            args += ["--network-alias", alias]
        for mount in mounts:
            args += ["--mount", mount]
        for key in env or {}:
            args += ["--env", key]
        ident = command(args + ["--entrypoint", argv[0], image or self.image, *argv[1:]],
                        env={**os.environ, **(env or {})}).strip()
        for extra, extra_alias in additional:
            self.connect(extra, name, extra_alias)
        command(["docker", "start", name])
        return ident

    def connect(self, network, container, alias):
        command(["docker", "network", "connect", "--alias", alias, network, container])

    def volume(self, name):
        command(["docker", "volume", "create", "--label", "secops.c02=" + self.ident, name])
        self.volumes.append(name)
        return name

    def request(self, container, request):
        if container not in self.probes:
            process = subprocess.Popen(["docker", "exec", "--interactive", container, "python", "-m",
                "scripts.pep_lab", "rpc-probe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1)
            responses = queue.Queue(maxsize=4)

            def receive():
                while line := process.stdout.readline(1048577):
                    responses.put(line)
                responses.put(None)

            thread = threading.Thread(target=receive, daemon=True)
            thread.start()
            self.probes[container] = (process, responses, thread)
        process, responses, _ = self.probes[container]
        try:
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            raw = responses.get(timeout=12)
            flow.require(raw is not None and len(raw) <= 1048576, "c02_probe_closed")
            return json.loads(raw)
        except (OSError, queue.Empty):
            self.close_probe(container)
            raise flow.CheckFailed("c02_probe_unavailable") from None

    def close_probe(self, container):
        if container in self.probes:
            process, _, thread = self.probes.pop(container)
            try:
                process.stdin.close()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            thread.join(timeout=2)
            process.stdout.close()

    def wait(self, predicate, label, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.3)
        raise flow.CheckFailed("c02_timeout_" + label)

    def prepare_transport(self, prefix, networks):
        return {"network": networks["core"], "mounts": [], "args": []}

    def transport_checks(self, prefix, record, keys, bridge):
        """Optional transport experiment; original C02 behavior remains HTTP."""

    def trial(self, candidate, iteration):
        print(json.dumps({"candidate": candidate, "iteration": iteration, "stage": "starting"}), flush=True)
        prefix = f"{self.ident}-{iteration}-{candidate}"
        directory = self.directory / prefix
        assets = flow.initialize_assets(directory)
        registry = json.loads(assets["registry"].read_text())
        registry["sources"][0]["roles"].append("administrator")
        other = json.loads(json.dumps(registry["sources"][0]))
        other["tenant_id"] = "other"
        registry["sources"].append(other)
        assets["registry"].write_text(json.dumps(registry), encoding="utf-8")
        networks = {}
        for label in ["client", "auth", "core", "resource", "consume"]:
            name = prefix + "-" + label
            command(["docker", "network", "create", "--internal", "--label", "secops.c02=" + self.ident, name])
            self.networks.append(name)
            networks[label] = name
        data, secretvol = self.volume(prefix + "-data"), self.volume(prefix + "-secret")
        secret = secrets.token_urlsafe(32)
        command(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL", "--user", "10001:10001",
            "--mount", f"type=volume,src={secretvol},dst=/data", "--entrypoint", "python", "--interactive", self.image,
            "-c", "import pathlib,sys,os; p=pathlib.Path('/data/secret'); p.write_text(sys.stdin.read()); os.chmod(p,0o600)"], input=secret)
        shared = [f"type=volume,src={data},dst=/data", f"type=bind,src={assets['registry']},dst=/signals/sources.json,readonly"]
        base_env = {"APP_ENVIRONMENT": "local", "ANALYZER_MODE": "rule", "AUTH_MODE": "api_key",
            "ZERO_TRUST_DB_PATH": "/data/zero-trust.sqlite3", "TRUSTED_SIGNAL_SOURCES_PATH": "/signals/sources.json",
            "AUDIT_LOG_PATH": "/tmp/audit.jsonl", "CASE_LOG_PATH": "/tmp/cases.jsonl", "OUTBOX_LOG_PATH": "/tmp/outbox.jsonl",
            "ALLOWED_HOSTS": "core,localhost,127.0.0.1"}
        keys = {kind: secrets.token_urlsafe(32) for kind in ["a", "b", "c"]}
        cores = {}
        for kind, key in keys.items():
            name = prefix + "-core-" + kind
            cores[kind] = name
            self.start(name, networks["core"], ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"],
                mounts=shared, alias="core" if kind == "a" else "core-" + kind, memory=256, cpus=.5,
                env=base_env | {"API_KEY_SHA256": hashlib.sha256(key.encode()).hexdigest(), "API_KEY_ROLES": "responder",
                    "API_KEY_SUBJECT": "operator-" + kind, "API_KEY_TENANT_ID": "other" if kind == "b" else "local"})
            self.wait(lambda n=name: self.request(n, {"path": "/health/live"})["status"] == 200, "core_ready")
        mounts = [f"type=volume,src={secretvol},dst=/data,readonly"]
        transport = self.prepare_transport(prefix, networks)
        bridge, resource, client = [prefix + "-" + label for label in ["bridge", "resource", "client"]]
        self.start(bridge, networks["auth"], ["python", "-m", "scripts.pep_lab", "bridge", "--secret-file", "/data/secret", *transport["args"]], mounts=mounts + transport["mounts"], alias="bridge")
        self.connect(transport["network"], bridge, "bridge")
        self.connect(networks["consume"], bridge, "bridge")
        self.start(resource, networks["resource"], ["python", "-m", "scripts.pep_lab", "resource", "--secret-file", "/data/secret"], mounts=mounts, alias="resource")
        self.connect(networks["consume"], resource, "resource")
        self.start(client, networks["client"], ["python", "-c", "import time; time.sleep(3600)"])
        proxy = prefix + "-proxy"
        if candidate == "nginx":
            argv, config = ["nginx", "-c", "/config/nginx.conf", "-g", "daemon off;"], "nginx.conf"
        else:
            argv, config = ["envoy", "-c", "/config/envoy.yaml", "--concurrency", "1", "--disable-hot-restart", "--log-level", "error"], "envoy.yaml"
        ident = self.start(proxy, networks["auth"], argv, image=self.lock["tools"][candidate]["image"],
            mounts=[f"type=bind,src={ROOT / 'infra/pep' / config},dst=/config/{config},readonly"], memory=256, cpus=1,
            additional=[(networks["client"], "proxy"), (networks["resource"], "proxy")])
        probe = {"host": "proxy", "port": 8080, "path": "/documents"}
        self.wait(lambda: self.request(client, probe)["status"] == 403, "proxy_ready")
        record = {"candidate": candidate, "iteration": iteration, "checks": [], "completed": False, "started_at": flow.timestamp()}
        self.report["runs"].append(record)
        hardening = []
        for name in [n for n in self.containers if n.startswith(prefix + "-")]:
            config = json.loads(command(["docker", "inspect", name]))[0]
            host = config["HostConfig"]
            flow.require(config["Config"]["User"] == "10001:10001" and host["ReadonlyRootfs"]
                and "ALL" in host["CapDrop"] and "no-new-privileges:true" in host["SecurityOpt"]
                and not host["PortBindings"] and not any(config["NetworkSettings"]["Ports"].values()), "c02_container_boundary")
            hardening.append({"service": name.removeprefix(prefix + "-"), "uid": config["Config"]["User"],
                "read_only": True, "cap_drop_all": True, "no_new_privileges": True, "published_ports": False,
                "memory_bytes": host["Memory"], "nano_cpus": host["NanoCpus"]})
        flow.require(all(n["Internal"] for n in json.loads(command(["docker", "network", "inspect", *networks.values()]))), "c02_network_boundary")
        record["hardening"] = hardening
        sampler = Sampler({ident: candidate}, directory / "proxy-stats.jsonl", 1)
        sampler.thread.start()

        def control(path, payload=None, kind="a"):
            req = {"path": path, "headers": [["X-API-Key", keys[kind]]], "private_control": True}
            if payload is not None:
                req.update(method="POST", payload=payload)
            response = self.request(cores[kind], req)
            flow.require(response["status"] in {200, 202}, "c02_control_status_" + str(response["status"]))
            return json.loads(response["body"])

        counter = 0

        def mint(kind="a", proof_seconds=110, user=flow.USERS[2], device=flow.DEVICES[4], vault=False):
            nonlocal counter
            counter += 1
            session = f"c02-{iteration}-{candidate}-{counter:03}"
            signed = SignedSessionSignal.model_validate(flow.signed_session(session, user, device, assets["keys"]["session"]))
            if vault:
                event = signed.event.model_dump(mode="json")
                event["user"]["role"] = "administrator"
                event["resource"].update(resource_id="zt-demo-vault", resource_type="database")
                signed = SignedSessionSignal.model_validate(signed.model_dump(mode="json") | {"event": event})
            signed = signed.model_copy(update={"tenant_id": "other" if kind == "b" else "local",
                "expires_at": datetime.now(UTC) + timedelta(seconds=proof_seconds)})
            payload = flow.sign(signed, assets["keys"]["session"]).model_dump(mode="json")
            result = control("/zero-trust/signals/evaluate", payload, kind)
            flow.require(result["grant_token"] and result["session"]["decision"] == "ALLOW", "c02_mint_allow")
            return session, result["grant_token"]

        def access(pair, **changes):
            return probe | {"headers": [["X-API-Key", keys["a"]], ["X-Session-ID", pair[0]], ["X-Grant-Token", pair[1]]]} | changes

        def served():
            return json.loads(self.request(resource, {"port": 8083, "path": "/_stats", "private_control": True})["body"])["served"]

        def rejected_reason(pair, expected):
            response = self.request(cores["a"], {"path": "/zero-trust/protected-access", "method": "POST",
                "headers": [["X-API-Key", keys["a"]]], "private_control": True, "payload": {
                    "session_id": pair[0], "grant_token": pair[1], "resource_id": "zt-demo-documents", "action": "READ"}})
            flow.require(response["status"] == 403 and json.loads(response["body"])["reason_code"] == expected,
                         "c02_expected_reason_" + expected)
            record["checks"][-1]["core_reason"] = expected
            self.save()

        def check(label, request, allowed=0, *, container=client):
            before = served()
            responses = self.request(container, request)
            rows = responses if isinstance(responses, list) else [responses]
            successful = [r for r in rows if 200 <= r["status"] < 300]
            flow.require(len(successful) == allowed, "c02_status_" + label)
            flow.require(all(r["body_sha256"] == pep.DOCUMENT_HASH for r in successful), "c02_content_" + label)
            flow.require(all(r["body_sha256"] != pep.DOCUMENT_HASH for r in rows if r not in successful), "c02_leak_" + label)
            flow.require(served() - before == allowed, "c02_resource_count_" + label)
            record["checks"].append({"label": label, "passed": True, "statuses": [r["status"] for r in rows],
                "resource_deliveries": allowed, "http_ms": [r["elapsed_ms"] for r in rows]})
            self.save()

        try:
            self.transport_checks(prefix, record, keys, bridge)
            valid = mint()
            check("valid_once", access(valid), 1)
            check("grant_replay", access(valid))
            check("concurrent_single_use", [access(mint_pair := mint())] * 8, 1)
            check("concurrent_replay", access(mint_pair))
            for missing in ["X-API-Key", "X-Session-ID", "X-Grant-Token"]:
                req = access(mint())
                req["headers"] = [h for h in req["headers"] if h[0] != missing]
                check("missing_" + missing.lower(), req)
            req = access(mint())
            req["headers"][0][1] = "invalid" * 6
            check("bad_api_key", req)
            req = access(mint())
            req["headers"][2][1] = "x" * 43
            check("wrong_grant", req)
            req = access(mint())
            req["headers"][1][1] = "unknown-session"
            check("unknown_session", req)
            scoped = mint(vault=True)
            check("resource_scope_mismatch", access(scoped))
            rejected_reason(scoped, "SCOPE_DENIED")
            req = access(mint())
            req["headers"] += [req["headers"][0]]
            check("duplicate_credentials", req)
            for method in ["POST", "HEAD", "PUT", "DELETE", "OPTIONS"]:
                check("method_" + method.lower(), access(mint(), method=method))
            for index, path in enumerate(["/_authorize", "/", "/documents?scope=vault", "/%64ocuments", "//documents", "/x/../documents", "/documents%2f"]):
                check(f"path_{index}", access(mint(), path=path))
            req = access(mint())
            req["headers"] += [["X-PEP-Handoff", "x" * 43], ["X-User", "administrator"], ["X-Tenant", "other"], ["X-C02-Target", "/vault"]]
            check("spoofed_headers_cannot_change_scope", req, 1)
            for kind in ["b", "c"]:
                req = access(mint(kind))
                req["headers"] += [["X-User", "operator-" + kind], ["X-Tenant", "other" if kind == "b" else "local"]]
                check("binding_" + kind, req)
            revoked = mint()
            control("/zero-trust/sessions/" + revoked[0] + "/revoke", {"expected_version": 1, "note": "C02 local revocation check"})
            check("revoked_before_request", access(revoked))
            rejected_reason(revoked, "SESSION_NOT_AUTHORIZED")
            proof_expired = mint(proof_seconds=2)
            time.sleep(2.1)
            check("signed_proof_expired", access(proof_expired))
            rejected_reason(proof_expired, "SIGNAL_PROOF_EXPIRED")
            # Client network has neither resource nor core DNS/routes.
            check("direct_client_resource", {"host": "resource", "port": 8083, "path": "/documents", "headers": [["X-PEP-Handoff", "x" * 43]]})
            check("direct_client_core", {"host": "core", "port": 8000, "path": "/zero-trust/protected-access"})
            check("resource_forged_handoff", {"port": 8083, "path": "/documents", "headers": [["X-PEP-Handoff", "x" * 43]]}, container=resource)
            # Mint late enough that proof (110s) stays valid when the unchanged grant (60s) expires.
            expiry = mint()
            expiry_deadline = time.monotonic() + 61
            # Consume one core grant, then lose its in-memory handoff on a real bridge restart.
            pending = mint()
            authorization = self.request(bridge, access(pending, host="127.0.0.1", port=8081, private_control=True))
            flow.require(authorization["status"] == 200 and authorization["handoff"], "c02_pending_handoff")
            self.close_probe(bridge)
            command(["docker", "restart", "--time", "2", bridge])
            self.wait(lambda: self.request(bridge, {"port": 8081, "path": pep.PATH})["status"] == 403, "bridge_ready")
            check("bridge_restart_loses_pending_handoff", {"port": 8083, "path": pep.PATH,
                "headers": [["X-PEP-Handoff", authorization["handoff"]]]}, container=resource)
            check("bridge_restart_no_grant_refund", access(pending))
            # Networkless existing worker handles a signed adverse observation; PEP sees the restriction.
            affected = mint(user=flow.USERS[0], device=flow.DEVICES[0])
            observation = flow.signed_observation(prefix + "-adverse", flow.USERS[0], assets["keys"]["identity"])
            control("/zero-trust/signals/inbox", observation.model_dump(mode="json"))
            worker = prefix + "-worker"
            self.start(worker, "none", ["python", "-m", "scripts.signal_worker", "--once"], mounts=shared,
                       env=base_env | {"AUTH_MODE": "disabled"})  # No HTTP server/network/credential in worker.
            worker_config = json.loads(command(["docker", "inspect", worker]))[0]
            flow.require(worker_config["HostConfig"]["NetworkMode"] == "none", "c02_worker_networkless")
            record["worker_network"] = "none"
            self.wait(lambda: control("/zero-trust/signals/inbox/" + observation.event_id)["state"] == "completed", "adverse_processed")
            check("signed_adverse_signal_revokes_before_request", access(affected))
            rejected_reason(affected, "SESSION_NOT_AUTHORIZED")
            check("unrelated_user_still_allowed", access(mint()), 1)
            unavailable = mint()
            command(["docker", "pause", cores["a"]])
            try:
                check("pdp_timeout", access(unavailable))
            finally:
                command(["docker", "unpause", cores["a"]])
            # A timeout may already have committed; never require/retry a successful regrant.
            self.close_probe(cores["a"])
            command(["docker", "stop", "--time", "2", cores["a"]])
            check("pdp_unavailable", access(mint_pair))
            command(["docker", "start", cores["a"]])
            self.wait(lambda: self.request(cores["a"], {"path": "/health/live"})["status"] == 200, "core_restarted")
            if time.monotonic() < expiry_deadline:
                time.sleep(expiry_deadline - time.monotonic())
            check("grant_expired_unchanged_60s_policy", access(expiry))
            rejected_reason(expiry, "GRANT_EXPIRED")
            source_revoked = mint()
            registry["sources"][0]["keys"][0]["enabled"] = False
            assets["registry"].write_text(json.dumps(registry), encoding="utf-8")
            check("signing_key_disabled", access(source_revoked))
            rejected_reason(source_revoked, "SIGNAL_SOURCE_REVOKED")
            self.close_probe(bridge)
            command(["docker", "stop", "--time", "2", bridge])
            check("auth_bridge_unavailable", access(mint_pair))
            command(["docker", "start", bridge])
            self.wait(lambda: self.request(bridge, {"port": 8081, "path": pep.PATH})["status"] == 403, "bridge_restarted")
            check("bridge_restart_no_replay", access(valid))
            labels = [check["label"] for check in record["checks"]]
            flow.require(len(labels) == len(set(labels)) and set(labels) == set(self.contract["expected_checks"]), "c02_check_coverage")
            record["completed"] = True
        finally:
            sampler.stop()
            record["resource_samples"], record["resource_errors"] = sampler.rows, sampler.errors
            if not sampler.rows or sampler.errors:
                record["completed"] = False
            record["finished_at"] = flow.timestamp()
            record["http_duration"] = distribution([t for check in record["checks"] for t in check["http_ms"]])
            self.save()
            self.cleanup_trial(prefix)

    def cleanup_trial(self, prefix):
        for collection, args in [(self.containers, ["rm", "--force", "--volumes"]), (self.volumes, ["volume", "rm"]), (self.networks, ["network", "rm"])]:
            for name in list(collection):
                if name.startswith(prefix + "-"):
                    if args[0] == "rm":
                        self.close_probe(name)
                        log = subprocess.run(["docker", "logs", "--tail", "150", name], capture_output=True,
                                             text=True, encoding="utf-8", errors="replace", check=False)
                        (self.directory / (name + ".private.log")).write_text(log.stdout + log.stderr, encoding="utf-8")
                    result = subprocess.run(["docker", *args, name], capture_output=True, check=False)
                    if result.returncode == 0:
                        collection.remove(name)

    def cleanup(self):
        self.cleanup_trial(self.ident)
        subprocess.run(["docker", "image", "rm", self.image], capture_output=True, check=False)
        self.report["cleanup"] = {"containers_remaining": len(self.containers), "volumes_remaining": len(self.volumes),
                                  "networks_remaining": len(self.networks)}
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02")
    parser.add_argument("--repeats", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    lab = Lab(args.directory)
    try:
        lab.prepare()
        for iteration in range(1, args.repeats + 1):
            for candidate in (["nginx", "envoy"] if iteration % 2 else ["envoy", "nginx"]):
                lab.trial(candidate, iteration)
        flow.require(all(run["completed"] for run in lab.report["runs"]), "c02_incomplete_evidence")
        lab.report["comparison"] = {}
        for candidate in lab.lock["tools"]:
            runs = [run for run in lab.report["runs"] if run["candidate"] == candidate]
            rows = [row for run in runs for row in run["resource_samples"]]
            checks = [check for run in runs for check in run["checks"]]
            lab.report["comparison"][candidate] = {"repeats": len(runs), "checks_passed": len(checks),
                "client_requests": sum(len(c["statuses"]) for c in checks),
                "resource_deliveries": sum(c["resource_deliveries"] for c in checks),
                "allowed_http_duration": distribution([duration for c in checks
                    for status, duration in zip(c["statuses"], c["http_ms"], strict=True) if status == 200]),
                "resource_samples": len(rows), "memory_peak_bytes_estimate": max(r["memory_bytes_estimate"] for r in rows),
                "cpu_peak_percent": max(r["cpu_percent"] for r in rows)}
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, flow.CheckFailed) as exc:
        # Suppress payloads/CLI stderr; fixed labels only.
        lab.report["failure"] = str(exc) if isinstance(exc, flow.CheckFailed) else type(exc).__name__
        raise SystemExit(lab.report["failure"]) from None
    finally:
        lab.report["finished_at"] = flow.timestamp()
        lab.cleanup()


if __name__ == "__main__":
    main()
