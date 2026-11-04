"""Trusted-host control of two pinned local Docker daemons and CA DB recovery.

Only explicit owned service-host containers are fenced. Neither application nor
CA containers receive a Docker socket. A local DinD host is a simulation of an
independent service host, not protection from failure of the physical PC.
"""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import time
from contextlib import nullcontext
from pathlib import Path

from scripts.authority_rotation_coordinator import DockerBackend, lease
from scripts.certificate_controller import LifecycleError, save


def lsn(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9A-F]+/[0-9A-F]+", value):
        raise LifecycleError("recovery_lsn_shape")
    high, low = value.split("/")
    return (int(high, 16) << 32) + int(low, 16)


class Hosts(DockerBackend):
    def __init__(self, profile):
        if type(self) is Hosts and profile.get('management'):
            raise LifecycleError('control_management_backend_required')
        super().__init__(profile)
        self.hosts = profile["service_hosts"]
        if set(self.hosts) != {"a", "b"}:
            raise LifecycleError("recovery_host_count")
        for host in self.hosts.values():
            if (not re.fullmatch(re.escape(self.project) + r"-[a-z0-9-]+", host["name"])
                    or not re.fullmatch(r"[a-f0-9]{64}", host["id"])
                    or not re.fullmatch(r"sha256:[a-f0-9]{64}", host["image"])):
                raise LifecycleError("recovery_host_scope")
        for name in [*profile.get("gateways", []), *[profile[k] for k in ["client_network", "cluster_network", "witness_volume", "backup_volume", "backup_key_volume"] if k in profile]]:
            if not re.fullmatch(re.escape(self.project) + r"-[a-z0-9-]+", name):
                raise LifecycleError("recovery_resource_scope")

    def directory(self):
        directory = Path(self.profile["control_directory"]).resolve()
        if not directory.is_relative_to(Path(__file__).resolve().parents[1] / "runtime/c02") or not directory.name.startswith(self.project + "-"):
            raise LifecycleError("recovery_control_directory_scope")
        return directory

    def persist_profile(self):
        save(self.directory() / "profile.json", self.profile)

    def host(self, label, *, running=True):
        expected = self.hosts[label]
        found = json.loads(self.command(["inspect", expected["name"]]))[0]
        if (found["Id"] != expected["id"] or found["Image"] != expected["image"] or found["Name"] != "/" + expected["name"]
                or found["HostConfig"]["RestartPolicy"]["Name"] not in {"", "no"}
                or any(m["Destination"].endswith("docker.sock") for m in found["Mounts"])):
            raise LifecycleError("recovery_host_replaced")
        if running and not found["State"]["Running"]:
            raise LifecycleError("recovery_host_stopped")
        return found

    def inner(self, label, args, payload=None, timeout=30):
        self.host(label)
        command = ["exec", "-i", self.hosts[label]["name"], "docker", *args]
        return self.command(command, payload, timeout)

    def inner_raw(self, label, args, body=None, timeout=60):
        self.host(label)
        result = subprocess.run(["docker", "exec", "-i", self.hosts[label]["name"], "docker", *args], input=body,
            capture_output=True, timeout=timeout, check=False)
        if result.returncode:
            raise LifecycleError("recovery_inner_command_failed")
        return result.stdout

    def witness(self, operation, **fields):
        record = json.loads(self.command(["inspect", self.profile["gateways"][0]]))[0]
        if record["Image"] != self.profile["image"] or record["Id"] != self.profile["gateway_ids"][0]:
            raise LifecycleError("recovery_witness_replaced")
        return json.loads(self.command(["exec", "-i", self.profile["gateways"][0], "python", "-m", "scripts.ca_recovery_state", "rpc"],
            {"operation": operation, **fields}))

    def wait_quiet(self, *, timeout=20):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.witness("freeze")
            except LifecycleError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.2)

    def node_for(self, expected):
        labels = [label for label, host in self.hosts.items() if host["ca"]["id"] == expected["id"] and host["ca"]["name"] == expected["name"]]
        if len(labels) != 1:
            raise LifecycleError("recovery_inner_identity")
        return labels[0]

    def owned_ca(self, label):
        host = self.hosts[label]
        found = json.loads(self.inner(label, ["inspect", host["ca"]["name"]]))[0]
        mounts = [m for m in found["Mounts"] if m["Destination"] == "/ca"]
        if (found["Id"] != host["ca"]["id"] or found["Image"] != self.profile["image"]
                or len(mounts) != 1 or mounts[0].get("Name") != host["ca_volume"] or mounts[0]["RW"]
                or any(m["Destination"] in {"/vault", "/var/run/docker.sock"} for m in found["Mounts"])):
            raise LifecycleError("recovery_ca_boundary")
        return found

    def ca_assets(self):
        args = ["run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
            "--mount", f"type=volume,src={self.profile['volumes']['ca']},dst=/ca,readonly", "--entrypoint", "python", self.profile["image"],
            "-c", "import json;from pathlib import Path;c=json.loads(Path('/ca/ca.json').read_bytes());names={'ca.json','password.txt',c['crt'].split('/')[-1],c['key'].split('/')[-1]};names.update(p.split('/')[-1] for p in (c['root'] if isinstance(c['root'],list) else [c['root']]));print(json.dumps({n:Path('/ca',n).read_text() for n in names}))"]
        return json.loads(self.command(args))  # Trusted-host RAM, never host files/logs.

    def sync_ca(self, label, *, purge=False):
        self.owned_ca(label)
        files = self.ca_assets()
        host = self.hosts[label]
        program = """import json,os,sys
from pathlib import Path
from scripts.certificate_controller import atomic
request=json.load(sys.stdin);files=request['files'];root=Path('/ca')
if any(Path(n).name!=n or '/' in n or '\\\\' in n for n in files):raise ValueError('asset_scope')
for n,v in files.items():atomic(root/n,v)
for p in root.iterdir():
 if request['purge'] and p.is_file() and p.name not in files:p.unlink()
print('{}')"""
        self.inner(label, ["run", "--rm", "-i", "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
            "--mount", f"type=volume,src={host['ca_volume']},dst=/ca", "--entrypoint", "python", self.profile["image"], "-c", program], {"files": files, "purge": purge})

    def restart_ca(self):
        for label in self.hosts:
            self.owned_ca(label)
        for label in self.hosts:
            self.sync_ca(label)
            self.inner(label, ["restart", "--time", "2", self.hosts[label]["ca"]["name"]])
            deadline = time.monotonic() + 25
            while True:
                try:
                    self.leaf("endpoint_health", endpoint="ca-" + label)
                    break
                except LifecycleError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.3)

    def custodian(self, operation, payload=None):
        result = super().custodian(operation, payload)
        if operation == "finish":
            for label in self.hosts:
                self.sync_ca(label, purge=True)
            self.wait_quiet()
            authority = hashlib.sha256(json.dumps(json.loads(self.ca_assets()["ca.json"]), sort_keys=True).encode()).hexdigest()
            self.witness("authority", authority=authority)
            self.witness("checkpoint")
            self.witness("unfreeze")
        return result

    def sql(self, label, statement):
        return self.inner_raw(label, ["exec", "-i", self.hosts[label]["database"], "psql", "-h", "/tmp", "-U", "postgres", "-d", "stepca",
            "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"], statement.encode()).decode().strip()

    def fence(self, label):
        before = self.host(label, running=False)
        # Close gateway admission before a stopped old host can ever be restarted.
        # A missing/replaced/unreachable Docker object is not proof of fencing.
        self.command(["stop", "--time", "2", before["Id"]])
        after = self.host(label, running=False)
        if after["State"]["Running"] or after["State"].get("Restarting"):
            raise LifecycleError("recovery_fence_unconfirmed")
        self.witness("fence", node=label, verified_stopped=True)
        self.admission_network(label, enabled=False)
        return {"node": label, "id": after["Id"], "running": False, "finished_at": after["State"]["FinishedAt"], "client_network_detached": True}

    def admission_network(self, label, *, enabled):
        index = {"a": 0, "b": 1}[label]
        name = self.profile["gateways"][index]
        record = json.loads(self.command(["inspect", name]))[0]
        if (record["Id"] != self.profile["gateway_ids"][index] or record["Image"] != self.profile["image"]
                or record["Name"] != "/" + name):
            raise LifecycleError("recovery_gateway_replaced")
        network = self.profile["client_network"]
        attached = network in record["NetworkSettings"]["Networks"]
        if attached and not enabled:
            self.command(["network", "disconnect", network, record["Id"]])
        elif enabled and not attached:
            aliases = ["--alias", "ca-" + label] + (["--alias", "ca"] if label == "a" else [])
            self.command(["network", "connect", *aliases, network, record["Id"]])
        verified = json.loads(self.command(["inspect", name]))[0]
        if (verified["Id"] != record["Id"] or verified["Image"] != record["Image"]
                or (network in verified["NetworkSettings"]["Networks"]) != enabled):
            raise LifecycleError("recovery_gateway_network_unconfirmed")

    def failover(self, old, target):
        with lease(self.directory()), self.management_operation() if hasattr(self, 'management_operation') else nullcontext():
            self.quiesce()
            return self._failover(old, target)

    def _failover(self, old, target):
        if old == target or target not in self.hosts or old not in self.hosts:
            raise LifecycleError("recovery_failover_scope")
        receipt = self.fence(old)
        candidate = self.host(target)
        if self.sql(target, "SELECT pg_is_in_recovery();") != "t":
            raise LifecycleError("recovery_candidate_not_standby")
        witness = self.witness("status")
        if self.sql(target, "SELECT system_identifier FROM pg_control_system();") != witness["incarnation"]:
            raise LifecycleError("recovery_candidate_database_identity")
        required = lsn(witness["checkpoint_lsn"])
        replay = self.sql(target, "SELECT pg_last_wal_replay_lsn();")
        if lsn(replay) < required:
            raise LifecycleError("recovery_candidate_behind_checkpoint")
        self.sql(target, "SELECT pg_promote(true,10);")
        self.sql(target, "ALTER SYSTEM SET synchronous_standby_names='';\nSELECT pg_reload_conf();")
        self.wait_quiet()
        self.witness("checkpoint")
        self.witness("unfreeze")
        return {"fence": receipt, "target_id": candidate["Id"], "replay_lsn": replay,
            "required_lsn": witness["checkpoint_lsn"], "mode": "degraded_single_durable_primary_until_rejoin"}

    def node_tls_assets(self, label):
        node = self.hosts[label]
        return json.loads(self.inner(label, ["run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
            "--mount", f"type=volume,src={node['tls_volume']},dst=/tls,readonly", "--entrypoint", "python", self.profile["image"], "-c",
            "import json;from pathlib import Path;p=Path('/tls');assert all(v.is_file() and not v.is_symlink() for v in p.iterdir());print(json.dumps({v.name:v.read_text() for v in p.iterdir()}))"]))

    def node_health(self, label):
        """Management-only TLS probe while managed admission remains frozen."""
        self.owned_ca(label)
        assets = self.ca_assets()
        config = json.loads(assets["ca.json"])
        roots = config["root"] if isinstance(config["root"], list) else [config["root"]]
        request = {"node": label, "roots": "".join(assets[Path(p).name] for p in roots), "issuer": assets[Path(config["crt"]).name]}
        program = """import json,sys,ssl,socket,http.client
from cryptography import x509
p=json.load(sys.stdin);c=ssl.create_default_context(cadata=p['roots'])
with c.wrap_socket(socket.create_connection(('host-'+p['node'],9000),timeout=2),server_hostname='ca-'+p['node']) as s:
 x509.load_der_x509_certificate(s.getpeercert(binary_form=True)).verify_directly_issued_by(x509.load_pem_x509_certificate(p['issuer'].encode()))
 s.sendall(b'GET /health HTTP/1.1\\r\\nHost: ca\\r\\nConnection: close\\r\\n\\r\\n');r=http.client.HTTPResponse(s);r.begin();assert r.status==200 and json.loads(r.read(4096))['status']=='ok'
print('{}')"""
        deadline = time.monotonic() + 30
        while True:
            try:
                self.node_tls_probe(program, request)
                return
            except LifecycleError:
                if time.monotonic() > deadline:
                    raise LifecycleError("recovery_pre_admission_tls_health") from None
                time.sleep(.3)

    def node_tls_probe(self, program, request):
        self.command(["exec", "-i", self.profile["gateways"][0], "python", "-c", program], request, timeout=5)

    def private_backup_job(self, payload):
        args = ["run", "--rm", "-i", "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--memory", "512m", "--cpus", "1"]
        mounts = [(self.profile["backup_volume"], "/backups", False), (self.profile["backup_key_volume"], "/backup-key", False),
            (self.profile["witness_volume"], "/witness", True)]
        mounts += [(self.profile["volumes"][key], destination, True) for key, destination in [("ca", "/ca"), ("vault", "/vault"), ("renewal", "/renewal"), ("leaf", "/controller")]]
        for volume, destination, readonly in mounts:
            args += ["--mount", f"type=volume,src={volume},dst={destination}" + (",readonly" if readonly else "")]
        return json.loads(self.command([*args, "--entrypoint", "python", self.profile["image"], "-m", "scripts.ca_recovery_state", "backup-job"], payload, timeout=60))

    def quiesce(self):
        self.leaf("pause", value=True)
        deadline = time.monotonic() + 30
        while not self.leaf("status")["paused"]:
            if time.monotonic() > deadline:
                raise LifecycleError("recovery_leaf_not_quiescent")
            time.sleep(.2)
        control = (self.load_control() if hasattr(self, 'load_control') else
            json.loads((self.directory() / "authority-coordinator.json").read_bytes()))
        if control["phase"] != "idle":
            raise LifecycleError("recovery_authority_transition_pending")
        self.wait_quiet()

    def settle(self, primary):
        """A TCP close alone cannot prove an interrupted SQL request completed.

        Stop every reachable writer, prove all CA DB sessions have gone, then
        seal a recoverable sequence. Ordinary connection snapshots are advisory
        until this explicit maintenance barrier. Any later connection invalidates
        the sealed sequence; unexpected uncheckpointed loss must fail closed.
        """
        witness = self.witness("status")
        if (not witness["frozen"] or witness["pending"]
                or self.sql(primary, "SELECT pg_is_in_recovery();") != "f"
                or self.sql(primary, "SELECT system_identifier FROM pg_control_system();") != witness["incarnation"]):
            raise LifecycleError("recovery_settle_primary_identity")
        active = []
        for label in self.hosts:
            host = self.host(label, running=False)
            if not host["State"]["Running"]:
                if label in self.witness("status")["enabled"]:
                    raise LifecycleError("recovery_unfenced_writer")
                continue
            ca = self.owned_ca(label)
            if ca["State"]["Running"]:
                self.inner(label, ["stop", "--time", "2", ca["Id"]])
                active.append(label)
            if self.owned_ca(label)["State"]["Running"]:
                raise LifecycleError("recovery_writer_stop_unconfirmed")
        deadline = time.monotonic() + 15
        while self.sql(primary, "SELECT count(*) FROM pg_stat_activity WHERE usename='secops_ca';") != "0":
            if time.monotonic() > deadline:
                raise LifecycleError("recovery_database_writers_pending")
            time.sleep(.2)
        self.witness("settle", verified_writers_stopped=True)
        # No client bytes can arrive while the gateways remain frozen.
        for label in active:
            self.inner(label, ["start", self.hosts[label]["ca"]["id"]])
            self.node_health(label)

    def backup(self, name, primary):
        with lease(self.directory()), self.management_operation() if hasattr(self, 'management_operation') else nullcontext():
            self.quiesce()
            self.settle(primary)
            database = self.inner_raw(primary, ["exec", self.hosts[primary]["database"], "pg_dump", "-h", "/tmp", "-U", "postgres", "-d", "stepca", "-Fc"], timeout=60)
            result = self.private_backup_job({"operation": "backup", "name": name, "database": base64.b64encode(database).decode(),
                "node_tls": {label: self.node_tls_assets(label) for label in self.hosts}})
            self.witness("unfreeze")
            return result

    def restore_check(self, name, primary=None):
        with lease(self.directory()), self.management_operation() if hasattr(self, 'management_operation') else nullcontext():
            self.quiesce()
            if primary is not None:
                self.settle(primary)
            value = self.private_backup_job({"operation": "restore", "name": name})
            return {"verified": True, "backup_sequence": value["manifest"]["sequence"],
                "latest_security_sha256": value["security"]["sha256"], "latest_lsn": value["security"]["lsn"]}

    def seal_recovery(self, primary):
        with lease(self.directory()), self.management_operation() if hasattr(self, 'management_operation') else nullcontext():
            self.quiesce()
            self.settle(primary)
            return self.witness("status")

    def rejoin(self, label, primary, backup_name):
        from scripts.ca_recovery_nodes import Rebuilder
        with lease(self.directory()), self.management_operation() if hasattr(self, 'management_operation') else nullcontext():
            return self._rejoin(label, primary, backup_name, Rebuilder(self))

    def _rejoin(self, label, primary, backup_name, factory):
        if label == primary or label not in self.hosts or primary not in self.hosts:
            raise LifecycleError("recovery_rejoin_scope")
        self.quiesce()
        if self.host(label, running=False)["State"]["Running"]:
            raise LifecycleError("recovery_old_host_not_fenced")
        self.settle(primary)
        value = self.private_backup_job({"operation": "restore", "name": backup_name})
        tls = value["backup"]["node_tls"][label]
        factory.host(label)
        factory.assets(label, self.hosts[label]["tls_volume"], tls)
        factory.assets(label, self.hosts[label]["ca_volume"], self.ca_assets())
        factory.standby(label, primary)
        factory.ca(label)
        self.node_health(label)
        self.witness("checkpoint")
        self.witness("enable", node=label)
        self.admission_network(label, enabled=True)
        self.witness("unfreeze")
        return {"node": label, "new_host_id": self.hosts[label]["id"], "daemon_id": self.hosts[label]["daemon_id"], "mode": "synchronous_standby"}

    def restore(self, name):
        from scripts.ca_recovery_nodes import Rebuilder
        with lease(self.directory()), self.management_operation() if hasattr(self, 'management_operation') else nullcontext():
            self.quiesce()
            value = self.private_backup_job({"operation": "restore", "name": name})
            before = self.witness("status")
            receipts = [self.fence(label) for label in self.hosts]
            factory = Rebuilder(self)
            for label in self.hosts:
                factory.host(label)
            ca_files = {n: base64.b64decode(body).decode() for n, body in value["backup"]["folders"]["ca"].items() if n != "db"}
            for label, node in self.hosts.items():
                factory.assets(label, node["tls_volume"], value["backup"]["node_tls"][label])
                factory.assets(label, node["ca_volume"], ca_files)
            factory.primary("a")
            self.inner_raw("a", ["exec", "-i", self.hosts["a"]["database"], "pg_restore", "-h", "/tmp", "-U", "postgres", "-d", "stepca", "--exit-on-error", "--clean", "--if-exists"],
                base64.b64decode(value["backup"]["database"], validate=True), timeout=60)
            self.sql("a", value["replay_sql"])
            # Read through the same restricted TLS role, without overwriting the
            # independent checkpoint until reconciliation has been verified.
            script = "import json;from pathlib import Path;from scripts.ca_recovery_state import snapshot;c=json.loads(Path('/witness/config.json').read_bytes());s=snapshot(c['dsn']);print(json.dumps({'sha256':s['sha256']}))"
            restored = json.loads(self.command(["exec", self.profile["gateways"][0], "python", "-c", script]))
            if restored["sha256"] != value["security"]["sha256"]:
                raise LifecycleError("recovery_reconciliation_mismatch")
            factory.standby("b", "a")
            for label in self.hosts:
                factory.ca(label)
            for label in self.hosts:
                self.node_health(label)
            incarnation = self.sql("a", "SELECT system_identifier FROM pg_control_system();")
            self.witness("adopt", incarnation=incarnation)
            self.witness("checkpoint")
            for label in self.hosts:
                self.witness("enable", node=label)
                self.admission_network(label, enabled=True)
            self.witness("unfreeze")
            for label in self.hosts:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        self.leaf("endpoint_health", endpoint="ca-" + label)
                        break
                    except LifecycleError:
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(.3)
            return {"fenced_hosts": receipts, "backup_sequence": value["manifest"]["sequence"], "reconciled_sequence": before["sequence"],
                "security_sha256": restored["sha256"], "old_incarnation": before["incarnation"], "new_incarnation": incarnation,
                "mode": "restored_with_latest_security_checkpoint_and_synchronous_standby"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["failover", "status", "backup", "restore-check", "restore", "rejoin", "seal"])
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--old", choices=["a", "b"], default="a")
    parser.add_argument("--target", choices=["a", "b"], default="b")
    parser.add_argument("--backup-name")
    args = parser.parse_args()
    profile = json.loads(args.profile.read_bytes())
    if profile.get('management'):
        from scripts.control_plane_ha import Management
        backend = Management(profile)
    else:
        backend = Hosts(profile)
    if args.operation == "failover":
        result = backend.failover(args.old, args.target)
    elif args.operation == "status":
        result = backend.witness("status")
    elif args.operation == "backup":
        result = backend.backup(args.backup_name, args.target)
    elif args.operation == "restore-check":
        result = backend.restore_check(args.backup_name)
    elif args.operation == "rejoin":
        result = backend.rejoin(args.old, args.target, args.backup_name)
    elif args.operation == "seal":
        result = backend.seal_recovery(args.target)
    else:
        result = backend.restore(args.backup_name)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
