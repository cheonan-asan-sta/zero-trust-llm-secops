"""Explicit replacement of already fenced, pinned local service-host nodes."""

import subprocess
import time

from scripts.certificate_controller import LifecycleError


class Rebuilder:
    def __init__(self, backend):
        self.b = backend
        self.p = backend.profile

    def wait(self, predicate, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.3)
        raise LifecycleError("recovery_rebuild_timeout")

    def image(self, label, image):
        source = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            response = subprocess.run(["docker", "exec", "-i", self.b.hosts[label]["name"], "docker", "load"], stdin=source.stdout,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240, check=False)
            source.stdout.close()
            if response.returncode or source.wait(timeout=15):
                raise LifecycleError("recovery_rebuild_image_transfer")
        finally:
            source.stdout.close()
            if source.poll() is None:
                source.kill(); source.wait(timeout=10)

    def host(self, label):
        old = self.b.host(label, running=False)
        if old["State"]["Running"] or label in self.b.witness("status")["enabled"]:
            raise LifecycleError("recovery_rebuild_requires_fenced_host")
        node = self.b.hosts[label]
        self.b.command(["rm", "--volumes", old["Id"]])
        generation = node.get("rebuild_generation", 0) + 1
        volume = self.p["project"] + f"-host-{label}-rebuild-{generation}"
        self.b.command(["volume", "create", "--label", "secops.c02=" + self.p["project"], volume])
        self.p.setdefault("additional_volumes", []).append(volume)
        ident = self.b.command(["create", "--name", node["name"], "--network", self.p["cluster_network"], "--ip", node["address"],
            "--network-alias", "host-" + label, "--network-alias", "db-" + label, "--restart", "no", "--privileged", "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
            "--mount", f"type=volume,src={volume},dst=/var/lib/docker", "--entrypoint", "dockerd", node["image"],
            "--host=unix:///var/run/docker.sock", "--storage-driver=overlay2"]).strip()
        node.update(id=ident, docker_volume=volume, rebuild_generation=generation)
        self.b.persist_profile()
        self.b.command(["start", ident])
        self.wait(lambda: subprocess.run(["docker", "exec", ident, "docker", "info"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False).returncode == 0)
        node["daemon_id"] = self.b.inner(label, ["info", "--format", "{{.ID}}"] ).strip()
        for image in [self.p["image"], self.p["postgres_image"]]:
            self.image(label, image)
        self.b.persist_profile()

    def assets(self, label, volume, files):
        self.b.inner(label, ["volume", "create", volume])
        self.b.inner(label, ["run", "--rm", "-i", "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
            "--mount", f"type=volume,src={volume},dst=/data", "--entrypoint", "python", self.p["image"], "-c",
            "import json;import sys;from pathlib import Path;from scripts.certificate_controller import atomic;v=json.load(sys.stdin);assert all(Path(n).name==n for n in v);Path('/data').chmod(0o700);[(atomic(Path('/data')/n,b)) for n,b in v.items()]"], files)

    def start(self, label, name, argv, mounts, *, pg=False, port):
        args = ["create", "--name", name, "--restart", "unless-stopped", "--user", "10001:10001", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/tmp:rw,size=64m", "-p", port]
        for peer, node in self.b.hosts.items():
            args += ["--add-host", "db-" + peer + ":" + node["address"]]
        for mount in mounts:
            args += ["--mount", mount]
        ident = self.b.inner(label, [*args, "--entrypoint", argv[0], self.p["postgres_image"] if pg else self.p["image"], *argv[1:]]).strip()
        self.b.inner(label, ["start", ident])
        return ident

    def database(self, label):
        node = self.b.hosts[label]
        self.start(label, node["database"], ["postgres", "-D", "/pgdata", "-c", "config_file=/db-tls/postgresql.conf"],
            [f"type=volume,src={node['data_volume']},dst=/pgdata", f"type=volume,src={node['tls_volume']},dst=/db-tls,readonly"], pg=True, port="5432:5432")
        self.wait(lambda: subprocess.run(["docker", "exec", node["name"], "docker", "exec", node["database"], "pg_isready", "-h", "/tmp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0)

    def primary(self, label):
        node = self.b.hosts[label]
        self.assets(label, node["data_volume"], {})
        self.b.inner(label, ["run", "--rm", "--read-only", "--user", "10001:10001", "--mount", f"type=volume,src={node['data_volume']},dst=/pgdata",
            "--entrypoint", "initdb", self.p["postgres_image"], "-D", "/pgdata", "-U", "postgres", "--auth-local=trust", "--auth-host=reject", "--data-checksums"])
        self.database(label)
        self.b.inner_raw(label, ["exec", "-i", node["database"], "psql", "-h", "/tmp", "-U", "postgres", "-v", "ON_ERROR_STOP=1"],
            b"CREATE ROLE secops_ca LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE replicator LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE recovery_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE DATABASE stepca OWNER secops_ca; ALTER ROLE secops_ca SET default_transaction_isolation='serializable'; ALTER ROLE secops_ca SET statement_timeout='3s'; ALTER ROLE recovery_reader SET default_transaction_read_only=on;")

    def standby(self, label, source):
        node = self.b.hosts[label]
        self.assets(label, node["data_volume"], {})
        slot = "node_" + label
        if self.b.sql(source, f"SELECT count(*) FROM pg_replication_slots WHERE slot_name='{slot}';") == "1":
            self.b.sql(source, f"SELECT pg_drop_replication_slot('{slot}');")
        conn = f"host=db-{source} port=5432 user=replicator sslmode=verify-full sslrootcert=/db-tls/root.pem sslcert=/db-tls/replicator.pem sslkey=/db-tls/replicator.key application_name={slot} connect_timeout=2"
        args = ["run", "--rm", "--read-only", "--user", "10001:10001", "--tmpfs", "/tmp:rw,size=16m"]
        for peer, host in self.b.hosts.items():
            args += ["--add-host", "db-" + peer + ":" + host["address"]]
        args += ["--mount", f"type=volume,src={node['data_volume']},dst=/pgdata", "--mount", f"type=volume,src={node['tls_volume']},dst=/db-tls,readonly",
            "--entrypoint", "pg_basebackup", self.p["postgres_image"], "--dbname", conn, "-D", "/pgdata", "-R", "-X", "stream", "-c", "fast", "-S", slot, "-C", "--no-password"]
        self.b.inner_raw(label, args, timeout=90)
        self.assets(label, node["data_volume"], {"replication.auto.conf": f"primary_conninfo='{conn}'\nprimary_slot_name='{slot}'\n"})
        self.database(label)
        self.wait(lambda: self.b.sql(source, f"SELECT count(*) FROM pg_stat_replication WHERE application_name='{slot}' AND state='streaming';") == "1")
        self.b.sql(source, f"ALTER SYSTEM SET synchronous_standby_names='FIRST 1 ({slot})';\nSELECT pg_reload_conf();")
        self.wait(lambda: self.b.sql(source, f"SELECT sync_state FROM pg_stat_replication WHERE application_name='{slot}';") == "sync")

    def ca(self, label):
        node = self.b.hosts[label]
        ident = self.start(label, node["ca"]["name"], ["/tools/step-ca", "/ca/ca.json", "--password-file", "/ca/password.txt"],
            [f"type=volume,src={node['ca_volume']},dst=/ca,readonly", f"type=volume,src={node['tls_volume']},dst=/db-tls,readonly"], port="9000:9000")
        node["ca"]["id"] = ident
        self.p["ca"] = dict(self.b.hosts["a"]["ca"])
        self.p["ca_replicas"] = [n["ca"] | {"endpoint": "ca-" + label} for label, n in self.b.hosts.items()]
        self.b.persist_profile()
