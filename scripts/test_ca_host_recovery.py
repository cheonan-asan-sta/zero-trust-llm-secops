"""Local two-Docker-host synchronous CA DB replication and sealed recovery pilot."""

import argparse
import base64
import hashlib
import json
import secrets
import subprocess
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from scripts import certificate_authority as bootstrap
from scripts import test_signal_compose as flow
from scripts.authority_rotation_coordinator import Coordinator
from scripts.ca_host_recovery import Hosts
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT, Lab, command
from scripts.compare_supply_chain import sha256
from scripts.mtls_fixtures import authority, leaf
from scripts.test_authority_key_rotation import AuthorityLab
from scripts.test_ca_high_availability import HALab
from scripts.test_certificate_automation import SERVERS
from scripts.test_private_key_rotation import KeyRotationLab

RECOVERY_SOURCES = ["scripts/ca_recovery_state.py", "scripts/ca_host_recovery.py", "scripts/ca_recovery_nodes.py", "scripts/test_ca_host_recovery.py",
    "scripts/authority_rotation_coordinator.py", "scripts/authority_rotation_runtime.py", "scripts/authority_custodian.py",
    "scripts/certificate_controller.py", "scripts/certificate_authority.py", "scripts/certificate_key_rotation.py",
    "scripts/test_authority_key_rotation.py", "scripts/test_ca_high_availability.py", "scripts/test_private_key_rotation.py",
    "scripts/test_certificate_automation.py", "scripts/ca_endpoints.py"]
IMPORTED = {p: sha256(ROOT / p) for p in RECOVERY_SOURCES}


class RecoveryLab(HALab):
    def drive_until(self, predicate, label, timeout=180):
        # Two independent nested daemons and per-connection security snapshots
        # add control-plane latency. This is a harness deadline, not an HA SLA.
        return super().drive_until(predicate, label, timeout=max(timeout, 360))

    def prepare(self):
        super().prepare()
        self.report["schema"] = "ca-host-recovery-1"
        lock = json.loads((ROOT / "infra/mtls/ca-recovery-tools.lock.json").read_bytes())
        self.report["recovery_tools"] = lock
        self.recovery_lock = lock
        build = self.directory / "recovery-build"
        build.mkdir(exist_ok=True)
        for wheel in lock["wheels"]:
            target = build / wheel["name"]
            with urllib.request.urlopen(wheel["url"], timeout=60) as source:
                target.write_bytes(source.read())
            flow.require(sha256(target) == wheel["sha256"], "recovery_wheel_digest")
        # This native-service profile needs the CA tools, not the unrelated PEP
        # proxy layers. Each independent daemon still imports its own full image.
        (build / "Dockerfile").write_text(f"FROM {self.image} AS tools\nFROM {self.ident}-app\nUSER 0\nCOPY --from=tools /tools /tools\nCOPY *.whl /tmp/\nRUN pip install --no-index /tmp/*.whl && rm /tmp/*.whl\nUSER 10001:10001\nHEALTHCHECK NONE\n")
        self.authority_image = self.image
        self.image = self.ident + "-recovery-tools"
        build_result = subprocess.run(["docker", "build", "--tag", self.image, str(build)], capture_output=True, timeout=300, check=False)
        (self.directory / "recovery-build.private.log").write_bytes(build_result.stdout + build_result.stderr)
        flow.require(build_result.returncode == 0, "recovery_tools_build")
        self.report["certificate_execution_image_id"] = command(["docker", "image", "inspect", self.image, "--format", "{{.Id}}"]).strip()
        command(["docker", "pull", "--platform", "linux/amd64", lock["docker_host"]["image"]], timeout=600)
        actual = json.loads(command(["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--entrypoint", "python", self.image,
            "-c", "import json,hashlib,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"], input=json.dumps(RECOVERY_SOURCES)))
        flow.require(actual == IMPORTED, "recovery_source_image_mismatch")
        self.report["recovery_image_source_sha256"] = actual
        self.report["source_input_sha256"].update(IMPORTED)
        self.report["source_input_sha256"]["infra/mtls/ca-recovery-tools.lock.json"] = sha256(ROOT / "infra/mtls/ca-recovery-tools.lock.json")
        self.report["recovery_scope"] = {"hosts": "two privileged DinD hosts with independent daemons and storage on one physical PC",
            "online_services": "uid 10001; no parent Docker socket or offline root/backup-key mounts",
            "database": "CA state only; remote_apply synchronous physical standby; explicit fenced promotion",
            "control_plane": "single trusted surviving witness, vault and leaf controller; no consensus or whole-site recovery"}
        self.save()

    def node_command(self, node, args, *, body=None, timeout=60):
        result = subprocess.run(["docker", "exec", "-i", node["name"], "docker", *args], input=body,
            capture_output=True, timeout=timeout, check=False)
        if result.returncode:
            (self.directory / "node-command-failure.private.log").write_bytes(result.stderr)
            raise flow.CheckFailed("recovery_node_command_failed")
        return result.stdout

    def copy_image(self, node, image):
        source = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            target = subprocess.run(["docker", "exec", "-i", node["name"], "docker", "load"], stdin=source.stdout,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240, check=False)
            source.stdout.close()
            flow.require(target.returncode == 0 and source.wait(timeout=15) == 0, "recovery_image_transfer")
        finally:
            source.stdout.close()
            if source.poll() is None:
                source.kill(); source.wait(timeout=10)

    def create_host(self, label, generation=0):
        self.report["recovery_stage"] = "starting_service_host_" + label
        self.save()
        name = self.prefix + "-host-" + label
        volume = self.volume(self.prefix + f"-host-{label}-docker-{generation}")
        self.containers.append(name)
        args = ["docker", "create", "--name", name, "--network", self.cluster_network, "--network-alias", "host-" + label,
            "--network-alias", "db-" + label, "--restart", "no", "--privileged", "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
            "--mount", f"type=volume,src={volume},dst=/var/lib/docker", "--entrypoint", "dockerd", self.recovery_lock["docker_host"]["image"],
            "--host=unix:///var/run/docker.sock", "--storage-driver=overlay2"]
        ident = command(args).strip()
        command(["docker", "start", name])
        self.wait(lambda: subprocess.run(["docker", "exec", name, "docker", "info"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False).returncode == 0, "inner_daemon_" + label, timeout=45)
        inspect = json.loads(command(["docker", "inspect", name]))[0]
        node = {"name": name, "id": ident, "image": inspect["Image"], "docker_volume": volume,
            "address": inspect["NetworkSettings"]["Networks"][self.cluster_network]["IPAddress"],
            "database": self.prefix + "-db-" + label, "ca_volume": self.prefix + "-ca-local-" + label}
        node["daemon_id"] = self.node_command(node, ["info", "--format", "{{.ID}}"], timeout=10).decode().strip()
        for image in [self.report["certificate_execution_image_id"], self.report["ha_postgres_image_id"]]:
            self.report["recovery_stage"] = "importing_host_" + label + "_" + ("ca" if image == self.report["certificate_execution_image_id"] else "postgres")
            self.save()
            self.copy_image(node, image)
        return node

    def node_assets(self, node, volume, files):
        self.node_command(node, ["volume", "create", volume])
        self.node_command(node, ["run", "--rm", "-i", "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
            "--mount", f"type=volume,src={volume},dst=/data", "--entrypoint", "python", self.report["certificate_execution_image_id"], "-c",
            "import json,sys;from pathlib import Path;from scripts.certificate_controller import atomic;files=json.load(sys.stdin);assert all(Path(p).name==p for p in files);Path('/data').chmod(0o700);[(atomic(Path('/data')/p,v)) for p,v in files.items()]"], body=json.dumps(files).encode())

    def inner_start(self, label, name, argv, mounts, *, pg=False, ports=()):
        node = self.nodes[label]
        args = ["create", "--name", name, "--restart", "unless-stopped", "--user", "10001:10001", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/tmp:rw,size=64m"]
        for peer, host in self.nodes.items():
            args += ["--add-host", "db-" + peer + ":" + host["address"]]
        for mount in mounts:
            args += ["--mount", mount]
        for mapping in ports:
            args += ["-p", mapping]
        image = self.report["ha_postgres_image_id"] if pg else self.report["certificate_execution_image_id"]
        ident = self.node_command(node, [*args, "--entrypoint", argv[0], image, *argv[1:]]).decode().strip()
        self.node_command(node, ["start", name])
        return ident

    def sql(self, statement, label=None):
        return self.node_command(self.nodes[label or self.primary], ["exec", "-i", self.nodes[label or self.primary]["database"],
            "psql", "-h", "/tmp", "-U", "postgres", "-d", "stepca", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"],
            body=statement.encode()).decode().strip()

    def start_database(self, label):
        self.report["recovery_stage"] = "starting_database_" + label
        self.save()
        node = self.nodes[label]
        self.inner_start(label, node["database"], ["postgres", "-D", "/pgdata", "-c", "config_file=/db-tls/postgresql.conf"],
            [f"type=volume,src={node['data_volume']},dst=/pgdata", f"type=volume,src={node['tls_volume']},dst=/db-tls,readonly"], pg=True, ports=["5432:5432"])
        self.wait(lambda: subprocess.run(["docker", "exec", node["name"], "docker", "exec", node["database"], "pg_isready", "-h", "/tmp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0,
            "database_" + label, timeout=40)

    def seed_standby(self, label, source):
        node = self.nodes[label]
        slot = "node_" + label
        if self.sql(f"SELECT count(*) FROM pg_replication_slots WHERE slot_name='{slot}';", source) == "1":
            self.sql(f"SELECT pg_drop_replication_slot('{slot}');", source)
        conn = f"host=db-{source} port=5432 user=replicator sslmode=verify-full sslrootcert=/db-tls/root.pem sslcert=/db-tls/replicator.pem sslkey=/db-tls/replicator.key application_name={slot} connect_timeout=2"
        args = ["run", "--rm", "--read-only", "--user", "10001:10001", "--cap-drop=ALL", "--tmpfs", "/tmp:rw,size=16m"]
        for peer, host in self.nodes.items():
            args += ["--add-host", "db-" + peer + ":" + host["address"]]
        args += ["--mount", f"type=volume,src={node['data_volume']},dst=/pgdata", "--mount", f"type=volume,src={node['tls_volume']},dst=/db-tls,readonly",
            "--entrypoint", "pg_basebackup", self.report["ha_postgres_image_id"], "--dbname", conn, "-D", "/pgdata", "-R", "-X", "stream", "-c", "fast", "-S", slot, "-C", "--no-password"]
        self.node_command(node, args, timeout=90)
        self.node_assets(node, node["data_volume"], {"replication.auto.conf": f"primary_conninfo='{conn}'\nprimary_slot_name='{slot}'\n"})
        self.start_database(label)
        self.wait(lambda: self.sql(f"SELECT count(*) FROM pg_stat_replication WHERE application_name='{slot}' AND state='streaming';", source) == "1",
            "replica_streaming", timeout=30)
        self.sql(f"ALTER SYSTEM SET synchronous_standby_names='FIRST 1 ({slot})';\nSELECT pg_reload_conf();", source)
        self.wait(lambda: self.sql(f"SELECT sync_state FROM pg_stat_replication WHERE application_name='{slot}';", source) == "sync", "replica_sync")

    def graph_authority(self):
        result = KeyRotationLab.graph_authority(self)
        command(["docker", "stop", "--time", "1", self.ca_server])
        command(["docker", "rm", "--volumes", self.ca_server])
        self.containers.remove(self.ca_server)
        self.cluster_network = self.prefix + "-hosts"
        command(["docker", "network", "create", "--internal", "--label", "secops.c02=" + self.ident, self.cluster_network])
        self.networks.append(self.cluster_network)
        self.nodes = {label: self.create_host(label) for label in ["a", "b"]}
        self.primary = "a"
        transport = authority("CA cluster transport")
        root = transport[1].public_bytes(serialization.Encoding.PEM).decode()
        replicator, reader = leaf(transport, "replicator"), leaf(transport, "recovery_reader")
        self.reader_volume = self.volume(self.prefix + "-reader-tls")
        self.write_assets(self.reader_volume, {"root.pem": root, "client.pem": reader["cert"], "client.key": reader["key"]})
        self.node_tls = {}
        for label, node in self.nodes.items():
            server, client = leaf(transport, "db-" + label, server=True), leaf(transport, "secops_ca")
            files = {"root.pem": root, "server.pem": server["cert"], "server.key": server["key"],
                "client.pem": client["cert"], "client.key": client["key"], "replicator.pem": replicator["cert"], "replicator.key": replicator["key"],
                "pg_hba.conf": "local all postgres trust\nhostssl replication replicator 0.0.0.0/0 cert\nhostssl stepca secops_ca 0.0.0.0/0 cert\nhostssl stepca recovery_reader 0.0.0.0/0 cert\nhost all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n",
                "postgresql.conf": "listen_addresses='*'\nunix_socket_directories='/tmp'\nssl=on\nssl_min_protocol_version='TLSv1.2'\nssl_cert_file='/db-tls/server.pem'\nssl_key_file='/db-tls/server.key'\nssl_ca_file='/db-tls/root.pem'\nhba_file='/db-tls/pg_hba.conf'\nwal_level=replica\nmax_wal_senders=5\nmax_replication_slots=5\nwal_keep_size='64MB'\nhot_standby=on\nsynchronous_commit='remote_apply'\nsynchronous_standby_names=''\nshared_buffers='32MB'\nmax_connections=50\ninclude_if_exists='/pgdata/replication.auto.conf'\n"}
            self.node_tls[label] = files
            node.update(tls_volume=self.prefix + "-db-tls-" + label, data_volume=self.prefix + "-db-data-" + label)
            self.node_assets(node, node["tls_volume"], files)
            self.node_assets(node, node["data_volume"], {})
        self.node_command(self.nodes["a"], ["run", "--rm", "--read-only", "--user", "10001:10001", "--mount", f"type=volume,src={self.nodes['a']['data_volume']},dst=/pgdata",
            "--entrypoint", "initdb", self.report["ha_postgres_image_id"], "-D", "/pgdata", "-U", "postgres", "--auth-local=trust", "--auth-host=reject", "--data-checksums"])
        self.start_database("a")
        self.node_command(self.nodes["a"], ["exec", "-i", self.nodes["a"]["database"], "psql", "-h", "/tmp", "-U", "postgres", "-v", "ON_ERROR_STOP=1"],
            body=b"CREATE ROLE secops_ca LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE replicator LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE recovery_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE DATABASE stepca OWNER secops_ca; ALTER ROLE secops_ca SET default_transaction_isolation='serializable'; ALTER ROLE secops_ca SET statement_timeout='3s'; ALTER ROLE recovery_reader SET default_transaction_read_only=on;")
        self.ca_files_current = self.helper_ca_files()
        config = json.loads(self.ca_files_current["ca.json"])
        config["dnsNames"] = ["ca", "ca-a", "ca-b"]
        config["db"] = {"type": "postgresql", "database": "stepca", "dataSource": "postgresql://secops_ca@db-a:5432,db-b:5432/stepca?target_session_attrs=read-write&sslmode=verify-full&sslrootcert=/db-tls/root.pem&sslcert=/db-tls/client.pem&sslkey=/db-tls/client.key&connect_timeout=2"}
        self.ca_files_current["ca.json"] = json.dumps(config)
        self.write_assets(self.ca_volume, self.ca_files_current)
        for label, node in self.nodes.items():
            self.node_assets(node, node["ca_volume"], self.ca_files_current)
        # Start primary-side CA to create its supported schema before streaming.
        self.start_ca("a")
        self.wait(lambda: self.sql("SELECT count(*) FROM information_schema.tables WHERE table_name='used_ott';") == "1", "ca_schema")
        self.sql("GRANT SELECT ON used_ott,revoked_x509_certs,x509_certs,x509_certs_data TO recovery_reader;")
        self.seed_standby("b", "a")
        self.start_ca("b")
        self.incarnation = self.sql("SELECT system_identifier FROM pg_control_system();")
        self.witness_volume = self.volume(self.prefix + "-security-witness")
        authority_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        self.write_assets(self.witness_volume, {"security.key": base64.b64encode(secrets.token_bytes(32)).decode(),
            "config.json": json.dumps({"dsn": "postgresql://recovery_reader@db-a:5432,db-b:5432/stepca?target_session_attrs=primary&sslmode=verify-full&sslrootcert=/reader/root.pem&sslcert=/reader/client.pem&sslkey=/reader/client.key&connect_timeout=2"}),
            "state.json": json.dumps({"sequence": 0, "pending": {}, "enabled": ["a", "b"], "frozen": True, "checkpoint": None,
                "checkpoint_sequence": -1, "checkpoint_lsn": "0/0", "checkpoint_hash": None, "error": None, "authority": authority_hash, "incarnation": self.incarnation})})
        # Convert key material inside its Linux volume, not through host files.
        command(["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001", "--mount", f"type=volume,src={self.witness_volume},dst=/witness",
            "--entrypoint", "python", self.image, "-c", "import base64;from pathlib import Path;from scripts.certificate_controller import atomic;p=Path('/witness/security.key');atomic(p,base64.b64decode(p.read_bytes()))"])
        self.gateway_names = []
        for label in self.nodes:
            name = self.prefix + "-admission-" + label
            Lab.start(self, name, self.ca_network, ["python", "-m", "scripts.ca_recovery_state", "gateway", "--node", label, "--backend", "host-" + label],
                alias="ca" if label == "a" else "ca-b", additional=[(self.cluster_network, "admission-" + label)], memory=256, cpus=1,
                mounts=[f"type=volume,src={self.witness_volume},dst=/witness", f"type=volume,src={self.reader_volume},dst=/reader,readonly"])
            if label == "a":
                command(["docker", "network", "disconnect", self.ca_network, name])
                command(["docker", "network", "connect", "--alias", "ca", "--alias", "ca-a", self.ca_network, name])
            self.gateway_names.append(name)
        self.ca_server = self.gateway_names[0]
        self.witness_rpc("checkpoint")
        self.witness_rpc("unfreeze")
        self.report["service_hosts"] = {label: {k: node[k] for k in ["name", "id", "image", "daemon_id", "docker_volume", "address"]} for label, node in self.nodes.items()}
        self.save()
        return result

    def helper_ca_files(self):
        return bootstrap.ca_files(self.offline_root, self.issuer, [p[0] for p in self.provisioners.values()] +
            [bootstrap.server_renewal_provisioner(name, self.server_signing_key(name).public_key()) for name in SERVERS])

    def start_ca(self, label):
        node = self.nodes[label]
        name = self.prefix + "-ca-" + label
        ident = self.inner_start(label, name, ["/tools/step-ca", "/ca/ca.json", "--password-file", "/ca/password.txt"],
            [f"type=volume,src={node['ca_volume']},dst=/ca,readonly", f"type=volume,src={node['tls_volume']},dst=/db-tls,readonly"], ports=["9000:9000"])
        node["ca"] = {"name": name, "id": ident}

    def witness_rpc(self, operation, **fields):
        return json.loads(command(["docker", "exec", "-i", self.gateway_names[0], "python", "-m", "scripts.ca_recovery_state", "rpc"],
            input=json.dumps({"operation": operation, **fields})))

    def init_authority(self):
        self.write_assets(self.controller_volume, {"ca-endpoints.json": json.dumps({"schema": "ca-endpoints-1", "hosts": ["ca-a", "ca-b"], "connect_timeout_seconds": 2})})
        providers = AuthorityLab.init_authority(self)
        profile = json.loads(self.authority_profile.read_bytes())
        profile["ca"] = dict(self.nodes["a"]["ca"])
        profile["ca_replicas"] = [node["ca"] | {"endpoint": "ca-" + label} for label, node in self.nodes.items()]
        profile["service_hosts"], profile["gateways"] = self.nodes, self.gateway_names
        profile["cluster_network"] = self.cluster_network
        profile["client_network"] = self.ca_network
        profile["gateway_ids"] = [json.loads(command(["docker", "inspect", name]))[0]["Id"] for name in self.gateway_names]
        profile["postgres_image"] = self.report["ha_postgres_image_id"]
        profile["witness_volume"] = self.witness_volume
        profile["backup_volume"] = self.volume(self.prefix + "-backups")
        profile["backup_key_volume"] = self.volume(self.prefix + "-backup-key")
        for key in ["backup_volume", "backup_key_volume"]:
            self.write_assets(profile[key], {})
        profile["control_directory"] = str(self.authority_profile.parent.resolve())
        self.authority_profile.write_text(json.dumps(profile), encoding="utf-8")
        self.backend = Hosts(profile)
        Coordinator(profile, self.authority_profile.parent, backend=self.backend).persist()
        self.early_backup = self.backend.backup("backup-before-key-rotation.sealed", "a")
        return providers

    def current_request(self):
        csr = self.private_rpc("import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());print(json.dumps(next(c['csr'] for c in s['credentials'].values() if c['name']=='collector' and c['purpose']=='clientAuth')))")
        program = """import json,sys
from pathlib import Path
from scripts.authority_custodian import unseal,load_key
from scripts.certificate_authority import bootstrap_token
v=Path('/vault');s=json.loads((v/'state.json').read_bytes());b=unseal((v/s['bundle']).read_bytes(),(v/'password').read_bytes())
p=next(p for p in b['providers'] if p['name']=='collector-clientAuth');csr=json.load(sys.stdin)
print(json.dumps({'csr':csr,'ott':bootstrap_token(p,load_key(b['keys'][p['name']]),csr,seconds=900),'notAfter':'20m'}))"""
        return json.loads(self.backend.command(["run", "--rm", "-i", "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
            "--mount", f"type=volume,src={self.vault},dst=/vault,readonly", "--entrypoint", "python", self.backend.profile["image"], "-c", program], csr))

    def rejected(self, callback, label, add):
        before = {k: n["id"] for k,n in self.backend.hosts.items()}
        try:
            callback()
        except LifecycleError as exc:
            flow.require(before == {k: n["id"] for k,n in self.backend.hosts.items()}, "recovery_rejection_mutated_hosts")
            add(label, reason=str(exc))
        else:
            raise flow.CheckFailed("recovery_expected_rejection_" + label)
        self.backend.wait_quiet(); self.backend.witness("checkpoint"); self.backend.witness("unfreeze")

    def smoke(self):
        AuthorityLab.smoke(self)
        self.report["recovery_checks"] = checks = []
        self.report["authority_history"] = self.coordinator_state()["history"]
        def add(label, **detail):
            checks.append({"label": label, "passed": True, **detail}); self.save()
        add("two_independent_docker_daemons_and_storage", hosts=self.report["service_hosts"])
        flow.require(len({n["daemon_id"] for n in self.nodes.values()}) == 2, "recovery_daemon_independence")
        flow.require(self.sql("SHOW synchronous_commit;") == "remote_apply" and self.sql("SELECT sync_state FROM pg_stat_replication;") == "sync", "recovery_sync_mode")
        add("synchronous_remote_apply_replication_before_host_fault")
        tls_rows = json.loads(self.sql("SELECT coalesce(json_agg(x),'[]') FROM (SELECT a.usename,s.ssl,s.version,s.client_dn FROM pg_stat_activity a JOIN pg_stat_ssl s USING(pid) WHERE a.usename IN ('secops_ca','replicator')) x;"))
        flow.require(len(tls_rows) >= 3 and all(row["ssl"] and row["client_dn"] for row in tls_rows), "recovery_database_transport_mtls")
        add("ca_and_physical_replication_connections_use_client_tls", connections=tls_rows)
        for node in self.nodes.values():
            record = json.loads(command(["docker", "inspect", node["name"]]))[0]
            flow.require(not record["HostConfig"]["PortBindings"] and not any(m["Destination"].endswith("docker.sock") for m in record["Mounts"]), "recovery_host_api_boundary")
        add("service_hosts_expose_no_pc_ports_or_parent_docker_socket")
        flow.require(self.report["smoke"]["history"][0]["evidence"]["old_jwks"]["total_denied"] == 132, "recovery_rotation_both_nodes")
        add("root_issuer_jwk_rotation_on_separate_hosts", identities=3, old_jwk_denials=132)
        self.backend.command(["stop", "--time", "2", self.nodes["b"]["id"]])
        try:
            flow.require(self.ca_call(self.current_request(), endpoint="ca-a")["status"] != 201, "recovery_sync_write_without_replica")
            add("missing_synchronous_replica_blocks_successful_new_issuance")
        finally:
            self.backend.command(["start", self.nodes["b"]["id"]])
        self.wait(lambda: self.sql("SELECT sync_state FROM pg_stat_replication;") == "sync", "recovery_standby_restart", timeout=40)
        self.wait(lambda: self.ca_call(self.current_request(), endpoint="ca-a")["status"] == 201, "recovery_sync_restored", timeout=30)
        add("fresh_issuance_recovers_after_synchronous_replica_returns")
        self.rejected(lambda: self.backend.restore_check("backup-before-key-rotation.sealed", "a"), "obsolete_authority_backup_rejected_before_fencing", add)
        backup = self.backend.backup("backup-current.sealed", "a")
        add("authenticated_encrypted_logical_and_key_backup", **backup)
        self.replay_request = self.current_request()
        import jwt
        self.token_expiry = jwt.decode(self.replay_request["ott"], options={"verify_signature": False})["exp"]
        issued = self.ca_call(self.replay_request, endpoint="ca-a")
        flow.require(issued["status"] == 201, "recovery_post_backup_issuance")
        add("fresh_one_time_token_consumed_after_backup", serial=issued["serial"])
        flow.require(self.ca_call({"serial": issued["serial"], "passive": True}, endpoint="ca-a", mode="revoke")["status"] == 200,
            "recovery_post_backup_revocation")
        add("certificate_revoked_after_backup")
        self.revoked_expiry = self.private_rpc("import json;from pathlib import Path;from scripts.certificate_controller import metadata;print(json.dumps(metadata(Path('/state/ha-revoked.pem').read_text())['not_after']))")
        self.backend.wait_quiet(); self.backend.witness("checkpoint"); self.backend.witness("unfreeze")
        self.rejected(lambda: self.backend.restore_check("backup-current.sealed"), "unsealed_post_backup_writes_refuse_cold_restore", add)
        # A replaced object must never qualify as proof that the old writer stopped.
        saved_id = self.backend.hosts["a"]["id"]
        self.backend.hosts["a"]["id"] = "0" * 64
        try:
            self.rejected(lambda: self.backend.failover("a", "b"), "unknown_fencing_identity_refuses_promotion", add)
            flow.require(self.sql("SELECT pg_is_in_recovery();", "b") == "t", "recovery_no_unsafe_promotion")
        finally:
            self.backend.hosts["a"]["id"] = saved_id
        event = self.backend.failover("a", "b")
        self.primary = "b"
        add("old_host_fenced_before_standby_promotion", **event)
        self.wait(lambda: self.rpc({"operation": "renew_attempt", "id": next(uid for uid,c in self.status()["credentials"].items() if c["name"]=='collector')})["allowed"], "recovery_survivor_mtls_renew", timeout=30)
        add("mtls_renewal_continues_after_entire_primary_host_loss")
        flow.require(self.ca_call(self.replay_request, endpoint="ca-b")["status"] in {400,401,403}, "recovery_failover_replay")
        add("consumed_token_stays_denied_after_host_failover")
        flow.require(self.ca_call({}, endpoint="ca-b", mode="renew_revoked")["status"] in {401,403}, "recovery_failover_revocation")
        add("revocation_stays_denied_after_host_failover")
        old_daemon = self.backend.hosts["a"]["daemon_id"]
        joined = self.backend.rejoin("a", "b", "backup-current.sealed")
        flow.require(joined["daemon_id"] != old_daemon, "recovery_rejoin_fresh_daemon")
        self.nodes = self.backend.hosts
        add("fenced_host_reseeded_into_new_storage_as_synchronous_standby", **joined)
        flow.require(self.sql("SELECT pg_is_in_recovery();", "a") == "t" and self.sql("SELECT sync_state FROM pg_stat_replication;", "b") == "sync", "recovery_rejoin_sync")
        add("rejoined_host_is_read_only_and_remote_apply_synchronous")
        flow.require(self.ca_call(self.current_request(), endpoint="ca-a")["status"] == 201, "recovery_rejoined_ca_issuance")
        add("rejoined_ca_issues_through_surviving_shared_primary")
        self.backend.wait_quiet(); self.backend.witness("checkpoint"); self.backend.witness("unfreeze")
        # Change ciphertext in a copy; retain the good archive for a real restore.
        self.backend.command(["run", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
            "--mount", f"type=volume,src={self.backend.profile['backup_volume']},dst=/backups", "--entrypoint", "python", self.backend.profile["image"], "-c",
            "import json;from pathlib import Path;from scripts.certificate_controller import save;p=Path('/backups');v=json.loads((p/'backup-current.sealed').read_bytes());s=v['ciphertext'];v['ciphertext']=('A' if s[0]!='A' else 'B')+s[1:];save(p/'backup-corrupt.sealed',v)"])
        self.rejected(lambda: self.backend.restore_check("backup-corrupt.sealed", "b"), "corrupt_ciphertext_rejected_before_fencing", add)
        verified = self.backend.restore_check("backup-current.sealed", "b")
        add("older_dump_verified_against_newer_independent_security_checkpoint", **verified)
        # Simulate complete loss after the verified maintenance checkpoint, with
        # admission still closed. Loss after an unsealed write is rejected.
        for node in self.backend.hosts.values():
            self.backend.command(["stop", "--time", "2", node["id"]])
        started = time.monotonic()
        restored = self.backend.restore("backup-current.sealed")
        self.primary = "a"; self.nodes = self.backend.hosts
        flow.require(restored["new_incarnation"] != restored["old_incarnation"], "recovery_new_database_identity")
        add("both_hosts_fenced_and_restored_to_fresh_databases", elapsed_seconds=round(time.monotonic()-started,3), **restored)
        flow.require(restored["reconciled_sequence"] > restored["backup_sequence"], "recovery_latest_security_applied")
        add("post_backup_security_rows_reconciled_before_admission")
        flow.require(time.time() < min(self.token_expiry, self.revoked_expiry), "recovery_security_fixture_expired")
        add("replay_and_revocation_fixtures_are_still_unexpired", remaining_token_seconds=round(self.token_expiry-time.time(),3),
            remaining_certificate_seconds=round(self.revoked_expiry-time.time(),3))
        for label in self.nodes:
            flow.require(self.ca_call(self.replay_request, endpoint="ca-"+label)["status"] in {400,401,403}, "recovery_restore_replay")
            add("restored_"+label+"_denies_unexpired_consumed_token")
            flow.require(self.ca_call({}, endpoint="ca-"+label, mode="renew_revoked")["status"] in {401,403}, "recovery_restore_revoked")
            add("restored_"+label+"_denies_revoked_certificate_renewal")
            flow.require(self.ca_call(self.current_request(), endpoint="ca-"+label)["status"] == 201, "recovery_restore_fresh_issuance")
            add("restored_"+label+"_accepts_new_valid_nonce")
        flow.require(self.sql("SHOW synchronous_commit;") == "remote_apply" and self.sql("SELECT sync_state FROM pg_stat_replication;") == "sync", "recovery_restored_sync")
        add("restored_cluster_has_synchronous_standby")
        self.rejected(lambda: self.backend.restore_check("backup-current.sealed", "a"), "previous_database_incarnation_backup_rejected", add)
        self.report["recovery_public_witness"] = self.witness_rpc("status")

    def cleanup(self):
        for label,node in getattr(self, "nodes", {}).items():
            for service in [node.get("database"), node.get("ca", {}).get("name")]:
                if service:
                    result = subprocess.run(["docker", "exec", node["name"], "docker", "logs", "--tail", "60", service], capture_output=True, check=False)
                    (self.directory / ("inner-"+label+"-"+("db" if service==node.get("database") else "ca")+".private.log")).write_bytes(result.stdout+result.stderr)
        if hasattr(self, "backend"):
            self.volumes.extend(v for v in self.backend.profile.get("additional_volumes", []) if v not in self.volumes)
        super().cleanup()
        if hasattr(self, "authority_image"):
            subprocess.run(["docker", "image", "rm", self.authority_image], capture_output=True, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/c04/recovery")
    args = parser.parse_args()
    lab = RecoveryLab(args.directory)
    lab.key_smoke = True
    try:
        lab.prepare(); lab.smoke()
        flow.require(all(sha256(ROOT / name) == value for name,value in lab.report["source_input_sha256"].items()), "recovery_sources_changed_during_run")
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError, flow.CheckFailed) as exc:
        lab.report["failure"] = str(exc) if isinstance(exc, (flow.CheckFailed, ValueError)) else type(exc).__name__
        if hasattr(lab, "authority_profile") and (lab.authority_profile.parent / "authority-coordinator.json").exists():
            lab.report["failure_coordinator_state"] = lab.coordinator_state()
        raise SystemExit(type(exc).__name__) from None
    finally:
        lab.report["finished_at"] = flow.timestamp(); lab.cleanup()


if __name__ == "__main__":
    main()
