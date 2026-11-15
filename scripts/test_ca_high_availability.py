"""Opt-in two-node CA tier, shared mTLS PostgreSQL and real failure/rotation tests.

No published ports, cloud, paid API, host private files or OS trust changes.
Database/host redundancy is deliberately outside this local CA-process profile.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from scripts import certificate_authority as bootstrap
from scripts import test_signal_compose as flow
from scripts.authority_rotation_coordinator import DockerBackend
from scripts.compare_pep import ROOT, Lab, command
from scripts.compare_supply_chain import sha256
from scripts.mtls_fixtures import authority, leaf
from scripts.test_authority_key_rotation import AUTHORITY_SOURCES, AuthorityLab
from scripts.test_certificate_automation import SERVERS
from scripts.test_private_key_rotation import KeyRotationLab

HA_SOURCES = [*AUTHORITY_SOURCES, "scripts/ca_endpoints.py", "scripts/test_ca_high_availability.py",
    "scripts/certificate_authority.py", "infra/mtls/ca-ha-tools.lock.json", "infra/mtls/ca-ha-contract.json"]
IMPORTED_HA_SHA256 = {name: sha256(ROOT / name) for name in HA_SOURCES if (ROOT / name).is_file()}


class HALab(AuthorityLab):
    canary_lifetime_seconds = 90
    canary_renew_before_seconds = 60

    def prepare(self):
        super().prepare()
        self.report["schema"] = "ca-high-availability-1"
        self.report["ha_canary_profile"] = {"static_and_automatic_lifetime_seconds": self.canary_lifetime_seconds,
            "renew_before_seconds": self.canary_renew_before_seconds,
            "boundary": "HA-only accelerated comparison; existing single-CA 30-second profile and ordinary 20-minute certificate policy remain unchanged"}
        self.ha_lock = json.loads((ROOT / "infra/mtls/ca-ha-tools.lock.json").read_bytes())
        self.report["ha_tools"] = self.ha_lock
        self.report["ha_contract"] = json.loads((ROOT / "infra/mtls/ca-ha-contract.json").read_bytes())
        image = self.ha_lock["postgres"]["image"]
        command(["docker", "pull", "--platform", "linux/amd64", image], timeout=600)
        build = self.directory / "postgres-build"
        build.mkdir(exist_ok=True)
        (build / "Dockerfile").write_text(f"FROM {image}\nUSER 0\nRUN groupadd -g 10001 secops && useradd -u 10001 -g 10001 secops && mkdir /pgdata && chown 10001:10001 /pgdata\nUSER 10001:10001\n")
        self.pg_image = self.ident + "-postgres"
        command(["docker", "build", "--tag", self.pg_image, str(build)], timeout=300)
        self.report["ha_postgres_image_id"] = command(["docker", "image", "inspect", self.pg_image, "--format", "{{.Id}}"]).strip()
        self.report["ha_postgres_version"] = command(["docker", "run", "--rm", "--network", "none", "--read-only",
            "--entrypoint", "postgres", self.pg_image, "--version"]).strip()
        actual = json.loads(command(["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--entrypoint", "python", self.image,
            "-c", "import json,hashlib,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"],
            input=json.dumps([name for name in HA_SOURCES if name.endswith(".py")])))
        flow.require(actual == {name: IMPORTED_HA_SHA256[name] for name in actual}, "ca_ha_image_source_changed")
        self.report["ha_image_source_sha256"] = actual
        self.report["source_input_sha256"].update(IMPORTED_HA_SHA256)
        self.save()

    def sql(self, statement):
        return command(["docker", "exec", "-i", self.pg_server, "psql", "-h", "/tmp", "-U", "postgres", "-d", "stepca",
            "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], input=statement, timeout=15).strip()

    def graph_authority(self):
        # Bootstrap the existing private keys/provisioners, then replace only the
        # empty initial CA DB before any grants are issued. No Badger migration.
        result = super().graph_authority()
        command(["docker", "stop", "--time", "2", self.ca_server])
        command(["docker", "rm", "--volumes", self.ca_server])
        self.containers.remove(self.ca_server)
        self.db_network = self.prefix + "-ca-db"
        command(["docker", "network", "create", "--internal", "--label", "secops.c02=" + self.ident, self.db_network])
        self.networks.append(self.db_network)
        transport_ca = authority("CA database transport only")
        root = transport_ca[1].public_bytes(serialization.Encoding.PEM).decode()
        server = leaf(transport_ca, "ca-db", server=True)
        self.db_client_volumes = {}
        for label in ["ca-a", "ca-b"]:
            volume = self.volume(self.prefix + "-db-client-" + label)
            material = leaf(transport_ca, "secops_ca")
            self.write_assets(volume, {"root.pem": root, "client.pem": material["cert"], "client.key": material["key"]})
            self.db_client_volumes[label] = volume
        server_volume = self.volume(self.prefix + "-db-server-tls")
        self.write_assets(server_volume, {"root.pem": root, "server.pem": server["cert"], "server.key": server["key"],
            "pg_hba.conf": "local all postgres trust\nhostssl stepca secops_ca 0.0.0.0/0 cert\nhost all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n",
            "postgresql.conf": "listen_addresses='*'\nport=5432\nunix_socket_directories='/tmp'\nssl=on\nssl_min_protocol_version='TLSv1.2'\nssl_cert_file='/pg-tls/server.pem'\nssl_key_file='/pg-tls/server.key'\nssl_ca_file='/pg-tls/root.pem'\nhba_file='/pg-tls/pg_hba.conf'\nmax_connections=50\nshared_buffers='32MB'\n"})
        self.pg_data = self.volume(self.prefix + "-postgres-data")
        self.write_assets(self.pg_data, {})  # Docker copy-up gives the volume UID 10001.
        self.pg_server = self.prefix + "-postgres"
        Lab.start(self, self.pg_server, self.db_network,
            ["sh", "-c", "test -f /pgdata/PG_VERSION || initdb -D /pgdata -U postgres --auth-local=trust --auth-host=reject; exec postgres -D /pgdata -c config_file=/pg-tls/postgresql.conf"],
            image=self.pg_image, alias="ca-db", memory=256, cpus=1,
            mounts=[f"type=volume,src={self.pg_data},dst=/pgdata", f"type=volume,src={server_volume},dst=/pg-tls,readonly"])
        self.wait(lambda: subprocess.run(["docker", "exec", self.pg_server, "pg_isready", "-h", "/tmp", "-U", "postgres"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0, "ca_ha_database_ready", timeout=45)
        command(["docker", "exec", "-i", self.pg_server, "psql", "-h", "/tmp", "-U", "postgres", "-v", "ON_ERROR_STOP=1"],
            input="CREATE ROLE secops_ca LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;\nCREATE DATABASE stepca OWNER secops_ca;\nALTER ROLE secops_ca SET default_transaction_isolation='serializable';\nALTER ROLE secops_ca SET statement_timeout='3s';\nALTER ROLE secops_ca SET lock_timeout='2s';\n")
        files = bootstrap.ca_files(self.offline_root, self.issuer, [p[0] for p in self.provisioners.values()] +
            [bootstrap.server_renewal_provisioner(name, self.server_signing_key(name).public_key()) for name in SERVERS])
        config = json.loads(files["ca.json"])
        config["dnsNames"] = ["ca", "ca-a", "ca-b"]
        config["db"] = {"type": "postgresql", "database": "stepca", "dataSource":
            "postgresql://secops_ca@ca-db:5432/stepca?sslmode=verify-full&sslrootcert=/db-tls/root.pem&sslcert=/db-tls/client.pem&sslkey=/db-tls/client.key&connect_timeout=2"}
        files["ca.json"] = json.dumps(config)
        self.write_assets(self.ca_volume, files)
        self.ca_replicas = []
        for label in ["ca-a", "ca-b"]:
            name = self.prefix + "-" + label
            ident = Lab.start(self, name, self.ca_network, ["/tools/step-ca", "/ca/ca.json", "--password-file", "/ca/password.txt"],
                alias="ca" if label == "ca-a" else label, memory=256, cpus=1,
                additional=[(self.db_network, label)],
                mounts=[f"type=volume,src={self.ca_volume},dst=/ca,readonly",
                        f"type=volume,src={self.db_client_volumes[label]},dst=/db-tls,readonly"])
            if label == "ca-a":
                # Retain the original single-endpoint alias for historical tests.
                command(["docker", "network", "disconnect", self.ca_network, name])
                command(["docker", "network", "connect", "--alias", "ca", "--alias", "ca-a", self.ca_network, name])
            self.ca_replicas.append({"name": name, "id": ident, "endpoint": label})
        self.ca_server = self.ca_replicas[0]["name"]
        return result

    def ca_call(self, payload, *, endpoint=None, mode="post"):
        return self.private_rpc("""import json,sys,ssl,http.client
from pathlib import Path
from scripts.certificate_controller import ca_post,issued_chain,metadata,atomic
p=json.load(sys.stdin); d=Path('/state'); s=json.loads((d/'state.json').read_bytes())
c=next(c for c in s['credentials'].values() if c['name']=='collector' and c['purpose']=='clientAuth')
try:
 identity=({'certificates':['/state/ha-issued.pem'],'key':c['key']} if p['mode']=='revoke' else
  {'certificates':['/state/ha-revoked.pem'],'key':'/state/ha-revoked.key'} if p['mode']=='renew_revoked' else None)
 target='/1.0/revoke' if p['mode']=='revoke' else '/1.0/renew' if p['mode']=='renew_revoked' else '/1.0/sign'
 code,result=ca_post(d,target,p['payload'],identity=identity,endpoint=p['endpoint'])
 out={'status':code}
 if code==201:
  from cryptography import x509
  chain=issued_chain(result); info=metadata(chain)
  x509.load_pem_x509_certificate(chain.encode()).verify_directly_issued_by(x509.load_pem_x509_certificate((d/'issuer.pem').read_bytes()))
  assert info['name']=='collector' and info['purpose']=='clientAuth'
  atomic(d/'ha-issued.pem',chain);out.update(serial=info['serial'])
 if code==200 and p['mode']=='revoke':
  atomic(d/'ha-revoked.pem',(d/'ha-issued.pem').read_bytes());atomic(d/'ha-revoked.key',Path(c['key']).read_bytes())
 print(json.dumps(out))
except (OSError,ValueError,http.client.HTTPException): print(json.dumps({'status':0,'failed_closed':True}))
""", {"payload": payload, "endpoint": endpoint, "mode": mode})

    def fresh_request(self, csr):
        provider, key = self.provisioners["collector-clientAuth"]
        return {"csr": csr, "ott": bootstrap.bootstrap_token(provider, key, csr), "notAfter": "20m"}

    def enable_ha(self):
        self.write_assets(self.controller_volume, {"ca-endpoints.json": json.dumps({"schema": "ca-endpoints-1",
            "hosts": ["ca-a", "ca-b"], "connect_timeout_seconds": 1})})

    def init_authority(self):
        self.enable_ha()
        self.ha_checks(self.ha_record)
        providers = super().init_authority()
        profile = json.loads(self.authority_profile.read_bytes())
        profile["ca_replicas"] = self.ca_replicas
        self.authority_profile.write_text(json.dumps(profile), encoding="utf-8")
        self.backend = DockerBackend(profile)
        return providers

    def certificate_checks(self, record, keys):
        # Preserve old single-CA outage comparisons before enabling HA selection.
        KeyRotationLab.certificate_checks(self, record, keys)
        self.ha_record, self.ha_keys = record, keys
        self.authority_checks(record, keys)
        self.rotation_ha_checks(record)

    def ha_checks(self, record):
        command(["docker", "start", self.controller])
        self.controller_config = self.private_rpc("from pathlib import Path;print(Path('/state/config.json').read_text())")
        self.paused(True)
        record["ha_checks"] = checks = []
        def add(label, **details):
            checks.append({"label": label, "passed": True, **details})
            self.save()
        identity = self.private_rpc("import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());print(json.dumps(next({k:c[k] for k in ['id','csr','generation']} for c in s['credentials'].values() if c['name']=='collector' and c['purpose']=='clientAuth')))")
        csr = identity["csr"]
        nodes = self.ca_replicas
        self.wait(lambda: all(self.ca_call(self.fresh_request(csr), endpoint=r["endpoint"])["status"] == 201 for r in nodes),
            "ca_ha_both_issuers", timeout=35)
        add("both_registered_ca_nodes_issue_valid_scoped_certificates")
        tls_rows = json.loads(self.sql("SELECT coalesce(json_agg(x),'[]') FROM (SELECT s.ssl,s.version,s.client_dn,s.client_serial::text FROM pg_stat_activity a JOIN pg_stat_ssl s USING(pid) WHERE a.usename='secops_ca') x;"))
        flow.require(len(tls_rows) >= 2 and all(row["ssl"] and row["client_dn"] for row in tls_rows)
            and len({row["client_serial"] for row in tls_rows}) == 2, "ca_ha_db_mtls")
        add("both_ca_database_connections_use_verified_client_tls", connections=tls_rows)
        role = json.loads(self.sql("SELECT row_to_json(x) FROM (SELECT rolsuper,rolcreatedb,rolcreaterole,rolconfig FROM pg_roles WHERE rolname='secops_ca') x;"))
        flow.require(not any(role[k] for k in ["rolsuper", "rolcreatedb", "rolcreaterole"])
            and "default_transaction_isolation=serializable" in role["rolconfig"], "ca_ha_db_role")
        add("database_role_is_unprivileged_and_transactions_serializable", role=role)
        for condition, query in [("plain", "sslmode=disable"), ("no_client_certificate", "sslmode=verify-full&sslrootcert=/db-tls/root.pem&host=ca-db&hostaddr=127.0.0.1"),
                ("wrong_server_name", "sslmode=verify-full&sslrootcert=/db-tls/root.pem&sslcert=/db-tls/client.pem&sslkey=/db-tls/client.key&host=wrong-db-name&hostaddr=127.0.0.1")]:
            # Run from the DB namespace with only a CA's transport credentials.
            args = ["docker", "run", "--rm", "--network", "container:" + self.pg_server, "--read-only", "--user", "10001:10001",
                "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--mount", f"type=volume,src={self.db_client_volumes['ca-a']},dst=/db-tls,readonly",
                "--entrypoint", "psql", self.pg_image, f"postgresql://secops_ca@127.0.0.1:5432/stepca?connect_timeout=2&{query}", "-X", "-q", "-c", "SELECT 1"]
            response = subprocess.run(args, capture_output=True, text=True, timeout=12, check=False)
            flow.require(response.returncode != 0, "ca_ha_db_reject_" + condition)
            add("database_rejects_" + condition)
        # True simultaneous submissions through different processes, not a
        # sequential replay. SERIALIZABLE aborts a racing absent-row UPSERT.
        races = []
        for _ in range(12):
            request = self.fresh_request(csr)
            result = self.private_rpc("""import json,sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from scripts.certificate_controller import ca_post
p=json.load(sys.stdin)
with ThreadPoolExecutor(max_workers=2) as pool:
 codes=list(pool.map(lambda h:ca_post(Path('/state'),'/1.0/sign',p,endpoint=h)[0],['ca-a','ca-b']))
print(json.dumps(codes))""", request)
            flow.require(result.count(201) == 1 and all(code in {201, 400, 401, 403, 500} for code in result), "ca_ha_token_race")
            races.append(result)
        add("shared_one_time_token_has_exactly_one_winner_across_nodes", races=races)
        replay = self.fresh_request(csr)
        issued = self.ca_call(replay, endpoint="ca-a")
        flow.require(issued["status"] == 201 and self.ca_call(replay, endpoint="ca-b")["status"] in {400, 401, 403}, "ca_ha_replay")
        add("token_consumed_on_ca_a_is_denied_by_ca_b")
        flow.require(self.ca_call({"serial": issued["serial"], "passive": True}, endpoint="ca-a", mode="revoke")["status"] == 200,
            "ca_ha_revoke_canary")
        flow.require(self.ca_call({}, endpoint="ca-b", mode="renew_revoked")["status"] in {401, 403}, "ca_ha_shared_revoke")
        add("certificate_revoked_on_ca_a_cannot_renew_on_ca_b")
        for fault in ["stop", "pause", "disconnect"]:
            command(["docker", "network", "disconnect", self.ca_network, nodes[0]["name"]] if fault == "disconnect"
                else ["docker", fault, *(["--time", "1"] if fault == "stop" else []), nodes[0]["name"]])
            try:
                before = time.monotonic()
                response = self.ca_call(self.fresh_request(csr))
                duration = time.monotonic() - before
                flow.require(response["status"] == 201, "ca_ha_failover_" + fault)
                add("fresh_issuance_survives_primary_" + fault, end_to_end_seconds=round(duration, 3))
                flow.require(self.rpc({"operation": "renew_attempt", "id": identity["id"]})["allowed"], "ca_ha_mtls_renew_" + fault)
                add("mtls_renewal_survives_primary_" + fault)
            finally:
                if fault == "disconnect":
                    command(["docker", "network", "connect", "--alias", "ca", "--alias", "ca-a", self.ca_network, nodes[0]["name"]])
                else:
                    command(["docker", "start" if fault == "stop" else "unpause", nodes[0]["name"]])
            self.wait(lambda: self.ca_call(self.fresh_request(csr), endpoint="ca-a")["status"] == 201, "ca_ha_primary_recovered")
        command(["docker", "stop", "--time", "1", nodes[1]["name"]])
        try:
            flow.require(self.ca_call(self.fresh_request(csr))["status"] == 201, "ca_ha_secondary_failure")
            add("fresh_issuance_survives_secondary_stop")
        finally:
            command(["docker", "start", nodes[1]["name"]])
        # Automatic generation publication (including client rekey/pin updates)
        # through the survivor; all other identities remain deliberately paused.
        saved = json.loads(json.dumps(self.controller_config))
        state = self.status()
        self.controller_config["disabled"] = [uid for uid in state["credentials"] if uid != identity["id"]]
        self.controller_config["key_rotation"]["interval_seconds"] = 1
        self.controller_config["renew_before"] = {}
        command(["docker", "stop", "--time", "1", nodes[0]["name"]])
        try:
            self.paused(False)
            self.wait(lambda: self.status()["phase"] is None and self.status()["credentials"][identity["id"]]["generation"] > state["credentials"][identity["id"]]["generation"],
                "ca_ha_automatic_publication", timeout=50)
            self.paused(True)
            add("automatic_leaf_rekey_and_pin_publication_continue_on_survivor")
        finally:
            self.controller_config = saved
            self.controller_config["paused"] = True
            self.controller_config["key_rotation"]["interval_seconds"] = 600
            self.write_assets(self.controller_volume, {"config.json": json.dumps(self.controller_config)})
            command(["docker", "start", nodes[0]["name"]])
        # Both CA and DB outages fail issuance closed while existing workload TLS
        # remains valid. No new-root or expired-identity reenrollment fallback.
        current_csr = self.private_rpc("import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());print(json.dumps(next(c['csr'] for c in s['credentials'].values() if c['name']=='collector' and c['purpose']=='clientAuth')))")
        for fault, targets in [("all_ca", [r["name"] for r in nodes]), ("database", [self.pg_server])]:
            for name in targets:
                command(["docker", "stop", "--time", "1", name])
            try:
                response = self.ca_call(self.fresh_request(current_csr))
                flow.require(response["status"] != 201, "ca_ha_closed_" + fault)
                add("issuance_fails_closed_when_" + fault + "_unavailable", status=response["status"])
                if self.ha_keys:
                    self.document_access(record, self.ha_keys, "ha-" + fault)
                else:
                    flow.require(self.request(self.controller, {"tls_profile": "/managed/smoke/profile.json", "path": "/health/live"})["status"] == 200,
                        "ca_ha_existing_service_access")
                add("existing_protected_access_continues_during_" + fault + "_outage")
            finally:
                for name in targets:
                    command(["docker", "start", name])
            self.wait(lambda: self.ca_call(self.fresh_request(current_csr))["status"] == 201, "ca_ha_recovery_" + fault, timeout=35)
        flow.require(self.ca_call(replay, endpoint="ca-b")["status"] in {400, 401, 403}, "ca_ha_replay_persistent")
        add("used_token_state_survives_both_ca_and_database_restarts")
        flow.require(self.ca_call({}, endpoint="ca-b", mode="renew_revoked")["status"] in {401, 403}, "ca_ha_revocation_persistent")
        add("revoked_certificate_stays_denied_after_ca_and_database_restarts")
        self.report.setdefault("ha_pre_rotation", []).append({"checks": checks, "revoked_serial": issued["serial"]})
        self.private_rpc("from pathlib import Path;[(Path('/state')/n).unlink(missing_ok=True) for n in ['ha-issued.pem','ha-revoked.pem','ha-revoked.key']];print('{}')")
        flow.require({c["label"] for c in checks} == set(self.report["ha_contract"]["expected_checks"]), "ca_ha_check_coverage")

    def rotation_ha_checks(self, record):
        history = record.get("authority_history") or self.coordinator_state()["history"]
        observations = []
        for item in history:
            tls = item["evidence"]["final_ca_tls"]["replicas"]
            fresh = item["evidence"]["new_jwk_issuance"]["replicas"]
            denied = item["evidence"].get("old_jwks", {})
            flow.require(set(tls) == set(fresh) == {"ca-a", "ca-b"}, "ca_ha_rotation_node_coverage")
            if item["changed"]["jwk"]:
                flow.require(denied["total_denied"] == 132 and all(v["denied"] == 66 for v in denied["replicas"].values()), "ca_ha_old_jwk_both_nodes")
            observations.append({"epoch": item["epoch"], "tls": tls, "fresh_jwk": fresh, "old_jwks": denied})
        record["ha_rotation_checks"] = [{"label": "all_ca_nodes_prove_current_issuer_and_new_jwk_before_leaf_migration", "passed": True},
            {"label": "all_ca_nodes_reject_every_old_jwk_before_old_key_retirement", "passed": True}]
        record["ha_rotation_observations"] = observations
        self.save()

    def smoke(self):
        self.ha_keys = None
        self.report["ha_smoke"] = self.ha_record = {}
        super().smoke()
        self.rotation_ha_checks(self.ha_record)

    def cleanup(self):
        super().cleanup()
        if hasattr(self, "pg_image"):
            subprocess.run(["docker", "image", "rm", self.pg_image], capture_output=True, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c02/c04/ha")
    parser.add_argument("--repeats", type=int, choices=range(1, 3), default=1)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    lab = HALab(args.directory)
    lab.key_smoke = args.smoke
    try:
        lab.prepare()
        if args.smoke:
            lab.smoke()
        else:
            for iteration in range(1, args.repeats + 1):
                lab.trial("nginx", iteration)
        flow.require(all(sha256(ROOT / name) == value for name, value in lab.report["source_input_sha256"].items()), "ca_ha_sources_changed_during_run")
        lab.report["completed"] = True
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError, flow.CheckFailed) as exc:
        lab.report["failure"] = str(exc) if isinstance(exc, flow.CheckFailed) else type(exc).__name__
        raise SystemExit(lab.report["failure"]) from None
    finally:
        lab.report["finished_at"] = flow.timestamp()
        lab.cleanup()


if __name__ == "__main__":
    main()
