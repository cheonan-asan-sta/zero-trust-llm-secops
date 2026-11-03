"""Opt-in trusted-host scheduler for isolated local Docker authority rotation.

Root custodian jobs have network=none; ordinary CA/leaf containers have no vault
or Docker socket. The host operator already controls the explicitly pinned Docker
objects. This is a single-authority software ceremony, not distributed consensus.
"""

import argparse
import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from scripts.authority_custodian import digest, verify_plan
from scripts.certificate_controller import LifecycleError, save


class DockerBackend:
    def __init__(self, profile):
        self.profile = profile
        self.project = profile["project"]
        if not re.fullmatch(r"c02-[a-f0-9]{12}", self.project) or not re.fullmatch(r"sha256:[a-f0-9]{64}", profile["image"]):
            raise LifecycleError("authority_docker_scope")
        for name in [profile["ca"]["name"], profile["leaf"]["name"], *profile["volumes"].values()]:
            if not re.fullmatch(re.escape(self.project) + r"-[A-Za-z0-9_.-]+", name):
                raise LifecycleError("authority_docker_scope")
        replicas = profile.get("ca_replicas")
        if replicas is not None and (not isinstance(replicas, list) or not 2 <= len(replicas) <= 4
                    or any(not isinstance(r, dict) or set(r) != {"name", "id", "endpoint"}
                        or not re.fullmatch(re.escape(self.project) + r"-[A-Za-z0-9_.-]+", r.get("name", ""))
                        or not re.fullmatch(r"[a-f0-9]{64}", r.get("id", ""))
                        or not re.fullmatch(r"ca-[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", r.get("endpoint", "")) for r in replicas)
                    or any(len({r[field] for r in replicas}) != len(replicas) for field in ["name", "id", "endpoint"])
                    or {k: replicas[0][k] for k in ["name", "id"]} != profile["ca"]):
            raise LifecycleError("authority_ca_replica_scope")

    def command(self, args, payload=None, timeout=30):
        try:
            response = subprocess.run(["docker", *args], input=json.dumps(payload) if payload is not None else None,
                capture_output=True, text=True, encoding="utf-8", timeout=timeout, check=False)
        except subprocess.SubprocessError:
            raise LifecycleError("authority_docker_timeout") from None
        if response.returncode:
            codes = re.findall(r"LifecycleError: ([a-z_]+)\s*$", response.stderr)
            raise LifecycleError("authority_child_" + codes[-1] if codes else "authority_docker_command_failed")
        return response.stdout

    def owned(self, role):
        return self.owned_container(self.profile[role])

    def owned_container(self, expected):
        found = json.loads(self.command(["inspect", expected["name"]]))[0]
        if found["Id"] != expected["id"] or found["Name"] != "/" + expected["name"] or found["Image"] != self.profile["image"]:
            raise LifecycleError("authority_container_replaced")
        if any(m["Destination"].endswith("docker.sock") or m["Destination"] == "/vault" for m in found["Mounts"]):
            raise LifecycleError("authority_online_vault_exposure")
        if self.profile.get("ca_replicas") and expected["name"] != self.profile["leaf"]["name"]:
            mounts = [m for m in found["Mounts"] if m["Destination"] == "/ca"]
            if len(mounts) != 1 or mounts[0].get("Name") != self.profile["volumes"]["ca"] or mounts[0].get("RW"):
                raise LifecycleError("authority_replica_configuration_mount")
        return expected["name"]

    def leaf(self, operation, plan=None, **fields):
        name = self.owned("leaf")
        return json.loads(self.command(["exec", "-i", name, "python", "-m", "scripts.authority_rotation_runtime"],
            {"operation": operation, **fields, **({"plan": plan} if plan is not None else {})}))

    def custodian(self, operation, payload=None):
        args = ["run", "--rm", "--name", self.project + "-authority-custodian", "--network", "none", "--read-only",
            "--user", "10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory", "256m", "--cpus", "1", "-i"]
        for label, destination in [("vault", "/vault"), ("ca", "/ca"), ("renewal", "/renewal"), ("leaf", "/controller")]:
            args += ["--mount", f"type=volume,src={self.profile['volumes'][label]},dst={destination}"]
        args += ["--entrypoint", "python", self.profile["image"], "-m", "scripts.authority_custodian", operation]
        try:
            return json.loads(self.command(args, payload))
        except LifecycleError:
            # A lost Docker CLI response must not strand a root job with mounted keys.
            name = self.project + "-authority-custodian"
            found = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=5, check=False)
            if found.returncode == 0:
                inspected = json.loads(found.stdout)[0]
                if (inspected["Image"] == self.profile["image"] and inspected["HostConfig"]["NetworkMode"] == "none"
                        and any(m.get("Name") == self.profile["volumes"]["vault"] and m["Destination"] == "/vault" for m in inspected["Mounts"])):
                    subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=10, check=False)
            raise

    def restart_ca(self):
        if not self.profile.get("ca_replicas"):
            self.command(["restart", "--time", "2", self.owned("ca")])
            return
        # Validate every pinned object before mutating any. Key ceremonies keep
        # the leaf publisher paused until all nodes prove the new configuration.
        replicas = self.profile["ca_replicas"]
        names = [self.owned_container(replica) for replica in replicas]
        for name, replica in zip(names, replicas, strict=True):
            self.command(["restart", "--time", "2", name])
            deadline = time.monotonic() + 20
            while True:
                try:
                    self.leaf("endpoint_health", endpoint=replica["endpoint"])
                    break
                except LifecycleError:
                    if time.monotonic() >= deadline:
                        raise LifecycleError("authority_replica_restart_unhealthy") from None
                    time.sleep(.4)


class Coordinator:
    def __init__(self, profile, directory, backend=None):
        self.profile, self.directory = profile, directory
        self.backend = backend or DockerBackend(profile)
        self.path = directory / "authority-coordinator.json"
        self.state = json.loads(self.path.read_bytes()) if self.path.exists() else {
            "schema": "authority-coordinator-1", "phase": "idle", "epoch": 0, "root": profile["initial_root"],
            "manifest_hash": None, "history": [], "plan": None, "last_error": None}

    def persist(self):
        save(self.path, self.state)

    def tick(self):
        s, b = self.state, self.backend
        phase, plan = s["phase"], s["plan"]
        if phase == "idle":
            if s.get("next_due_at", 0) > time.time():
                return
            b.leaf("pause", value=True)
            s.update(phase="quiescing", started_at=time.time())
        elif phase == "quiescing":
            if not b.leaf("status")["paused"]:
                return
            candidate = b.custodian("prepare")
            if not candidate["due"]:
                b.leaf("pause", value=False)
                s.update(phase="idle", not_due=True, next_due_at=min(candidate["next_due_at"],
                    time.time() + self.profile.get("policy_refresh_seconds", 300)))
            else:
                plan = candidate["plan"]
                verify_plan(plan, s["root"], epoch=s["epoch"] + 1, previous=s["manifest_hash"])
                s.update(plan=plan, phase="prepared", not_due=False, evidence={"custody": candidate.get("custody")})
        elif phase == "prepared":
            s["evidence"]["trust_overlap"] = b.leaf("stage", plan)
            s["phase"] = "trust_staged"
        elif phase == "trust_staged":
            s["evidence"]["old_services_with_overlap"] = b.leaf("ready", plan)
            b.custodian("install", {"phase": "overlap"})
            b.restart_ca()
            s["phase"] = "ca_activated"
        elif phase == "ca_activated":
            s["evidence"]["new_ca_tls"] = b.leaf("health", plan)
            if self.profile.get("ca_replicas"):
                observations = {}
                for replica in self.profile["ca_replicas"]:
                    probe = b.leaf("probe_csr", plan)
                    b.custodian("probe", probe)  # Fresh nonce per shared-DB node.
                    observations[replica["endpoint"]] = b.leaf("probe", plan, endpoint=replica["endpoint"])
                s["evidence"]["new_jwk_issuance"] = {"replicas": observations}
            else:
                probe = b.leaf("probe_csr", plan)
                b.custodian("probe", probe)
                s["evidence"]["new_jwk_issuance"] = b.leaf("probe", plan)
            s["phase"] = "leaf_activating"
        elif phase == "leaf_activating":
            b.leaf("activate", plan)
            s["phase"] = "migrating"
        elif phase == "migrating":
            if not b.leaf("migration", plan)["ready"]:
                return
            b.leaf("pause", value=True)
            s["phase"] = "quiescing_retirement"
        elif phase == "quiescing_retirement":
            if not b.leaf("status")["paused"]:
                return
            s["evidence"]["migrated_services"] = b.leaf("verify", plan)
            s["evidence"]["retired_trust"] = b.leaf("retire", plan)
            b.custodian("install", {"phase": "final"})
            b.restart_ca()
            s["phase"] = "trust_retired"
        elif phase == "trust_retired":
            s["evidence"]["final_ca_tls"] = b.leaf("health", plan)
            s["evidence"]["final_services"] = b.leaf("verify", plan)
            if plan["changed"]["jwk"]:
                if self.profile.get("ca_replicas"):
                    observations = {}
                    for replica in self.profile["ca_replicas"]:
                        b.custodian("old-probes")  # Fresh CSR/nonce per node, never a replay rejection.
                        observations[replica["endpoint"]] = b.leaf("old_keys_denied", plan, endpoint=replica["endpoint"])
                    counts = {value["denied"] for value in observations.values()}
                    if len(counts) != 1:
                        raise LifecycleError("authority_replica_old_key_coverage")
                    s["evidence"]["old_jwks"] = {"denied": counts.pop(), "replicas": observations,
                        "total_denied": sum(value["denied"] for value in observations.values())}
                else:
                    b.custodian("old-probes")
                    s["evidence"]["old_jwks"] = b.leaf("old_keys_denied", plan)
                b.leaf("health", plan)  # Positive CA control after the denied requests.
            s["phase"] = "committing"
        elif phase == "committing":
            finished = b.custodian("finish", {"plan_hash": digest(plan), "migration_verified": True, "retired_trust_verified": True})
            b.leaf("finish", plan)
            s["history"].append({"epoch": plan["epoch"], "changed": plan["changed"], "plan_hash": digest(plan),
                "plan": plan,
                "root_public_key_sha256": plan["root_public_key_sha256"], "issuer_public_key_sha256": plan["issuer_public_key_sha256"],
                "provider_public_keys": {p["name"]: p["key"] for p in plan["final_ca"]["authority"]["provisioners"]},
                "evidence": s["evidence"], "finished_at": time.time()})
            s.update(epoch=plan["epoch"], root=plan["root"], manifest_hash=digest(plan), phase="idle", plan=None,
                next_due_at=min(finished.get("next_due_at", time.time() + 300), time.time() + self.profile.get("policy_refresh_seconds", 300)))
        else:
            raise LifecycleError("authority_coordinator_phase")
        s["last_error"] = None
        self.persist()


@contextmanager
def lease(directory):
    with (directory / "authority-coordinator.lock").open("a+b") as stream:
        stream.seek(0)
        if stream.read(1) == b"":
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["tick", "once", "run"])
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_bytes())
    directory = args.profile.resolve().parent
    with lease(directory):
        coordinator = Coordinator(profile, directory)
        deadline = time.time() + profile.get("transition_timeout_seconds", 600)
        while True:
            try:
                coordinator.tick()
            except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
                coordinator.state["last_error"] = str(exc) if isinstance(exc, LifecycleError) else type(exc).__name__
                coordinator.persist()
            s = coordinator.state
            if args.mode == "tick" or (args.mode == "once" and s["phase"] == "idle"):
                print(json.dumps({"phase": s["phase"], "epoch": s["epoch"], "error": s["last_error"]}))
                return
            if time.time() > deadline and s["phase"] != "idle":
                raise SystemExit("authority_transition_timeout_no_rollback")
            if s["phase"] == "idle":
                deadline = time.time() + profile.get("transition_timeout_seconds", 600)
            time.sleep(max(.2, min(30, profile.get("poll_seconds", 2))))


if __name__ == "__main__":
    main()
