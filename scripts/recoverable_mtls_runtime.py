"""Use the existing local mTLS Docker stack with a single approved app restore."""

import argparse
import json
import subprocess
from pathlib import Path

from scripts import app_storage_contract as storage
from scripts import runtime_release as release
from scripts.ca_recovery_state import locked
from scripts.continuous_mtls_runtime import (
    ROOT,
    VOLUMES,
    Runtime,
    RuntimeFailure,
    command,
    compose_spec,
)
from scripts.mtls_app_recovery import WRITERS

RECOVERY_VOLUMES = ("recovery-authority", "recovery-public", "recovered-data")


def recovery_spec(project, image, nginx, *, restored, spec=None):
    spec = compose_spec(project, image, nginx) if spec is None else spec
    for volume in RECOVERY_VOLUMES:
        spec["volumes"][volume] = {"external": True, "name": project + "-" + volume}
    for role in WRITERS:
        definition = spec["services"][role]
        mode = "approved" if restored else "original"
        definition["entrypoint"] = ["python", "-m", "scripts.mtls_app_recovery", "writer", role, mode]
        definition["volumes"] = [*definition["volumes"], "recovery-public:/admission:ro"]
        if role == "collector":
            continue
        data = "/data"
        if restored:
            definition["volumes"].remove("data:/data")
            definition["volumes"].append("recovered-data:/data")
            data = "/data/active"
        definition["environment"].update(
            ZERO_TRUST_DB_PATH=f"{data}/app.sqlite3", AUDIT_BACKEND="jsonl",
            AUDIT_LOG_PATH=f"{data}/{storage.FILES['audit']}",
            CASE_LOG_PATH=f"{data}/{storage.FILES['cases']}",
            OUTBOX_LOG_PATH=f"{data}/{storage.FILES['outbox']}",
        )
    return spec


class RecoverableRuntime(Runtime):
    volumes = VOLUMES + RECOVERY_VOLUMES

    def release_inputs(self):
        identities = ("kmtls-000000000000", "sha256:" + "0" * 64, "sha256:" + "1" * 64)
        return release.capture(ROOT, {
            "original": recovery_spec(*identities, restored=False),
            "approved": recovery_spec(*identities, restored=True),
        })

    def active_definition(self, project, image, nginx):
        return recovery_spec(project, image, nginx, restored="restore_id" in self.state)

    def make_assets(self):
        assets = super().make_assets()
        assets["data"] = {"storage.json": json.dumps(storage.CONTRACT),
                          **dict.fromkeys(storage.FILES.values(), "")}
        assets["recovery-public"] = {"phase.json": json.dumps({"phase": "original"})}
        return assets

    def _volume(self, label):
        name = self.state["volumes"][label]
        detail = json.loads(command(["docker", "volume", "inspect", name]))[0]
        if detail.get("Labels", {}).get("secops.runtime") != self.state["project"]:
            raise RuntimeFailure("mtls_recovery_volume_scope")
        return name

    def _container_job(self, argv, mounts, *, name=None):
        flags = ["docker", "run", "--rm", "--network", "none", "--read-only",
                 "--user", "10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                 "--pids-limit", "128", "--memory", "896m", "--memory-swap", "896m",
                 "--label", "secops.runtime=" + self.state["project"],
                 "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,uid=10001,gid=10001",
                 "--tmpfs", "/data:rw,nosuid,nodev,size=1m,uid=10001,gid=10001"]
        if name is not None:
            flags.extend(["--name", self.state["project"] + "-" + name])
        for label, path, readonly in mounts:
            suffix = ",readonly" if readonly else ""
            flags.extend(["--mount", f"type=volume,src={self._volume(label)},dst={path}{suffix}"])
        return json.loads(command([*flags, "--entrypoint", "python", self.state["image_id"], *argv], timeout=600))

    def phase(self):
        return self._container_job(["-m", "scripts.mtls_app_recovery", "phase"],
                                   [("recovery-public", "/admission", True)])

    def _assert_unused(self, *labels):
        for label in labels:
            if command(["docker", "ps", "--quiet", "--filter", "volume=" + self._volume(label)]).strip():
                raise RuntimeFailure("mtls_recovery_writer_still_running")

    def before_start(self):
        state = self.phase()
        selected = self.state.get("restore_id")
        if state["phase"] == "maintenance" or (selected is not None and state.get("restore_id") != selected):
            raise RuntimeFailure("mtls_recovery_requires_resume")
        if state["phase"] == "approved":
            self._assert_unused("data")
            self.state["restore_id"] = state["restore_id"]
            self.save()
            self.write_manifest()

    def _stop_writers(self):
        for role in WRITERS:
            try:
                self.container(role)
            except RuntimeFailure as exc:
                if str(exc) != "runtime_container_missing":
                    raise
        self.compose("stop", "--timeout", "10", *WRITERS)
        self._assert_unused("data", "registry", "collector-state", "recovered-data", "recovery-authority")

    def recovery_job(self, argv=None):
        return self._container_job(
            argv or ["-m", "scripts.mtls_app_recovery", "restore"],
            [("data", "/source", True), ("registry", "/signals", True),
             ("recovery-public", "/admission", False),
             ("recovery-authority", "/authority", False), ("recovered-data", "/restored", False)],
            name="app-recovery",
        )

    def recover(self):
        self.load()
        if not self.state.get("initialized"):
            raise RuntimeFailure("runtime_initialization_incomplete")
        self.verify_release()
        release.image_identity(json.loads(command(["docker", "image", "inspect", self.state["image"]]))[0],
                               self.state["image_id"])
        self.verify_public_configuration()
        state = self.phase()
        selected = self.state.get("restore_id")
        if selected is not None and state.get("restore_id") != selected:
            raise RuntimeFailure("mtls_recovery_pin_changed")
        if state["phase"] != "approved":
            if state["phase"] == "original":
                self._container_job(["-m", "scripts.mtls_app_recovery", "fence"],
                                    [("recovery-public", "/admission", False)])
            self._stop_writers()
            self.recovery_job()
            state = self.phase()
            if state["phase"] != "approved":
                raise RuntimeFailure("mtls_recovery_publication_incomplete")
        return self.up() | {"recovery": state}


    def down(self, *, purge=False):
        self.load()
        if self.state.get("initialized"):
            self._assert_unused("recovery-authority")
        return super().down(purge=purge)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("up", "status", "down", "recover"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--purge", action="store_true")
    args = parser.parse_args(argv)
    try:
        runtime = RecoverableRuntime(args.directory)
        runtime.directory.mkdir(parents=True, exist_ok=True)
        with locked(runtime.directory):
            if args.mode == "up":
                result = runtime.up()
            elif args.mode == "recover":
                result = runtime.recover()
            elif args.mode == "down":
                result = runtime.down(purge=args.purge)
            else:
                runtime.load()
                result = {"project": runtime.state["project"], "recovery": runtime.phase()}
        print(json.dumps(result))
        return 0
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"runtime": "unavailable"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
