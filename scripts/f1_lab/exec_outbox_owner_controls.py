"""Owned nonroot systemd checker acceptance on copies of signed evidence."""

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.shared_execution_collector import READ_ENV


def run(lab, root, outbox, scope, check):
    owned = Path("/run") / ("zt-exec-outbox-owner-" + uuid.uuid4().hex)
    owned.mkdir(mode=0o755)
    unit = "secops-outbox-status-" + uuid.uuid4().hex + ".service"
    unit_file = Path("/run/systemd/system") / unit
    uid, gid = 65534, 65534

    def command(*args):
        return subprocess.run(
            ["/usr/bin/systemctl", *args],
            env=READ_ENV,
            capture_output=True,
            timeout=25,
            check=False,
        )

    try:
        live, queue, public = [owned / name for name in ("live", "outbox", "public")]
        # Only this test's dedicated signed data stores are copied, not the
        # broker/app directory, signing credentials, tokens or worker argv.
        shutil.copytree(root, live, symlinks=True)
        shutil.copytree(outbox, queue, symlinks=True)
        for directory in (live, queue):
            for path in [directory, *directory.rglob("*")]:
                require(not path.is_symlink(), "outbox_owner_copy_link")
                os.chown(path, uid, gid)
                path.chmod(0o700 if path.is_dir() else 0o600)
        public.mkdir(mode=0o755)
        os.chown(public, uid, gid)
        service_registry, caller_registry = owned / "service.json", owned / "caller.json"
        service_registry.write_bytes(lab.broker.joiner.registry.path.read_bytes())
        caller_registry.write_bytes(lab.broker.registry.path.read_bytes())
        for path in (service_registry, caller_registry):
            path.chmod(0o644)
        probe = owned / "readonly-probe.py"
        protected = [str(live / "latest.json"), str(next(queue.glob("*.json")))]
        probe.write_text(
            "import errno,json,os\n"
            + "for path in "
            + repr(protected)
            + ":\n"
            + "    try: fd=os.open(path,os.O_WRONLY|os.O_APPEND)\n"
            + "    except OSError as error: assert error.errno in (errno.EROFS,errno.EACCES)\n"
            + "    else:\n        os.close(fd)\n        raise AssertionError('evidence writable')\n"
            + "print(json.dumps({'readonly_evidence_probe':True}))\n",
            encoding="utf8",
        )
        probe.chmod(0o644)
        python_path = os.environ["PYTHONPATH"]
        require('"' not in python_path and "\n" not in python_path, "outbox_owner_python_path")
        argv = (
            f"--tenant {scope.tenant_id} --server {scope.server_id} --unit {scope.unit} "
            f"--source {scope.source_id} --root {live} --outbox {queue} "
            f"--registry {service_registry} --registry-sha256 {lab.broker.joiner.registry.expected_sha256} "
            f"--caller-registry {caller_registry} --caller-registry-sha256 {lab.broker.registry.sha256} "
            f"--caller-environment local_oidc --status-output {public / 'status.json'} --observe-worker-security"
        )
        unit_file.write_text(
            f"""[Service]
Type=oneshot
User=nobody
Group=nogroup
ExecStart=/usr/bin/python3 -m scripts.exec_outbox_status {argv}
ExecStartPost=/usr/bin/python3 {probe}
Environment="PYTHONPATH={python_path}" PYTHONDONTWRITEBYTECODE=1 AWS_EC2_METADATA_DISABLED=true
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths={live / ".capture-store.lock"} {queue / ".capture-store.lock"} {public}
CPUQuota=50%
MemoryMax=256M
TasksMax=8
TimeoutStartSec=20
StandardOutput=journal
StandardError=journal
""",
            encoding="utf8",
        )
        require(command("daemon-reload").returncode == 0, "outbox_owner_reload")
        require(command("start", unit).returncode == 0, "outbox_owner_worker_start")
        diagnostic = subprocess.run(
            ["/usr/bin/journalctl", "--no-pager", "-u", unit, "-n", "30", "-o", "cat"],
            env=READ_ENV,
            capture_output=True,
            timeout=10,
            check=True,
        ).stdout
        require(len(diagnostic) <= 32768, "outbox_owner_journal_bound")
        values = [
            json.loads(line) for line in diagnostic.decode().splitlines() if line.startswith("{")
        ]
        statuses = [v for v in values if "worker_security" in v]
        require(len(statuses) == 1 and statuses[0]["state"] == "pending", "outbox_owner_status")
        security = statuses[0]["worker_security"]
        require(
            security
            == {
                "effective_uid": uid,
                "effective_capabilities": 0,
                "bounding_capabilities": 0,
                "no_new_privileges": True,
            },
            "outbox_owner_sandbox",
        )
        check("actual_nonroot_systemd_status_worker_has_zero_capabilities_and_nnp")
        body = json.loads((public / "status.json").read_bytes())
        require(
            body["state"] == "pending" and body["values"]["pending"] == 1,
            "outbox_owner_public_counts",
        )
        check("nonroot_status_worker_revalidates_signed_copies_without_any_private_key")
        require(
            any(v.get("readonly_evidence_probe") is True for v in values),
            "outbox_owner_evidence_readonly",
        )
        check("nonroot_checker_can_publish_status_but_cannot_open_evidence_for_writing")
        return security
    finally:
        command("stop", unit)
        command("reset-failed", unit)
        unit_file.unlink(missing_ok=True)
        command("daemon-reload")
        require(
            owned.parent == Path("/run") and owned.name.startswith("zt-exec-outbox-owner-"),
            "outbox_owner_cleanup_scope",
        )
        shutil.rmtree(owned)
        require(not owned.exists() and not unit_file.exists(), "outbox_owner_cleanup")
