"""Exercise UUID-owned real systemd witness units, then remove only those units.

Requires root on local Linux/systemd and public source staged under /run/ztw-code-.
Uses the existing daemon UID as a nonroot fixture, creates no account, modifies
no /etc configuration and never starts production services or cloud resources.
"""

import argparse
import asyncio
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult
from app.scenarios import synthetic_events
from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import canonical, require
from app.services.policy import response_preview
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.systemd_resources import snapshot as resource_snapshot

READ_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"}


def command(*args, check=True):
    return subprocess.run(args, env=READ_ENV, capture_output=True, text=True, timeout=30, check=check)


def wait_for(callback, seconds=40):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = callback()
            if value:
                return value
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.2)
    raise RuntimeError("owned witness systemd condition timed out")


def run(directory):
    require(os.name == "posix" and os.geteuid() == 0
            and Path("/proc/1/comm").read_text().strip() == "systemd", "witness_systemd_root_required")
    import pwd
    source = Path(__file__).resolve().parents[1]
    require(source.parent == Path("/run") and source.name.startswith("ztw-code-"),
            "witness_systemd_owned_public_source_required")
    output = Path(directory)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    tag = uuid.uuid4().hex
    root = Path("/run") / ("ztw-owned-" + tag)
    root.mkdir(mode=0o755, exist_ok=False)
    user = pwd.getpwnam("daemon")
    prefix = "ztw-" + tag[:12]
    (output / "ownership.json").write_bytes(canonical({"unit_prefix": prefix, "state_root": str(root),
                                                       "public_source": str(source)}) + b"\n")
    units, files, created_trees = [], [], []
    result = {"schema": "local-witness-systemd-controls-1", "completed": False, "checks": [],
              "fixture_uid": user.pw_uid, "fixture_account_created": False,
              "production_installation_completed": False, "etc_configuration_changed": False,
              "paid_api_calls": 0, "aws_resources_created": False, "docker_resources_created": False,
              "independent_storage_verified": False, "automatic_activation_allowed": False}

    def check(name, condition):
        require(condition, "witness_systemd_" + name)
        result["checks"].append({"name": name, "passed": True})

    def owned_tree(path, *, public=False):
        path.mkdir(mode=0o755 if public else 0o700, parents=True, exist_ok=True)
        created_trees.append(path)
        return path

    def assign(path):
        require(path.resolve().is_relative_to(root), "witness_systemd_chown_scope")
        for item in [path, *path.rglob("*")]:
            require(not item.is_symlink() and item.resolve().is_relative_to(root), "witness_systemd_chown_link")
            os.chown(item, user.pw_uid, user.pw_gid)

    def props(unit):
        raw = command("/usr/bin/systemctl", "show", unit,
                      "--property=InvocationID,MainPID,User,NoNewPrivileges,PrivateNetwork,ProtectSystem,Result,ExecMainStatus,ControlGroup")
        return dict(line.split("=", 1) for line in raw.stdout.splitlines() if "=" in line)

    def logs(unit):
        return command("/usr/bin/journalctl", "--no-pager", "--lines=80", "--output=cat", "--unit=" + unit).stdout

    def public(path):
        return json.loads(path.read_bytes())

    try:
        state = owned_tree(root / "state/lab")
        control, signer = state / "control", state / "signer"
        audit = owned_tree(root / "audit/lab")
        source_db = SQLiteAuditStore(audit / "audit.sqlite3")
        event = synthetic_events()[0]
        assessment = RuleBasedAnalyzer().assess(event)
        asyncio.run(source_db.save(AnalysisResult(event_id=event.event_id, analyzer="rule", assessment=assessment,
                                                  policy_decision=response_preview(assessment, event), latency_ms=1)))
        before = source_db.path.read_bytes()
        key_pin = witness.initialize(signer, source_db.path, "systemd-fixture")["public_key_sha256"]
        first = witness.observe(signer, source_db.path, key_pin, expected_receipt=witness.GENESIS)
        minimum = first["receipt_sha256"]
        pin = observer.initialize(control, signer, source_db.path, key_pin, expected_receipt=minimum,
                                  interval_seconds=1, max_age_seconds=10, capacity_warning=0)["profile_sha256"]
        observer.cycle(control, pin, minimum_receipt=minimum)
        package_dir = owned_tree(root / "backups/lab")
        package = package_dir / "control.aesgcm"
        key = secrets.token_bytes(32)
        saved = backup.backup(control, pin, minimum, package, key)
        owned_tree(root / "reviews")
        review = root / "reviews/lab"
        restored = backup.restore(package, review, saved["backup_sha256"], pin, minimum, key)
        del key
        cache = owned_tree(root / "cache/lab", public=True)
        restore_cache = owned_tree(root / "restore-cache/lab", public=True)
        for path in (state, package_dir, review, cache, restore_cache):
            assign(path)
        # Explicit read group on the test-only source: the service owns neither
        # the audit file nor its parent and receives no source write permission.
        for path in (root / "audit", audit):
            path.chmod(0o750)
            os.chown(path, 0, user.pw_gid)
        source_db.path.chmod(0o640)
        os.chown(source_db.path, 0, user.pw_gid)
        for name in ("state", "backups", "reviews", "cache", "restore-cache"):
            (root / name).chmod(0o755)
        dependencies = Path(sys.prefix) / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
        require(dependencies.is_dir(), "witness_systemd_dependencies")
        deps = owned_tree(root / "deps", public=True)
        configs = owned_tree(root / "config", public=True)
        restore_configs = owned_tree(root / "restore-config", public=True)
        base_env = f"PYTHONPATH={source}:{deps}\nWITNESS_PROFILE_SHA256={pin}\nWITNESS_MINIMUM_RECEIPT={minimum}\n"
        (configs / "lab.conf").write_text(base_env)
        (restore_configs / "lab.conf").write_text(base_env + f"WITNESS_BACKUP_SHA256={saved['backup_sha256']}\n"
                                                  + f"WITNESS_RESTORE_RECEIPT_SHA256={restored['restore_receipt_sha256']}\n")
        replacements = {
            "/etc/secops/audit-witness-restore": str(restore_configs),
            "/etc/secops/audit-witness": str(configs),
            "/var/lib/secops-audit-witness-backups": str(root / "backups"),
            "/var/lib/secops-audit-witness-reviews": str(root / "reviews"),
            "/var/lib/secops-audit-witness": str(root / "state"),
            "/var/lib/secops-audit": str(root / "audit"),
            "/var/cache/secops-audit-witness-restore": str(root / "restore-cache"),
            "/var/cache/secops-audit-witness": str(root / "cache"),
            "/opt/secops/.venv/bin/python": "/usr/bin/python3", "WorkingDirectory=/opt/secops": "WorkingDirectory=" + str(source),
            "User=secops-witness": "User=daemon", "Group=secops-witness": "Group=daemon", "RestartSec=5": "RestartSec=1",
        }
        for kind, template in (("collector", "secops-audit-witness@.service"),
                               ("restore", "secops-audit-witness-restore-status@.service")):
            text = (source / "infra/systemd" / template).read_text()
            for old, new in replacements.items():
                text = text.replace(old, new)
            text = text.replace("[Service]\n", f"[Service]\nBindReadOnlyPaths={dependencies}:{deps}\n")
            name = prefix + "-" + kind + "@lab.service"
            path = Path("/run/systemd/system") / name
            path.write_text(text)
            files.append(path)
            units.append(name)
            probe_text = "\n".join(line if not line.startswith("ExecStart=") else (
                f"ExecStart=/usr/bin/python3 -m scripts.witness_systemd_probe --database {source_db.path} "
                f"--private-key {signer / 'private.key'} --cache {cache if kind == 'collector' else restore_cache}"
            ) for line in text.splitlines()) + "\n"
            probe_text = probe_text.replace("Type=simple", "Type=oneshot").replace("Restart=on-failure", "Restart=no")
            probe_name = prefix + "-" + kind + "-probe@lab.service"
            probe_path = Path("/run/systemd/system") / probe_name
            probe_path.write_text(probe_text)
            files.append(probe_path)
            units.append(probe_name)
        command("/usr/bin/systemd-analyze", "verify", *(str(p) for p in files))
        command("/usr/bin/systemctl", "daemon-reload")
        for kind in ("collector", "restore"):
            name = prefix + "-" + kind + "-probe@lab.service"
            command("/usr/bin/systemctl", "start", name)
            raw = logs(name)
            (output / (kind + "-probe.log")).write_text(raw)
            values = [json.loads(line.split("=", 1)[1]) for line in raw.splitlines()
                      if line.startswith("WITNESS_SANDBOX_PROBE=")]
            require(len(values) == 1, "witness_systemd_probe_receipt")
            value = values[0]
            result[kind + "_probe"] = value
            check(kind + "_nonroot_empty_capabilities", value["uid"] == user.pw_uid != 0
                  and value["effective_capabilities"] == value["permitted_capabilities"]
                  == value["inheritable_capabilities"] == 0 and value["no_new_privileges"])
            check(kind + "_socket_and_process_inspection_restrictions", not value["ipv4_socket_allowed"]
                  and value["unix_socket_allowed"] and not value["proc_readable"]
                  and all(v is True for v in value["process_memory_syscalls_denied"].values()))
            check(kind + "_cache_allowed_source_key_writes_denied", value["cache_writable"]
                  and not value["database_write_open_allowed"] and not value["private_key_write_open_allowed"])
            check(kind + "_role_read_boundary", value["database_readable"] == (kind == "collector")
                  and value["private_key_readable"] == (kind == "collector"))
        collector = prefix + "-collector@lab.service"
        status_file = cache / "observer.json"
        command("/usr/bin/systemctl", "start", collector)
        wait_for(lambda: status_file.exists() and public(status_file)["values"]["anchor_count"] >= 2)
        initial = props(collector)
        groups = Path(f"/proc/{initial['MainPID']}/cgroup").read_text()
        require(any(line.split(":", 2)[-1].endswith("/" + collector) for line in groups.splitlines()),
                "witness_systemd_cgroup_scope")
        limits = resource_snapshot(groups)
        result["kernel_resource_limits"] = limits
        check("collector_kernel_resource_limits_match_template",
              limits["memory_limit_bytes"] == 512 * 1024 * 1024 and limits["tasks_limit"] == 8
              and limits["cpu_quota_percent"] == 50)
        check("collector_real_private_network_namespace", Path("/proc/1/ns/net").readlink()
              != Path(f"/proc/{initial['MainPID']}/ns/net").readlink())
        before_restart = public(status_file)["values"]["anchor_count"]
        command("/usr/bin/systemctl", "kill", "--signal=SIGKILL", collector)
        changed = wait_for(lambda: (p if (p := props(collector))["InvocationID"] != initial["InvocationID"]
                                    and int(p["MainPID"]) > 0 else None))
        wait_for(lambda: public(status_file)["values"]["anchor_count"] > before_restart)
        result["restart"] = {"before_invocation": initial["InvocationID"], "after_invocation": changed["InvocationID"],
                             "before_anchor_count": before_restart,
                             "after_anchor_count": public(status_file)["values"]["anchor_count"]}
        check("supervisor_restart_preserves_profile_and_progresses", changed["User"] == "daemon"
              and public(status_file)["profile_sha256"] == pin)
        checker = prefix + "-restore@lab.service"
        command("/usr/bin/systemctl", "start", checker)
        review_file = restore_cache / "restore.json"
        checked = public(review_file)
        check("actual_keyless_checker_verifies_copy_without_live_source_access", bool(checked["values"])
              and checked["decryption_checked"] is False and checked["live_source_checked"] is False)
        timer = prefix + "-restore@lab.timer"
        text = (source / "infra/systemd/secops-audit-witness-restore-status@.timer").read_text()
        text = text.replace("Unit=secops-audit-witness-restore-status@%i.service", "Unit=" + checker)
        timer_path = Path("/run/systemd/system") / timer
        timer_path.write_text(text)
        files.append(timer_path)
        units.append(timer)
        command("/usr/bin/systemd-analyze", "verify", str(timer_path))
        command("/usr/bin/systemctl", "daemon-reload")
        command("/usr/bin/systemctl", "start", timer)

        def subsequent(previous):
            value = public(review_file)
            return value if datetime.fromisoformat(value["checked_at"]) > datetime.fromisoformat(previous) else None

        first_check = wait_for(lambda: subsequent(checked["checked_at"]))
        second_check = wait_for(lambda: subsequent(first_check["checked_at"]))
        check("timer_runs_real_keyless_checks", bool(first_check["values"]) and bool(second_check["values"]))
        check("timer_preserves_original_restore_start", second_check["values"]["restore_started_at"]
              == checked["values"]["restore_started_at"])
        check("source_bytes_unchanged", source_db.path.read_bytes() == before)
        result["completed"] = True
    except Exception as error:
        result["failure_type"] = type(error).__name__
        if isinstance(error, subprocess.CalledProcessError):
            result["failure_exit_code"] = error.returncode
            result["failure_stderr"] = (error.stderr or "")[-4000:]
        raise
    finally:
        for name in sorted(units, key=lambda item: not item.endswith(".timer")):
            require(name.startswith(prefix + "-") and name.endswith(("@lab.service", "@lab.timer")),
                    "witness_systemd_cleanup_unit")
            command("/usr/bin/systemctl", "stop", name, check=False)
            (output / (name + ".log")).write_text(logs(name))
            command("/usr/bin/systemctl", "reset-failed", name, check=False)
        for path in files:
            require(path.parent == Path("/run/systemd/system") and path.name.startswith(prefix + "-"),
                    "witness_systemd_cleanup_file")
            path.unlink(missing_ok=True)
        command("/usr/bin/systemctl", "daemon-reload", check=False)
        result["owned_units_removed"] = all("LoadState=not-found" in command(
            "/usr/bin/systemctl", "show", name, "--property=LoadState", check=False).stdout for name in units)
        require(root.parent == Path("/run") and root.name == "ztw-owned-" + tag and not root.is_symlink(),
                "witness_systemd_cleanup_root")
        shutil.rmtree(root)
        result["owned_state_removed"] = not root.exists()
        if not result["owned_units_removed"] or not result["owned_state_removed"]:
            result["completed"] = False
        (output / "report.json").write_bytes(canonical(result) + b"\n")
    return result


def main():
    def terminate(_signum, _frame):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.directory)))


if __name__ == "__main__":
    main()
