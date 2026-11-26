"""Exercise the installed login queue unit templates in owned temporary systemd units."""

import argparse
import hashlib
import json
import os
import pwd
import secrets
import shutil
import socket
import subprocess
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from uuid import uuid4

import httpx

from app.services.sqlite_audit import SQLiteAuditStore
from app.zero_trust_models import LoginDeliveryRequest
from scripts import login_queue_activation as activation
from scripts import login_queue_backup as backup
from scripts import login_queue_host_handoff as handoff
from scripts.evaluate_local_remote_holdout import write
from scripts.f1_lab.capture_backup import fresh_file
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.login_delivery_spool import LoginDeliverySpool
from scripts.run_login_queue_recovery import FIELDS, events, flagged


def systemctl(*args):
    result = subprocess.run(
        ["systemctl", *args], capture_output=True, text=True, timeout=55, check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or str(args))
    return result.stdout.strip()


@contextmanager
def account(user):
    os.setegid(user.pw_gid)
    os.seteuid(user.pw_uid)
    try:
        yield
    finally:
        os.seteuid(0)
        os.setegid(0)


def until(check):
    deadline = monotonic() + 35
    while monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (httpx.TransportError, OSError, ValueError, KeyError):
            pass
        sleep(0.2)
    raise RuntimeError("Login queue systemd condition timed out")


def render(source, root, env, prefix, user, created):
    suffix = "lab"
    unit_root = Path("/run/systemd/system")
    unit_names = [f"{prefix}-{kind}@{suffix}.service" for kind in ("api", "sender")]
    state = Path("/var/lib") / prefix / suffix
    status_file = Path("/run") / f"{prefix}-status" / suffix / "status.json"
    replacements = {
        "secops-login-queue-api@": f"{prefix}-api@",
        "/opt/secops": str(root / "code"),
        "/etc/secops/login-queue": str(env),
        "User=secops-login": f"User={user.pw_name}",
        "Group=secops-login": "Group=daemon",
        "secops-login-queue/%i": f"{prefix}/%i",
        "secops-login-queue-status/%i": f"{prefix}-status/%i",
    }
    for kind, name in zip(("api", "sender"), unit_names, strict=True):
        raw = (source / f"infra/systemd/secops-login-queue-{kind}@.service").read_text()
        for old, new in replacements.items():
            raw = raw.replace(old, new)
        path = unit_root / name
        with path.open("x", encoding="utf-8") as unit:
            created.append(path)
            unit.write(raw)
        path.chmod(0o644)
    return unit_names, state, status_file


def fixture(root, env, state, origin, user, port, key):
    fresh_file(env / "lab.analysis-key", key.encode())
    scope = {"origin": origin, "tenant_id": "systemd-lab", "collector_subject": "systemd-login-collector"}
    profile = root / f"{state.parent.name}-queue-profile.json"
    write(profile, {
        "analysis_origin": origin, "tenant_id": scope["tenant_id"],
        "collector_subject": scope["collector_subject"], "queue_file": str(state / "unused-queue.sqlite3"),
    })
    settings = {
        "LOGIN_QUEUE_API_PORT": port, "LOGIN_QUEUE_ORIGIN": origin, "ALLOWED_HOSTS": "127.0.0.1",
        "APP_ENVIRONMENT": "test", "ANALYZER_MODE": "rule", "AUTH_MODE": "api_key",
        "API_KEY_SHA256": hashlib.sha256(key.encode()).hexdigest(), "API_KEY_ROLES": "analyst",
        "API_KEY_TENANT_ID": scope["tenant_id"], "API_KEY_SUBJECT": scope["collector_subject"],
        "AUDIT_BACKEND": "sqlite", "AUDIT_DB_PATH": state / "unused-audit.sqlite3",
        "DASHBOARD_LOGIN_QUEUE_PROFILE": profile, "AUDIT_LOG_PATH": state / "unused-audit.jsonl",
        "ZERO_TRUST_DB_PATH": state / "zero-trust.sqlite3", "CASE_LOG_PATH": state / "cases.jsonl",
        "OUTBOX_LOG_PATH": state / "outbox.jsonl", "AWS_EC2_METADATA_DISABLED": "true",
    }
    fresh_file(env / "lab.env", "".join(f"{k}={v}\n" for k, v in settings.items()).encode())
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chown(state, user.pw_uid, user.pw_gid)
    return scope


def exercise(state, status_file, units, standby, scope, key, user):
    api_unit, sender_unit = units
    control, original = state / "control", state / "original"
    staged, package, recovery_key = state / "candidate", state / "package", state / "backup-key"
    cases = list(events(4))
    before, after = counts(), counts()
    with account(user):
        control.mkdir(mode=0o700)
        original.mkdir(mode=0o700)
        queue = LoginDeliverySpool(original / backup.QUEUE, **scope)
        old_audit = SQLiteAuditStore(original / backup.AUDIT)
        activation.initialize(control, queue.path, old_audit.path, **scope)
        for event, _ in cases[:2]:
            activation.stage_login(control, event, None)
        fresh_file(recovery_key, secrets.token_bytes(32))

    def ready(selected):
        current = json.loads(status_file.read_bytes())
        return current["scope_sha256"] == selected.status_scope_sha256 and current["values"]["pending"] == 0

    def pid(unit):
        return int(systemctl("show", unit, "--value", "--property=MainPID"))

    with httpx.Client(
        base_url=scope["origin"], headers={"X-API-Key": key}, trust_env=False, timeout=5,
    ) as api:
        systemctl("start", sender_unit)
        until(lambda: ready(queue))
        assert old_audit.integrity()["verified_lines"] == 2
        expected = {}
        for event, truth in cases:
            result = api.post("/analysis", json=event.analysis_payload())
            result.raise_for_status()
            expected[event.event_id] = result.json()
            record(before, truth, flagged(result.json()))

        first_api, first_sender = pid(api_unit), pid(sender_unit)
        assert first_api and first_sender
        systemctl("restart", api_unit)
        until(lambda: pid(api_unit) not in {0, first_api} and pid(sender_unit) not in {0, first_sender})
        until(lambda: ready(queue))
        assert old_audit.integrity()["verified_lines"] == 6

        systemctl("stop", api_unit)
        assert not pid(api_unit) and not pid(sender_unit)
        assert not status_file.exists()
        with account(user):
            for event, _ in cases[2:]:
                activation.stage_login(control, event, None)
            pin = backup.backup(queue.path, old_audit.path, package, recovery_key, **scope)["package_sha256"]
            backup.restore(package, pin, staged, recovery_key, **scope)
            approval = activation.approve(control, package, pin, staged, recovery_key, note="Verify service restart")
            assert activation.activate(control, approval, package, recovery_key) == 2

        systemctl("start", sender_unit)
        current = LoginDeliverySpool(staged / backup.QUEUE, **scope, create=False)
        until(lambda: ready(current))
        audit = SQLiteAuditStore.open_existing(staged / backup.AUDIT)
        assert queue.counts() == {"pending": 2, "held": 0}
        assert old_audit.integrity()["verified_lines"] == 6
        assert audit.integrity()["verified_lines"] == 8
        for event, truth in cases:
            body = LoginDeliveryRequest(event=event, tenant_id=scope["tenant_id"],
                                        collector_subject=scope["collector_subject"])
            response = api.post("/analysis/login-delivery", json=body.model_dump(mode="json"))
            response.raise_for_status()
            receipt = response.json()
            result = receipt["result"]
            assert receipt["duplicate"] and all(result[field] == expected[event.event_id][field] for field in FIELDS)
            record(after, truth, flagged(result))
        assert audit.integrity()["verified_lines"] == 8
        planned = move_to_standby(state, units, standby, current, audit, scope, api, user)
    assert before == after == {"tp": 2, "fp": 0, "fn": 0, "tn": 2, "inference_errors": 0}
    assert not (state / "unused-queue.sqlite3").exists() and not (state / "unused-audit.sqlite3").exists()
    return {
        "systemd_api_restart_restarted_sender": True, "systemd_api_stop_drained_processes_and_removed_status": True,
        "generation_2_used_by_both_units": True, "previous_generation_preserved": True,
        "status_bound_to_active_queue": True, "durable_records_on_api_restart": 6,
        "old_generation_audit_records": 6, "active_generation_audit_records": 8,
        "before": metrics(before), "after": metrics(after), "duplicate_analysis_or_audit_records": 0,
        "aws_calls": 0, "paid_api_calls": 0,
        "planned_host_handoff": planned,
    }


@contextmanager
def denied(message, error_type=activation.ActivationConflict):
    try:
        yield
    except error_type as error:
        assert message in str(error)
    else:
        raise AssertionError(f"Expected rejection containing {message!r}")


def move_to_standby(state, units, standby, queue, audit, scope, api, user):
    standby_units, standby_state, standby_status = standby
    control = state / "control"
    standby_control = standby_state / "control"
    package = state / "handoff.package"
    key_file = state / "backup-key"
    receipt = state / "handoff.json"
    cases = list(events(6))[4:]
    with account(user):
        standby_control.mkdir(mode=0o700)
        standby_id = handoff.prepare(standby_control)
        assert handoff.prepare(standby_control) == standby_id
        with denied("No committed source retirement"):
            handoff.publish(control, receipt)
        with denied("active.lock"):
            handoff.retire(control, "absent", package, key_file, standby_id)

    systemctl("stop", units[0])
    with account(user):
        for event, _ in cases:
            activation.stage_login(control, event, None)
        pin = backup.backup(queue.path, audit.path, package, key_file, **scope)["package_sha256"]
        staging = state / "handoff-candidate"
        backup.restore(package, pin, staging, key_file, **scope)
        approval = activation.approve(control, package, pin, staging, key_file, note="Planned standby transfer")
        handoff.retire(control, approval, package, key_file, standby_id)
        assert activation.status(control)["host_handoff"]["direction"] == "outgoing"
        with denied("retired"):
            activation.stage_login(control, cases[0][0], None)
        receipt_pin = handoff.publish(control, receipt)
        assert handoff.publish(control, state / "handoff-reissued.json") == receipt_pin

        received_package, received_key = standby_state / "handoff.package", standby_state / "backup-key"
        received_receipt = standby_state / "handoff.json"
        candidate = standby_state / "selected"
        for old, new in ((package, received_package), (key_file, received_key), (receipt, received_receipt)):
            fresh_file(new, old.read_bytes())
        backup.restore(received_package, pin, candidate, received_key, **scope)
        with denied("pin_mismatch", ValueError):
            handoff.receive(standby_control, received_receipt, "0" * 64, received_package, received_key, candidate)
        unrelated = standby_state / "unrelated-control"
        unrelated.mkdir(mode=0o700)
        handoff.prepare(unrelated)
        with denied("different prepared standby"):
            handoff.receive(unrelated, received_receipt, receipt_pin, received_package, received_key, candidate)

    # Try to start the retired source before the standby listens. A loopback
    # bind collision therefore cannot account for the rejection.
    systemctl("start", units[0])
    until(lambda: systemctl("show", units[0], "--value", "--property=Result") == "exit-code")
    journal = subprocess.run(
        ["journalctl", "--no-pager", "-n", "25", "-u", units[0]],
        capture_output=True, text=True, check=True, timeout=15,
    )
    assert "retired by an approved handoff" in journal.stdout
    systemctl("stop", units[0])
    with account(user):
        assert handoff.receive(
            standby_control, received_receipt, receipt_pin, received_package, received_key, candidate,
        ) == 3
        with denied("already initialized"):
            handoff.receive(standby_control, received_receipt, receipt_pin, received_package, received_key, candidate)
        assert activation.status(standby_control)["host_handoff"]["direction"] == "incoming"

    systemctl("start", standby_units[1])
    selected = LoginDeliverySpool(candidate / backup.QUEUE, **scope, create=False)

    def drained():
        report = json.loads(standby_status.read_bytes())
        return report["scope_sha256"] == selected.status_scope_sha256 and not report["values"]["pending"]

    until(drained)
    standby_audit = SQLiteAuditStore.open_existing(candidate / backup.AUDIT)
    assert standby_audit.integrity()["verified_lines"] == 10
    assert audit.integrity()["verified_lines"] == 8 and queue.counts() == {"pending": 2, "held": 0}
    for event, truth in cases:
        body = LoginDeliveryRequest(event=event, tenant_id=scope["tenant_id"],
                                    collector_subject=scope["collector_subject"])
        answer = api.post("/analysis/login-delivery", json=body.model_dump(mode="json"))
        answer.raise_for_status()
        assert answer.json()["duplicate"] and flagged(answer.json()["result"]) == truth
    assert standby_audit.integrity()["verified_lines"] == 10
    return {
        "scope": "two independent state directories and unit pairs on one WSL systemd host",
        "retirement_blocked_while_source_active": True, "retired_source_restart_failed_before_standby_started": True,
        "receipt_pin_and_standby_binding_checked": True, "received_handoff_could_not_be_reinitialized": True,
        "generation": 3, "replayed_standby_events": 2, "retained_audit_records": 8,
        "final_standby_audit_records": 10, "duplicate_analysis_or_audit_records": 0,
    }


def run(venv):
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("Run as root on a local Linux systemd test host")
    source = Path(__file__).resolve().parents[1]
    user = pwd.getpwnam("daemon")
    prefix = "zt-login-" + uuid4().hex[:12]
    with TemporaryDirectory(prefix=f"{prefix}-", dir="/run") as work:
        root = Path(work)
        root.chmod(0o755)
        code = root / "code"
        for name in ("app", "scripts"):
            shutil.copytree(source / name, code / name, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(venv, code / ".venv", symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        origin = f"http://127.0.0.1:{port}/"
        paths = []
        all_units = []
        states = []
        loaded = False
        try:
            instances = []
            key = secrets.token_urlsafe(32)
            for tag in (prefix, f"{prefix}-peer"):
                env = root / tag
                env.mkdir(mode=0o700)
                state_root = Path("/var/lib") / tag
                state_root.mkdir(mode=0o755, exist_ok=False)
                states.append(state_root)
                units, state, status_file = render(source, root, env, tag, user, paths)
                all_units.extend(units)
                instances.append((units, state, status_file))
                scope = fixture(root, env, state, origin, user, port, key)
            subprocess.run(["systemd-analyze", "verify", *map(str, paths)], check=True, timeout=30)
            systemctl("daemon-reload")
            loaded = True
            (units, state, status_file), standby = instances
            return exercise(state, status_file, units, standby, scope, key, user)
        except Exception:
            if loaded:
                subprocess.run(
                    ["journalctl", "--no-pager", "-n", "45", *[arg for unit in all_units for arg in ("-u", unit)]],
                    check=False, timeout=15,
                )
            raise
        finally:
            if loaded:
                systemctl("stop", *all_units)
            for path in paths:
                path.unlink()
            if loaded:
                systemctl("daemon-reload")
            for state_root in states:
                assert state_root.resolve() == state_root
                shutil.rmtree(state_root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--venv", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.venv)
    write(args.output, result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
