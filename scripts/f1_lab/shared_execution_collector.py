"""Read-only Linux service/proc collection. Never executes captured arguments."""

import base64
import hashlib
import os
import re
import stat
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.shared_execution_evidence import (
    ProcessObservation,
    ServiceEvent,
    ServiceProof,
    digest,
    proof_bytes,
)

PROC = Path("/proc")
READ_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "SYSTEMD_PAGER": "",
    "SYSTEMD_COLORS": "0",
}


def bounded(path, maximum):
    with Path(path).open("rb") as stream:
        body = stream.read(maximum + 1)
    require(len(body) <= maximum, "service_collection_bound")
    return body


def boot_id():
    value = uuid.UUID(bounded(PROC / "sys/kernel/random/boot_id", 64).decode().strip()).hex
    require(value != "0" * 32, "service_boot_id")
    return value


def process_tag(body, pid):
    text = body.decode("utf8", errors="strict")
    end = text.rfind(")")
    require(end > 0 and text[: text.index("(")].strip() == str(pid), "service_proc_pid")
    fields = text[end + 1 :].split()
    require(len(fields) >= 20 and fields[0] not in {"Z", "X", "x"}, "service_proc_state")
    parent, start = int(fields[1]), int(fields[19])
    require(0 <= parent < 4294967295 and start > 0, "service_proc_identity")
    return parent, start


def process_uids(body):
    rows = [
        line.split()[1:] for line in body.decode("ascii").splitlines() if line.startswith("Uid:")
    ]
    require(len(rows) == 1 and len(rows[0]) == 4, "service_proc_uid")
    values = tuple(int(value) for value in rows[0])
    require(all(0 <= n < 4294967295 for n in values), "service_proc_uid_range")
    return values


def optional_audit_id(path):
    try:
        raw = bounded(path, 32).decode("ascii").strip()
    except (OSError, UnicodeError):
        return None
    require(re.fullmatch(r"\d{1,10}", raw) is not None, "service_audit_identifier")
    value = int(raw)
    require(value <= 4294967295, "service_audit_identifier_range")
    return value if value < 4294967295 else None


def executable_hash(path):
    # /proc/PID/exe is intentionally a kernel magic link. Hash the open file,
    # compare inode metadata, and recheck the process identity around capture.
    with Path(path).open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 128 * 1024**2,
            "service_executable_bound",
        )
        total, result = 0, hashlib.sha256()
        while body := stream.read(1024**2):
            total += len(body)
            require(total <= 128 * 1024**2, "service_executable_growth")
            result.update(body)
        after = os.fstat(stream.fileno())
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and total == before.st_size,
            "service_executable_changed",
        )
        return result.hexdigest()


def snapshot_process(pid):
    require(os.name == "posix" and type(pid) is int and 0 < pid < 4294967295, "service_linux_pid")
    root = PROC / str(pid)
    boot = boot_id()
    tag = process_tag(bounded(root / "stat", 65536), pid)
    uids = process_uids(bounded(root / "status", 65536))
    command = bounded(root / "cmdline", 65536)
    require(
        command.endswith(b"\0") and 1 <= command.count(b"\0") <= 256 and command != b"\0",
        "service_command_complete",
    )
    executable = executable_hash(root / "exe")
    login, session = optional_audit_id(root / "loginuid"), optional_audit_id(root / "sessionid")
    parent_ref = None
    if tag[0] > 0:
        parent = PROC / str(tag[0])
        try:
            ptag = process_tag(bounded(parent / "stat", 65536), tag[0])
            pexe = executable_hash(parent / "exe")
            require(
                ptag == process_tag(bounded(parent / "stat", 65536), tag[0]) and ptag[1] <= tag[1],
                "service_parent_changed",
            )
            parent_ref = digest([boot, tag[0], ptag[1], pexe])
        except (OSError, ValueError):
            pass  # Missing parent does not become an authenticated initiator.
    require(
        tag == process_tag(bounded(root / "stat", 65536), pid)
        and uids == process_uids(bounded(root / "status", 65536))
        and command == bounded(root / "cmdline", 65536)
        and executable == executable_hash(root / "exe")
        and boot_id() == boot,
        "service_process_changed_during_collection",
    )
    observation = ProcessObservation(
        pid=pid,
        start_ticks=tag[1],
        parent_pid=tag[0],
        real_uid=uids[0],
        effective_uid=uids[1],
        login_uid=login,
        audit_session_id=session,
        executable_sha256=executable,
        command_sha256=hashlib.sha256(command).hexdigest(),
        argument_count=command.count(b"\0"),
        parent_ref_sha256=parent_ref,
    )
    return boot, observation


def journal_event(raw, *, tenant_id, server_id):
    """Only journald's trusted underscore fields; no fallback from unit name.

    Callers must obtain input from the local journal, not a client-posted JSON
    document. Plain audit SERVICE_START/STOP lacks these bindings and returns
    unavailable; a collected config's mtime is not a live event timestamp.
    """
    try:
        require(type(raw) is bytes and 0 < len(raw) <= MAX_ROW, "service_journal_bound")
        row = decode(raw)
        require(
            isinstance(row, dict)
            and all(
                isinstance(row.get(key), str)
                for key in (
                    "_BOOT_ID",
                    "_SYSTEMD_INVOCATION_ID",
                    "_SYSTEMD_UNIT",
                    "_PID",
                    "__CURSOR",
                    "__REALTIME_TIMESTAMP",
                )
            ),
            "service_journal_native_fields",
        )
        require(
            0 < len(row["__CURSOR"]) <= 2048
            and re.fullmatch(r"\d{1,18}", row["__REALTIME_TIMESTAMP"])
            and re.fullmatch(r"\d{1,10}", row["_PID"]),
            "service_journal_native_values",
        )
        return ServiceEvent(
            tenant_id=tenant_id,
            server_id=server_id,
            unit=row["_SYSTEMD_UNIT"],
            boot_id=row["_BOOT_ID"],
            invocation_id=row["_SYSTEMD_INVOCATION_ID"],
            process_id=int(row["_PID"]),
            event_id=digest([server_id, row["__CURSOR"]]),
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            observed_at=datetime.fromtimestamp(int(row["__REALTIME_TIMESTAMP"]) / 1000000, UTC),
            mode="systemd",
            collection_basis="native_journal",
        )
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def manager_state(unit):
    require(
        isinstance(unit, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service", unit),
        "service_unit",
    )
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=Id,MainPID,InvocationID",
            "--",
            unit,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
        env=READ_ENV,
    )
    require(result.returncode == 0 and len(result.stdout) <= 8192, "service_manager_unavailable")
    pairs = [line.split("=", 1) for line in result.stdout.decode("ascii").splitlines()]
    require(
        len(pairs) == 3 and all(len(p) == 2 for p in pairs) and len({p[0] for p in pairs}) == 3,
        "service_manager_fields",
    )
    values = dict(pairs)
    require(
        set(values) == {"Id", "MainPID", "InvocationID"}
        and values["Id"] == unit
        and re.fullmatch(r"[a-f0-9]{32}", values["InvocationID"])
        and values["InvocationID"] != "0" * 32
        and re.fullmatch(r"\d{1,10}", values["MainPID"])
        and 0 < int(values["MainPID"]) < 4294967295,
        "service_manager_binding",
    )
    return int(values["MainPID"]), values["InvocationID"]


def runtime_proof(event, observation, private_key, *, source_id, key_id, observed_at=None):
    event = ServiceEvent.model_validate(event.model_dump())
    observation = ProcessObservation.model_validate(observation.model_dump())
    observed_at = datetime.now(UTC) if observed_at is None else observed_at
    require(
        isinstance(event, ServiceEvent)
        and observation.pid == event.process_id
        and event.observed_at <= observed_at <= event.observed_at + timedelta(seconds=5),
        "service_capture_window",
    )
    proof = ServiceProof(
        tenant_id=event.tenant_id,
        source_id=source_id,
        key_id=key_id,
        event_sha256=event.sha256,
        observed_at=observed_at,
        issued_at=observed_at,
        expires_at=observed_at + timedelta(seconds=30),
        observation=observation,
        signature="A" * 86,
    )
    signature = private_key.sign(proof_bytes(proof))
    return proof.model_copy(
        update={"signature": base64.urlsafe_b64encode(signature).decode().rstrip("=")}
    )


def collect_systemd(event, private_key, *, source_id, key_id):
    event = ServiceEvent.model_validate(event.model_dump())
    require(event.mode == "systemd", "service_real_manager_mode")
    before = manager_state(event.unit)
    require(before == (event.process_id, event.invocation_id), "service_manager_event_mismatch")
    boot, observation = snapshot_process(before[0])
    require(
        boot == event.boot_id and manager_state(event.unit) == before, "service_manager_changed"
    )
    return runtime_proof(event, observation, private_key, source_id=source_id, key_id=key_id)


def collect_current_systemd(unit, private_key, *, tenant_id, server_id, source_id, key_id):
    """Fresh manager observation, not a backfilled historical SERVICE_START."""
    pid, invocation = manager_state(unit)
    observed_at = datetime.now(UTC)
    boot = boot_id()
    capture_id = digest(["systemd-manager-snapshot", uuid.uuid4().hex])
    receipt = {
        "unit": unit,
        "pid": pid,
        "invocation_id": invocation,
        "boot_id": boot,
        "observed_at": observed_at.isoformat(),
        "capture_id": capture_id,
    }
    event = ServiceEvent(
        tenant_id=tenant_id,
        server_id=server_id,
        unit=unit,
        boot_id=boot,
        invocation_id=invocation,
        process_id=pid,
        event_id=capture_id,
        raw_sha256=digest(receipt),
        observed_at=observed_at,
        mode="systemd",
        collection_basis="manager_snapshot",
    )
    return event, collect_systemd(event, private_key, source_id=source_id, key_id=key_id)


def collect_latest_systemd(unit, private_key, *, tenant_id, server_id, source_id, key_id):
    # Validate before constructing the fixed read-only command; no shell or
    # service start/stop/reload operation is exposed by this collector.
    manager_state(unit)
    fields = "_BOOT_ID,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT,_PID,__CURSOR,__REALTIME_TIMESTAMP"
    result = subprocess.run(
        [
            "/usr/bin/journalctl",
            "--no-pager",
            "--boot=0",
            "--lines=32",
            "--output=json",
            "--output-fields=" + fields,
            "--unit=" + unit,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
        env=READ_ENV,
    )
    require(
        result.returncode == 0 and len(result.stdout) <= 2 * 1024**2, "service_journal_unavailable"
    )
    for raw in reversed(result.stdout.splitlines(keepends=True)):
        event = journal_event(raw, tenant_id=tenant_id, server_id=server_id)
        if event is not None and event.unit == unit:
            return event, collect_systemd(event, private_key, source_id=source_id, key_id=key_id)
    raise ValueError("service_native_event_unavailable")
