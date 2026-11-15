"""Opt-in bounded outbox aggregates. Queue health never grants execution."""

import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.capture_archive import MAX_BYTES, MAX_RECORDS
from scripts.f1_lab.collector_status_bridge import MAX_REPORT, read_public, scope_hash, timestamp
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical

SCHEMA = "zt-exec-outbox-status-1"
REPORT_TTL = 60
COUNTERS = {"records", "raw_bytes", "pending", "published"}


def validate(value, binding):
    require(type(binding) is str and re.fullmatch(r"[a-f0-9]{64}", binding), "outbox_status_scope")
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "scope_sha256",
            "checked_at",
            "state",
            "values",
            "oldest_pending_at",
            "automatic_execution_allowed",
            "authorization_asserted",
        },
        "outbox_status_shape",
    )
    require(
        value["schema"] == SCHEMA
        and value["scope_sha256"] == binding
        and value["state"] in {"ready", "pending", "unavailable"}
        and value["automatic_execution_allowed"] is False
        and value["authorization_asserted"] is False,
        "outbox_status_binding",
    )
    checked = timestamp(value["checked_at"])
    data = value["values"]
    require(
        type(data) is dict
        and set(data) == (set() if value["state"] == "unavailable" else COUNTERS),
        "outbox_status_values",
    )
    if data:
        require(
            all(
                type(v) is int and 0 <= v <= MAX_RECORDS
                for k, v in data.items()
                if k != "raw_bytes"
            )
            and type(data["raw_bytes"]) is int
            and 0 <= data["raw_bytes"] <= MAX_BYTES
            and data["pending"] + data["published"] == data["records"]
            and (value["state"] == "pending") == (data["pending"] > 0),
            "outbox_status_counts",
        )
        if data["pending"]:
            require(
                value["oldest_pending_at"] is not None
                and timestamp(value["oldest_pending_at"]) <= checked,
                "outbox_status_age",
            )
        else:
            require(value["oldest_pending_at"] is None, "outbox_status_no_pending")
    else:
        require(value["oldest_pending_at"] is None, "outbox_status_unavailable")
    return checked


def report(scope, values=None, *, now=None):
    now = datetime.now(UTC) if now is None else now
    oldest = values["oldest_pending_at"] if values is not None else None
    value = {
        "schema": SCHEMA,
        "scope_sha256": scope_hash(scope),
        "checked_at": now.isoformat(),
        "state": "unavailable" if values is None else "pending" if values["pending"] else "ready",
        "values": {k: values[k] for k in COUNTERS} if values is not None else {},
        "oldest_pending_at": oldest.isoformat() if oldest is not None else None,
        "automatic_execution_allowed": False,
        "authorization_asserted": False,
    }
    validate(value, value["scope_sha256"])
    return value


def publish(path, value):
    path = Path(path)
    checked = validate(value, value["scope_sha256"])
    info = path.parent.lstat()
    require(
        path.is_absolute()
        and not path.is_symlink()
        and not path.parent.is_symlink()
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and not stat.S_IMODE(info.st_mode) & 0o022,
        "outbox_status_public_parent",
    )
    if path.exists():
        require(
            path.stat().st_uid == os.geteuid()
            and validate(read_public(path), value["scope_sha256"]) <= checked,
            "outbox_status_publication_clock",
        )
    raw = canonical(value) + b"\n"
    require(len(raw) <= MAX_REPORT, "outbox_status_public_bound")
    fd, temporary = tempfile.mkstemp(prefix=".outbox-status-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), 0o644)
            stream.flush()
            os.fsync(stream.fileno())
        require(not path.is_symlink(), "outbox_status_destination_link")
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_profile(path):
    value = read_public(path)
    require(
        type(value) is dict
        and set(value)
        == {"schema", "scope_sha256", "status_file", "max_pending_age_seconds", "max_records"}
        and value["schema"] == "zt-exec-outbox-metrics-profile-1"
        and type(value["scope_sha256"]) is str
        and re.fullmatch(r"[a-f0-9]{64}", value["scope_sha256"]),
        "outbox_profile",
    )
    require(
        type(value["status_file"]) is str
        and 0 < len(value["status_file"]) <= 4096
        and Path(value["status_file"]).is_absolute()
        and type(value["max_pending_age_seconds"]) is int
        and 1 <= value["max_pending_age_seconds"] <= 86400
        and type(value["max_records"]) is int
        and 1 <= value["max_records"] <= MAX_RECORDS,
        "outbox_profile_policy",
    )
    return value


def metrics(profile, *, now=None):
    now = datetime.now(UTC) if now is None else now
    rows = ["# TYPE secops_exec_outbox_bridge_enabled gauge", "secops_exec_outbox_bridge_enabled 1"]
    value = None
    valid = False
    try:
        value = read_public(profile["status_file"])
        checked = validate(value, profile["scope_sha256"])
        require(
            timedelta(0) <= now - checked < timedelta(seconds=REPORT_TTL), "outbox_status_expired"
        )
        valid = value["state"] != "unavailable"
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        pass
    rows.append(f"secops_exec_outbox_status_success {int(valid)}")
    if valid:
        data = value["values"]
        for key, count in data.items():
            rows.append(f"secops_exec_outbox_{key} {count}")
        age = (
            (now - timestamp(value["oldest_pending_at"])).total_seconds() if data["pending"] else 0
        )
        rows.extend(
            [
                f"secops_exec_outbox_oldest_pending_age_seconds {age}",
                f"secops_exec_outbox_pending_overdue {int(data['pending'] > 0 and age > profile['max_pending_age_seconds'])}",
                f"secops_exec_outbox_capacity_pressure {int(data['records'] >= profile['max_records'])}",
            ]
        )
    return "\n".join(rows) + "\n"
