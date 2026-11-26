"""Publish and export a bounded, keyless summary of the login delivery queue."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.services.audit_transfer import AuditTransferError, require
from app.services.collector_spool import SpoolBindingMismatch, SpoolUnavailable
from scripts.f1_lab import status_publication
from scripts.f1_lab.collector_status_bridge import read_public, timestamp
from scripts.login_delivery_spool import MAX_LOGIN_QUEUE_RECORDS

SCHEMA = "zt-login-queue-status-1"
PROFILE_SCHEMA = "zt-login-queue-metrics-profile-1"
REPORT_TTL = timedelta(seconds=30)
STATES = ("pending", "held")
COUNTERS = {*STATES, "pending_age_unknown", "held_age_unknown"}
TIMES = {"oldest_pending_at", "oldest_held_at", "retry_at"}
ERRORS = (AuditTransferError, OSError, ValueError, TypeError, RecursionError, KeyError, OverflowError)


def validate(value, expected_scope):
    require(
        isinstance(expected_scope, str) and re.fullmatch(r"[a-f0-9]{64}", expected_scope)
        and type(value) is dict and set(value) == {"schema", "scope_sha256", "checked_at", "values"}
        and value["schema"] == SCHEMA and value["scope_sha256"] == expected_scope,
        "login_queue_status_binding",
    )
    checked = timestamp(value["checked_at"])
    data = value["values"]
    require(type(data) is dict and (not data or set(data) == (COUNTERS | TIMES)), "login_queue_status_shape")
    if not data:
        return checked
    require(
        all(type(data[name]) is int and 0 <= data[name] <= MAX_LOGIN_QUEUE_RECORDS for name in COUNTERS)
        and data["pending"] + data["held"] <= MAX_LOGIN_QUEUE_RECORDS,
        "login_queue_status_counts",
    )
    for state in STATES:
        unknown = data[f"{state}_age_unknown"]
        oldest = data[f"oldest_{state}_at"]
        require(
            0 <= unknown <= data[state]
            and ((oldest is None and unknown == data[state])
                 or (unknown < data[state] and oldest is not None and timestamp(oldest) <= checked)),
            "login_queue_status_age",
        )
    require(
        (data["retry_at"] is None and not data["pending"])
        or (data["pending"] > 0 and data["retry_at"] is not None
            and timestamp(data["retry_at"]) <= checked + timedelta(hours=1)),
        "login_queue_status_retry",
    )
    return checked


def publish_queue_status(queue, path, *, now=None):
    try:
        data = queue.status_snapshot()
    except (*ERRORS, SpoolUnavailable, SpoolBindingMismatch):
        data = {}
    checked = datetime.now(UTC) if now is None else now
    scope = queue.status_scope_sha256
    value = {"schema": SCHEMA, "scope_sha256": scope, "checked_at": checked.isoformat(), "values": data}
    try:
        validate(value, scope)
    except ERRORS:
        value["values"] = {}
    status_publication.publish(path, value, lambda doc: validate(doc, scope))


def load_profile(path):
    value = read_public(path)
    require(
        type(value) is dict and set(value) == {
            "schema", "scope_sha256", "status_file", "max_pending_age_seconds", "capacity_warning_records",
        }
        and value["schema"] == PROFILE_SCHEMA
        and isinstance(value["scope_sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", value["scope_sha256"])
        and isinstance(value["status_file"], str) and 0 < len(value["status_file"]) <= 4096
        and Path(value["status_file"]).is_absolute()
        and type(value["max_pending_age_seconds"]) is int and 1 <= value["max_pending_age_seconds"] <= 86400
        and type(value["capacity_warning_records"]) is int
        and 1 <= value["capacity_warning_records"] <= MAX_LOGIN_QUEUE_RECORDS,
        "login_queue_metrics_profile",
    )
    return value


def metrics(profile, *, now=None):
    now = datetime.now(UTC) if now is None else now
    rows = ["# TYPE secops_login_queue_bridge_enabled gauge", "secops_login_queue_bridge_enabled 1"]
    try:
        value = read_public(profile["status_file"])
        checked = validate(value, profile["scope_sha256"])
        data = value["values"]
        require(timedelta(0) <= now - checked < REPORT_TTL and bool(data), "login_queue_report_unavailable")
    except ERRORS:
        return "\n".join(rows + ["secops_login_queue_status_success 0"]) + "\n"

    rows.append("secops_login_queue_status_success 1")
    for state in STATES:
        rows.append(f"secops_login_queue_{state} {data[state]}")
        rows.append(f"secops_login_queue_{state}_age_unknown {data[state + '_age_unknown']}")
        oldest = data[f"oldest_{state}_at"]
        if oldest is not None or data[state] == 0:
            age = (now - timestamp(oldest)).total_seconds() if oldest is not None else 0
            rows.append(f"secops_login_queue_oldest_{state}_age_seconds {age}")
    oldest = data["oldest_pending_at"]
    overdue = oldest is not None and (now - timestamp(oldest)).total_seconds() > profile["max_pending_age_seconds"]
    retry = max(0, (timestamp(data["retry_at"]) - now).total_seconds()) if data["retry_at"] else 0
    pressure = data["pending"] + data["held"] >= profile["capacity_warning_records"]
    rows.extend([
        f"secops_login_queue_pending_attention {int(overdue or data['pending_age_unknown'] > 0)}",
        f"secops_login_queue_retry_wait_seconds {retry}",
        f"secops_login_queue_capacity_pressure {int(pressure)}",
    ])
    return "\n".join(rows) + "\n"
