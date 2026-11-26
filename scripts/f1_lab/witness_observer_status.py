"""Opt-in cached witness monitoring. Unsigned local aggregates confer no trust.

Scrapes never open the audit database or signing key. Producers retain original
observation times; cache checks cannot refresh a stale observation. Publication
requires POSIX ownership/locking/directory durability, not Windows lab chmod.
"""

import math
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.services import audit_witness as witness
from app.services import audit_witness_observer as observer
from app.services.audit_transfer import AuditTransferError, require
from app.services.federated_audit import AuditQueryUnavailable
from scripts.f1_lab import status_publication
from scripts.f1_lab.collector_status_bridge import read_public, timestamp

SCHEMA = "zt-witness-observer-status-2"
LEGACY_SCHEMA = "zt-witness-observer-status-1"
PROFILE_SCHEMA = "zt-witness-observer-metrics-profile-1"
GENERATION_SCHEMA = "zt-witness-observer-status-3"
GENERATION_PROFILE_SCHEMA = "zt-witness-observer-metrics-profile-2"
TTL = 30
STATES = (
    "healthy", "offline", "uninitialized", "pending", "stale", "unobserved",
    "clock_regression", "witness_advanced", "capacity_pressure", "capacity_exhausted", "unavailable",
)
FIELDS = {
    "state", "live_checked", "audit_minimum_verified", "observed_at", "pending_started_at",
    "max_age_seconds", "capacity_warning", "anchor_count", "remaining_receipts", "unobserved_rows",
    "interval_seconds",
}
ERRORS = (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError, sqlite3.Error)


def validate(value, profile_sha256, minimum_receipt, record_sha256=None):
    require(witness._hex(profile_sha256) and witness._hex(minimum_receipt), "witness_status_pins")
    fields = {
        "schema", "profile_sha256", "minimum_receipt", "checked_at", "values", "cycle_success",
        "independent_storage_verified", "automatic_activation_allowed", "authorization_asserted",
    }
    schemas = {SCHEMA, LEGACY_SCHEMA}
    if record_sha256 is not None:
        require(witness._hex(record_sha256), "witness_generation_pin")
        fields.add("record_sha256")
        schemas = {GENERATION_SCHEMA}
    require(type(value) is dict and set(value) == fields, "witness_status_shape")
    require(value["schema"] in schemas and value.get("record_sha256") == record_sha256
            and value["profile_sha256"] == profile_sha256
            and value["minimum_receipt"] == minimum_receipt
            and all(value[k] is False for k in (
                "independent_storage_verified", "automatic_activation_allowed", "authorization_asserted"
            )), "witness_status_binding")
    checked = timestamp(value["checked_at"])
    require(value["cycle_success"] is None or type(value["cycle_success"]) is bool,
            "witness_status_cycle")
    data = value["values"]
    fields = FIELDS - {"interval_seconds"} if value["schema"] == LEGACY_SCHEMA else FIELDS
    require(type(data) is dict and (not data or set(data) == fields), "witness_status_values")
    if data:
        require(type(data["state"]) is str and data["state"] in STATES
                and all(type(data[k]) is bool for k in ("live_checked", "audit_minimum_verified")),
                "witness_status_state")
        interval = data.get("interval_seconds", 1)
        require(type(interval) is int and 1 <= interval <= 3600
                and type(data["max_age_seconds"]) is int and 2 * interval <= data["max_age_seconds"] <= 86400
                and type(data["capacity_warning"]) is int
                and 0 <= data["capacity_warning"] <= witness.MAX_RECEIPTS
                and type(data["anchor_count"]) is int
                and 0 <= data["anchor_count"] <= witness.MAX_RECEIPTS,
                "witness_status_policy")
        for key, maximum in (("remaining_receipts", witness.MAX_RECEIPTS),
                             ("unobserved_rows", 1_000_000)):
            require(data[key] is None or (type(data[key]) is int and 0 <= data[key] <= maximum),
                    "witness_status_count")
        for key in ("observed_at", "pending_started_at"):
            if data[key] is not None:
                instant = observer._time(data[key])
                require(instant <= checked or data["state"] == "clock_regression",
                        "witness_status_future_time")
        require(data["state"] != "pending" or data["pending_started_at"] is not None,
                "witness_status_pending_time_missing")
        if data["state"] == "healthy":
            require(data["live_checked"] and data["audit_minimum_verified"]
                    and data["observed_at"] is not None and data["pending_started_at"] is None
                    and data["unobserved_rows"] == 0 and data["remaining_receipts"] is not None
                    and data["remaining_receipts"] > data["capacity_warning"]
                    and timedelta(0) <= checked - observer._time(data["observed_at"])
                    <= timedelta(seconds=data["max_age_seconds"]), "witness_status_false_healthy")
    return checked


def report(profile_sha256, minimum_receipt, state=None, *, now=None, cycle_success=None,
           record_sha256=None):
    value = {
        "schema": SCHEMA, "profile_sha256": profile_sha256, "minimum_receipt": minimum_receipt,
        "checked_at": (datetime.now(UTC) if now is None else now).isoformat(),
        "values": {} if state is None else {k: state.get(k) for k in FIELDS},
        "cycle_success": cycle_success,
        "independent_storage_verified": False, "automatic_activation_allowed": False,
        "authorization_asserted": False,
    }
    if record_sha256 is not None:
        value.update(schema=GENERATION_SCHEMA, record_sha256=record_sha256)
    validate(value, profile_sha256, minimum_receipt, record_sha256)
    return value


def inspect(directory, profile_sha256, minimum_receipt, *, cycle_success=None, record_sha256=None):
    try:
        state = observer.status(directory, profile_sha256, minimum_receipt=minimum_receipt)
        return report(profile_sha256, minimum_receipt, state, cycle_success=cycle_success,
                      record_sha256=record_sha256)
    except ERRORS:
        return report(profile_sha256, minimum_receipt, cycle_success=cycle_success,
                      record_sha256=record_sha256)


def publish(path, value):
    return status_publication.publish(
        path, value, lambda doc: validate(
            doc, value["profile_sha256"], value["minimum_receipt"], value.get("record_sha256")
        )
    )


def load_profile(path):
    value = read_public(path)
    require(type(value) is dict, "witness_metrics_profile")
    fields = {"schema", "profile_sha256", "minimum_receipt", "status_file"}
    generation = value.get("schema") == GENERATION_PROFILE_SCHEMA
    if generation:
        fields.add("record_sha256")
    require(set(value) == fields and value["schema"] in {PROFILE_SCHEMA, GENERATION_PROFILE_SCHEMA}
            and (not generation or witness._hex(value["record_sha256"]))
            and witness._hex(value["profile_sha256"]) and witness._hex(value["minimum_receipt"])
            and isinstance(value["status_file"], str) and 0 < len(value["status_file"]) <= 4096
            and Path(value["status_file"]).is_absolute(), "witness_metrics_profile")
    return value


def metrics(profile, *, now=None):
    try:
        value = read_public(profile["status_file"])
    except (AuditTransferError, ValueError, OSError, TypeError, KeyError, RecursionError):
        value = None
    return render_report(profile, value, now=now)


def render_report(profile, value, *, now=None):
    """Pure validation/rendering, separate from native file-permission checks."""
    now = datetime.now(UTC) if now is None else now
    rows = ["# TYPE secops_witness_bridge_enabled gauge", "secops_witness_bridge_enabled 1"]
    try:
        checked = validate(value, profile["profile_sha256"], profile["minimum_receipt"],
                           profile.get("record_sha256"))
        require(bool(value["values"]), "witness_status_no_observation")
        interval = value["values"].get("interval_seconds", 1)
        # Permit the configured collection cadence, not an arbitrary 30s gap in
        # a healthy default 60s worker. Observation age is checked separately.
        ttl = max(TTL, 2 * interval)
        require(timedelta(0) <= now - checked <= timedelta(seconds=ttl), "witness_status_expired")
    except (AuditTransferError, ValueError, OSError, TypeError, KeyError, RecursionError):
        rows += ["secops_witness_status_success 0", "secops_witness_observation_healthy 0"]
        return "\n".join(rows) + "\n"
    data = value["values"]
    state = data["state"]
    age = None if data["observed_at"] is None else (
        now - observer._time(data["observed_at"])).total_seconds()
    if age is not None and age < 0:
        state = "clock_regression"
    elif state == "healthy" and age > data["max_age_seconds"]:
        state = "stale"
    pending_age = None if data["pending_started_at"] is None else (
        now - observer._time(data["pending_started_at"])).total_seconds()
    action_required = state not in {"healthy", "capacity_pressure"}
    if state == "pending":
        action_required = pending_age is None or pending_age > 2 * interval or (
            age is not None and age > data["max_age_seconds"])
    elif state == "unobserved":
        action_required = age is None or age > data["max_age_seconds"]
    # No cadence allowance can replenish a verified exhausted signer. Keep old
    # pending/new-row facts intact while surfacing this terminal condition now.
    if data["remaining_receipts"] == 0:
        action_required = True
    rows += ["secops_witness_status_success 1",
             f'secops_witness_observation_healthy {int(state == "healthy")}',
             f"secops_witness_observation_action_required {int(action_required)}",
             f"secops_witness_collection_interval_seconds {interval}",
             f"secops_witness_anchor_count {data['anchor_count']}"]
    if value["cycle_success"] is not None:
        rows.append(f'secops_witness_last_cycle_success {int(value["cycle_success"])}')
    for name in STATES:
        rows.append(f'secops_witness_state{{state="{name}"}} {int(state == name)}')
    for key in ("remaining_receipts", "unobserved_rows"):
        if data[key] is not None:
            rows.append(f"secops_witness_{key} {data[key]}")
    if age is not None and age >= 0 and math.isfinite(age):
        rows.append(f"secops_witness_observation_age_seconds {age}")
    if pending_age is not None and pending_age >= 0:
        rows.append(f"secops_witness_pending_age_seconds {pending_age}")
    return "\n".join(rows) + "\n"
