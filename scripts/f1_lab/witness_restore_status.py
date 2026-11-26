"""Keyless pinned restore aggregates, distinct from live observation health."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.services import audit_witness as witness
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import AuditTransferError, require
from app.services.federated_audit import AuditQueryUnavailable
from scripts.f1_lab import status_publication
from scripts.f1_lab.collector_status_bridge import read_public, timestamp

SCHEMA = "zt-witness-restore-status-1"
PROFILE_SCHEMA = "zt-witness-restore-metrics-profile-1"
TTL = 30
PINS = ("profile_sha256", "minimum_receipt", "backup_sha256", "restore_receipt_sha256")
FALSE_FLAGS = ("decryption_checked", "live_source_checked", "independent_storage_verified",
               "automatic_activation_allowed")
VALUES = {"backup_created_at", "restore_started_at", "snapshot_anchor_count", "current_anchor_count", "pending"}
ERRORS = (AuditTransferError, AuditQueryUnavailable, OSError, ValueError, TypeError, RecursionError, sqlite3.Error)


def validate(value, binding):
    require(all(witness._hex(binding.get(k)) for k in PINS), "witness_restore_status_pins")
    require(type(value) is dict and set(value) == {
        "schema", "checked_at", "values", *PINS, *FALSE_FLAGS
    } and value["schema"] == SCHEMA and all(value[k] == binding[k] for k in PINS)
            and all(value[k] is False for k in FALSE_FLAGS), "witness_restore_status_binding")
    checked = timestamp(value["checked_at"])
    data = value["values"]
    require(type(data) is dict and (not data or set(data) == VALUES), "witness_restore_status_values")
    if data:
        require(timestamp(data["backup_created_at"]) <= timestamp(data["restore_started_at"]) <= checked,
                "witness_restore_status_chronology")
        require(type(data["snapshot_anchor_count"]) is int and type(data["current_anchor_count"]) is int
                and 0 <= data["snapshot_anchor_count"] <= data["current_anchor_count"] <= witness.MAX_RECEIPTS
                and type(data["pending"]) is bool, "witness_restore_status_counts")
    return checked


def report(binding, proof=None, *, now=None):
    value = {"schema": SCHEMA, "checked_at": (datetime.now(UTC) if now is None else now).isoformat(),
             **{k: binding[k] for k in PINS}, **dict.fromkeys(FALSE_FLAGS, False), "values": {}}
    if proof is not None:
        require(proof["ciphertext_pin_verified"] is True and proof["restore_receipt_pin_verified"] is True
                and proof["signed_snapshot_minimum_present"] is True
                and all(proof[k] is False for k in FALSE_FLAGS), "witness_restore_proof_flags")
        value["values"] = {"backup_created_at": proof["backup_created_at"],
                           "restore_started_at": proof["restore_started_at"],
                           "snapshot_anchor_count": proof["snapshot_scope"]["anchor_count"],
                           "current_anchor_count": proof["current_scope"]["anchor_count"],
                           "pending": proof["current_scope"]["pending"]}
    validate(value, binding)
    return value


def inspect(package, directory, binding):
    try:
        proof = backup.inspect_restore(package, directory, binding["backup_sha256"],
                                       binding["restore_receipt_sha256"], binding["profile_sha256"],
                                       binding["minimum_receipt"])
        return report(binding, proof)
    except ERRORS:
        return report(binding)


def publish(path, value):
    return status_publication.publish(path, value, lambda doc: validate(doc, value))


def load_profile(path):
    value = read_public(path)
    require(type(value) is dict and set(value) == {
        "schema", "status_file", "max_backup_age_seconds", "max_restore_age_seconds", *PINS
    } and value["schema"] == PROFILE_SCHEMA and all(witness._hex(value[k]) for k in PINS)
            and isinstance(value["status_file"], str) and 0 < len(value["status_file"]) <= 4096
            and Path(value["status_file"]).is_absolute(), "witness_restore_metrics_profile")
    for key, maximum in (("max_backup_age_seconds", 604800), ("max_restore_age_seconds", 2592000)):
        require(type(value[key]) is int and 60 <= value[key] <= maximum, "witness_restore_metrics_age")
    return value


def render_report(profile, value, *, now=None):
    now = datetime.now(UTC) if now is None else now
    rows = ["# TYPE secops_witness_restore_bridge_enabled gauge", "secops_witness_restore_bridge_enabled 1"]
    try:
        checked = validate(value, profile)
        require(timedelta(0) <= now - checked <= timedelta(seconds=TTL) and bool(value["values"]),
                "witness_restore_status_expired")
        data = value["values"]
        backup_age = (now - timestamp(data["backup_created_at"])).total_seconds()
        restore_age = (now - timestamp(data["restore_started_at"])).total_seconds()
        require(0 <= backup_age and 0 <= restore_age, "witness_restore_age_regressed")
    except (AuditTransferError, ValueError, OSError, TypeError, KeyError, RecursionError):
        return "\n".join(rows + ["secops_witness_restore_status_success 0"]) + "\n"
    rows += ["secops_witness_restore_status_success 1",
             f"secops_witness_restore_backup_age_seconds {backup_age}",
             f"secops_witness_restore_review_age_seconds {restore_age}",
             f"secops_witness_restore_recent {int(backup_age <= profile['max_backup_age_seconds'] and restore_age <= profile['max_restore_age_seconds'])}",
             f"secops_witness_restore_snapshot_anchor_count {data['snapshot_anchor_count']}",
             f"secops_witness_restore_current_anchor_count {data['current_anchor_count']}",
             f"secops_witness_restore_pending {int(data['pending'])}"]
    return "\n".join(rows) + "\n"


def metrics(profile, *, now=None):
    try:
        value = read_public(profile["status_file"])
    except (AuditTransferError, OSError, ValueError, TypeError, RecursionError):
        value = None
    return render_report(profile, value, now=now)
