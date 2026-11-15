"""Pinned backup/review integrity aggregates; no keys, grants or automatic pin updates."""

import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.capture_backup import (
    MAX_CIPHERTEXT,
    CaptureBackup,
    Manifest,
    aware,
    pinned,
    private_directory,
)
from scripts.f1_lab.collector_status_bridge import MAX_REPORT, read_public, scope_hash
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical

SCHEMA = "zt-backup-recovery-status-1"
REPORT_TTL = 180
VALUES = {"snapshot_at", "backup_at", "restored_at", "records", "raw_bytes"}


def validate(value, binding):
    require(type(binding) is str and re.fullmatch(r"[a-f0-9]{64}", binding), "backup_status_scope")
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "scope_sha256",
            "checked_at",
            "state",
            "values",
            "automatic_activation_allowed",
            "authenticity_or_freshness_asserted",
        },
        "backup_status_shape",
    )
    require(
        value["schema"] == SCHEMA
        and value["scope_sha256"] == binding
        and type(value["state"]) is str
        and value["state"] in {"verified", "unavailable"}
        and value["automatic_activation_allowed"] is False
        and value["authenticity_or_freshness_asserted"] is False,
        "backup_status_binding",
    )
    checked = aware(value["checked_at"])
    data = value["values"]
    require(
        type(data) is dict and set(data) == (VALUES if value["state"] == "verified" else set()),
        "backup_status_values",
    )
    if data:
        require(
            aware(data["snapshot_at"])
            <= aware(data["backup_at"])
            <= aware(data["restored_at"])
            <= checked,
            "backup_status_chronology",
        )
        require(
            type(data["records"]) is int
            and 0 <= data["records"] <= 10000
            and type(data["raw_bytes"]) is int
            and 0 <= data["raw_bytes"] <= 1024**3,
            "backup_status_counts",
        )
    return checked


def report(scope, values=None, *, now=None):
    value = {
        "schema": SCHEMA,
        "scope_sha256": scope_hash(scope),
        "checked_at": (datetime.now(UTC) if now is None else now).isoformat(),
        "state": "verified" if values is not None else "unavailable",
        "values": values or {},
        "automatic_activation_allowed": False,
        "authenticity_or_freshness_asserted": False,
    }
    validate(value, value["scope_sha256"])
    return value


def inspect(
    scope,
    package,
    manifest_sha256,
    checkpoint,
    checkpoint_sha256,
    review,
    receipt_sha256,
    *,
    now=None,
):
    """Reverify encrypted bytes and the already-restored DB, without a recovery key."""
    manager = CaptureBackup(scope)
    package = private_directory(package)
    require(
        set(os.listdir(package)) == {"manifest.json", "payload.aesgcm"}, "backup_status_inventory"
    )
    manifest = Manifest.model_validate(
        decode(pinned(package / "manifest.json", manifest_sha256, 16384))
    )
    manager.validate_checkpoint(manifest.snapshot)
    payload = pinned(package / "payload.aesgcm", manifest.payload_sha256, MAX_CIPHERTEXT)
    require(
        len(payload) == manifest.payload_bytes == manifest.database_bytes + 16,
        "backup_status_payload_size",
    )
    review = private_directory(review)
    receipt = decode(pinned(review / "restore.json", receipt_sha256, 16384))
    verified = manager.verify(review, receipt_sha256, checkpoint, checkpoint_sha256)
    require(
        receipt["manifest_sha256"] == manifest_sha256
        and receipt["database_sha256"] == manifest.database_sha256
        and (receipt["records"], receipt["raw_bytes"], receipt["head"])
        == (manifest.snapshot.records, manifest.snapshot.raw_bytes, manifest.snapshot.head)
        and verified["completed"]
        and verified["head"] == manifest.snapshot.head,
        "backup_status_review_binding",
    )
    return report(
        scope,
        {
            "snapshot_at": manifest.snapshot.issued_at,
            "backup_at": manifest.created_at,
            "restored_at": receipt["restored_at"],
            "records": receipt["records"],
            "raw_bytes": receipt["raw_bytes"],
        },
        now=now,
    )


def public_destination(path, package, review, checkpoint):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "backup_status_output")
    resolved = path.resolve()
    for protected in (
        Path(package).resolve(),
        Path(review).resolve(),
        Path(checkpoint).parent.resolve(),
    ):
        require(
            resolved != protected
            and protected not in resolved.parents
            and resolved not in protected.parents,
            "backup_status_output_overlap",
        )
    return path


def publish(path, value):
    path = Path(path)
    checked = validate(value, value["scope_sha256"])
    parent = path.parent.lstat()
    require(
        path.is_absolute()
        and not path.is_symlink()
        and not path.parent.is_symlink()
        and stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == os.geteuid()
        and not stat.S_IMODE(parent.st_mode) & 0o022,
        "backup_status_public_parent",
    )
    if path.exists():
        require(path.stat().st_uid == os.geteuid(), "backup_status_public_owner")
        previous = read_public(path)
        require(
            validate(previous, value["scope_sha256"]) <= checked, "backup_status_clock_regression"
        )
    body = canonical(value) + b"\n"
    require(len(body) <= MAX_REPORT, "backup_status_public_bound")
    fd, temporary = tempfile.mkstemp(prefix=".backup-status-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        require(not path.is_symlink(), "backup_status_public_link")
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
        == {
            "schema",
            "scope_sha256",
            "status_file",
            "max_snapshot_age_seconds",
            "max_restore_age_seconds",
        }
        and value["schema"] == "zt-backup-recovery-metrics-profile-1",
        "backup_status_profile",
    )
    require(
        type(value["scope_sha256"]) is str
        and re.fullmatch(r"[a-f0-9]{64}", value["scope_sha256"])
        and type(value["status_file"]) is str
        and 0 < len(value["status_file"]) <= 4096
        and Path(value["status_file"]).is_absolute(),
        "backup_status_profile_binding",
    )
    for name, maximum in [
        ("max_snapshot_age_seconds", 604800),
        ("max_restore_age_seconds", 2592000),
    ]:
        require(
            type(value[name]) is int and 60 <= value[name] <= maximum, "backup_status_profile_age"
        )
    return value


def metrics(profile, *, now=None):
    now = datetime.now(UTC) if now is None else now
    rows = [
        "# TYPE secops_capture_backup_bridge_enabled gauge",
        "secops_capture_backup_bridge_enabled 1",
    ]
    value = None
    valid = False
    try:
        value = read_public(profile["status_file"])
        checked = validate(value, profile["scope_sha256"])
        require(
            timedelta(0) <= now - checked < timedelta(seconds=REPORT_TTL), "backup_status_expired"
        )
        valid = value["state"] == "verified"
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        pass
    rows.append(f"secops_capture_backup_status_success {int(valid)}")
    recent = False
    if valid:
        data = value["values"]
        snapshot_age = (now - aware(data["snapshot_at"])).total_seconds()
        restore_age = (now - aware(data["restored_at"])).total_seconds()
        recent = (
            snapshot_age <= profile["max_snapshot_age_seconds"]
            and restore_age <= profile["max_restore_age_seconds"]
        )
        rows.extend(
            [
                f"secops_capture_backup_snapshot_age_seconds {snapshot_age}",
                f"secops_capture_backup_restore_age_seconds {restore_age}",
                f"secops_capture_backup_records {data['records']}",
                f"secops_capture_backup_raw_bytes {data['raw_bytes']}",
            ]
        )
    rows.append(f"secops_capture_backup_recovery_recent {int(recent)}")
    return "\n".join(rows) + "\n"
