"""Bounded advisory status bridge; public aggregates, never credentials or grants.

Writers and local configuration are trusted host components. These unsigned
snapshots preserve the last check, not a remote attestation of current trust.
Readers expire snapshots and never expose raw capture content or identities.
"""

import hashlib
import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.collector_freshness import inspect_capture, read_capture
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_evidence import ServiceProof

SCHEMA = "zt-collector-status-1"
MAX_REPORT = 8192
TTL = {"health": 25, "archive": 180}
COUNTERS = (
    "hot_after_records",
    "hot_after_bytes",
    "archive_records",
    "archive_raw_bytes",
    "archive_compressed_payload_bytes",
    "archive_database_file_bytes",
)


def scope_hash(scope):
    value = scope.model_dump(mode="json")
    return hashlib.sha256(
        canonical({k: value[k] for k in ("tenant_id", "server_id", "unit", "source_id")})
    ).hexdigest()


def timestamp(text):
    require(type(text) is str and len(text) <= 40, "bridge_timestamp")
    value = datetime.fromisoformat(text)
    require(value.tzinfo is not None and value.utcoffset() == timedelta(0), "bridge_UTC")
    return value


def read_public(path):
    path = Path(path)
    require(not path.is_symlink(), "bridge_file_link")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and not stat.S_IMODE(before.st_mode) & 0o022
            and 0 < before.st_size <= MAX_REPORT,
            "bridge_file_shape",
        )
        raw = stream.read(MAX_REPORT + 1)
        after = os.fstat(stream.fileno())
        require(
            len(raw) == before.st_size
            and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "bridge_file_changed",
        )
    return decode(raw)


def validate(report, kind, expected_scope):
    require(
        type(report) is dict
        and set(report)
        == {
            "schema",
            "kind",
            "scope_sha256",
            "checked_at",
            "state",
            "observed_at",
            "expires_at",
            "values",
        },
        "bridge_envelope",
    )
    require(
        report["schema"] == SCHEMA
        and report["kind"] == kind
        and report["scope_sha256"] == expected_scope
        and re.fullmatch(r"[a-f0-9]{64}", expected_scope),
        "bridge_binding",
    )
    checked = timestamp(report["checked_at"])
    require(type(report["values"]) is dict, "bridge_values")
    if kind == "health":
        require(
            report["state"] in {"fresh", "stale", "unavailable"} and not report["values"],
            "bridge_health",
        )
        if report["state"] == "unavailable":
            require(report["observed_at"] is report["expires_at"] is None, "bridge_unavailable")
        else:
            observed, expires = timestamp(report["observed_at"]), timestamp(report["expires_at"])
            require(
                observed <= checked and observed < expires <= observed + timedelta(seconds=30),
                "bridge_observation_window",
            )
            require((checked < expires) == (report["state"] == "fresh"), "bridge_health_state")
    else:
        require(
            kind == "archive"
            and report["state"] in {"ready", "storage_pressure", "unavailable"}
            and report["observed_at"] is report["expires_at"] is None
            and set(report["values"]) in (set(), set(COUNTERS)),
            "bridge_archive",
        )
        require(
            report["state"] != "ready" or set(report["values"]) == set(COUNTERS),
            "bridge_archive_ready_values",
        )
        for name, value in report["values"].items():
            require(
                type(value) is int
                and 0 <= value <= (10000 if name.endswith("records") else 8 * 1024**3),
                "bridge_counter",
            )
    return checked


def report(kind, scope, state, *, checked_at=None, observed_at=None, expires_at=None, values=None):
    now = datetime.now(UTC) if checked_at is None else checked_at
    value = {
        "schema": SCHEMA,
        "kind": kind,
        "scope_sha256": scope_hash(scope),
        "checked_at": now.isoformat(),
        "state": state,
        "observed_at": observed_at.isoformat() if observed_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "values": values or {},
    }
    validate(value, kind, value["scope_sha256"])
    return value


def health_report(scope, result, capture, pinned):
    now = datetime.now(UTC)
    if result.state == "unavailable":
        return report("health", scope, "unavailable", checked_at=now)
    payload = read_capture(capture)
    current = inspect_capture(payload, scope, pinned, now=now)
    require(
        current.state in {"fresh", "stale"}
        and current.event_sha256 == result.event_sha256
        and current.observed_at == result.observed_at,
        "bridge_health_capture_changed",
    )
    proof = ServiceProof.model_validate(payload["runtime_proof"])
    expires = min(current.observed_at + timedelta(seconds=30), proof.expires_at)
    return report(
        "health",
        scope,
        current.state,
        checked_at=now,
        observed_at=current.observed_at,
        expires_at=expires,
    )


def archive_report(scope, result):
    values = {k: result[k] for k in COUNTERS} if result.get("completed") else {}
    return report("archive", scope, result["state"], values=values)


def publish(path, value):
    path = Path(path)
    validate(value, value["kind"], value["scope_sha256"])
    parent = path.parent.lstat()
    require(
        stat.S_ISDIR(parent.st_mode)
        and not path.parent.is_symlink()
        and parent.st_uid == os.geteuid()
        and not stat.S_IMODE(parent.st_mode) & 0o022,
        "bridge_writer_parent",
    )
    if path.exists() or path.is_symlink():
        require(path.lstat().st_uid == os.geteuid(), "bridge_writer_owner")
        previous = read_public(path)
        validate(previous, value["kind"], value["scope_sha256"])
        require(
            timestamp(previous["checked_at"]) <= timestamp(value["checked_at"]),
            "bridge_publication_clock_regression",
        )
    body = canonical(value) + b"\n"
    require(len(body) <= MAX_REPORT, "bridge_publication_bound")
    fd, temporary = tempfile.mkstemp(prefix=".collector-status-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        require(not path.is_symlink(), "bridge_publication_link")
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
        and set(value) == {"schema", "scope_sha256", "health_file", "archive_file"}
        and value["schema"] == "zt-collector-metrics-profile-1"
        and type(value["scope_sha256"]) is str
        and re.fullmatch(r"[a-f0-9]{64}", value["scope_sha256"]),
        "bridge_profile",
    )
    for name in ("health_file", "archive_file"):
        require(
            type(value[name]) is str
            and 0 < len(value[name]) <= 4096
            and Path(value[name]).is_absolute(),
            "bridge_profile_path",
        )
    require(value["health_file"] != value["archive_file"], "bridge_profile_distinct_files")
    return value


def metrics(profile, *, now=None):
    now = datetime.now(UTC) if now is None else now
    rows = ["# TYPE secops_collector_bridge_enabled gauge", "secops_collector_bridge_enabled 1"]
    for kind in ("health", "archive"):
        valid, value = False, None
        try:
            value = read_public(profile[kind + "_file"])
            checked = validate(value, kind, profile["scope_sha256"])
            require(
                timedelta(0) <= now - checked < timedelta(seconds=TTL[kind]),
                "bridge_report_expired",
            )
            valid = True
        except (ValueError, OSError, TypeError, KeyError, RecursionError):
            pass
        rows.append(f'secops_collector_status_success{{worker="{kind}"}} {int(valid)}')
        if kind == "health":
            fresh = valid and value["state"] == "fresh" and now < timestamp(value["expires_at"])
            rows.append(f"secops_collector_observation_fresh {int(fresh)}")
            if valid and value["observed_at"] is not None:
                rows.append(
                    "secops_collector_observation_age_seconds "
                    + str((now - timestamp(value["observed_at"])).total_seconds())
                )
        elif valid:
            rows.append(
                "secops_collector_archive_storage_pressure "
                + str(int(value["state"] == "storage_pressure"))
            )
            # A valid failure report is still unavailable for archival work.
            if value["state"] == "unavailable":
                rows[-2] = 'secops_collector_status_success{worker="archive"} 0'
            for name, amount in value["values"].items():
                rows.append("secops_collector_" + name + " " + str(amount))
    return "\n".join(rows) + "\n"
