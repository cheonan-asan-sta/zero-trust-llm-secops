"""Owned native nonroot status worker/timer; no key and no production activation."""

import hashlib
import json
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from scripts.f1_lab.backup_recovery_status import metrics, read_public, scope_hash, validate
from scripts.f1_lab.collector_schedule_runtime import command, property_value
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.shared_execution_collector import READ_ENV


def credential_definitions(unit, fragment):
    require(
        property_value(unit, "LoadState") == "loaded"
        and property_value(unit, "FragmentPath") == str(fragment),
        "native_recovery_unit_binding",
    )

    def bus(*args):
        result = subprocess.run(
            ["/usr/bin/busctl", "--system", "--json=short", *args],
            env=READ_ENV,
            capture_output=True,
            timeout=5,
            check=True,
        ).stdout
        require(len(result) <= 8192, "native_recovery_dbus_bound")
        return decode(result)

    lookup = bus(
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "GetUnit",
        "s",
        unit,
    )
    require(
        type(lookup) is dict
        and set(lookup) == {"type", "data"}
        and lookup["type"] == "o"
        and type(lookup["data"]) is list
        and len(lookup["data"]) == 1
        and type(lookup["data"][0]) is str
        and re.fullmatch(r"/org/freedesktop/systemd1/unit/[a-zA-Z0-9_]+", lookup["data"][0]),
        "native_recovery_dbus_unit",
    )
    counts = {}
    for name in ("LoadCredential", "LoadCredentialEncrypted"):
        value = bus(
            "get-property",
            "org.freedesktop.systemd1",
            lookup["data"][0],
            "org.freedesktop.systemd1.Service",
            name,
        )
        require(
            type(value) is dict
            and set(value) == {"type", "data"}
            and value["type"] == "a(ss)"
            and type(value["data"]) is list,
            "native_recovery_dbus_credentials",
        )
        counts[name] = len(value["data"])
        require(value["data"] == [], "native_recovery_credentials_present")
    return counts


def run_controls(
    source,
    scope,
    package,
    manifest_pin,
    checkpoint,
    checkpoint_pin,
    review,
    receipt_pin,
    config_dir,
    output,
    check,
):
    tag = uuid.uuid4().hex
    prefix = "zt81r-" + tag[:12]
    instance = scope.unit.removesuffix(".service")
    unit = prefix + "@" + instance + ".service"
    timer = prefix + "@" + instance + ".timer"
    state_name = "secops-recovery-v81-" + tag
    state = Path("/var/lib") / state_name
    status_file = state / instance / "status.json"
    config = config_dir / ("recovery-status-" + tag + ".conf")
    paths = [
        Path("/run/systemd/system") / (prefix + "@." + suffix) for suffix in ("service", "timer")
    ]
    created = []
    summaries = []
    profile = {
        "scope_sha256": scope_hash(scope),
        "status_file": str(status_file),
        "max_snapshot_age_seconds": 86400,
        "max_restore_age_seconds": 604800,
    }
    private = [
        package / "manifest.json",
        package / "payload.aesgcm",
        checkpoint,
        review / "restore.json",
        review / "review/archive.sqlite3",
    ]
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in private}
    record = {
        "completed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "production_activated": False,
        "recovery_key_read": False,
    }

    def configure(pin):
        config.write_text(
            "CAPTURE_BACKUP_PATH="
            + str(package)
            + "\nCAPTURE_BACKUP_MANIFEST_SHA256="
            + pin
            + "\nCAPTURE_CHECKPOINT_PATH="
            + str(checkpoint)
            + "\nCAPTURE_CHECKPOINT_SHA256="
            + checkpoint_pin
            + "\nCAPTURE_REVIEW_PATH="
            + str(review)
            + "\nCAPTURE_RESTORE_RECEIPT_SHA256="
            + receipt_pin
            + "\n"
        )
        config.chmod(0o644)

    def execute(expected):
        command("stop", "--", unit, check=False)
        result = command("start", "--", unit, check=False)
        raw = subprocess.run(
            ["/usr/bin/journalctl", "--no-pager", "-n", "8", "-o", "cat", "-u", unit],
            env=READ_ENV,
            capture_output=True,
            timeout=5,
            check=True,
        ).stdout
        values = [decode(line) for line in raw.splitlines() if line.startswith(b'{"completed":')]
        require(
            values and (result.returncode == 0) == expected and values[-1]["completed"] is expected,
            "native_recovery_status_outcome",
        )
        if result.returncode:
            command("reset-failed", "--", unit, check=False)
        summaries.append(values[-1])
        return values[-1]

    try:
        configure(manifest_pin)
        body = (source / "infra/systemd/secops-capture-recovery-status@.service").read_text()
        for old, new in {
            "User=secops-collector": "User=daemon",
            "Group=secops-collector": "Group=daemon",
            "/opt/secops/.venv/bin/python": "/usr/bin/python3",
            "/opt/secops": str(source),
            "/etc/secops/collector.conf": str(config_dir / "collector.conf"),
            "/etc/secops/capture-recovery-status.conf": str(config),
            "/var/lib/secops-capture-backups": str(package.parent.parent),
            "/var/lib/secops-capture-checkpoints": str(checkpoint.parent.parent),
            "/var/lib/secops-capture-reviews": str(review.parent.parent),
            "/var/lib/secops-capture-recovery-status": str(state),
            "StateDirectory=secops-capture-recovery-status/%i": "StateDirectory="
            + state_name
            + "/%i",
        }.items():
            body = body.replace(old, new)
        timer_body = (source / "infra/systemd/secops-capture-recovery-status@.timer").read_text()
        timer_body = timer_body.replace("secops-capture-recovery-status@", prefix + "@")
        timer_body = (
            timer_body.replace("OnBootSec=30s", "OnBootSec=0.2s")
            .replace("OnUnitActiveSec=60s", "OnUnitActiveSec=1s")
            .replace("AccuracySec=1s", "AccuracySec=0.1s")
        )
        # Hold only the inspection fixture after exit so its D-Bus object is
        # still present. Restore the original oneshot before the timer test.
        inspection_body = body.replace("[Service]", "[Service]\nRemainAfterExit=yes")
        for path, content in zip(paths, (inspection_body, timer_body), strict=True):
            with path.open("x") as stream:
                stream.write(content)
            created.append(path)
        command("daemon-reload")
        normal = execute(True)
        security = normal["worker_security"]
        record["credential_definition_counts"] = credential_definitions(unit, paths[0])
        check(
            "recovery_status_worker_is_nonroot_without_capabilities_or_key_credential",
            security["effective_uid"] == 1
            and security["effective_capabilities"] == security["bounding_capabilities"] == 0
            and security["no_new_privileges"],
        )
        value = read_public(status_file)
        validate(value, profile["scope_sha256"])
        check(
            "recovery_status_verified_public_aggregate_never_grants",
            value["state"] == "verified"
            and value["automatic_activation_allowed"] is False
            and value["authenticity_or_freshness_asserted"] is False
            and "secops_capture_backup_recovery_recent 1\n" in metrics(profile),
        )
        configure("0" * 64)
        execute(False)
        check(
            "wrong_backup_pin_replaces_success_with_empty_unavailable",
            read_public(status_file)["state"] == "unavailable"
            and not read_public(status_file)["values"]
            and "secops_capture_backup_records " not in metrics(profile),
        )
        configure(manifest_pin)
        execute(True)
        value = read_public(status_file)
        check("recovery_status_recovers_only_after_valid_pins", value["state"] == "verified")
        command("stop", "--", unit)
        paths[0].write_text(body)
        command("daemon-reload")
        require(property_value(unit, "RemainAfterExit") == "no", "native_recovery_original_oneshot")
        command("start", "--", timer)
        seen = {value["checked_at"]}
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and len(seen) < 3:
            current = read_public(status_file)
            require(current["values"] == value["values"], "native_recovery_dates_changed")
            seen.add(current["checked_at"])
            time.sleep(0.2)
        command("stop", "--", timer)
        command("stop", "--", unit, check=False)
        check("real_status_timer_rechecks_without_renewing_backup_or_restore_time", len(seen) >= 3)
        check(
            "recovery_status_does_not_change_private_backup_checkpoint_or_review_bytes",
            before == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in private},
        )
        check(
            "public_backup_status_contains_no_private_paths_or_original_identity",
            all(
                s not in status_file.read_text()
                for s in [str(review), str(package), scope.tenant_id, scope.unit]
            ),
        )
        record.update(
            completed=True,
            summaries=summaries,
            timer_observations=len(seen),
            source_private_bytes_unchanged=True,
            final_aggregate_sha256=hashlib.sha256(status_file.read_bytes()).hexdigest(),
        )
    finally:
        for owned in (timer, unit):
            command("stop", "--", owned, check=False)
            command("reset-failed", "--", owned, check=False)
        for path in created:
            path.unlink()
        command("daemon-reload")
        if state.exists():
            resolved = state.resolve()
            require(
                resolved.parent in {Path("/var/lib"), Path("/var/lib/private")}
                and resolved.name == state_name,
                "native_recovery_cleanup_scope",
            )
            shutil.rmtree(resolved)
        config.unlink(missing_ok=True)
        record.update(
            summaries=summaries,
            owned_units_removed=all(not p.exists() for p in created),
            owned_status_state_removed=not state.exists(),
            owned_public_configuration_removed=not config.exists(),
        )
        (output / "backup-recovery-controls.json").write_text(json.dumps(record, indent=2) + "\n")
    check(
        "recovery_status_owned_units_state_and_public_configuration_removed",
        record["owned_units_removed"]
        and record["owned_status_state_removed"]
        and record["owned_public_configuration_removed"],
    )
    return record
