"""Owned real-systemd timer acceptance, with a real collection outage.

Public templates are path/account/interval substituted only in unique /run
fixtures. No operational timers or accounts are installed or enabled.
"""

import hashlib
import json
import shutil
import sqlite3
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.capture_archive import CaptureArchive
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.shared_execution_collector import READ_ENV
from scripts.f1_lab.shared_execution_evidence import ServiceEvent, ServiceProof


def command(*args, check=True):
    return subprocess.run(
        ["/usr/bin/systemctl", *args], env=READ_ENV, capture_output=True, timeout=20, check=check
    )


def property_value(unit, name):
    return command("show", "--value", "--property=" + name, "--", unit).stdout.decode().strip()


def messages(unit):
    result = subprocess.run(
        [
            "/usr/bin/journalctl",
            "--no-pager",
            "--lines=256",
            "--output=json",
            "--output-fields=MESSAGE",
            "--unit=" + unit,
        ],
        env=READ_ENV,
        capture_output=True,
        timeout=5,
        check=True,
    )
    values = []
    for line in result.stdout.splitlines():
        text = decode(line).get("MESSAGE")
        if isinstance(text, str) and text.startswith("{"):
            value = decode(text.encode())
            if isinstance(value, dict) and "state" in value:
                values.append(value)
    return values


def wait_for(predicate, seconds, code):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = predicate()
        if value:
            return value
        time.sleep(0.15)
    raise ValueError("schedule_timeout_" + code)


def run_schedule_controls(
    source,
    root,
    scope,
    monitor,
    provider,
    restore_provider,
    authorize,
    output,
    check,
    collector_unit,
):
    tag = uuid.uuid4().hex
    archive_prefix, health_prefix = "zt73a-" + tag[:12], "zt73h-" + tag[:12]
    collector_prefix = collector_unit.split("@", 1)[0]
    require(
        collector_prefix.startswith("zt70c-") and root.parent.name.startswith("secops-v70-"),
        "schedule_owned_collector",
    )
    archive_unit = archive_prefix + "@" + root.name + ".service"
    health_unit = health_prefix + "@" + root.name + ".service"
    services = [collector_unit, archive_unit, health_unit]
    timers = [unit.removesuffix(".service") + ".timer" for unit in services]
    health_name = "secops-health-v73-" + tag
    health_state = Path("/var/lib") / health_name
    config_dir = Path("/run") / root.parent.name
    latest = root / "latest.json"
    created = []
    replacement = None
    observations = []
    initial_deliveries = provider.delivered
    report = {
        "completed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "real_elapsed_outage_tested": True,
        "OS_clock_changed": False,
        "production_timers_enabled": False,
        "fixture_intervals_substituted": True,
    }

    def install(name, text):
        path = Path("/run/systemd/system") / name
        with path.open("x", encoding="utf8") as stream:
            created.append(path)
            stream.write(text)

    def service_template(name):
        text = (source / "infra/systemd" / name).read_text()
        for old, new in {
            "User=secops-collector": "User=daemon",
            "Group=secops-collector": "Group=daemon",
            "/opt/secops/.venv/bin/python": "/usr/bin/python3",
            "/opt/secops": str(source),
            "/etc/secops/collector.conf": str(config_dir / "collector.conf"),
            "/etc/secops/service-registry.json": str(config_dir / "service-registry.json"),
            "/var/lib/secops-evidence": str(root.parent),
            "StateDirectory=secops-evidence": "StateDirectory=" + root.parent.name,
            "/var/lib/secops-capture-health": str(health_state),
            "StateDirectory=secops-capture-health": "StateDirectory=" + health_name,
        }.items():
            text = text.replace(old, new)
        return text

    def timer_template(name, prefix, interval):
        text = (source / "infra/systemd" / name).read_text()
        original_prefix = name.split("@", 1)[0]
        replacements = {
            "OnActiveSec": "1s",
            "OnUnitInactiveSec": str(interval) + "s",
            "AccuracySec": "100ms",
            "RandomizedDelaySec": "0",
        }
        lines = []
        for line in text.replace(original_prefix, prefix).splitlines():
            key = line.partition("=")[0]
            lines.append(key + "=" + replacements[key] if key in replacements else line)
        return "\n".join(lines) + "\n"

    def stop_timers():
        command("stop", "--", *timers, check=False)
        wait_for(
            lambda: all(
                property_value(unit, "ActiveState") in {"inactive", "failed"} for unit in services
            ),
            25,
            "oneshots_drain",
        )

    def fresh_after(previous, not_before=None):
        raw = latest.read_bytes()
        if raw == previous:
            return None
        payload = decode(raw)
        event = ServiceEvent.model_validate(payload["event"])
        proof = ServiceProof.model_validate(payload["runtime_proof"])
        if not_before is not None and event.observed_at < not_before:
            return None
        require(monitor.check(latest).state == "fresh", "schedule_new_capture_fresh")
        authorize(event, proof)
        observations.append(
            {
                "event_sha256": event.sha256,
                "observed_at": event.observed_at.isoformat(),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        return raw

    def health_state_is(state, event_sha=None):
        values = messages(health_unit)
        if not values:
            return None
        value = values[-1]
        return (
            value
            if value["state"] == state
            and (event_sha is None or value.get("event_sha256") == event_sha)
            else None
        )

    try:
        archive_body = service_template("secops-capture-archive@.service").replace(
            " --apply ", " --apply --max-hot-records 2 "
        )
        install(archive_prefix + "@.service", archive_body)
        install(health_prefix + "@.service", service_template("secops-capture-health@.service"))
        for template, prefix, interval in [
            ("secops-execution-collector@.timer", collector_prefix, 2),
            ("secops-capture-archive@.timer", archive_prefix, 3),
            ("secops-capture-health@.timer", health_prefix, 2),
        ]:
            install(prefix + "@.timer", timer_template(template, prefix, interval))
        command("daemon-reload")
        check(
            "timers_are_disabled_before_explicit_fixture_start",
            all(
                command("is-enabled", "--", unit, check=False).stdout.strip() == b"disabled"
                for unit in timers
            ),
        )
        original = latest.read_bytes()
        command("start", "--", timers[0])
        first = wait_for(lambda: fresh_after(original), 20, "first_collection")
        wait_for(lambda: fresh_after(first), 15, "second_collection")
        check("timer_repeats_new_signed_normal_observations", len(observations) == 2)
        command("start", "--", timers[2])
        initial_health = wait_for(lambda: health_state_is("fresh"), 15, "initial_health")
        security = initial_health["worker_security"]
        check(
            "scheduled_health_worker_is_nonroot_without_capabilities",
            security["effective_uid"] == 1
            and security["effective_capabilities"] == 0
            and security["bounding_capabilities"] == 0
            and security["no_new_privileges"],
        )
        check(
            "scheduled_health_never_claims_authorization_or_enforcement",
            not initial_health["authorization_checked"]
            and not initial_health["automatic_enforcement_allowed"],
        )
        command("start", "--", timers[1])
        wait_for(
            lambda: any(v.get("deleted_hot_files", 0) > 0 for v in messages(archive_unit)),
            20,
            "automatic_archive",
        )
        stop_timers()
        # Quiescent comparison of the actual archive against all remaining hot
        # files: every archived payload validates and the current hot latest is kept.
        database = root / "archive.sqlite3"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as con:
            rows = con.execute("SELECT run_id,raw_bytes,payload,raw_sha FROM captures").fetchall()
            for _, size, packed, expected in rows:
                CaptureArchive.unpack(packed, size, expected)
        hot_count = len(list(root.glob("*/capture.json")))
        preserved = {row[3] for row in rows} | {
            hashlib.sha256(path.read_bytes()).hexdigest() for path in root.glob("*/capture.json")
        }
        check(
            "archive_timer_preserves_payloads_and_current_latest",
            len(rows) > 3
            and hot_count >= 1
            and monitor.check(latest).state == "fresh"
            and all(item["raw_sha256"] in preserved for item in observations),
        )
        # Stop archive/collection before the outage snapshot. Health continues
        # independently; only the collector timer is retried without its socket.
        before_outage = latest.read_bytes()
        provider.close()
        outage_started = time.monotonic()
        command("start", "--", timers[0], timers[2])
        wait_for(
            lambda: property_value(collector_unit, "ExecMainStatus") == "243",
            15,
            "credential_failure",
        )
        check(
            "scheduled_provider_failure_preserves_last_signed_capture",
            latest.read_bytes() == before_outage,
        )
        stale = wait_for(lambda: health_state_is("stale"), 45, "real_elapsed_stale")
        elapsed = time.monotonic() - outage_started
        event = ServiceEvent.model_validate(decode(before_outage)["event"])
        age = (datetime.now(UTC) - event.observed_at).total_seconds()
        check(
            "actual_collection_gap_becomes_stale_without_clock_injection",
            age >= 30
            and latest.read_bytes() == before_outage
            and not stale["automatic_enforcement_allowed"],
        )
        replacement = restore_provider()
        recovered = wait_for(lambda: fresh_after(before_outage), 20, "automatic_recovery")
        recovered_sha = observations[-1]["event_sha256"]
        recovered_health = wait_for(
            lambda: health_state_is("fresh", recovered_sha), 15, "health_recovery"
        )
        check(
            "timer_recovers_after_provider_restore_without_manual_collector_start",
            recovered != before_outage and recovered_health["state"] == "fresh",
        )
        stop_timers()
        resume_at = datetime.now(UTC)
        before_resume = latest.read_bytes()
        command("start", "--", *timers)
        wait_for(lambda: fresh_after(before_resume, resume_at), 20, "timer_restart")
        check(
            "timer_restart_collects_current_observation_not_backfill",
            datetime.fromisoformat(observations[-1]["observed_at"]) >= resume_at,
        )
        stop_timers()
        stable = latest.read_bytes()
        paths = {str(p) for p in root.glob("*/capture.json")}
        time.sleep(5)
        check(
            "stopped_timers_do_not_keep_collecting",
            stable == latest.read_bytes()
            and paths == {str(p) for p in root.glob("*/capture.json")},
        )
        check("timed_normal_observations_preserve_baseline", len(observations) == 4)
        report.update(
            completed=True,
            observations=observations,
            normal_controls=len(observations),
            normal_added_alerts=0,
            real_outage_elapsed_seconds=round(elapsed, 3),
            stale_observation_age_seconds=round(age, 3),
            initial_health=initial_health,
            stale_health=stale,
            recovered_health=recovered_health,
            verified_archive_records=len(rows),
            quiescent_hot_records=hot_count,
            fixture_account_substituted=True,
            operational_account_created=False,
        )
    finally:
        command("stop", "--", *timers, check=False)
        # These two services and all timer files were created by this helper;
        # the parent owns and cleans its existing collector/target services.
        for unit in [archive_unit, health_unit]:
            command("stop", "--", unit, check=False)
            command("reset-failed", "--", unit, check=False)
        command("stop", "--", collector_unit, check=False)
        command("reset-failed", "--", collector_unit, check=False)
        for path in created:
            require(path.parent == Path("/run/systemd/system"), "schedule_unit_cleanup_scope")
            path.unlink()
        command("daemon-reload")
        if health_state.exists():
            resolved = health_state.resolve()
            require(
                resolved.name == health_name
                and resolved.parent in {Path("/var/lib"), Path("/var/lib/private")},
                "schedule_health_cleanup_scope",
            )
            shutil.rmtree(resolved)
            if health_state.is_symlink():
                health_state.unlink()
        report.update(
            owned_timer_and_service_files_removed=all(not p.exists() for p in created),
            owned_health_state_removed=not health_state.exists(),
        )
        (output / "schedule-controls.json").write_text(json.dumps(report, indent=2) + "\n")
    require(replacement is not None, "schedule_replacement_provider")
    report["credential_deliveries"] = (
        provider.delivered + replacement.delivered - initial_deliveries
    )
    (output / "schedule-controls.json").write_text(json.dumps(report, indent=2) + "\n")
    return report, replacement
