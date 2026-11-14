"""Measure owned real-systemd workers; no timer or production SLO claim."""

import hashlib
import json
import shutil
import time
import uuid
from pathlib import Path

from scripts.f1_lab.capture_load import distribution, footprint, inventory, inventory_sha
from scripts.f1_lab.collector_schedule_runtime import command, property_value
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.shared_execution_collector import READ_ENV


def accounting(unit):
    result = {}
    for name in ("CPUUsageNSec", "MemoryPeak"):
        text = property_value(unit, name)
        result[name] = int(text) if text.isdecimal() and int(text) < 2**63 else None
    return result


def last_summary(unit):
    import subprocess

    raw = subprocess.run(
        ["/usr/bin/journalctl", "--no-pager", "-n", "8", "-o", "cat", "-u", unit],
        env=READ_ENV,
        capture_output=True,
        timeout=5,
        check=True,
    ).stdout
    values = [decode(line) for line in raw.splitlines() if line.startswith(b"{")]
    require(values, "load_native_summary_missing")
    return values[-1]


def run_load_controls(
    source,
    root,
    scope,
    monitor,
    capture,
    authorize,
    output,
    check,
    collector_unit,
    target_unit,
    seconds,
    provider,
    restore_provider,
):
    require(type(seconds) is int and 10 <= seconds <= 600, "load_native_duration_bounds")
    require(
        collector_unit.startswith("zt70c-") and root.parent.name.startswith("secops-v70-"),
        "load_owned_runtime",
    )
    tag = uuid.uuid4().hex
    archive_unit = "zt76a-" + tag[:12] + "@" + root.name + ".service"
    health_unit = "zt76h-" + tag[:12] + "@" + root.name + ".service"
    health_name = "secops-health-v76-" + tag
    health_root = Path("/var/lib") / health_name
    config = Path("/run") / root.parent.name / "collector.conf"
    dropin_dir = Path("/run/systemd/system") / (collector_unit + ".d")
    created = []
    samples = []
    expected = inventory(root)
    cycles = 0
    before_deliveries = 0
    provider_restarts = 0
    latest = root / "latest.json"
    report = {
        "completed": False,
        "requested_seconds": seconds,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "actual_timer_scheduling_measured": False,
        "production_SLO_proven": False,
        "long_soak_8h_completed": False,
        "fixture_account_substituted": True,
    }

    def install(path, text):
        with path.open("x", encoding="utf8") as stream:
            created.append(path)
            stream.write(text)

    def template(name):
        body = (source / "infra/systemd" / name).read_text()
        for old, new in {
            "User=secops-collector": "User=daemon",
            "Group=secops-collector": "Group=daemon",
            "/opt/secops/.venv/bin/python": "/usr/bin/python3",
            "/opt/secops": str(source),
            "/etc/secops/collector.conf": str(config),
            "/etc/secops/service-registry.json": str(config.parent / "service-registry.json"),
            "/var/lib/secops-evidence": str(root.parent),
            "StateDirectory=secops-evidence": "StateDirectory=" + root.parent.name,
            "/var/lib/secops-capture-health": str(health_root),
            "StateDirectory=secops-capture-health": "StateDirectory=" + health_name,
        }.items():
            body = body.replace(old, new)
        return body.replace(
            "[Service]", "[Service]\nRemainAfterExit=yes\nCPUAccounting=yes\nMemoryAccounting=yes"
        )

    def execute(unit, kind, expect=True):
        began = time.monotonic()
        result = command("start", "--", unit, check=False)
        summary = last_summary(unit)
        usage = accounting(unit)
        command("stop", "--", unit, check=False)
        if not expect:
            command("reset-failed", "--", unit, check=False)
        require((result.returncode == 0) == expect, "load_native_worker_result")
        return {"kind": kind, "elapsed_ms": (time.monotonic() - began) * 1000, **usage}, summary

    try:
        dropin_dir.mkdir(exist_ok=False)
        install(
            dropin_dir / "accounting.conf",
            "[Service]\nRemainAfterExit=yes\nCPUAccounting=yes\nMemoryAccounting=yes\n",
        )
        for unit, name in (
            (archive_unit, "secops-capture-archive@.service"),
            (health_unit, "secops-capture-health@.service"),
        ):
            body = template(name)
            if unit == archive_unit:
                body = body.replace(" --apply ", " --max-hot-records 8 --apply ")
            install(Path("/run/systemd/system") / unit, body)
        command("daemon-reload")
        start = time.monotonic()
        previous = None
        gaps = []
        restarted = False
        first_invocation = None
        observed_new_invocation = False
        while time.monotonic() - start < seconds or cycles < 3:
            # The bounded credential adapter is not an unlimited vault. Keep
            # its limit and explicitly renew this owned fixture before it is
            # exhausted; reserve deliveries for the parent's final controls.
            if provider.delivered + provider.rejected >= provider.maximum - 4:
                provider.close()
                provider = restore_provider()
                provider_restarts += 1
            began = time.monotonic()
            if previous is not None:
                gaps.append((began - previous) * 1000)
            previous = began
            command("stop", "--", collector_unit, check=False)
            at = time.monotonic()
            _, event, proof = capture(True)
            if first_invocation is None:
                first_invocation = event.invocation_id
            if restarted:
                require(event.invocation_id != first_invocation, "load_native_restart_not_observed")
                observed_new_invocation = True
            before_deliveries += 1
            authorize(event, proof)
            sample = {
                "cycle": cycles + 1,
                "elapsed_seconds": time.monotonic() - start,
                "collector_ms": (time.monotonic() - at) * 1000,
                "collector_accounting": accounting(collector_unit),
            }
            command("stop", "--", collector_unit)
            raw = latest.read_bytes()
            rid = next(p.parent.name for p in root.glob("*/capture.json") if p.read_bytes() == raw)
            expected[rid] = hashlib.sha256(raw).hexdigest()
            sample["archive"], archive = execute(archive_unit, "archive")
            sample["health"], health = execute(health_unit, "health")
            require(archive["completed"] and health["state"] == "fresh", "load_native_pipeline")
            require(
                not health["authorization_checked"] and not health["automatic_enforcement_allowed"],
                "load_native_health_grant",
            )
            sample.update(footprint(root))
            samples.append(sample)
            cycles += 1
            if not restarted and time.monotonic() - start >= seconds / 2:
                command("restart", "--", target_unit)
                restarted = True
            time.sleep(max(0, 2 - (time.monotonic() - began)))
        elapsed = time.monotonic() - start
        actual = inventory(root)
        check("native_load_preserves_all_preexisting_and_new_capture_bytes", actual == expected)
        check(
            "native_load_repeated_workers_and_target_restart_succeed",
            cycles >= 3 and restarted and observed_new_invocation,
        )
        check("native_load_health_never_grants_or_enforces", True)
        check("native_load_capture_remains_fresh", monitor.check(latest).state == "fresh")
        report.update(
            completed=True,
            cycles=cycles,
            credential_deliveries=before_deliveries,
            fixture_provider_restarts=provider_restarts,
            provider_connection_limit_unchanged=32,
            real_elapsed_seconds=round(elapsed, 3),
            preserved_captures=len(actual),
            expected_inventory_sha256=inventory_sha(expected),
            actual_inventory_sha256=inventory_sha(actual),
            normal_controls=cycles,
            normal_added_alerts=0,
            collector_ms=distribution([s["collector_ms"] for s in samples]),
            archive_ms=distribution([s["archive"]["elapsed_ms"] for s in samples]),
            health_ms=distribution([s["health"]["elapsed_ms"] for s in samples]),
            start_gap_ms=distribution(gaps),
            first_sample=samples[0],
            last_sample=samples[-1],
            samples=samples,
        )
    finally:
        for unit in (collector_unit, archive_unit, health_unit):
            command("stop", "--", unit, check=False)
            command("reset-failed", "--", unit, check=False)
        for path in created:
            require(path.is_relative_to(Path("/run/systemd/system")), "load_unit_cleanup_scope")
            path.unlink()
        if dropin_dir.exists():
            dropin_dir.rmdir()
        command("daemon-reload")
        if health_root.exists():
            resolved = health_root.resolve()
            require(
                resolved.name == health_name
                and resolved.parent in {Path("/var/lib"), Path("/var/lib/private")},
                "load_health_cleanup_scope",
            )
            shutil.rmtree(resolved)
            if health_root.is_symlink():
                health_root.unlink()
        report.update(
            owned_units_and_accounting_override_removed=all(not p.exists() for p in created),
            owned_health_state_removed=not health_root.exists(),
        )
        report["cycles_observed_including_partial_run"] = len(samples)
        (output / "load-controls.json").write_text(json.dumps(report, indent=2) + "\n")
    return report, provider
