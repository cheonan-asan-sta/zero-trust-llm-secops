"""Owned real-systemd status drop-in acceptance; no operational installation."""

import json
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

from scripts.f1_lab.collector_status_bridge import load_profile, metrics, read_public, scope_hash
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.shared_execution_collector import READ_ENV


def command(*args, check=True):
    return subprocess.run(
        ["/usr/bin/systemctl", *args], env=READ_ENV, capture_output=True, timeout=20, check=check
    )


def run_status_controls(source, root, scope, output, check):
    tag = uuid.uuid4().hex
    prefix = "zt74-" + tag[:12]
    cache_name = "secops-status-v74-" + tag
    cache = Path("/var/cache") / cache_name
    health_name = "secops-health-v74-" + tag
    health_state = Path("/var/lib") / health_name
    config = Path("/run") / root.parent.name
    paths = []
    units = []
    report = {
        "completed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "operational_installation_completed": False,
    }

    def replace(text):
        for old, new in {
            "User=secops-collector": "User=daemon",
            "Group=secops-collector": "Group=daemon",
            "/opt/secops/.venv/bin/python": "/usr/bin/python3",
            "/opt/secops": str(source),
            "/etc/secops/collector.conf": str(config / "collector.conf"),
            "/etc/secops/service-registry.json": str(config / "service-registry.json"),
            "/var/lib/secops-evidence": str(root.parent),
            "StateDirectory=secops-evidence": "StateDirectory=" + root.parent.name,
            "/var/lib/secops-capture-health": str(health_state),
            "StateDirectory=secops-capture-health": "StateDirectory=" + health_name,
            "/var/cache/secops-capture-status": str(cache),
            "CacheDirectory=secops-capture-status": "CacheDirectory=" + cache_name,
        }.items():
            text = text.replace(old, new)
        return text

    def start(kind):
        unit = prefix + kind + "@" + root.name + ".service"
        result = command("start", "--", unit, check=False)
        value = read_public(cache / (root.name + "-" + kind + ".json"))
        if result.returncode:
            command("reset-failed", "--", unit, check=False)
        return result, value

    try:
        for kind, base in [
            ("health", "secops-capture-health"),
            ("archive", "secops-capture-archive"),
        ]:
            template = Path("/run/systemd/system") / (prefix + kind + "@.service")
            with template.open("x") as stream:
                paths.append(template)
                stream.write(replace((source / "infra/systemd" / (base + "@.service")).read_text()))
            drop = Path(str(template) + ".d")
            drop.mkdir(exist_ok=False)
            paths.append(drop)
            snippet = drop / "collector-metrics.conf"
            with snippet.open("x") as stream:
                paths.append(snippet)
                stream.write(
                    replace(
                        (
                            source
                            / "infra/systemd"
                            / (base + "@.service.d")
                            / "collector-metrics.conf"
                        ).read_text()
                    )
                )
            units.append(prefix + kind + "@" + root.name + ".service")
        command("daemon-reload")
        result, health = start("health")
        check(
            "status_dropin_publishes_revalidated_fresh_observation",
            result.returncode == 0 and health["state"] == "fresh",
        )
        result, archive = start("archive")
        check(
            "status_dropin_publishes_current_archive_counters",
            result.returncode == 0
            and archive["state"] == "ready"
            and archive["values"]["archive_records"] >= 4,
        )
        check(
            "status_snapshots_are_public_aggregates_without_original_identity",
            all(
                value not in json.dumps([health, archive])
                for value in [scope.tenant_id, scope.server_id, scope.unit]
            ),
        )
        check(
            "public_status_permissions_do_not_change_private_capture_permissions",
            stat.S_IMODE(cache.stat().st_mode) == 0o755
            and all(stat.S_IMODE(p.stat().st_mode) == 0o644 for p in cache.glob("*.json"))
            and stat.S_IMODE(root.stat().st_mode) == 0o700,
        )
        profile = {
            "schema": "zt-collector-metrics-profile-1",
            "scope_sha256": scope_hash(scope),
            "health_file": str(cache / (root.name + "-health.json")),
            "archive_file": str(cache / (root.name + "-archive.json")),
        }
        profile_path = cache / "profile.json"
        profile_path.write_text(json.dumps(profile))
        profile_path.chmod(0o644)
        fixed = load_profile(profile_path)
        text = metrics(fixed)
        check(
            "native_status_files_feed_bounded_exporter_metrics",
            "secops_collector_observation_fresh 1" in text
            and "secops_collector_archive_records " in text,
        )
        original = (root / "latest.json").read_bytes()
        # Only this owned drop-in command is overridden for fault acceptance.
        health_snippet = (
            Path("/run/systemd/system") / (prefix + "health@.service.d") / "collector-metrics.conf"
        )
        body = health_snippet.read_text()
        health_snippet.write_text(body.rstrip() + " --registry-sha256 " + "0" * 64 + "\n")
        command("daemon-reload")
        result, bad = start("health")
        check(
            "invalid_current_trust_publishes_unavailable_not_old_fresh",
            result.returncode != 0
            and bad["state"] == "unavailable"
            and "secops_collector_observation_fresh 0" in metrics(fixed),
        )
        health_snippet.write_text(body)
        command("daemon-reload")
        result, recovered = start("health")
        check(
            "valid_trust_recovers_status_without_replacing_capture",
            result.returncode == 0
            and recovered["state"] == "fresh"
            and (root / "latest.json").read_bytes() == original,
        )
        archive_snippet = (
            Path("/run/systemd/system") / (prefix + "archive@.service.d") / "collector-metrics.conf"
        )
        body = archive_snippet.read_text()
        archive_snippet.write_text(body.rstrip() + " --max-records 1\n")
        command("daemon-reload")
        result, pressure = start("archive")
        check(
            "archive_capacity_failure_publishes_pressure_and_preserves_latest",
            result.returncode != 0
            and pressure["state"] == "storage_pressure"
            and (root / "latest.json").read_bytes() == original
            and "secops_collector_archive_storage_pressure 1" in metrics(fixed),
        )
        archive_snippet.write_text(body)
        command("daemon-reload")
        result, final = start("archive")
        check(
            "archive_report_recovers_after_capacity_configuration_restored",
            result.returncode == 0 and final["state"] == "ready",
        )
        public = output / "public-status"
        public.mkdir(exist_ok=False)
        for kind in ("health", "archive"):
            (public / (kind + ".json")).write_bytes(
                (cache / (root.name + "-" + kind + ".json")).read_bytes()
            )
        report.update(
            completed=True,
            health=recovered,
            archive=final,
            pressure=pressure,
            native_metrics=text,
            fixture_account_substituted=True,
            private_capture_permissions_preserved=True,
        )
    finally:
        for unit in units:
            command("stop", "--", unit, check=False)
            command("reset-failed", "--", unit, check=False)
        for path in reversed(paths):
            require(
                path.parent == Path("/run/systemd/system")
                or path.parent.parent == Path("/run/systemd/system"),
                "status_cleanup_unit_scope",
            )
            path.rmdir() if path.is_dir() else path.unlink()
        command("daemon-reload")
        for path, name, parent in [
            (cache, cache_name, Path("/var/cache")),
            (health_state, health_name, Path("/var/lib")),
        ]:
            if path.exists():
                resolved = path.resolve()
                require(
                    resolved.name == name and resolved.parent == parent,
                    "status_cleanup_state_scope",
                )
                shutil.rmtree(resolved)
        report["owned_status_units_removed"] = all(not p.exists() for p in paths)
        report["owned_status_state_removed"] = not cache.exists() and not health_state.exists()
        (output / "status-controls.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
