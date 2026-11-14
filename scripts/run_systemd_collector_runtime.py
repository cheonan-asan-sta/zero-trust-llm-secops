"""Run the hardened collector template on an owned real systemd service.

All keys are generated in memory. Only public configuration and signed captures
are persisted. Temporary unit files and state directories are uniquely owned.
This is local functional acceptance, not organizational SSO or attack accuracy.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from scripts.f1_lab.collector_freshness import CollectorMonitor, CollectorScope
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.shared_execution_collector import READ_ENV, executable_hash
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    PolicyObservation,
    ServiceEvent,
    ServiceEvidenceJoiner,
    ServiceProof,
    VerifiedServiceRisk,
)
from scripts.f1_lab.systemd_credentials import CredentialSocket
from scripts.run_shared_execution_controls import sign_policy
from scripts.run_systemd_caller_controls import FIXTURE, setup_broker


def command(*arguments, check=True):
    return subprocess.run(
        ["/usr/bin/systemctl", *arguments],
        env=READ_ENV,
        capture_output=True,
        timeout=20,
        check=check,
    )


def run(
    directory,
    *,
    freshness=False,
    archival=False,
    scheduling=False,
    reporting=False,
    backups=False,
    load_seconds=0,
):
    require(not archival or freshness, "archive_fixture_requires_freshness")
    require(not scheduling or archival, "schedule_fixture_requires_archive")
    require(not reporting or scheduling, "reporting_fixture_requires_schedule")
    require(not backups or reporting, "backup_fixture_requires_reporting")
    require(
        type(load_seconds) is int and (load_seconds == 0 or 10 <= load_seconds <= 600),
        "load_duration",
    )
    require(not load_seconds or backups, "load_fixture_requires_backups")
    require(os.name == "posix" and os.geteuid() == 0, "collector_runtime_root_required")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "collector_runtime_systemd")
    source = Path(__file__).resolve().parents[1]
    require(str(source).startswith("/run/"), "collector_runtime_public_source_required")
    output = Path(directory)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    tag = uuid.uuid4().hex
    # systemd v255 binds a client AF_UNIX address containing unit + credential
    # name. Keep this owned fixture's full instance name within that limit.
    fixture_name = "zt70-" + tag[:12]
    target_unit = fixture_name + ".service"
    prefix = "zt70c-" + tag[:12]
    collector_unit = prefix + "@" + fixture_name + ".service"
    template_path = Path("/run/systemd/system") / (prefix + "@.service")
    target_path = Path("/run/systemd/system") / target_unit
    config_dir = Path("/run") / ("secops-v70-" + tag)
    state_name = "secops-v70-" + tag
    state_dir = Path("/var/lib") / state_name
    created = []
    config_dir.mkdir(mode=0o755, exist_ok=False)
    keys, registry, _, _ = setup_broker(output / "public-setup", target_unit)
    registry_path = config_dir / "service-registry.json"
    environment_path = config_dir / "collector.conf"
    credential_dir = config_dir / "credentials"
    credential_dir.mkdir(mode=0o700)
    credential_path = credential_dir / "key.sock"
    active_key = [keys["runtime"]]
    captures = []
    report = {
        "schema": "extra-capture-load-runtime-1"
        if load_seconds
        else "extra-capture-backup-runtime-1"
        if backups
        else "extra-collector-alert-runtime-1"
        if reporting
        else "extra-collector-schedule-runtime-1"
        if scheduling
        else "extra-capture-archive-runtime-1"
        if archival
        else "extra-collector-freshness-runtime-1"
        if freshness
        else "extra-systemd-collector-runtime-1",
        "completed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "goal_qualified": False,
        "scope": "real systemd collector sandbox and credential lifecycle, local functional controls",
        "real_human_login_tested": False,
        "production_installation_completed": False,
        "cases": [],
        "collector_runs": [],
    }
    previous = OperationDecision(0.1, 0.1, False, False, "baseline")
    expected_caps = (1 << 19) | (1 << 2)  # SYS_PTRACE, DAC_READ_SEARCH
    executable = executable_hash(Path("/usr/bin/python3"))
    fixture_script = (
        FIXTURE.replace("time.sleep(90)", "time.sleep(" + str(load_seconds + 300) + ")")
        if load_seconds
        else FIXTURE.replace("time.sleep(90)", "time.sleep(180)")
        if scheduling
        else FIXTURE
    )
    argv = ["/usr/bin/python3", "-u", "-c", fixture_script]
    command_hash = hashlib.sha256(b"".join(v.encode() + b"\0" for v in argv)).hexdigest()
    versions = [0]
    latest_path = state_dir / fixture_name / "latest.json"
    scope = CollectorScope(
        tenant_id="local-lab",
        server_id="shared-lab",
        unit=target_unit,
        source_id="local-proc",
        key_id="proc-1",
    )

    def check(name, condition):
        require(condition, "collector_runtime_control_" + name)
        report["cases"].append({"name": name, "passed": True})

    def configure(value):
        versions[0] += 1
        value = value.model_copy(update={"version": versions[0]})
        registry_path.write_bytes(canonical(value.model_dump(mode="json")))
        registry_path.chmod(0o644)
        pin = hashlib.sha256(registry_path.read_bytes()).hexdigest()
        environment_path.write_text(
            "TENANT_ID=local-lab\nSERVER_ID=shared-lab\nRUNTIME_SOURCE_ID=local-proc\n"
            "RUNTIME_KEY_ID=proc-1\nSERVICE_REGISTRY_SHA256=" + pin + "\n"
            "PYTHONPATH=" + os.environ["PYTHONPATH"] + "\n",
            encoding="utf8",
        )
        environment_path.chmod(0o644)
        return PinnedServiceRegistry(registry_path, pin, minimum_version=value.version)

    def all_captures():
        return sorted(state_dir.glob("*/*/capture.json")) if state_dir.exists() else []

    def capture(expected_success, *, credential_failure=False):
        before = set(all_captures())
        result = command("start", "--", collector_unit, check=False)
        messages = subprocess.run(
            [
                "/usr/bin/journalctl",
                "--no-pager",
                "--lines=64",
                "--output=json",
                "--output-fields=MESSAGE",
                "--unit=" + collector_unit,
            ],
            env=READ_ENV,
            capture_output=True,
            timeout=5,
            check=True,
        ).stdout
        private = active_key[0].private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        require(private not in messages, "collector_key_not_in_journal")
        (output / ("collector-attempt-" + str(len(report["collector_runs"])) + ".log")).write_bytes(
            messages
        )
        summaries = []
        for line in messages.splitlines():
            row = decode(line)
            message = row.get("MESSAGE")
            if isinstance(message, str) and message.startswith('{"completed":'):
                summaries.append(decode(message.encode()))
        added = set(all_captures()) - before
        if credential_failure:
            state = command(
                "show", "--no-pager", "--property=Result,ExecMainStatus", "--", collector_unit
            ).stdout
            require(
                result.returncode != 0 and not added and b"ExecMainStatus=243" in state,
                "collector_credential_start_failure",
            )
            report["collector_runs"].append(
                {
                    "succeeded": False,
                    "new_captures": 0,
                    "summary": {"failure_stage": "systemd_credentials"},
                }
            )
            command("reset-failed", "--", collector_unit, check=False)
            return None
        if not summaries:
            report["collector_start_failure"] = (
                command(
                    "show", "--no-pager", "--property=Result,ExecMainStatus", "--", collector_unit
                )
                .stdout.decode("ascii")
                .strip()
            )
        require(bool(summaries), "collector_summary_missing")
        latest = summaries[-1]
        require(
            (result.returncode == 0) == expected_success
            and latest["completed"] == expected_success
            and len(added) == (1 if expected_success else 0),
            "collector_expected_outcome",
        )
        report["collector_runs"].append(
            {"succeeded": expected_success, "new_captures": len(added), "summary": latest}
        )
        if not expected_success:
            command("reset-failed", "--", collector_unit, check=False)
            return None
        path = added.pop()
        payload = decode(path.read_bytes())
        event = ServiceEvent.model_validate(payload["event"])
        proof = ServiceProof.model_validate(payload["runtime_proof"])
        captures.append((event, proof))
        require(
            proof.observation.command_sha256 == command_hash
            and proof.observation.executable_sha256 == executable,
            "collector_actual_command",
        )
        return latest, event, proof

    def authorized(event, runtime, pinned, observed):
        policy = PolicyObservation(
            decision="allow",
            policy_sha256=registry.policy_sha256,
            policy_version=1,
            executable_sha256=executable,
            command_sha256=command_hash,
        )
        permission = sign_policy(
            event, policy, keys["authorization"], observed_at=observed, issued_at=datetime.now(UTC)
        )
        joiner = ServiceEvidenceJoiner(pinned, output / ("join-" + uuid.uuid4().hex + ".sqlite3"))
        require(
            joiner.check(event, [runtime, permission]).state == "consistent",
            "collector_signed_join",
        )
        require(
            VerifiedServiceRisk(joiner).decide(previous, event=event, proofs=[runtime, permission])
            is previous,
            "collector_normal_baseline_unchanged",
        )
        return permission

    try:
        pin = configure(registry)
        with target_path.open("x", encoding="utf8") as stream:
            created.append(target_path)
            stream.write(
                "[Service]\nType=exec\nUser=nobody\nPrivateNetwork=yes\nNoNewPrivileges=yes\n"
                "ProtectSystem=strict\nProtectHome=yes\nMemoryMax=64M\nTasksMax=8\n"
                + (
                    "RuntimeMaxSec=" + str(load_seconds + 360) + "\n"
                    if load_seconds
                    else "RuntimeMaxSec=240\n"
                    if scheduling
                    else "RuntimeMaxSec=120\n"
                )
                + 'Restart=no\nExecStart=/usr/bin/python3 -u -c "'
                + fixture_script
                + '"\n'
            )
        template = (source / "infra/systemd/secops-execution-collector@.service").read_text()
        if freshness:
            # Exercise bounded fault cases quickly on this owned fixture only.
            template = template.replace("[Unit]", "[Unit]\nStartLimitBurst=30")
        # Use an existing static nonroot fixture account; never create/change
        # real host accounts in this acceptance harness.
        template = template.replace("User=secops-collector", "User=daemon")
        template = template.replace("Group=secops-collector", "Group=daemon")
        template = template.replace("/opt/secops/.venv/bin/python", "/usr/bin/python3")
        template = template.replace("/opt/secops", str(source))
        template = template.replace("/etc/secops/collector.conf", str(environment_path))
        template = template.replace("/etc/secops/service-registry.json", str(registry_path))
        template = template.replace(
            "/run/secops-credentials/runtime-key.sock", str(credential_path)
        )
        template = template.replace(
            "StateDirectory=secops-evidence", "StateDirectory=" + state_name
        )
        template = template.replace("/var/lib/secops-evidence", str(state_dir))
        with template_path.open("x", encoding="utf8") as stream:
            created.append(template_path)
            stream.write(template)
        command("daemon-reload")
        users = subprocess.run(
            [
                "/usr/bin/systemd-sysusers",
                "--dry-run",
                str(source / "infra/systemd/secops-collector.sysusers"),
            ],
            env=READ_ENV,
            capture_output=True,
            timeout=5,
            check=False,
        )
        check("service_account_configuration_dry_run", users.returncode == 0)
        command("start", "--", target_unit)
        with (
            CredentialSocket(
                credential_path,
                lambda: active_key[0].private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                ),
            ) as provider,
            ExitStack() as replacements,
        ):
            active_provider = provider
            credential_providers = [provider]
            scheduled_deliveries = 0
            reporting_deliveries = 0
            load_deliveries = 0
            observed = datetime.now(UTC)
            summary, first_event, first_proof = capture(True)
            security = summary["collector_security"]
            check("collector_is_static_nonroot_fixture", security["effective_uid"] == 1)
            check(
                "only_required_effective_and_bounding_capabilities",
                security["effective_capabilities"]
                == security["bounding_capabilities"]
                == expected_caps,
            )
            check("no_new_privileges_is_observed", security["no_new_privileges"])
            first_permission = authorized(first_event, first_proof, pin, observed)
            check("normal_capture_and_authorization_keep_baseline", first_permission is not None)
            check("credential_was_a_socket_not_key_file", credential_path.is_socket())
            if freshness:
                monitor = CollectorMonitor(scope, pin, output / "freshness.sqlite3")
                check("initial_signed_latest_is_fresh", monitor.check(latest_path).state == "fresh")
                stale_monitor = CollectorMonitor(scope, pin, output / "controlled-clock.sqlite3")
                check(
                    "controlled_31_second_gap_is_stale",
                    stale_monitor.check(
                        latest_path, now=first_event.observed_at + timedelta(seconds=31)
                    ).state
                    == "stale",
                )
                restarted_clock = CollectorMonitor(scope, pin, output / "controlled-clock.sqlite3")
                check(
                    "controlled_clock_rollback_after_restart_is_unavailable",
                    restarted_clock.check(
                        latest_path, now=first_event.observed_at + timedelta(seconds=30)
                    ).reason
                    == "clock_regression",
                )
            active_key[0] = Ed25519PrivateKey.generate()
            check("rotated_key_without_current_pin_is_rejected", capture(False) is None)
            public = (
                base64.urlsafe_b64encode(
                    active_key[0].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                )
                .decode()
                .rstrip("=")
            )
            rotated = registry.model_copy(
                update={
                    "version": 2,
                    "authorities": [
                        a.model_copy(update={"public_key": public}) if a.kind == "runtime" else a
                        for a in registry.authorities
                    ],
                }
            )
            pin = configure(rotated)
            observed = datetime.now(UTC)
            _, next_event, next_proof = capture(True)
            authorized(next_event, next_proof, pin, observed)
            check(
                "rotation_with_new_public_pin_collects_fresh_evidence",
                first_event.event_id != next_event.event_id,
            )
            check(
                "old_key_proof_is_rejected_by_current_registry",
                ServiceEvidenceJoiner(pin, output / "revoked.sqlite3")
                .check(first_event, [first_proof, first_permission])
                .state
                == "unavailable",
            )
            if freshness:
                last_bytes = latest_path.read_bytes()
                expired_at = datetime.now(UTC)
                expired = rotated.model_copy(
                    update={
                        "authorities": [
                            a.model_copy(
                                update={
                                    "issued_at": expired_at - timedelta(seconds=60),
                                    "expires_at": expired_at - timedelta(seconds=1),
                                }
                            )
                            if a.kind == "runtime"
                            else a
                            for a in rotated.authorities
                        ]
                    }
                )
                configure(expired)
                check("expired_signing_authority_cannot_create_capture", capture(False) is None)
                check(
                    "failed_expired_key_keeps_previous_latest",
                    latest_path.read_bytes() == last_bytes,
                )
                future_at = datetime.now(UTC) + timedelta(seconds=60)
                future = rotated.model_copy(
                    update={
                        "authorities": [
                            a.model_copy(update={"issued_at": future_at})
                            if a.kind == "runtime"
                            else a
                            for a in rotated.authorities
                        ]
                    }
                )
                configure(future)
                check("not_yet_valid_signing_authority_is_rejected", capture(False) is None)
                short_expiry = datetime.now(UTC) + timedelta(seconds=20)
                short = rotated.model_copy(
                    update={
                        "authorities": [
                            a.model_copy(update={"expires_at": short_expiry})
                            if a.kind == "runtime"
                            else a
                            for a in rotated.authorities
                        ]
                    }
                )
                pin = configure(short)
                observed = datetime.now(UTC)
                _, short_event, short_proof = capture(True)
                authorized(short_event, short_proof, pin, observed)
                check(
                    "runtime_proof_expiry_is_clipped_to_signer",
                    short_proof.expires_at == short_expiry,
                )
                pin = configure(rotated)
                before_outage = latest_path.read_bytes()
                provider.close()
                check(
                    "missing_key_provider_fails_at_systemd_credentials",
                    capture(False, credential_failure=True) is None,
                )
                check(
                    "provider_outage_cannot_replace_latest",
                    latest_path.read_bytes() == before_outage,
                )
                active_provider = replacements.enter_context(
                    CredentialSocket(
                        credential_path,
                        lambda: active_key[0].private_bytes(
                            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                        ),
                    )
                )
                credential_providers.append(active_provider)
                observed = datetime.now(UTC)
                _, recovered_event, recovered_proof = capture(True)
                authorized(recovered_event, recovered_proof, pin, observed)
                monitor.registry = pin
                check(
                    "provider_restart_collects_new_signed_evidence",
                    recovered_event.sha256 != short_event.sha256
                    and monitor.check(latest_path).state == "fresh",
                )
                old_path = output / "old-latest.json"
                old_path.write_bytes(before_outage)
                check(
                    "restoring_an_older_valid_capture_is_rejected",
                    monitor.check(old_path).reason == "capture_regression",
                )
                if archival:
                    from scripts.f1_lab.capture_archive_runtime import run_archive_controls

                    report["archive_controls"] = run_archive_controls(
                        source,
                        state_dir / fixture_name,
                        latest_path,
                        scope,
                        monitor,
                        short_event,
                        output,
                        check,
                    )
                if scheduling:
                    from scripts.f1_lab.collector_schedule_runtime import run_schedule_controls

                    def restore_provider():
                        replacement = replacements.enter_context(
                            CredentialSocket(
                                credential_path,
                                lambda: active_key[0].private_bytes(
                                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                                ),
                            )
                        )
                        credential_providers.append(replacement)
                        return replacement

                    schedule_report, active_provider = run_schedule_controls(
                        source,
                        state_dir / fixture_name,
                        scope,
                        monitor,
                        active_provider,
                        restore_provider,
                        lambda event, proof: authorized(event, proof, pin, event.observed_at),
                        output,
                        check,
                        collector_unit,
                    )
                    report["schedule_controls"] = schedule_report
                    scheduled_deliveries = schedule_report["credential_deliveries"]
                if reporting:
                    from scripts.f1_lab.collector_status_runtime import run_status_controls

                    observed = datetime.now(UTC)
                    _, status_event, status_proof = capture(True)
                    check(
                        "fresh_normal_capture_precedes_public_status",
                        authorized(status_event, status_proof, pin, observed) is not None,
                    )
                    reporting_deliveries = 1
                    report["status_controls"] = run_status_controls(
                        source, state_dir / fixture_name, scope, output, check
                    )
                if backups:
                    from scripts.f1_lab.capture_backup_runtime import run_backup_controls

                    report["backup_controls"] = run_backup_controls(
                        source, state_dir / fixture_name, scope, monitor, output, check
                    )
                if load_seconds:
                    from scripts.f1_lab.capture_load_runtime import run_load_controls

                    report["load_controls"], active_provider = run_load_controls(
                        source,
                        state_dir / fixture_name,
                        scope,
                        monitor,
                        capture,
                        lambda event, proof: authorized(event, proof, pin, event.observed_at),
                        output,
                        check,
                        collector_unit,
                        target_unit,
                        load_seconds,
                        active_provider,
                        restore_provider,
                    )
                    load_deliveries = report["load_controls"]["credential_deliveries"]
            disabled = rotated.model_copy(
                update={
                    "version": 3,
                    "authorities": [
                        a.model_copy(update={"enabled": False}) if a.kind == "runtime" else a
                        for a in rotated.authorities
                    ],
                }
            )
            configure(disabled)
            check("disabled_collector_key_cannot_create_capture", capture(False) is None)
            configure(rotated.model_copy(update={"version": 4}))
            command("stop", "--", target_unit)
            check("stopped_target_cannot_be_backfilled", capture(False) is None)
            check(
                "only_root_manager_read_credentials",
                sum(item.delivered for item in credential_providers)
                == (9 if freshness else 5)
                + scheduled_deliveries
                + reporting_deliveries
                + load_deliveries
                and all(item.rejected == 0 for item in credential_providers),
            )
        check(
            "credential_socket_removed_and_provider_stopped",
            not credential_path.exists() and not provider.thread.is_alive(),
        )
        report.update(
            completed=True,
            normal_controls=len(captures),
            normal_added_alerts=0,
            private_key_disk_files_created=0,
            systemd_memory_credential_copy=True,
            private_key_persisted=False,
            tokens_persisted=False,
            real_systemd_tested=True,
            template_security_directives_preserved=True,
            template_installation_paths_substituted=True,
            collector_security=security,
            existing_static_fixture_account_used=True,
            real_service_account_created=False,
            freshness_controlled_clock_used=freshness,
            scheduling_real_elapsed_outage_used=scheduling,
            systemd_version=subprocess.check_output(
                ["/usr/bin/systemctl", "--version"], env=READ_ENV, text=True
            ).splitlines()[0],
        )
    finally:
        for unit, owned_path in ((collector_unit, template_path), (target_unit, target_path)):
            if owned_path in created:
                command("stop", "--", unit, check=False)
                command("reset-failed", "--", unit, check=False)
        for path in created:
            path.unlink()
        command("daemon-reload")
        if state_dir.exists():
            resolved = state_dir.resolve()
            require(
                resolved.name == state_name
                and resolved.parent in {Path("/var/lib"), Path("/var/lib/private")},
                "collector_state_cleanup_scope",
            )
            shutil.rmtree(resolved)
            if state_dir.is_symlink():
                state_dir.unlink()
        require(
            config_dir.parent == Path("/run") and config_dir.name == "secops-v70-" + tag,
            "collector_config_cleanup_scope",
        )
        shutil.rmtree(config_dir)
        report["owned_units_removed"] = all(not p.exists() for p in created)
        report["owned_state_removed"] = not state_dir.exists()
        report["owned_config_and_socket_removed"] = not config_dir.exists()
        report["systemd_credentials_removed"] = not (
            Path("/run/credentials") / collector_unit
        ).exists()
        (output / "run.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    result = run(parser.parse_args().directory)
    print(json.dumps({"completed": result["completed"], "cases": len(result["cases"])}))


if __name__ == "__main__":
    main()
