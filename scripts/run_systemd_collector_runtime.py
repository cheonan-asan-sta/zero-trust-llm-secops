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
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

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


def run(directory):
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
        "schema": "extra-systemd-collector-runtime-1",
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
    argv = ["/usr/bin/python3", "-u", "-c", FIXTURE]
    command_hash = hashlib.sha256(b"".join(v.encode() + b"\0" for v in argv)).hexdigest()

    def check(name, condition):
        require(condition, "collector_runtime_control_" + name)
        report["cases"].append({"name": name, "passed": True})

    def configure(value):
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

    def capture(expected_success):
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
        added = set(all_captures()) - before
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
                'RuntimeMaxSec=120\nRestart=no\nExecStart=/usr/bin/python3 -u -c "'
                + FIXTURE
                + '"\n'
            )
        template = (source / "infra/systemd/secops-execution-collector@.service").read_text()
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
            ["/usr/bin/systemd-sysusers", "--dry-run", str(source / "infra/systemd/secops-collector.sysusers")],
            env=READ_ENV, capture_output=True, timeout=5, check=False,
        )
        check("service_account_configuration_dry_run", users.returncode == 0)
        command("start", "--", target_unit)
        with CredentialSocket(
            credential_path,
            lambda: active_key[0].private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        ) as provider:
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
                provider.delivered == 5 and provider.rejected == 0,
            )
        check(
            "credential_socket_removed_and_provider_stopped",
            not credential_path.exists() and not provider.thread.is_alive(),
        )
        report.update(
            completed=True,
            normal_controls=2,
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
            systemd_version=subprocess.check_output(
                ["/usr/bin/systemctl", "--version"], env=READ_ENV, text=True
            ).splitlines()[0],
        )
    finally:
        for unit in (collector_unit, target_unit):
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
