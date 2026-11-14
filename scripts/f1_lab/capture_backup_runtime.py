"""Owned real-systemd encrypted archive backup and source-loss restore controls."""

import json
import secrets
import shutil
import sqlite3
import subprocess
import uuid
from contextlib import ExitStack
from pathlib import Path

from scripts.f1_lab.capture_archive import CaptureArchive
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.shared_execution_collector import READ_ENV
from scripts.f1_lab.systemd_credentials import CredentialSocket


def command(*args, check=True):
    return subprocess.run(
        ["/usr/bin/systemctl", *args], env=READ_ENV, capture_output=True, timeout=20, check=check
    )


def run_backup_controls(source, root, scope, monitor, output, check):
    tag = uuid.uuid4().hex
    prefix = "zt75b-" + tag[:12]
    unit = prefix + "@" + root.name + ".service"
    unit_path = Path("/run/systemd/system") / (prefix + "@.service")
    names = ["secops-cp-v75-" + tag, "secops-backup-v75-" + tag, "secops-review-v75-" + tag]
    bases = [Path("/var/lib") / name for name in names]
    checkpoint_dir, backup_dir, review_dir = [base / root.name for base in bases]
    checkpoint = checkpoint_dir / "checkpoint.json"
    config_dir = Path("/run") / root.parent.name
    public_config = config_dir / "capture-backup.conf"
    credential_dir = config_dir / "backup-credentials"
    credential_dir.mkdir(mode=0o700)
    socket_path = credential_dir / "key.sock"
    key = secrets.token_bytes(32)
    supplied = [key]
    cp_pin = ["0" * 64]
    created = False
    results = []
    latest = (root / "latest.json").read_bytes()
    database = (root / "archive.sqlite3").read_bytes()
    saved = root / ("archive-offline-" + tag)
    require(root.parent.name.startswith("secops-v70-"), "backup_fixture_source_scope")

    def rows(path):
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as con:
            return {
                rid: CaptureArchive.unpack(payload, size, digest)
                for rid, size, payload, digest in con.execute(
                    "SELECT run_id,raw_bytes,payload,raw_sha FROM captures ORDER BY seq"
                )
            }

    originals = rows(root / "archive.sqlite3")
    rid = next(reversed(originals))
    base = (source / "infra/systemd/secops-capture-backup@.service").read_text()
    replacements = {
        "User=secops-collector": "User=daemon",
        "Group=secops-collector": "Group=daemon",
        "/opt/secops/.venv/bin/python": "/usr/bin/python3",
        "/opt/secops": str(source),
        "/etc/secops/collector.conf": str(config_dir / "collector.conf"),
        "/etc/secops/capture-backup.conf": str(public_config),
        "/run/secops-credentials/capture-backup-key.sock": str(socket_path),
        "/var/lib/secops-evidence": str(root.parent),
        "/var/lib/secops-capture-checkpoints": str(bases[0]),
        "/var/lib/secops-capture-backups": str(bases[1]),
        "StateDirectory=secops-capture-backups/%i": "StateDirectory="
        + " ".join(name + "/%i" for name in names),
    }
    for old, new in replacements.items():
        base = base.replace(old, new)

    def configure():
        public_config.write_text(
            "CAPTURE_BACKUP_KEY_ID=capture-native-recovery\nCAPTURE_CHECKPOINT_PATH="
            + str(checkpoint)
            + "\nCAPTURE_CHECKPOINT_SHA256="
            + cp_pin[0]
            + "\n"
        )
        public_config.chmod(0o644)

    common = (
        f"/usr/bin/python3 -m scripts.capture_archive_backup {{mode}} --tenant {scope.tenant_id} "
        f"--server {scope.server_id} --unit {scope.unit} --source {scope.source_id} "
    )

    def execute(mode, extra="", key_needed=False, credential_failure=False):
        body = base
        if mode != "backup":
            lines = body.splitlines()
            position = next(i for i, line in enumerate(lines) if line.startswith("ExecStart="))
            if mode == "extract":
                argv = (
                    f"/usr/bin/python3 -m scripts.archive_service_captures --root {review_dir}/restored/review "
                    f"--tenant {scope.tenant_id} --server {scope.server_id} --unit {scope.unit} --source {scope.source_id} "
                    f"--restore {rid} --output {review_dir}/extracted"
                )
            else:
                argv = (
                    common.format(mode=mode)
                    + extra
                    + (" --systemd-credential" if key_needed else "")
                )
            lines[position] = "ExecStart=" + argv
            if not key_needed:
                lines = [line for line in lines if not line.startswith("LoadCredential=")]
            if mode == "checkpoint":
                lines = [line for line in lines if not line.startswith("ReadOnlyPaths=")]
                lines.append("ReadOnlyPaths=" + str(root))
            body = "\n".join(lines) + "\n"
        unit_path.write_text(body)
        command("daemon-reload")
        result = command("start", "--", unit, check=False)
        journal = subprocess.run(
            [
                "/usr/bin/journalctl",
                "--no-pager",
                "--lines=64",
                "--output=json",
                "--output-fields=MESSAGE",
                "--unit=" + unit,
            ],
            env=READ_ENV,
            capture_output=True,
            timeout=5,
            check=True,
        ).stdout
        require(
            key not in journal and key.hex().encode() not in journal, "backup_key_not_in_journal"
        )
        if credential_failure:
            state = command(
                "show", "--value", "--property=ExecMainStatus", "--", unit
            ).stdout.strip()
            require(
                result.returncode != 0 and state == b"243", "backup_fixture_credentials_failure"
            )
            value = {"completed": False, "stage": "systemd_credentials"}
        else:
            messages = []
            for line in journal.splitlines():
                text = decode(line).get("MESSAGE")
                if isinstance(text, str) and text.startswith('{"completed":'):
                    messages.append(decode(text.encode()))
            require(messages, "backup_fixture_summary")
            value = messages[-1]
            require((result.returncode == 0) == value["completed"], "backup_fixture_outcome")
        if result.returncode:
            command("reset-failed", "--", unit, check=False)
        results.append({"mode": mode, "summary": value})
        return value

    report = {
        "completed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "recovery_key_persisted": False,
        "private_signing_key_in_backup": False,
        "automatic_activation_allowed": False,
        "production_installation_completed": False,
    }
    try:
        configure()
        with unit_path.open("x") as stream:
            created = True
            stream.write(base)
        with ExitStack() as stack:
            checkpoint_result = execute("checkpoint", f"--root {root} --output {checkpoint}")
            require(checkpoint_result["completed"], "native_checkpoint_created")
            cp_pin[0] = checkpoint_result["checkpoint_sha256"]
            configure()
            check(
                "cold_archive_checkpoint_is_published_outside_source",
                checkpoint.is_file() and root not in checkpoint.parents,
            )
            provider = stack.enter_context(CredentialSocket(socket_path, lambda: supplied[0]))
            backed = execute("backup", key_needed=True)
            require(backed["completed"], "native_backup_completed")
            security = backed["worker_security"]
            check(
                "backup_service_is_nonroot_without_capabilities",
                security["effective_uid"] == 1
                and security["effective_capabilities"] == security["bounding_capabilities"] == 0
                and security["no_new_privileges"],
            )
            packages = [p for p in backup_dir.iterdir() if p.is_dir()]
            require(len(packages) == 1, "native_single_backup_package")
            package = packages[0]
            check(
                "backup_is_encrypted_and_contains_no_hot_latest",
                {p.name for p in package.iterdir()} == {"manifest.json", "payload.aesgcm"}
                and not (package / "payload.aesgcm").read_bytes().startswith(b"SQLite format 3"),
            )
            arguments = (
                f"--backup {package} --manifest-sha256 {backed['manifest_sha256']} --checkpoint {checkpoint} "
                f"--checkpoint-sha256 {cp_pin[0]} --key-id capture-native-recovery "
            )
            supplied[0] = secrets.token_bytes(32)
            wrong = execute(
                "restore", arguments + f"--output {review_dir}/wrong-key", key_needed=True
            )
            check(
                "wrong_recovery_key_creates_no_review",
                not wrong["completed"] and not (review_dir / "wrong-key").exists(),
            )
            supplied[0] = key
            before = set(backup_dir.iterdir())
            provider.close()
            unavailable = execute("backup", key_needed=True, credential_failure=True)
            check(
                "missing_backup_key_provider_cannot_publish_package",
                not unavailable["completed"] and set(backup_dir.iterdir()) == before,
            )
            replacement = stack.enter_context(CredentialSocket(socket_path, lambda: supplied[0]))
            (root / "archive.sqlite3").rename(saved)
            try:
                restored = execute(
                    "restore", arguments + f"--output {review_dir}/restored", key_needed=True
                )
                check(
                    "restore_succeeds_while_original_archive_database_is_absent",
                    restored["completed"] and not (root / "archive.sqlite3").exists(),
                )
                verified = execute(
                    "verify",
                    f"--checkpoint {checkpoint} --checkpoint-sha256 {cp_pin[0]} "
                    f"--receipt-sha256 {restored['receipt_sha256']} --output {review_dir}/restored",
                )
                check(
                    "isolated_restored_archive_matches_all_original_capture_bytes",
                    verified["completed"]
                    and rows(review_dir / "restored/review/archive.sqlite3") == originals,
                )
                extracted = execute("extract")
                check(
                    "extracted_historical_capture_does_not_become_fresh",
                    extracted["completed"]
                    and (review_dir / "extracted/capture.json").read_bytes() == originals[rid]
                    and monitor.check(review_dir / "extracted/capture.json").state != "fresh",
                )
            finally:
                if saved.exists():
                    saved.rename(root / "archive.sqlite3")
            check(
                "backup_restore_never_changes_original_database_or_latest",
                (root / "archive.sqlite3").read_bytes() == database
                and (root / "latest.json").read_bytes() == latest,
            )
            check(
                "only_root_manager_receives_separate_recovery_credential",
                provider.delivered + replacement.delivered == 3
                and provider.rejected == replacement.rejected == 0,
            )
            report.update(
                completed=True,
                records=len(originals),
                results=results,
                worker_security=security,
                source_database_unchanged=True,
                latest_unchanged=True,
                all_original_cold_capture_bytes_preserved=True,
                systemd_memory_credential_copy=True,
            )
    finally:
        if saved.exists():
            saved.rename(root / "archive.sqlite3")
        if created:
            command("stop", "--", unit, check=False)
            command("reset-failed", "--", unit, check=False)
            unit_path.unlink()
            command("daemon-reload")
        for base_path in bases:
            if base_path.exists():
                resolved = base_path.resolve()
                require(
                    resolved.parent == Path("/var/lib") and resolved.name in names,
                    "backup_fixture_cleanup_scope",
                )
                shutil.rmtree(resolved)
        if public_config.exists():
            public_config.unlink()
        if credential_dir.exists():
            require(credential_dir.parent == config_dir, "backup_credential_cleanup_scope")
            shutil.rmtree(credential_dir)
        report["owned_units_removed"] = not unit_path.exists()
        report["owned_backup_state_removed"] = all(not p.exists() for p in bases)
        report["owned_credential_socket_removed"] = not socket_path.exists()
        (output / "backup-controls.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
