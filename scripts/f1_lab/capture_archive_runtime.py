"""Owned real-systemd archive controls; no production installation or key input."""

import hashlib
import json
import shutil
import sqlite3
import subprocess
import uuid
from pathlib import Path

from scripts.f1_lab.capture_archive import CaptureArchive
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.shared_execution_collector import READ_ENV
from scripts.f1_lab.shared_execution_evidence import ServiceEvent


def command(*args, check=True):
    return subprocess.run(
        ["/usr/bin/systemctl", *args], capture_output=True, env=READ_ENV, timeout=20, check=check
    )


def run_archive_controls(source, root, latest, scope, monitor, short_event, output, check):
    tag = uuid.uuid4().hex
    prefix = "zt72a-" + tag[:12]
    unit = prefix + "@" + root.name + ".service"
    unit_path = Path("/run/systemd/system") / (prefix + "@.service")
    restore_name = "secops-archive-restore-" + tag
    restore_base = Path("/var/lib") / restore_name
    before = {p.parent.name: p.read_bytes() for p in root.glob("*/capture.json")}
    latest_before = latest.read_bytes()
    restore_id = next(
        rid
        for rid, raw in before.items()
        if ServiceEvent.model_validate(decode(raw)["event"]).sha256 == short_event.sha256
    )
    config = Path("/run") / root.parent.name / "collector.conf"
    require(config.is_file(), "archive_fixture_configuration")
    body = (source / "infra/systemd/secops-capture-archive@.service").read_text()
    body = body.replace("User=secops-collector", "User=daemon").replace(
        "Group=secops-collector", "Group=daemon"
    )
    body = body.replace("/opt/secops/.venv/bin/python", "/usr/bin/python3").replace(
        "/opt/secops", str(source)
    )
    body = body.replace("/etc/secops/collector.conf", str(config))
    body = body.replace("/var/lib/secops-evidence", str(root.parent))
    body = body.replace(
        "StateDirectory=secops-evidence", "StateDirectory=" + root.parent.name + " " + restore_name
    )
    created = False
    summaries = []

    def execute(mode, extra=""):
        current = body.replace(" --apply ", " ") if mode in {"preview", "restore"} else body
        lines = current.splitlines()
        indices = [i for i, line in enumerate(lines) if line.startswith("ExecStart=")]
        require(len(indices) == 1, "archive_fixture_command")
        lines[indices[0]] += " --max-hot-records 1 --max-hot-bytes 1048576 " + extra
        unit_path.write_text("\n".join(lines) + "\n")
        command("daemon-reload")
        result = command("start", "--", unit, check=False)
        raw = subprocess.run(
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
        messages = []
        for line in raw.splitlines():
            text = decode(line).get("MESSAGE")
            if isinstance(text, str) and text.startswith('{"completed":'):
                messages.append(decode(text.encode()))
        require(messages, "archive_fixture_summary")
        summary = messages[-1]
        require((result.returncode == 0) == (mode != "pressure"), "archive_fixture_outcome")
        if mode == "pressure":
            command("reset-failed", "--", unit, check=False)
        summaries.append({"mode": mode, "summary": summary})
        return summary

    try:
        with unit_path.open("x", encoding="utf8") as stream:
            created = True
            stream.write(body)
        preview = execute("preview")
        check(
            "archive_preview_keeps_every_hot_byte",
            preview["planned"] == 3
            and not (root / "archive.sqlite3").exists()
            and before == {p.parent.name: p.read_bytes() for p in root.glob("*/capture.json")},
        )
        security = preview["worker_security"]
        check(
            "archive_worker_is_nonroot_without_capabilities",
            security["effective_uid"] == 1
            and security["effective_capabilities"] == security["bounding_capabilities"] == 0
            and security["no_new_privileges"],
        )
        pressure = execute("pressure", "--max-records 2")
        check(
            "archive_capacity_pressure_keeps_hot_and_latest",
            not pressure["completed"]
            and pressure["error_type"] == "ArchiveFull"
            and latest.read_bytes() == latest_before
            and before == {p.parent.name: p.read_bytes() for p in root.glob("*/capture.json")},
        )
        applied = execute("apply")
        check(
            "committed_archive_keeps_latest_and_meets_hot_limit",
            applied["archive_records"] == 3
            and applied["deleted_hot_files"] == 3
            and applied["hot_after_records"] == 1
            and applied["managed_budget_satisfied"]
            and latest.read_bytes() == latest_before,
        )
        database = root / "archive.sqlite3"
        con = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT run_id,raw_bytes,payload,raw_sha FROM captures").fetchall()
            require(len(rows) == 3, "archive_fixture_count")
            for rid, size, payload, expected in rows:
                require(
                    CaptureArchive.unpack(payload, size, expected) == before[rid],
                    "archive_fixture_byte_comparison",
                )
        finally:
            con.close()
        check("all_cold_payloads_equal_original_hot_bytes", True)
        restored = execute(
            "restore", "--restore " + restore_id + " --output " + str(restore_base / "restored")
        )
        restored_path = restore_base / "restored/capture.json"
        check(
            "restore_preserves_every_original_byte",
            restored_path.read_bytes() == before[restore_id]
            and restored["raw_sha256"] == hashlib.sha256(before[restore_id]).hexdigest(),
        )
        check(
            "restored_old_capture_does_not_become_current",
            monitor.check(restored_path).reason == "capture_regression",
        )
        check("latest_remains_fresh_after_compaction", monitor.check(latest).state == "fresh")
        report = {
            "completed": True,
            "scope": "owned real-systemd lossless archival controls",
            "runs": summaries,
            "restored_raw_sha256": restored["raw_sha256"],
            "all_three_archived_payloads_byte_equal": True,
            "cold_payload_compression_is_not_database_file_size": True,
            "paid_api_calls": 0,
            "aws_calls": 0,
            "fixture_account_substituted": True,
            "operational_service_account_created": False,
        }
    finally:
        if created:
            command("stop", "--", unit, check=False)
            command("reset-failed", "--", unit, check=False)
            unit_path.unlink()
            command("daemon-reload")
        if restore_base.exists():
            resolved = restore_base.resolve()
            require(
                resolved.name == restore_name
                and resolved.parent in {Path("/var/lib"), Path("/var/lib/private")},
                "archive_restore_cleanup_scope",
            )
            shutil.rmtree(resolved)
            if restore_base.is_symlink():
                restore_base.unlink()
    report["owned_archive_unit_removed"] = not unit_path.exists()
    report["owned_restore_state_removed"] = not restore_base.exists()
    (output / "archive-controls.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
