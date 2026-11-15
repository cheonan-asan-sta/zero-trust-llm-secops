"""Actual managed execution through pending, complete backup and safe cleanup."""

import json
import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature

from scripts.f1_lab import exec_outbox_status as status
from scripts.f1_lab import managed_exec_retention as retention
from scripts.f1_lab.capture_archive import CaptureArchive
from scripts.f1_lab.capture_backup import CaptureBackup
from scripts.f1_lab.exec_history_launcher import HistoryUnitLauncher
from scripts.f1_lab.exec_outbox import inspect_outbox, prune_outbox, snapshot_outbox
from scripts.f1_lab.exec_outbox_owner_controls import run as run_owner
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical


def begin(lab, launcher, private, root, outbox, scope, public, output, check):
    for name in ("request.json", "capture.json"):
        (launcher.directory / name).unlink()
    next_launcher = HistoryUnitLauncher(
        lab.target, launcher.argv, launcher.directory, source_id="local-proc", key_id="proc-1"
    )
    gate = lab.gate(lab.new_request(), lab.new_access())
    with patch.object(
        retention, "publish_sealed", side_effect=OSError("owned publication interruption")
    ):
        try:
            retention.dispatch_and_retain(gate, next_launcher, lab.permission, root, outbox)
        except OSError:
            pass
        else:
            raise AssertionError("publication fault was not injected")
    pending = outbox / (gate.request.request_id + ".json")
    original = pending.read_bytes()
    require(not (root / gate.request.request_id).exists(), "outbox_unpublished_fixture")
    check("actual_fourth_exec_seals_durable_outbox_before_injected_publication_failure")

    def inspect():
        return inspect_outbox(outbox, root, scope, lab.broker.joiner.registry, lab.broker.registry)

    initial = inspect()
    require(
        initial["records"] == 4 and initial["pending"] == 1 and initial["published"] == 3,
        "outbox_actual_pending",
    )
    status.publish(public / "outbox-pending.json", status.report(scope, initial))
    check("actual_pending_record_is_detected_without_treating_old_latest_as_complete")
    security = run_owner(lab, root, outbox, scope, check)
    mirror = private / "outbox-mirror"
    mirrored = snapshot_outbox(outbox, root, scope, mirror)
    require(mirrored["records"] == 4, "outbox_mirror_all")
    check("full_mirror_includes_newest_hot_and_unpublished_sealed_records")
    manager = CaptureBackup(scope)
    checkpoint = private / "outbox-checkpoint.json"
    cp = manager.checkpoint(mirror, checkpoint)
    key = secrets.token_bytes(32)
    packages = private / "outbox-packages"
    packages.mkdir(mode=0o700)
    package, review = packages / "encrypted", private / "outbox-restored"
    backup = manager.backup(mirror, package, checkpoint, cp["checkpoint_sha256"], key, "outbox-1")
    (mirror / "archive.sqlite3").unlink()
    receipt = manager.restore(
        package,
        backup["manifest_sha256"],
        checkpoint,
        cp["checkpoint_sha256"],
        review,
        key,
        "outbox-1",
    )
    require(
        manager.verify(review, receipt["receipt_sha256"], checkpoint, cp["checkpoint_sha256"])[
            "records"
        ]
        == 4,
        "outbox_restore_all",
    )
    recovered = CaptureArchive(review / "review", scope)
    source_records = {p.stem: p.read_bytes() for p in outbox.glob("*.json")}
    for rid, raw in source_records.items():
        destination = private / ("outbox-extracted-" + rid)
        recovered.restore(rid, destination)
        require((destination / "capture.json").read_bytes() == raw, "outbox_restore_bytes")
    check("encrypted_full_outbox_restores_four_original_records_after_mirror_database_loss")
    args = (
        outbox,
        root,
        scope,
        review,
        receipt["receipt_sha256"],
        checkpoint,
        cp["checkpoint_sha256"],
    )
    preview = prune_outbox(*args, now=datetime.now(UTC) + timedelta(seconds=65), min_age_seconds=60)
    require(preview["eligible"] == 3 and preview["deleted"] == 0, "outbox_prune_preview")
    check("cleanup_preview_requires_published_and_pinned_restore_matches")
    cleaned = prune_outbox(
        *args, now=datetime.now(UTC) + timedelta(seconds=65), min_age_seconds=60, apply=True
    )
    require(
        cleaned["deleted"] == 3
        and cleaned["pending_preserved"] == 1
        and pending.read_bytes() == original,
        "outbox_cleanup_protects_pending",
    )
    check("controlled_age_cleanup_removes_three_backed_published_records_and_keeps_pending")
    repeat = prune_outbox(
        *args, now=datetime.now(UTC) + timedelta(seconds=65), min_age_seconds=60, apply=True
    )
    require(repeat["deleted"] == 0 and repeat["pending_preserved"] == 1, "outbox_cleanup_repeat")
    check("cleanup_retry_is_idempotent_and_cannot_delete_unpublished_record")
    damaged = json.loads(original)
    signature = damaged["signature"]
    damaged["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    pending.write_bytes(canonical(damaged))
    try:
        try:
            inspect()
        except (ValueError, InvalidSignature):
            status.publish(public / "outbox-unavailable.json", status.report(scope))
        else:
            raise AssertionError("damaged outbox seal accepted")
    finally:
        pending.write_bytes(original)
    check("actual_seal_damage_becomes_unavailable_without_stale_queue_counts")

    def finish():
        retention.publish_sealed(original, root, lab.broker.joiner.registry, lab.broker.registry)
        final = inspect()
        require(
            final["records"] == 1
            and final["pending"] == 0
            and final["published"] == 1
            and pending.read_bytes() == original
            and (root / "latest.json").read_bytes() == original,
            "outbox_resume_without_execution",
        )
        status.publish(public / "outbox-ready.json", status.report(scope, final))
        check("pending_resume_republishes_same_bytes_without_command_retry_or_timestamp_renewal")
        (output / "outbox-controls.json").write_text(
            json.dumps(
                {
                    "completed": True,
                    "actual_executions_including_reused_three": 4,
                    "backed_and_byte_exact_restored": 4,
                    "published_outbox_files_pruned": 3,
                    "pending_preserved_during_prune": 1,
                    "command_reexecuted_for_recovery": False,
                    "cleanup_age_clock_controlled": True,
                    "production_role_installation_completed": False,
                    "nonroot_status_worker_security": security,
                    "aws_calls": 0,
                    "paid_api_calls": 0,
                },
                indent=2,
            )
            + "\n"
        )

    return finish
