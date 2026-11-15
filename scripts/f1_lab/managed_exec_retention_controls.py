"""Actual completed systemd records through the existing cold recovery flow."""

import json
import secrets
from datetime import UTC, datetime, timedelta

from scripts.f1_lab import backup_recovery_status as backup_status
from scripts.f1_lab.capture_archive import ArchivePolicy, ArchiveScope, CaptureArchive
from scripts.f1_lab.capture_backup import CaptureBackup
from scripts.f1_lab.collector_freshness import CollectorMonitor, CollectorScope
from scripts.f1_lab.collector_status_bridge import archive_report, health_report, publish
from scripts.f1_lab.exec_history_launcher import HistoryUnitLauncher
from scripts.f1_lab.managed_exec_capture import ManagedExecCapture
from scripts.f1_lab.managed_exec_retention import (
    dispatch_and_retain,
    publish_sealed,
    seal_completed,
)
from scripts.f1_lab.native_jsonl import decode, require


def run(lab, gate, result, launcher, private, output, check, *, outbox_recovery=False,
        intent_recovery=False, recovery_observability=False, coherent_backup=False,
        bundle_observability=False):
    root, outbox, intents = private / "retained", private / "outbox", private / "intents"
    for path in (root, outbox, intents):
        path.mkdir(mode=0o700)
    scope = CollectorScope(
        tenant_id=lab.target.tenant_id,
        server_id=lab.target.server_id,
        unit=lab.target.unit,
        source_id="local-proc",
        key_id="proc-1",
    )
    archive_scope = ArchiveScope.model_validate(scope.model_dump(exclude={"key_id"}))
    first = seal_completed(gate, result, decode((launcher.directory / "capture.json").read_bytes()))
    pending = outbox / (gate.request.request_id + ".json")
    pending.write_bytes(first)
    pending.chmod(0o600)
    publish_sealed(first, root, lab.broker.joiner.registry, lab.broker.registry)
    records = [(gate.request.request_id, first)]
    for _ in range(2):
        # Only the UUID-owned oneshot worker's prior, consumed files are removed.
        # The completed, signed evidence is already durable in the separate outbox.
        for name in ("request.json", "capture.json"):
            (launcher.directory / name).unlink()
        current = HistoryUnitLauncher(
            lab.target, launcher.argv, launcher.directory, source_id="local-proc", key_id="proc-1"
        )
        next_gate = lab.gate(lab.new_request(), lab.new_access())
        _, published = dispatch_and_retain(next_gate, current, lab.permission, root, outbox,
                                           intent_root=intents)
        raw = (outbox / (published["run_id"] + ".json")).read_bytes()
        records.append((published["run_id"], raw))
    require(len(records) == 3, "retention_native_records")
    check("three_actual_exec_records_seal_runtime_caller_and_app_use")
    latest = (root / "latest.json").read_bytes()
    monitor = CollectorMonitor(
        scope,
        lab.broker.joiner.registry,
        private / "retention-health.db",
        caller_registry=lab.broker.registry,
    )
    fresh = monitor.check(root / "latest.json")
    require(fresh.state == "fresh", "retention_native_fresh")
    # DrvFS exports do not provide the Linux ownership/mode contract. Exercise
    # the real publisher here, then export only already-verified public bytes.
    public = private / "retention-public"
    public.mkdir(mode=0o755)
    publish(
        public / "health.json",
        health_report(
            scope,
            fresh,
            root / "latest.json",
            lab.broker.joiner.registry,
            caller_registry=lab.broker.registry,
        ),
    )
    check("managed_seal_and_current_caller_pin_feed_existing_health_status")
    archive = CaptureArchive(root, archive_scope, policy=ArchivePolicy(max_hot_records=1))
    compacted = archive.compact(apply=True)
    require(
        compacted["archive_records"] == 2
        and compacted["hot_after_records"] == 1
        and compacted["managed_budget_satisfied"]
        and compacted["archive_capacity_available"],
        "retention_native_cold_records",
    )
    publish(public / "archive.json", archive_report(scope, {**compacted, "state": "ready"}))
    check("existing_compaction_preserves_newest_and_archives_two_complete_records")
    finish_outbox = None
    if outbox_recovery:
        from scripts.f1_lab.exec_outbox_controls import begin

        finish_outbox = begin(
            lab, launcher, private, root, outbox, archive_scope, public, output, check
        )
    manager = CaptureBackup(archive_scope)
    checkpoint = private / "checkpoint.json"
    pinned = manager.checkpoint(root, checkpoint)
    packages = private / "cold-packages"
    packages.mkdir(mode=0o700)
    package, review = packages / "encrypted", private / "isolated-restore"
    key = secrets.token_bytes(32)
    backup = manager.backup(root, package, checkpoint, pinned["checkpoint_sha256"], key, "local-1")
    require(first not in (package / "payload.aesgcm").read_bytes(), "retention_ciphertext")
    check("existing_aes256gcm_backup_accepts_complete_managed_exec_records")
    # Source loss is limited to this disposable test's private cold database.
    (root / "archive.sqlite3").unlink()
    restored = manager.restore(
        package,
        backup["manifest_sha256"],
        checkpoint,
        pinned["checkpoint_sha256"],
        review,
        key,
        "local-1",
    )
    require(
        manager.verify(review, restored["receipt_sha256"], checkpoint, pinned["checkpoint_sha256"])[
            "completed"
        ],
        "retention_restore",
    )
    check("isolated_restore_verifies_after_owned_source_database_removed")
    recovered = CaptureArchive(review / "review", archive_scope)
    for number, (run_id, raw) in enumerate(records[:2]):
        destination = private / ("extracted-" + str(number))
        recovered.restore(run_id, destination)
        require((destination / "capture.json").read_bytes() == raw, "retention_original_bytes")
    check("runtime_authorization_caller_app_seal_and_original_times_restore_byte_exact")
    require((root / "latest.json").read_bytes() == latest, "retention_latest_unchanged")
    check("recovery_never_replaces_live_latest_or_reactivates_app_grant")
    capture = ManagedExecCapture.model_validate_json(first)
    stale_monitor = CollectorMonitor(
        scope,
        lab.broker.joiner.registry,
        private / "stale-health.db",
        caller_registry=lab.broker.registry,
    )
    stale = stale_monitor.check(
        private / "extracted-0/capture.json", now=capture.sealed_at + timedelta(seconds=65)
    )
    require(stale.state == "stale", "retention_recovered_stale")
    check("restored_old_record_remains_stale_after_original_expiry")
    arguments = (
        archive_scope,
        package,
        backup["manifest_sha256"],
        checkpoint,
        pinned["checkpoint_sha256"],
        review,
        restored["receipt_sha256"],
    )
    verified = backup_status.inspect(*arguments)
    backup_status.publish(public / "backup-verified.json", verified)
    check("keyless_backup_status_rechecks_actual_ciphertext_and_restored_managed_records")
    encrypted = (package / "payload.aesgcm").read_bytes()
    damaged = bytes([encrypted[0] ^ 1]) + encrypted[1:]
    (package / "payload.aesgcm").write_bytes(damaged)
    try:
        backup_status.inspect(*arguments)
    except ValueError:
        unavailable = backup_status.report(archive_scope)
        backup_status.publish(public / "backup-unavailable.json", unavailable)
    else:
        raise AssertionError("damaged encrypted evidence accepted")
    check("actual_encrypted_payload_damage_publishes_unavailable_without_a_recovery_key")
    (package / "payload.aesgcm").write_bytes(encrypted)
    recovered_status = backup_status.inspect(*arguments)
    backup_status.publish(public / "backup-recovered.json", recovered_status)
    require(verified["values"] == recovered_status["values"], "retention_recovery_times")
    check("rechecking_repaired_bytes_preserves_original_snapshot_backup_restore_times")
    # Replay outbox after a newer observation: retain history, never roll latest back.
    publish_sealed(first, root, lab.broker.joiner.registry, lab.broker.registry)
    require((root / "latest.json").read_bytes() == latest, "retention_retry_latest")
    check("sealed_outbox_retry_preserves_bytes_and_cannot_roll_latest_back")
    summaries = {
        "completed": True,
        "actual_executions": 4 if outbox_recovery else 3,
        "cold_records": 2,
        "byte_exact_restored_records": 2,
        "source_database_loss_tested": True,
        "snapshot_times_renewed": False,
        "automatic_activation_allowed": False,
        "capture_authorization_equals_permission": False,
        "aws_calls": 0,
        "paid_api_calls": 0,
        "scope_sha256": verified["scope_sha256"],
        "backup_status_source": "actual managed exec archive, AESGCM and isolated restore",
        "checked_at": datetime.now(UTC).isoformat(),
    }
    (output / "retention-controls.json").write_text(json.dumps(summaries, indent=2) + "\n")
    require(
        all(
            value not in json.dumps([verified, unavailable, recovered_status])
            for value in (lab.principal.subject, scope.tenant_id, scope.server_id, scope.unit)
        ),
        "retention_public_privacy",
    )
    check("only_bounded_aggregates_cross_to_monitoring_no_identity_grants_or_keys")
    if finish_outbox is not None:
        finish_outbox()
    if intent_recovery:
        from scripts.f1_lab.exec_intent_controls import run as run_intent

        run_intent(lab,launcher,private,root,outbox,output,check,
                   recovery_observability=recovery_observability,scope=archive_scope,
                   coherent_backup=coherent_backup,bundle_observability=bundle_observability)
    exported = output / "retention-public"
    exported.mkdir(exist_ok=False)
    for path in public.glob("*.json"):
        (exported / path.name).write_bytes(path.read_bytes())
