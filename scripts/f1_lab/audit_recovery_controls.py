"""Free actual HTTP audit recovery, with deliberate test-only candidate selection."""

import hashlib
import secrets
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from app.services.audit_backup import backup_sqlite, restore_sqlite, validate_head
from app.services.audit_checkpoint import capture_checkpoint, inspect_checkpoint, load_checkpoint
from app.services.audit_transfer import AuditTransferError
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab.native_jsonl import require
from scripts.local_review_intent import review_observed


def run(audit, payload, client, headers, directory, passed, stack):
    from app import main

    directory = Path(directory)
    original_digest = hashlib.sha256(audit.path.read_bytes()).hexdigest()
    key = secrets.token_bytes(32)
    package = directory / "native-audit.enc"
    backup = backup_sqlite(audit, package, key)
    passed("native_audit_sqlite_online_snapshot_and_encrypted_backup")
    destination = directory / "native-audit-restored.sqlite3"
    receipt = restore_sqlite(
        package, destination, backup["backup_sha256"], key, minimum_head=backup["head"]
    )
    restored = SQLiteAuditStore.open_existing(destination)
    require(
        restored.get(payload["event_id"], payload["tenant_id"]).model_dump(mode="json") == payload
        and receipt["automatic_activation_allowed"] is False,
        "native_audit_restored_snapshot",
    )
    passed("native_audit_restore_preserves_exact_analysis_context_and_guard")
    # This explicit local harness selection is not performed by restore_sqlite.
    stack.enter_context(patch.object(main, "audit_store", restored))
    fetched = client.get(f"/results/{payload['event_id']}", headers=headers)
    require(
        fetched.status_code == 200 and fetched.json() == payload, "native_audit_restored_http_read"
    )
    baseline_path = directory / "native-audit-baseline.checkpoint.json"
    baseline_checkpoint = capture_checkpoint(restored.path, baseline_path)
    require(
        baseline_checkpoint["head"] == backup["head"],
        "native_checkpoint_baseline_matches_restored_snapshot",
    )
    reviewed = review_observed(
        client,
        headers,
        payload,
        status="RESOLVED",
        note="Verified recovered native audit",
    )
    require(
        reviewed.status_code == 200
        and reviewed.json()["verification_context"] == payload["verification_context"]
        and reviewed.json()["assessment"] == payload["assessment"],
        "native_audit_recovered_http_review",
    )
    passed("native_audit_candidate_http_query_and_cas_review_preserve_advisory_assessment")
    with restored._transaction() as con:
        seq, head = validate_head(con, restored)
    checkpoint_path = directory / "native-audit-current.checkpoint.json"
    candidate_hash = hashlib.sha256(restored.path.read_bytes()).hexdigest()
    checkpoint = capture_checkpoint(
        restored.path,
        checkpoint_path,
        previous_checkpoint=baseline_path,
        previous_checkpoint_sha256=baseline_checkpoint["checkpoint_sha256"],
    )
    pinned = load_checkpoint(checkpoint_path, checkpoint["checkpoint_sha256"])
    require(
        pinned["head"] == {"seq": seq, "digest": head}
        and checkpoint["automatic_activation_allowed"] is False
        and hashlib.sha256(restored.path.read_bytes()).hexdigest() == candidate_hash,
        "native_checkpoint_capture_preserves_candidate_database",
    )
    passed("native_audit_checkpoint_verified_head_export_is_read_only")
    require(
        checkpoint["progression_check"]["monotonic_head_verified"]
        and checkpoint["progression_check"]["advanced_rows"] == 1,
        "native_checkpoint_advances_verified_prefix",
    )
    passed("native_audit_checkpoint_advances_from_verified_previous_head")
    try:
        capture_checkpoint(
            audit.path,
            directory / "rejected-lower.checkpoint.json",
            previous_checkpoint=checkpoint_path,
            previous_checkpoint_sha256=checkpoint["checkpoint_sha256"],
        )
    except AuditTransferError:
        require(
            not (directory / "rejected-lower.checkpoint.json").exists(),
            "native_checkpoint_lower_head_not_published",
        )
    else:
        raise ValueError("valid older audit DB lowered trusted checkpoint")
    older_status = inspect_checkpoint(audit.path, checkpoint_path, checkpoint["checkpoint_sha256"])
    require(
        older_status["status"] == "behind_checkpoint"
        and older_status["minimum_head_satisfied"] is False,
        "native_checkpoint_reports_older_source",
    )
    passed("native_audit_checkpoint_advance_refuses_valid_older_database")
    tampered_checkpoint = directory / "native-audit-tampered.checkpoint.json"
    tampered_checkpoint.write_bytes(checkpoint_path.read_bytes() + b" ")
    tampered_checkpoint.chmod(0o600)
    try:
        load_checkpoint(tampered_checkpoint, checkpoint["checkpoint_sha256"])
    except AuditTransferError as error:
        require("pin mismatch" in str(error), "native_checkpoint_external_pin_rejection")
    else:
        raise ValueError("tampered native audit checkpoint accepted")
    passed("native_audit_checkpoint_tamper_rejected_by_external_pin")
    try:
        restore_sqlite(
            package,
            directory / "old-candidate.sqlite3",
            backup["backup_sha256"],
            key,
            minimum_head=pinned["head"],
        )
    except AuditTransferError:
        require(
            not (directory / "old-candidate.sqlite3").exists(),
            "native_audit_old_candidate_not_published",
        )
    else:
        raise ValueError("old native audit snapshot accepted against newer checkpoint")
    passed("native_audit_old_authentic_backup_rejected_against_newer_review_head")
    raw = package.read_bytes()
    tampered = directory / "native-audit-tampered.enc"
    tampered.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    try:
        restore_sqlite(tampered, directory / "tampered.sqlite3", backup["backup_sha256"], key)
    except (InvalidTag, AuditTransferError):
        require(
            not (directory / "tampered.sqlite3").exists(), "native_audit_tampered_not_published"
        )
    else:
        raise ValueError("tampered native audit backup accepted")
    passed("native_audit_tampered_package_rejected_without_restored_output")
    require(
        hashlib.sha256(audit.path.read_bytes()).hexdigest() == original_digest,
        "native_audit_original_source_unchanged",
    )
    passed("native_audit_source_database_unchanged_by_backup_restore_candidate_review")
    return {
        "backup_sha256": backup["backup_sha256"],
        "snapshot_head": backup["head"],
        "candidate_review_head": {"seq": seq, "digest": head},
        "checkpoint": {
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "head": pinned["head"],
            "source_unchanged_by_capture": True,
            "external_pin_tamper_rejected": True,
            "independent_storage_verified": False,
            "latest_live_state_verified": False,
            "progression_check": checkpoint["progression_check"],
            "older_database_advance_rejected": True,
            "older_database_status": older_status["status"],
        },
        "automatic_activation_allowed": False,
        "test_harness_selected_candidate_for_read_and_review": True,
        "original_database_unchanged": True,
        "key_persisted": False,
        "access_grant_issued_by_recovery": False,
        "new_access_attempt_tested": False,
    }
