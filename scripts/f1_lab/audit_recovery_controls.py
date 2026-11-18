"""Free actual HTTP audit recovery, with deliberate test-only candidate selection."""

import hashlib
import secrets
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from app.services.audit_backup import backup_sqlite, restore_sqlite, validate_head
from app.services.audit_transfer import AuditTransferError
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab.native_jsonl import require


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
    reviewed = client.patch(
        f"/results/{payload['event_id']}/review",
        headers=headers,
        json={"status": "RESOLVED", "note": "Verified recovered native audit"},
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
    try:
        restore_sqlite(
            package,
            directory / "old-candidate.sqlite3",
            backup["backup_sha256"],
            key,
            minimum_head={"seq": seq, "digest": head},
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
        "automatic_activation_allowed": False,
        "test_harness_selected_candidate_for_read_and_review": True,
        "original_database_unchanged": True,
        "key_persisted": False,
        "access_grant_issued_by_recovery": False,
        "new_access_attempt_tested": False,
    }
