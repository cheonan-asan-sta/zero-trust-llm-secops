"""A withdrawn runtime checkpoint must prevent encrypted backup publication."""

import asyncio
import secrets

import pytest
from test_audit_checkpoint import ready
from test_sqlite_audit import initial

from app.services import audit_backup
from app.services.federated_audit import AuditQueryUnavailable
from app.services.guarded_sqlite_audit import GuardedSQLiteAuditStore


@pytest.mark.parametrize("change", ["missing", "tampered"])
def test_checkpoint_withdrawal_during_encryption_prevents_publication(
    tmp_path, monkeypatch, change
):
    store, _, path, receipt = ready(tmp_path)
    live = GuardedSQLiteAuditStore.open_guarded(store.path, path, receipt["checkpoint_sha256"])
    before = store.path.read_bytes()
    original = audit_backup.Cipher

    def withdraw(*args, **kwargs):
        if change == "missing":
            path.unlink()
        else:
            path.write_bytes(path.read_bytes() + b" ")
        return original(*args, **kwargs)

    monkeypatch.setattr(audit_backup, "Cipher", withdraw)
    target = tmp_path / "not-published.backup"
    with pytest.raises(AuditQueryUnavailable):
        audit_backup.backup_sqlite(live, target, secrets.token_bytes(32))
    assert not target.exists() and not list(tmp_path.glob(".audit-transfer-*"))
    assert store.path.read_bytes() == before and store.integrity()["ok"]


def test_source_append_during_encryption_keeps_copied_snapshot_semantics(tmp_path, monkeypatch):
    store, _, path, receipt = ready(tmp_path)
    live = GuardedSQLiteAuditStore.open_guarded(store.path, path, receipt["checkpoint_sha256"])
    original = audit_backup.Cipher

    def append(*args, **kwargs):
        asyncio.run(store.save(initial(2)))
        return original(*args, **kwargs)

    monkeypatch.setattr(audit_backup, "Cipher", append)
    key = secrets.token_bytes(32)
    target = tmp_path / "snapshot.backup"
    info = audit_backup.backup_sqlite(live, target, key)
    assert info["head"]["seq"] == 1 and store.integrity()["verified_lines"] == 2
    monkeypatch.setattr(audit_backup, "Cipher", original)
    restored = tmp_path / "restored.sqlite3"
    audit_backup.restore_sqlite(target, restored, info["backup_sha256"], key)
    checked = GuardedSQLiteAuditStore.open_guarded(restored, path, receipt["checkpoint_sha256"])
    assert checked.integrity()["verified_lines"] == 1
