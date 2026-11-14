import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest

from scripts.f1_lab import capture_backup as module
from scripts.f1_lab.capture_archive import CaptureArchive
from scripts.f1_lab.capture_backup import CaptureBackup
from scripts.f1_lab.collector_freshness import CollectorMonitor
from scripts.f1_lab.operation_context import canonical
from tests.test_capture_archive import fixture as capture_fixture

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="private POSIX archive and file locks"
)


def setup(tmp_path):
    root, originals, archive, pinned, scope, now = capture_fixture(tmp_path / "source")
    archive.compact(apply=True)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    for name in ["checkpoints", "packages", "reviews"]:
        (external / name).mkdir(mode=0o700)
    manager = CaptureBackup(archive.scope)
    cp_path = external / "checkpoints/first.json"
    cp = manager.checkpoint(root, cp_path)
    key = secrets.token_bytes(32)
    package = external / "packages/one"
    backup = manager.backup(
        root, package, cp_path, cp["checkpoint_sha256"], key, "capture-recovery-1"
    )
    return (
        root,
        originals,
        archive,
        manager,
        external,
        cp_path,
        cp,
        key,
        package,
        backup,
        pinned,
        scope,
        now,
    )


def restore(data, path="one", **changes):
    _, _, _, manager, external, cp_path, cp, key, package, backup, *_ = data
    args = {
        "package": package,
        "manifest_sha256": backup["manifest_sha256"],
        "checkpoint_path": cp_path,
        "checkpoint_sha256": cp["checkpoint_sha256"],
        "output": external / "reviews" / path,
        "key": key,
        "key_id": "capture-recovery-1",
    }
    args.update(changes)
    return manager.restore(**args), args["output"]


def test_encrypted_snapshot_and_isolated_restore_survive_total_source_loss(tmp_path):
    data = setup(tmp_path)
    root, originals, archive, manager, _, cp_path, cp, key, package, backup, pinned, scope, now = (
        data
    )
    before_db = (root / "archive.sqlite3").read_bytes()
    before_latest = (root / "latest.json").read_bytes()
    assert (
        manager.checkpoint(root, cp_path.parent / "second.json")["checkpoint"]["head"]
        == cp["checkpoint"]["head"]
    )
    assert (root / "archive.sqlite3").read_bytes() == before_db and (
        root / "latest.json"
    ).read_bytes() == before_latest
    assert set(os.listdir(package)) == {"manifest.json", "payload.aesgcm"}
    encrypted = (package / "payload.aesgcm").read_bytes()
    assert not encrypted.startswith(b"SQLite format 3") and key not in encrypted
    monitor = CollectorMonitor(scope, pinned, tmp_path / "monitor.sqlite3")
    assert monitor.check(root / "latest.json", now=now).state == "fresh"
    archived_ids = set(originals) - {p.parent.name for p in root.glob("*/capture.json")}
    # Rename simulates complete source unavailability; production source is never overwritten.
    root.rename(root.parent / "lost-source")
    result, output = restore(data)
    assert result["automatic_activation_allowed"] is False
    assert (
        manager.verify(output, result["receipt_sha256"], cp_path, cp["checkpoint_sha256"])[
            "records"
        ]
        == 3
    )
    review = output / "review"
    assert {p.name for p in review.iterdir()} <= {"archive.sqlite3", ".capture-store.lock"}
    assert not (review / "latest.json").exists()
    restored = CaptureArchive(review, archive.scope)
    for index, rid in enumerate(archived_ids):
        target = tmp_path / ("extracted-" + str(index))
        restored.restore(rid, target)
        assert (target / "capture.json").read_bytes() == originals[rid]
        assert monitor.check(target / "capture.json", now=now).reason == "capture_regression"
    assert manager.verify(output, result["receipt_sha256"], cp_path, cp["checkpoint_sha256"])[
        "completed"
    ]
    assert backup["records"] == 3


@pytest.mark.parametrize(
    "mode",
    [
        "key",
        "key_id",
        "manifest_pin",
        "checkpoint_pin",
        "payload",
        "manifest",
        "extra",
        "symlink",
        "hardlink",
        "foreign_scope",
        "future_checkpoint",
    ],
)
def test_bad_packages_or_authority_inputs_create_no_restore_state(tmp_path, mode):
    data = setup(tmp_path)
    root, _, archive, _, external, cp_path, _, _, package, _, *_ = data
    changes = {}
    if mode == "key":
        changes["key"] = secrets.token_bytes(32)
    elif mode == "key_id":
        changes["key_id"] = "other-key"
    elif mode == "manifest_pin":
        changes["manifest_sha256"] = "0" * 64
    elif mode == "checkpoint_pin":
        changes["checkpoint_sha256"] = "0" * 64
    elif mode == "payload":
        path = package / "payload.aesgcm"
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
    elif mode == "manifest":
        path = package / "manifest.json"
        value = json.loads(path.read_bytes())
        value["key_id"] = "other-key"
        path.write_bytes(canonical(value))
        changes.update(manifest_sha256=module.sha(path.read_bytes()), key_id="other-key")
    elif mode == "extra":
        (package / "extra").write_bytes(b"not allowed")
    elif mode in {"symlink", "hardlink"}:
        path = package / "payload.aesgcm"
        if mode == "symlink":
            original = external / "outside"
            path.rename(original)
            path.symlink_to(original)
        else:
            os.link(path, external / "alias")
    elif mode == "foreign_scope":
        foreign = archive.scope.model_copy(update={"server_id": "foreign"})
        data = (*data[:3], CaptureBackup(foreign), *data[4:])
    else:
        value = json.loads(cp_path.read_bytes())
        value["issued_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        cp_path.write_bytes(canonical(value))
        changes["checkpoint_sha256"] = module.sha(cp_path.read_bytes())
    with pytest.raises((ValueError, OSError, sqlite3.Error)):
        restore(data, **changes)
    assert not (external / "reviews/one").exists()
    assert (root / "latest.json").exists() and CaptureArchive(root, archive.scope).path.exists()


@pytest.mark.parametrize(
    "mode",
    ["existing", "source", "within_source", "package", "package_parent", "checkpoint", "link"],
)
def test_restore_never_overwrites_or_reuses_active_or_package_paths(tmp_path, mode):
    data = setup(tmp_path)
    root, _, _, _, external, cp_path, _, _, package, *_ = data
    target = external / "reviews/new"
    if mode == "existing":
        target.mkdir(mode=0o700)
    elif mode == "source":
        target = root
    elif mode == "within_source":
        target = root / "new"
    elif mode == "package":
        target = package
    elif mode == "package_parent":
        target = package.parent
    elif mode == "checkpoint":
        target = cp_path
    else:
        target.symlink_to(root, target_is_directory=True)
    before = (root / "archive.sqlite3").read_bytes()
    with pytest.raises((ValueError, OSError)):
        restore(data, output=target)
    assert (root / "archive.sqlite3").read_bytes() == before


def test_current_checkpoint_rejects_older_snapshot_and_cannot_be_minted_from_rollback(tmp_path):
    data = setup(tmp_path)
    root, _, archive, manager, external, cp_path, cp, _, _, _, *_ = data
    old = (root / "archive.sqlite3").read_bytes()
    archive.policy = archive.policy.model_copy(update={"max_hot_records": 1})
    archive.compact(apply=True)
    current_path = external / "checkpoints/current.json"
    current = manager.checkpoint(
        root, current_path, previous=cp_path, previous_sha256=cp["checkpoint_sha256"]
    )
    with pytest.raises(ValueError):
        restore(data, checkpoint_path=current_path, checkpoint_sha256=current["checkpoint_sha256"])
    (root / "archive.sqlite3").write_bytes(old)
    with pytest.raises(ValueError):
        manager.checkpoint(
            root,
            external / "checkpoints/rolledback.json",
            previous=current_path,
            previous_sha256=current["checkpoint_sha256"],
        )


def test_snapshot_requires_current_checkpoint_but_later_equal_head_anchor_can_validate_data(
    tmp_path,
):
    data = setup(tmp_path)
    root, _, archive, manager, external, cp_path, cp, key, _, _, *_ = data
    equal_path = external / "checkpoints/equal.json"
    equal = manager.checkpoint(
        root, equal_path, previous=cp_path, previous_sha256=cp["checkpoint_sha256"]
    )
    result, output = restore(
        data, checkpoint_path=equal_path, checkpoint_sha256=equal["checkpoint_sha256"]
    )
    assert manager.verify(output, result["receipt_sha256"], equal_path, equal["checkpoint_sha256"])[
        "completed"
    ]
    archive.policy = archive.policy.model_copy(update={"max_hot_records": 1})
    archive.compact(apply=True)
    with pytest.raises(ValueError):
        manager.backup(
            root,
            external / "packages/stale",
            cp_path,
            cp["checkpoint_sha256"],
            key,
            "capture-recovery-1",
        )
    assert not (external / "packages/stale").exists()


@pytest.mark.parametrize(
    "mode", ["database", "receipt", "extra", "pin", "checkpoint_inside", "missing_receipt"]
)
def test_restored_review_requires_receipt_pin_current_checkpoint_and_unmodified_database(
    tmp_path, mode
):
    data = setup(tmp_path)
    _, _, _, manager, _, cp_path, cp, *_ = data
    result, output = restore(data)
    receipt_pin = result["receipt_sha256"]
    if mode == "database":
        (output / "review/archive.sqlite3").write_bytes(b"corrupt")
    elif mode == "receipt":
        (output / "restore.json").write_bytes(b"{}")
    elif mode == "extra":
        (output / "review/latest.json").write_bytes(b"not activation")
    elif mode == "pin":
        receipt_pin = "0" * 64
    elif mode == "checkpoint_inside":
        copied = output / "checkpoint.json"
        shutil.copyfile(cp_path, copied)
        copied.chmod(0o600)
        cp_path = copied
    else:
        (output / "restore.json").unlink()
    with pytest.raises((ValueError, OSError, sqlite3.Error)):
        manager.verify(output, receipt_pin, cp_path, cp["checkpoint_sha256"])


@pytest.mark.parametrize(
    "point",
    [
        "after_backup_payload",
        "after_backup_publish",
        "before_restore_state",
        "before_restore_publish",
        "after_restore_state",
        "after_restore_publish",
    ],
)
def test_actual_process_exit_never_publishes_incomplete_review_as_complete(tmp_path, point):
    data = setup(tmp_path)
    root, _, archive, manager, external, cp_path, cp, key, package, backup, *_ = data
    output = external / ("packages/child" if point.startswith("after_backup") else "reviews/child")
    args = {
        "root": str(root),
        "output": str(output),
        "cp": str(cp_path),
        "cp_sha": cp["checkpoint_sha256"],
        "package": str(package),
        "manifest_sha": backup["manifest_sha256"],
        "scope": archive.scope.model_dump(),
        "point": point,
    }
    code = """import json,os,sys
from scripts.f1_lab.capture_backup import CaptureBackup
from scripts.f1_lab.capture_archive import ArchiveScope
a=json.loads(sys.argv[1]);m=CaptureBackup(ArchiveScope.model_validate(a['scope']))
m.phase=lambda point: os._exit(73) if point==a['point'] else None
key=sys.stdin.buffer.read(32)
if a['point'].startswith('after_backup'):m.backup(a['root'],a['output'],a['cp'],a['cp_sha'],key,'capture-recovery-1')
else:m.restore(a['package'],a['manifest_sha'],a['cp'],a['cp_sha'],a['output'],key,'capture-recovery-1')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, json.dumps(args)],
        input=key,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 73 and key not in result.stdout + result.stderr
    if point == "after_backup_publish":
        pin = module.sha((output / "manifest.json").read_bytes())
        restored = manager.restore(
            output,
            pin,
            cp_path,
            cp["checkpoint_sha256"],
            external / "reviews/completed",
            key,
            "capture-recovery-1",
        )
        assert restored["completed"]
    elif point == "after_backup_payload":
        with pytest.raises((ValueError, OSError)):
            manager.restore(
                output,
                "0" * 64,
                cp_path,
                cp["checkpoint_sha256"],
                external / "reviews/incomplete",
                key,
                "capture-recovery-1",
            )
    elif point == "after_restore_publish":
        pin = module.sha((output / "restore.json").read_bytes())
        assert manager.verify(output, pin, cp_path, cp["checkpoint_sha256"])["completed"]
    else:
        with pytest.raises((ValueError, OSError)):
            manager.verify(output, "0" * 64, cp_path, cp["checkpoint_sha256"])
    assert (root / "latest.json").is_file()


def test_backup_capacity_and_private_parent_errors_leave_source_unchanged(tmp_path, monkeypatch):
    data = setup(tmp_path)
    root, _, _, manager, external, cp_path, cp, key, *_ = data
    monkeypatch.setattr(module, "MAX_PACKAGES", 1)
    before = (root / "archive.sqlite3").read_bytes()
    with pytest.raises(ValueError):
        manager.backup(
            root,
            external / "packages/two",
            cp_path,
            cp["checkpoint_sha256"],
            key,
            "capture-recovery-1",
        )
    (external / "reviews").chmod(0o755)
    with pytest.raises(ValueError):
        restore(data)
    assert (root / "archive.sqlite3").read_bytes() == before


def test_encryption_uses_distinct_nonce_and_does_not_include_signing_keys(tmp_path):
    data = setup(tmp_path)
    root, _, _, manager, external, cp_path, cp, key, package, _, *_ = data
    second = external / "packages/two"
    manager.backup(root, second, cp_path, cp["checkpoint_sha256"], key, "capture-recovery-1")
    first_manifest = json.loads((package / "manifest.json").read_bytes())
    second_manifest = json.loads((second / "manifest.json").read_bytes())
    assert first_manifest["nonce"] != second_manifest["nonce"]
    assert (package / "payload.aesgcm").read_bytes() != (second / "payload.aesgcm").read_bytes()
    assert key not in (package / "manifest.json").read_bytes()


def test_same_scope_same_count_but_different_history_is_not_an_acceptable_checkpoint(tmp_path):
    data = setup(tmp_path / "one")
    other = setup(tmp_path / "two")
    with pytest.raises(ValueError):
        restore(data, checkpoint_path=other[5], checkpoint_sha256=other[6]["checkpoint_sha256"])


def test_authenticated_payload_still_requires_supported_sqlite_schema(tmp_path):
    import base64

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data = setup(tmp_path)
    _, _, _, manager, _, _, _, key, package, _, *_ = data
    manifest = module.Manifest.model_validate(json.loads((package / "manifest.json").read_bytes()))
    raw = AESGCM(key).decrypt(
        base64.urlsafe_b64decode(manifest.nonce),
        (package / "payload.aesgcm").read_bytes(),
        manager.aad(manifest),
    )
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(raw)
        con.execute("CREATE VIEW unsupported_view AS SELECT 1")
        raw = con.serialize()
    finally:
        con.close()
    manifest = manifest.model_copy(
        update={
            "nonce": base64.urlsafe_b64encode(secrets.token_bytes(12)).decode(),
            "database_sha256": module.sha(raw),
            "database_bytes": len(raw),
        }
    )
    payload = AESGCM(key).encrypt(
        base64.urlsafe_b64decode(manifest.nonce), raw, manager.aad(manifest)
    )
    manifest = manifest.model_copy(
        update={"payload_sha256": module.sha(payload), "payload_bytes": len(payload)}
    )
    (package / "payload.aesgcm").write_bytes(payload)
    encoded = canonical(manifest.model_dump(mode="json"))
    (package / "manifest.json").write_bytes(encoded)
    with pytest.raises(ValueError):
        restore(data, manifest_sha256=module.sha(encoded))


def test_database_bound_is_checked_before_creating_a_package(tmp_path, monkeypatch):
    data = setup(tmp_path)
    root, _, _, manager, external, cp_path, cp, key, *_ = data
    monkeypatch.setattr(module, "MAX_DATABASE", 100)
    with pytest.raises(ValueError):
        manager.backup(
            root,
            external / "packages/too-large",
            cp_path,
            cp["checkpoint_sha256"],
            key,
            "capture-recovery-1",
        )
    assert not (external / "packages/too-large").exists()
