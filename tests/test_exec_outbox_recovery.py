"""Recovery must preserve unpublished/newest bytes and never retry execution."""

import json
import secrets
import shutil
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts.f1_lab import exec_outbox as module
from scripts.f1_lab import managed_exec_retention as retention
from scripts.f1_lab.capture_archive import ArchivePolicy, CaptureArchive
from scripts.f1_lab.capture_backup import CaptureBackup
from scripts.f1_lab.operation_context import canonical
from tests.test_managed_exec_retention import fixture as execution_fixture

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="private POSIX outbox contracts")


def pending(f):
    before = {p.name for p in f.outbox.glob("*.json")}
    with (
        patch.object(retention, "publish_sealed", side_effect=OSError("owned publication fault")),
        pytest.raises(OSError),
    ):
        f.execute()
    added = [p for p in f.outbox.glob("*.json") if p.name not in before]
    assert len(added) == 1
    return added[0]


def setup(tmp_path):
    f = execution_fixture(tmp_path)
    executed = [f.execute() for _ in range(3)]
    pending_path = pending(f)
    originals = {p.stem: p.read_bytes() for p in f.outbox.glob("*.json")}
    latest = (f.root / "latest.json").read_bytes()
    mirror = tmp_path / "mirror"
    snapshot = module.snapshot_outbox(f.outbox, f.root, f.archive_scope, mirror)
    manager = CaptureBackup(f.archive_scope)
    checkpoint = tmp_path / "checkpoint.json"
    cp = manager.checkpoint(mirror, checkpoint)
    key = secrets.token_bytes(32)
    package = tmp_path / "encrypted"
    backup = manager.backup(mirror, package, checkpoint, cp["checkpoint_sha256"], key, "test-1")
    review = tmp_path / "restored"
    receipt = manager.restore(
        package,
        backup["manifest_sha256"],
        checkpoint,
        cp["checkpoint_sha256"],
        review,
        key,
        "test-1",
    )
    args = {
        "outbox": f.outbox,
        "root": f.root,
        "scope": f.archive_scope,
        "review": review,
        "receipt_sha256": receipt["receipt_sha256"],
        "checkpoint": checkpoint,
        "checkpoint_sha256": cp["checkpoint_sha256"],
    }
    return SimpleNamespace(
        f=f,
        executed=executed,
        pending_path=pending_path,
        originals=originals,
        latest=latest,
        mirror=mirror,
        manager=manager,
        checkpoint=checkpoint,
        cp=cp,
        key=key,
        package=package,
        backup=backup,
        review=review,
        receipt=receipt,
        args=args,
        snapshot=snapshot,
    )


def inspect(f, **kwargs):
    return module.inspect_outbox(
        f.outbox,
        f.root,
        f.archive_scope,
        f.lab.broker.joiner.registry,
        f.lab.broker.registry,
        **kwargs,
    )


def test_full_mirror_and_encrypted_restore_include_latest_and_unpublished(tmp_path):
    data = setup(tmp_path)
    assert data.snapshot["records"] == 4 and data.snapshot["includes_newest_and_pending"]
    assert not data.snapshot["inputs_deleted"]
    state = inspect(data.f)
    assert state["records"] == 4 and state["published"] == 3 and state["pending"] == 1
    before = {p.stem: p.read_bytes() for p in data.f.outbox.glob("*.json")}
    assert before == data.originals and (data.f.root / "latest.json").read_bytes() == data.latest
    assert not (data.mirror / "latest.json").exists()
    archive = CaptureArchive(data.review / "review", data.f.archive_scope)
    for rid, raw in data.originals.items():
        output = tmp_path / ("extracted-" + rid)
        archive.restore(rid, output)
        assert (output / "capture.json").read_bytes() == raw
    assert len(data.f.launches) == 4


def test_isolated_recovery_survives_all_owned_source_directories_lost(tmp_path):
    data = setup(tmp_path)
    for path in (data.f.root, data.f.outbox, data.mirror):
        assert path.resolve().parent == tmp_path.resolve()
        shutil.rmtree(path)
    data.manager.verify(
        data.review, data.receipt["receipt_sha256"], data.checkpoint, data.cp["checkpoint_sha256"]
    )
    archive = CaptureArchive(data.review / "review", data.f.archive_scope)
    for rid, raw in data.originals.items():
        output = tmp_path / ("recovered-" + rid)
        archive.restore(rid, output)
        assert (output / "capture.json").read_bytes() == raw
    assert not data.f.root.exists() and not data.f.outbox.exists()


def test_cleanup_previews_then_removes_only_old_published_backed_records(tmp_path):
    data = setup(tmp_path)
    later = datetime.now(UTC) + timedelta(seconds=65)
    preview = module.prune_outbox(**data.args, now=later, min_age_seconds=60)
    assert (
        preview["eligible"] == 3 and preview["deleted"] == 0 and preview["pending_preserved"] == 1
    )
    assert len(list(data.f.outbox.glob("*.json"))) == 4
    result = module.prune_outbox(**data.args, now=later, min_age_seconds=60, apply=True, limit=1)
    assert result["deleted"] == 1
    result = module.prune_outbox(**data.args, now=later, min_age_seconds=60, apply=True)
    assert result["deleted"] == 2
    result = module.prune_outbox(**data.args, now=later, min_age_seconds=60, apply=True)
    assert result["deleted"] == 0 and result["pending_preserved"] == 1
    assert {p.stem for p in data.f.outbox.glob("*.json")} == {data.pending_path.stem}
    assert (data.f.root / "latest.json").read_bytes() == data.latest and len(data.f.launches) == 4


def test_recent_and_new_unbacked_records_survive_cleanup(tmp_path):
    data = setup(tmp_path)
    recent = module.prune_outbox(**data.args, min_age_seconds=60, apply=True)
    assert recent["deleted"] == 0
    new_gate, _, _, raw = data.f.execute()
    later = datetime.now(UTC) + timedelta(seconds=65)
    result = module.prune_outbox(**data.args, now=later, min_age_seconds=60, apply=True)
    assert result["deleted"] == 3
    assert (data.f.outbox / (new_gate.request.request_id + ".json")).read_bytes() == raw
    assert data.pending_path.exists()


@pytest.mark.parametrize(
    "change",
    [
        "receipt_pin",
        "checkpoint_pin",
        "receipt",
        "database",
        "checkpoint",
        "outbox_link",
        "capture_link",
        "outbox_mode",
        "hot_collision",
    ],
)
def test_bad_backup_scope_or_private_file_never_prunes(tmp_path, change):
    data = setup(tmp_path)
    args = dict(data.args)
    if change == "receipt_pin":
        args["receipt_sha256"] = "0" * 64
    elif change == "checkpoint_pin":
        args["checkpoint_sha256"] = "0" * 64
    elif change in {"receipt", "database", "checkpoint"}:
        path = {
            "receipt": data.review / "restore.json",
            "database": data.review / "review/archive.sqlite3",
            "checkpoint": data.checkpoint,
        }[change]
        path.write_bytes(b"owned corruption fixture")
    elif change == "outbox_link":
        linked = tmp_path / "linked-outbox"
        linked.symlink_to(data.f.outbox, target_is_directory=True)
        args["outbox"] = linked
    elif change == "capture_link":
        selected = next(data.f.outbox.glob("*.json"))
        moved = tmp_path / "moved"
        selected.rename(moved)
        selected.symlink_to(moved)
    elif change == "outbox_mode":
        data.pending_path.chmod(0o644)
    else:
        (data.f.root / data.executed[0][0].request.request_id / "capture.json").write_bytes(
            b"wrong"
        )
    names = {p.name for p in data.f.outbox.glob("*.json")}
    with pytest.raises((ValueError, OSError)):
        module.prune_outbox(
            **args, now=datetime.now(UTC) + timedelta(seconds=65), min_age_seconds=60, apply=True
        )
    assert {p.name for p in data.f.outbox.glob("*.json")} == names


@pytest.mark.parametrize(
    "change", ["unknown", "wrong_id", "cross_scope", "extra_field", "link", "mode"]
)
def test_inventory_fails_closed_and_never_changes_originals(tmp_path, change):
    f = execution_fixture(tmp_path)
    gate, _, _, raw = f.execute()
    capture = f.outbox / (gate.request.request_id + ".json")
    if change == "unknown":
        (f.outbox / "unknown").write_text("owned fixture")
    elif change == "wrong_id":
        capture.rename(f.outbox / ("a" * 32 + ".json"))
    elif change == "cross_scope":
        f.archive_scope = f.archive_scope.model_copy(update={"server_id": "another-server"})
    elif change == "extra_field":
        value = json.loads(raw)
        value["extra"] = True
        capture.write_bytes(canonical(value))
    elif change == "link":
        moved = tmp_path / "moved"
        capture.rename(moved)
        capture.symlink_to(moved)
    else:
        capture.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        inspect(f)
    assert (f.root / "latest.json").read_bytes() == raw


def test_cold_publication_is_recognized_without_rehydrating_hot_files(tmp_path):
    f = execution_fixture(tmp_path)
    records = [f.execute() for _ in range(3)]
    archive = CaptureArchive(f.root, f.archive_scope, policy=ArchivePolicy(max_hot_records=1))
    archive.compact(apply=True)
    state = inspect(f)
    assert state["pending"] == 0 and state["published"] == 3
    assert not (f.root / records[0][0].request.request_id).exists()


def test_preserve_collision_rolls_back_whole_batch_and_never_deletes_input(tmp_path):
    f = execution_fixture(tmp_path)
    first, second = f.execute(), f.execute()
    mirror = tmp_path / "mirror"
    mirror.mkdir(mode=0o700)
    archive = CaptureArchive(mirror, f.archive_scope)
    archive.preserve([(first[0].request.request_id, first[3])])
    with pytest.raises(ValueError):
        archive.preserve(
            [(second[0].request.request_id, second[3]), (first[0].request.request_id, second[3])]
        )
    with archive.connection() as con:
        records, _, _, _ = archive.load(con)
    assert set(records) == {first[0].request.request_id}
    assert len(list(f.outbox.glob("*.json"))) == 2


@pytest.mark.parametrize(
    "name,value",
    [("min_age_seconds", 0), ("min_age_seconds", True), ("limit", 0), ("limit", 257), ("apply", 1)],
)
def test_prune_policy_is_strict(tmp_path, name, value):
    data = setup(tmp_path)
    with pytest.raises(ValueError):
        module.prune_outbox(**data.args, **{name: value})
    assert len(list(data.f.outbox.glob("*.json"))) == 4
