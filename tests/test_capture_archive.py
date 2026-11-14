import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from scripts.f1_lab.capture_archive import ArchiveFull, ArchivePolicy, ArchiveScope, CaptureArchive
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import CollectorMonitor, atomic_capture
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import runtime_proof
from tests.test_collector_freshness import envelope
from tests.test_collector_freshness import fixture as signed_fixture

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux cooperative directory locks and no-follow cleanup"
)


def fixture(tmp_path, count=5):
    keys, _, pinned, scope, event, proof, _, _, at = signed_fixture(tmp_path / "signed")
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    originals = {}
    for index in range(count):
        changed = event.model_copy(
            update={
                "event_id": hashlib.sha256(str(index).encode()).hexdigest(),
                "observed_at": at + timedelta(seconds=index),
            }
        )
        signed = runtime_proof(
            changed,
            proof.observation,
            keys["runtime"],
            source_id=scope.source_id,
            key_id=scope.key_id,
            observed_at=changed.observed_at,
        )
        raw = canonical(envelope(changed, signed)) + b"\n"
        identifier = uuid.uuid4().hex
        (root / identifier).mkdir(mode=0o700)
        atomic_capture(root / identifier / "capture.json", raw)
        originals[identifier] = raw
    atomic_capture(root / "latest.json", raw)
    binding = ArchiveScope(
        tenant_id=scope.tenant_id,
        server_id=scope.server_id,
        unit=scope.unit,
        source_id=scope.source_id,
    )
    archive = CaptureArchive(root, binding, policy=ArchivePolicy(max_hot_records=2))
    return root, originals, archive, pinned, scope, at + timedelta(seconds=count)


def hot(root):
    return {p.parent.name: p.read_bytes() for p in root.glob("*/capture.json") if p.is_file()}


def test_preview_preserves_originals_and_does_not_create_archive_database(tmp_path):
    root, originals, archive, *_ = fixture(tmp_path)
    before = (root / "latest.json").read_bytes()
    result = archive.compact()
    assert result["planned"] == 3 and result["projected_budget_satisfied"]
    assert result["deleted_hot_files"] == 0 and hot(root) == originals and not archive.path.exists()
    assert (root / "latest.json").read_bytes() == before


def test_compaction_is_lossless_latest_protected_and_restart_idempotent(tmp_path):
    root, originals, archive, pinned, scope, now = fixture(tmp_path)
    latest = (root / "latest.json").read_bytes()
    monitor = CollectorMonitor(scope, pinned, tmp_path / "monitor.sqlite3")
    assert monitor.check(root / "latest.json", now=now).state == "fresh"
    result = archive.compact(apply=True)
    assert result["deleted_hot_files"] == 3 and result["archive_records"] == 3
    assert result["hot_after_records"] == 2 and result["managed_budget_satisfied"]
    assert (
        result["archive_database_file_bytes"] > 0
        and result["archive_compressed_payload_bytes"] < result["archive_raw_bytes"]
    )
    assert (root / "latest.json").read_bytes() == latest
    assert monitor.check(root / "latest.json", now=now).state == "fresh"
    for identifier in originals.keys() - hot(root).keys():
        destination = tmp_path / ("restored-" + identifier)
        restored = archive.restore(identifier, destination)
        assert (destination / "capture.json").read_bytes() == originals[identifier]
        assert restored["authenticity_or_freshness_asserted"] is False
        assert monitor.check(destination / "capture.json", now=now).reason == "capture_regression"
    reopened = CaptureArchive(root, archive.scope, policy=archive.policy)
    again = reopened.compact(apply=True)
    assert again["deleted_hot_files"] == 0 and again["archive_records"] == 3 and hot(root)


@pytest.mark.parametrize("field,value", [("max_records", 2), ("max_raw_bytes", 1)])
def test_archive_capacity_keeps_every_hot_file_and_latest(tmp_path, field, value):
    root, originals, archive, *_ = fixture(tmp_path)
    archive.policy = archive.policy.model_copy(update={field: value})
    preview = archive.compact()
    assert not preview["archive_capacity_available"]
    with pytest.raises(ArchiveFull):
        archive.compact(apply=True)
    assert hot(root) == originals and not archive.path.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_hot_records", 0),
        ("max_records", True),
        ("max_raw_bytes", 0),
        ("batch_size", 0),
        ("batch_size", 257),
        ("max_hot_bytes", 1.1),
    ],
)
def test_policy_limits_are_explicit_and_strict(field, value):
    with pytest.raises(ValueError):
        ArchivePolicy(**{field: value})


@pytest.mark.parametrize(
    "mode", ["missing_latest", "corrupt_latest", "latest_scope", "unbacked_latest"]
)
def test_invalid_latest_stops_all_cleanup(tmp_path, mode):
    root, originals, archive, *_ = fixture(tmp_path)
    if mode == "missing_latest":
        (root / "latest.json").unlink()
    elif mode == "corrupt_latest":
        (root / "latest.json").write_bytes(b"bad")
    elif mode == "latest_scope":
        value = json.loads((root / "latest.json").read_bytes())
        value["event"]["server_id"] = "foreign"
        (root / "latest.json").write_bytes(canonical(value))
    else:
        (root / "latest.json").write_bytes((root / "latest.json").read_bytes() + b" ")
    expected_error = FileNotFoundError if mode == "missing_latest" else ValueError
    with pytest.raises(expected_error):
        archive.compact(apply=True)
    assert hot(root) == originals and not archive.path.exists()


@pytest.mark.parametrize(
    "mode", ["symlink", "hardlink", "extra_file", "foreign_scope", "unknown_directory"]
)
def test_unknown_or_unsafe_entries_are_preserved(tmp_path, mode):
    root, originals, archive, *_ = fixture(tmp_path)
    victim = next(iter(originals))
    capture = root / victim / "capture.json"
    if mode == "symlink":
        outside = tmp_path / "outside"
        outside.write_bytes(capture.read_bytes())
        capture.unlink()
        capture.symlink_to(outside)
    elif mode == "hardlink":
        os.link(capture, tmp_path / "outside")
    elif mode == "extra_file":
        (root / victim / "other.txt").write_bytes(b"preserve")
    elif mode == "foreign_scope":
        value = json.loads(capture.read_bytes())
        value["event"]["tenant_id"] = "foreign"
        capture.write_bytes(canonical(value))
    else:
        (root / "not-managed").mkdir()
        (root / "not-managed/data").write_bytes(b"preserve")
    result = archive.compact(apply=True)
    assert result["skipped_entries"] >= 1
    assert (
        capture.exists()
        if mode != "unknown_directory"
        else (root / "not-managed/data").read_bytes() == b"preserve"
    )
    if mode in {"symlink", "hardlink"}:
        assert (tmp_path / "outside").exists()


@pytest.mark.parametrize("boundary", ["after_commit", "after_unlink"])
def test_real_process_exit_after_preservation_resumes_without_duplicates(tmp_path, boundary):
    root, originals, archive, *_ = fixture(tmp_path)
    code = """import json,os,sys
from scripts.f1_lab.capture_archive import CaptureArchive,ArchiveScope,ArchivePolicy
a=CaptureArchive(sys.argv[1],ArchiveScope.model_validate(json.loads(sys.argv[2])),policy=ArchivePolicy(max_hot_records=2))
setattr(CaptureArchive,'after_archive_commit' if sys.argv[3]=='after_commit' else 'after_unlink',lambda self:os._exit(73))
a.compact(apply=True)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(root), json.dumps(archive.scope.model_dump()), boundary],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 73
    resumed = CaptureArchive(root, archive.scope, policy=archive.policy)
    completed = resumed.compact(apply=True)
    assert completed["archive_records"] == 3 and completed["hot_after_records"] == 2
    for identifier in originals.keys() - hot(root).keys():
        target = tmp_path / ("restored-" + identifier)
        resumed.restore(identifier, target)
        assert (target / "capture.json").read_bytes() == originals[identifier]


def test_failed_archive_commit_never_removes_hot_files(tmp_path, monkeypatch):
    root, originals, archive, *_ = fixture(tmp_path)

    def fail(con):
        raise sqlite3.OperationalError("controlled commit failure")

    monkeypatch.setattr(archive, "commit_archive", fail)
    with pytest.raises(sqlite3.Error):
        archive.compact(apply=True)
    assert hot(root) == originals
    with archive.connection() as con:
        assert archive.load(con)[0] == {}


def test_changed_source_after_commit_is_not_deleted(tmp_path, monkeypatch):
    root, _, archive, *_ = fixture(tmp_path)
    victim = next(iter(hot(root)))
    changed = b"changed after preservation"

    def alter():
        (root / victim / "capture.json").write_bytes(changed)

    monkeypatch.setattr(archive, "after_archive_commit", alter)
    with pytest.raises(ValueError):
        archive.compact(apply=True)
    assert (root / victim / "capture.json").read_bytes() == changed


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE captures SET payload=x'00'",
        "UPDATE captures SET raw_sha='bad'",
        "DELETE FROM captures WHERE seq=1",
        "UPDATE archive_head SET records=0",
        "UPDATE captures SET cleaned=9",
    ],
)
def test_corrupt_archive_stops_cleanup_and_restore(tmp_path, sql):
    root, _, archive, *_ = fixture(tmp_path)
    archive.compact(apply=True)
    before = hot(root)
    with sqlite3.connect(archive.path) as con:
        if "cleaned=9" in sql:
            con.execute("PRAGMA ignore_check_constraints=ON")
        con.execute(sql)
    with pytest.raises((ValueError, sqlite3.Error, zlib.error)):
        archive.compact(apply=True)
    assert hot(root) == before


def test_concurrent_compactors_preserve_one_archive_and_latest(tmp_path):
    root, _, archive, *_ = fixture(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _: CaptureArchive(root, archive.scope, policy=archive.policy).compact(
                    apply=True
                ),
                range(4),
            )
        )
    assert sum(x["deleted_hot_files"] for x in results) == 3
    assert all(x["archive_records"] == 3 and x["latest_protected"] for x in results)


def test_busy_lock_is_bounded_and_release_recovers(tmp_path):
    root, _, archive, *_ = fixture(tmp_path)
    with (
        capture_store_lock(root),
        pytest.raises(ValueError, match="lock_busy"),
        capture_store_lock(root, timeout=0.05),
    ):
        pass
    assert archive.compact()["planned"] == 3


def test_restore_rejects_existing_and_managed_targets(tmp_path):
    root, originals, archive, *_ = fixture(tmp_path)
    archive.compact(apply=True)
    identifier = next(iter(originals.keys() - hot(root).keys()))
    for target in (root / "new", root, tmp_path):
        with pytest.raises(ValueError):
            archive.restore(identifier, target)
