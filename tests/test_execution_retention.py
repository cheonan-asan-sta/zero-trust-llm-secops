"""Terminal execution history, protected input rotation and crash recovery."""

import json
import os
import sqlite3
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Event

import pytest

from scripts import behavior_execution_collector as module
from scripts import execution_archive as archive
from tests import test_execution_continuous as continuous

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def lab(tmp_path, monkeypatch):
    return continuous.lab.__wrapped__(tmp_path, monkeypatch)


def complete(lab, tmp_path, *, bundle=False):
    value = continuous.bundle(lab) if bundle else lab.record
    directory, path = continuous.feed(tmp_path, value)
    collector = lab.collector(context_transport=continuous.context_transport(lab, []))
    assert collector.tick(directory)["delivery"]["state"] == "acknowledged"
    if bundle:
        assert collector.status()["evaluations"]["acknowledged"] == 1
    return collector, directory, path


def test_archived_bundle_replays_after_expiry_without_resigning_or_consuming_approval(lab, tmp_path):
    collector, directory, path = complete(lab, tmp_path, bundle=True)
    before = path.read_bytes()
    assert collector.compact() == {"compacted": 1}
    assert collector.retire_inputs(directory) == 1
    assert not path.exists() and (directory / ".retired" / path.name).read_bytes() == before
    assert collector.status()["active_records"] == 0
    lab.clock.now += timedelta(minutes=6)
    restarted = lab.collector()
    capture = continuous.bundle(lab)["capture"]
    assert restarted.enqueue(lab.record, capture=capture)["duplicate"]
    assert restarted.send_once()["state"] == "idle"
    assert restarted.evaluate_once()["state"] == "idle"
    assert restarted.status()["evaluations"]["acknowledged"] == 1
    assert len(lab.sent) == 1
    with pytest.raises(ValueError, match="conflict"):
        restarted.enqueue(lab.record | {"actor": None})
    path.write_bytes(before)
    path.chmod(0o600)
    assert restarted.capture_one(directory) == {"state": "idle"}
    assert restarted.retire_inputs(directory) == 1
    path.write_text(json.dumps(lab.record | {"actor": None}))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="replaced"):
        restarted.capture_one(directory)


def test_pending_receipts_and_evaluations_are_never_archived(lab, tmp_path):
    directory, _ = continuous.feed(tmp_path, continuous.bundle(lab))
    real = continuous.context_transport(lab, [])

    def lost_evaluation(base, endpoint, payload, **options):
        result = real(base, endpoint, payload, **options)
        if endpoint.endswith("/evaluate"):
            raise OSError("response lost")
        return result

    collector = lab.collector(context_transport=lost_evaluation)
    assert collector.tick(directory)["evaluation"]["state"] == "pending"
    assert collector.compact()["compacted"] == 0
    assert collector.retire_inputs(directory) == 0
    lab.clock.now += timedelta(seconds=3)
    restarted = lab.collector(context_transport=real)
    assert restarted.evaluate_once()["state"] == "acknowledged"
    assert restarted.compact()["compacted"] == 1
    assert restarted.retire_inputs(directory) == 1
    assert restarted.status()["records"] == 1


def test_archive_transaction_rolls_back_on_process_death(lab, tmp_path):
    collector, _, _ = complete(lab, tmp_path)
    program = """
import os,sqlite3,sys
from scripts.execution_archive import compact
c=sqlite3.connect(sys.argv[1],isolation_level=None); c.row_factory=sqlite3.Row
c.execute('PRAGMA synchronous=FULL'); c.execute('BEGIN IMMEDIATE')
assert compact(c,100)==1
os._exit(73)
"""
    child = subprocess.run([sys.executable, "-c", program, str(collector.database)], cwd=ROOT, check=False)
    assert child.returncode == 73
    restarted = lab.collector()
    assert restarted.status()["active_records"] == 1
    assert restarted.status()["archived_records"] == 0
    assert restarted.compact()["compacted"] == 1
    assert lab.collector().status()["archived_records"] == 1


def test_input_rotation_resumes_after_link_but_before_unlink(lab, tmp_path, monkeypatch):
    collector, directory, path = complete(lab, tmp_path)
    collector.compact()
    original = Path.unlink

    def crash(self, *args, **kwargs):
        if self == path:
            raise OSError("simulated crash after link fsync")
        return original(self, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", crash)
        with pytest.raises(OSError):
            collector.retire_inputs(directory)
    assert path.read_bytes() == (directory / ".retired" / path.name).read_bytes()
    assert lab.collector().retire_inputs(directory) == 1
    assert not path.exists()


def test_failed_file_sync_never_removes_original_input(lab, tmp_path, monkeypatch):
    collector, directory, path = complete(lab, tmp_path)
    collector.compact()
    original = os.fsync

    def fail_file_sync(descriptor):
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("simulated file fsync failure")
        return original(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_file_sync)
        with pytest.raises(OSError):
            collector.retire_inputs(directory)
    assert path.read_bytes() == (directory / ".retired" / path.name).read_bytes()
    assert lab.collector().retire_inputs(directory) == 1


def test_rotation_refuses_replaced_symlink_and_conflicting_destination(lab, tmp_path):
    collector, directory, path = complete(lab, tmp_path)
    collector.compact()
    retired = directory / ".retired"
    retired.mkdir(mode=0o700)
    target = retired / path.name
    target.write_text("different")
    target.chmod(0o600)
    with pytest.raises(ValueError, match="conflict"):
        collector.retire_inputs(directory)
    assert path.exists() and target.read_text() == "different"
    target.unlink()
    target.symlink_to(path)
    with pytest.raises((ValueError, OSError)):
        collector.retire_inputs(directory)
    assert path.exists()


@pytest.mark.parametrize("mutation", [
    "DELETE FROM execution_archive",
    "UPDATE execution_archive SET payload=x'0001'",
    "UPDATE execution_archive SET raw_bytes=4194305",
    "UPDATE execution_archive_head SET head='changed'",
])
def test_archive_damage_does_not_forget_duplicate_history(lab, tmp_path, mutation):
    collector, _, _ = complete(lab, tmp_path)
    collector.compact()
    with sqlite3.connect(collector.database) as connection:
        connection.execute(mutation)
    with pytest.raises(ValueError):
        lab.collector()


def test_archive_full_preserves_active_records_and_old_duplicates(lab, tmp_path, monkeypatch):
    collector, _, _ = complete(lab, tmp_path)
    collector.compact()
    collector.enqueue(lab.record | {"evidence_id": "second"})
    collector.send_once()
    with collector._connection() as connection:
        used = connection.execute("SELECT raw_bytes FROM execution_archive_head WHERE id=1").fetchone()[0]
    with monkeypatch.context() as patch:
        patch.setattr(archive, "MAX_BYTES", used)
        with pytest.raises(ValueError, match="capacity"):
            collector.compact()
        assert collector.enqueue(lab.record)["duplicate"]
    assert lab.collector().status()["records"] == 2


def test_more_than_ten_thousand_records_keep_pending_and_archived_identity(lab):
    collector = lab.collector()
    record_base = lab.record | {"event_ids": lab.record["event_ids"][:1]}
    # Bulk seed valid signed terminal envelopes to exercise real storage limits
    # without quadratic enqueue validation. HTTP receipt semantics are tested above.
    with collector._connection() as connection:
        for index in range(10_000):
            record = record_base | {"evidence_id": f"bulk-{index}"}
            envelope = module.sign_record(record, collector.key, collector.config, collector.verifier, lab.clock.now)
            raw = module._canonical(envelope.model_dump(mode="json"))
            normalized = envelope.model_dump(mode="json", exclude=module.ENVELOPE_FIELDS)
            connection.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?)", (
                index + 1, envelope.evidence_id, module._sha(module._canonical(normalized)), raw.decode(),
                module._sha(raw), module._sha(module.canonical_execution_evidence(envelope)),
                "pending" if index == 9999 else "acknowledged", 1, lab.clock.now.isoformat(), None,
            ))
    queued = collector.enqueue(record_base | {"evidence_id": "after-10000"})
    assert not queued["duplicate"]
    restarted = lab.collector()
    status = restarted.status()
    assert status["records"] == 10_001 and status["active_records"] <= 10_000
    assert status["pending"] == 2 and status["archived_records"] > 0
    assert restarted.enqueue(record_base | {"evidence_id": "bulk-0"})["duplicate"]
    with pytest.raises(ValueError, match="conflict"):
        restarted.enqueue(record_base | {"evidence_id": "bulk-0", "actor": None})


def test_inflight_network_delivery_excludes_concurrent_compaction(lab):
    entered, release = Event(), Event()

    def blocked(base_url, payload, **options):
        entered.set()
        assert release.wait(10)
        return lab.transport(base_url, payload, **options)

    sender = lab.collector(transport=blocked)
    maintenance = lab.collector()
    sender.enqueue(lab.record)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(sender.send_once)
        try:
            assert entered.wait(10)
            with pytest.raises(OSError):
                maintenance.compact()
        finally:
            release.set()
        assert future.result(timeout=10)["state"] == "acknowledged"
    assert maintenance.compact()["compacted"] == 1


@pytest.mark.parametrize("table", ["bundles", "evaluations"])
def test_orphan_active_details_cannot_shadow_archived_bundle(lab, tmp_path, table):
    collector, _, _ = complete(lab, tmp_path, bundle=True)
    with collector._connection() as connection:
        item = dict(connection.execute("SELECT * FROM " + table).fetchone())
    collector.compact()
    with collector._connection() as connection:
        placeholders = ",".join("?" for _ in item)
        connection.execute("INSERT INTO " + table + " VALUES (" + placeholders + ")", tuple(item.values()))
    with pytest.raises(ValueError, match="orphan"):
        lab.collector()
