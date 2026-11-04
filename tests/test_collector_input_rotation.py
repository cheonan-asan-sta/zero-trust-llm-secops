"""Input generations preserve pending delivery and compacted duplicate history."""

import json
from datetime import timedelta

import pytest

from app.services.collector_spool import SpoolConflict, SpoolFull
from scripts import collector_input as inputs
from scripts.continuous_signal_collector import ContinuousCollector

pytest_plugins = ["test_continuous_signal_collector"]


def restarted(lab, **options):
    return ContinuousCollector(lab.directory, "http://127.0.0.1:18080",
                               clock=lambda: lab.clock[0], transport=lab.send, **options)


def test_rotation_retains_pending_exact_variants_retry_and_duplicate_cursor(lab):
    collector = lab.collector
    assert collector.capture_one()
    collector.transport = lambda *_args, **_kwargs: (503, {})
    assert collector.deliver_one() == "retry"
    due = lab.now + timedelta(seconds=2)
    pending = collector.spool.next_pending(due)
    assert pending["envelopes"] and pending["attempts"] == 1
    assert collector.rotate() == {"rotated": True, "generation": 1}
    assert not lab.feed.read_bytes()
    assert collector.spool.checkpoint()["offset"] == 0
    assert collector.spool.next_pending(due) == pending
    assert not list(lab.directory.glob("input.sealed.*.jsonl"))
    collector = restarted(lab)
    assert collector.append(lab.record) == {"appended": True}
    assert not collector.capture_one()
    assert collector.spool.summary()["captured"] == 1
    assert collector.spool.next_pending(due) == pending
    lab.clock[0] = due
    assert collector.deliver_one() == "acknowledged"
    assert lab.calls == pending["envelopes"]


@pytest.mark.parametrize("tail", [b"\n", b'{"event_id":"partial', b"unread\n"])
def test_rotation_refuses_every_uncaptured_tail_without_modifying_any_file(lab, tail):
    assert lab.collector.capture_one()
    checkpoint = lab.collector.spool.checkpoint()
    with lab.feed.open("ab") as file:
        file.write(tail)
    before = lab.feed.read_bytes()
    with pytest.raises(ValueError, match="completely captured"):
        lab.collector.rotate()
    assert lab.feed.read_bytes() == before
    assert lab.collector.spool.checkpoint() == checkpoint
    assert lab.collector.spool.rotation_checkpoint()["generation"] == 0
    assert not (lab.directory / inputs.JOURNAL).exists()


def test_unmanaged_truncate_does_not_become_an_authorized_rotation(lab):
    assert lab.collector.capture_one()
    checkpoint = lab.collector.spool.checkpoint()
    lab.feed.write_bytes(b"")
    with pytest.raises(ValueError, match="prefix changed"):
        lab.collector.rotate()
    assert lab.collector.spool.checkpoint() == checkpoint


def test_automatic_rotation_waits_for_eof_then_continues_next_generation(lab):
    collector = restarted(lab, rotate_bytes=1)
    assert collector.capture_one()
    assert collector.status()["input_generation"] == 0
    assert not collector.capture_one()
    assert collector.status()["input_generation"] == 1
    assert collector.status()["pending"] == 1
    collector.append(lab.record | {"event_id": "next-generation"})
    assert collector.capture_one()
    assert not collector.capture_one()
    assert collector.status()["input_generation"] == 2
    assert collector.spool.summary()["captured"] == 2
    assert collector.spool.next_pending(lab.now)["event_id"] == lab.record["event_id"]


def test_empty_rotation_is_idempotent_and_does_not_grow_history(lab):
    assert lab.collector.capture_one()
    assert lab.collector.rotate()["rotated"]
    for _ in range(3):
        assert lab.collector.rotate() == {"rotated": False, "generation": 1}
    assert not lab.collector.status()["input_rotation_pending"]


def test_rotation_history_cap_refuses_before_publishing_or_renaming_input(lab):
    collector = restarted(lab, max_rotations=1)
    collector.capture_one()
    collector.rotate()
    collector.append(lab.record | {"event_id": "next-file"})
    collector.capture_one()
    before, checkpoint = lab.feed.read_bytes(), collector.spool.checkpoint()
    with pytest.raises(SpoolFull):
        collector.rotate()
    assert lab.feed.read_bytes() == before
    assert collector.spool.checkpoint() == checkpoint
    assert collector.status()["input_generation"] == 1
    assert not collector.status()["input_rotation_pending"]
    assert not list(lab.directory.glob("input.sealed.*.jsonl"))


def test_capacity_automatically_compacts_ack_but_preserves_dedup_across_rotation(lab):
    collector = restarted(lab, max_records=1)
    assert collector.capture_one()
    assert collector.deliver_one() == "acknowledged"
    assert collector.rotate()["rotated"]
    collector.append(lab.record | {"event_id": "second"})
    assert collector.capture_one()
    assert collector.spool.storage_summary()["compacted"] == 1
    assert collector.spool.summary()["pending"] == 1
    collector.append(lab.record)
    assert not collector.capture_one()
    assert len(lab.calls) == 1
    assert collector.spool.summary()["captured"] == 2
    assert collector.deliver_one() == "acknowledged"
    assert len(lab.calls) == 2


def test_compacted_identifier_changed_content_stops_before_cursor_advance(lab):
    collector = lab.collector
    collector.capture_one()
    collector.deliver_one()
    assert collector.spool.compact() == 1
    collector.rotate()
    collector.append(lab.record | {"observation": lab.record["observation"] | {"active": True}})
    with pytest.raises(SpoolConflict):
        collector.capture_one()
    assert collector.spool.checkpoint()["offset"] == 0
    assert collector.spool.summary()["captured"] == 1
    assert len(lab.calls) == 1


def test_history_exhaustion_retains_next_input_instead_of_forgetting_ids(lab):
    collector = restarted(lab, max_records=1, max_history=1)
    collector.capture_one()
    collector.deliver_one()
    collector.append(lab.record | {"event_id": "second"})
    assert collector.capture_one()
    collector.deliver_one()
    prior = collector.spool.checkpoint()
    collector.append(lab.record | {"event_id": "third"})
    with pytest.raises(SpoolFull):
        collector.capture_one()
    assert collector.spool.checkpoint() == prior
    assert collector.spool.summary()["captured"] == 2
    assert collector.spool.storage_summary()["compacted"] == 1


@pytest.mark.parametrize("changed", [
    {"observed_at": "2099-01-01T00:00:00Z"},
    {"observation": {"kind": "identity", "subject_id": "other-user", "active": False,
                     "authentication_result": "failure"}},
    {"unknown": "field"},
])
def test_managed_append_validates_scope_time_and_fields_before_writing(lab, changed):
    before = lab.feed.read_bytes()
    with pytest.raises(ValueError):
        lab.collector.append(lab.record | changed)
    assert lab.feed.read_bytes() == before


def test_managed_append_and_capture_share_a_short_lived_lock(lab):
    before = lab.feed.read_bytes()
    with inputs.feed_lock(lab.directory):
        with pytest.raises(inputs.InputBusy):
            lab.collector.append(lab.record)
        with pytest.raises(inputs.InputBusy):
            lab.collector.capture_one()
    assert lab.feed.read_bytes() == before
    assert lab.collector.spool.summary()["captured"] == 0
    assert lab.collector.capture_one()


def test_managed_append_does_not_append_to_a_partial_line(lab):
    lab.feed.write_bytes(b'{"incomplete":')
    with pytest.raises(ValueError, match="partial"):
        lab.collector.append(lab.record)
    assert lab.feed.read_bytes() == b'{"incomplete":'


def test_managed_append_reports_capacity_before_writing(lab, monkeypatch):
    before = lab.feed.read_bytes()
    monkeypatch.setattr(inputs, "MAX_FEED", len(before))
    with pytest.raises(BlockingIOError):
        lab.collector.append(lab.record)
    assert lab.feed.read_bytes() == before


def test_unpublished_partial_preparation_is_removed_without_resetting_cursor(lab):
    lab.collector.capture_one()
    checkpoint = lab.collector.spool.checkpoint()
    (lab.directory / inputs.PREPARATION).write_bytes(b'{"partial')
    assert not lab.collector.capture_one()
    assert lab.collector.spool.checkpoint() == checkpoint
    assert not (lab.directory / inputs.PREPARATION).exists()


def test_corrupt_published_journal_stops_without_deleting_input_or_pending(lab):
    lab.collector.capture_one()
    checkpoint = lab.collector.spool.checkpoint()
    (lab.directory / inputs.JOURNAL).write_text(json.dumps({"rotation": {}, "sha256": "0" * 64}))
    before = lab.feed.read_bytes()
    with pytest.raises(ValueError):
        lab.collector.capture_one()
    assert lab.feed.read_bytes() == before
    assert lab.collector.spool.checkpoint() == checkpoint
    assert lab.collector.spool.summary()["pending"] == 1


def test_symlink_active_input_is_rejected_without_touching_target(lab, tmp_path):
    target = tmp_path / "outside.jsonl"
    target.write_bytes(lab.feed.read_bytes())
    lab.feed.unlink()
    lab.feed.symlink_to(target)
    before = target.read_bytes()
    with pytest.raises(ValueError, match="regular file"):
        lab.collector.capture_one()
    with pytest.raises(ValueError, match="regular file"):
        lab.collector.append(lab.record)
    assert target.read_bytes() == before
