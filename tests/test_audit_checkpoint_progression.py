"""Monotonic checkpoint advancement and read-only operator comparison."""

import asyncio
import json
from datetime import datetime
from unittest.mock import Mock

import pytest
from test_audit_checkpoint import ready
from test_sqlite_audit import initial

from app.services.audit_checkpoint import capture_checkpoint, inspect_checkpoint, load_checkpoint
from app.services.audit_transfer import AuditTransferError
from app.services.sqlite_audit import SQLiteAuditStore
from scripts import audit_storage


def test_advance_extends_previous_prefix_and_allows_same_head_refresh(tmp_path):
    store, _, previous, receipt = ready(tmp_path)
    original_bytes = previous.read_bytes()
    asyncio.run(store.save(initial(2)))
    source = store.path.read_bytes()
    target = tmp_path / "advanced.json"
    current = capture_checkpoint(
        store.path,
        target,
        previous_checkpoint=previous,
        previous_checkpoint_sha256=receipt["checkpoint_sha256"],
    )
    check = current["progression_check"]
    assert check["monotonic_head_verified"] and check["previous_checkpoint_has_history"]
    assert check["previous_head"] == receipt["head"] and check["advanced_rows"] == 1
    assert load_checkpoint(target, current["checkpoint_sha256"])["head"] == current["head"]
    same = capture_checkpoint(
        store.path,
        tmp_path / "same-head.json",
        previous_checkpoint=target,
        previous_checkpoint_sha256=current["checkpoint_sha256"],
    )
    assert same["progression_check"]["monotonic_head_verified"]
    assert same["progression_check"]["advanced_rows"] == 0 and same["head"] == current["head"]
    assert previous.read_bytes() == original_bytes and store.path.read_bytes() == source


@pytest.mark.parametrize("kind", ["older", "fork"])
def test_advance_refuses_valid_but_older_or_forked_source_without_publishing(tmp_path, kind):
    store, original, _, _ = ready(tmp_path)
    asyncio.run(store.save(initial(2)))
    previous = tmp_path / "known-current.json"
    receipt = capture_checkpoint(store.path, previous)
    source = SQLiteAuditStore(tmp_path / "candidate.sqlite3")
    if kind == "older":
        asyncio.run(source.save(original))
    else:
        asyncio.run(source.save(initial(7)))
        asyncio.run(source.save(initial(8)))
    before = source.path.read_bytes()
    output = tmp_path / "must-not-publish.json"
    with pytest.raises(AuditTransferError):
        capture_checkpoint(
            source.path,
            output,
            previous_checkpoint=previous,
            previous_checkpoint_sha256=receipt["checkpoint_sha256"],
        )
    assert not output.exists() and not list(tmp_path.glob(".audit-transfer-*"))
    assert source.path.read_bytes() == before and source.integrity()["ok"]


@pytest.mark.parametrize(
    "options",
    [
        {"previous_checkpoint": "not-read.json"},
        {"previous_checkpoint_sha256": "a" * 64},
    ],
)
def test_advance_partial_reference_fails_before_database_access(tmp_path, monkeypatch, options):
    opened = Mock(side_effect=AssertionError("source must not open for an invalid reference"))
    monkeypatch.setattr(SQLiteAuditStore, "open_existing", opened)
    with pytest.raises(AuditTransferError):
        capture_checkpoint("not-read.sqlite3", tmp_path / "not-created.json", **options)
    opened.assert_not_called()


@pytest.mark.parametrize(
    "state", ["at_checkpoint", "checkpoint_lagging", "behind_checkpoint", "history_conflict"]
)
def test_status_reports_comparison_without_modifying_any_state(tmp_path, state):
    store, original, previous, receipt = ready(tmp_path)
    source = store
    if state in {"checkpoint_lagging", "behind_checkpoint"}:
        asyncio.run(store.save(initial(2)))
    if state == "behind_checkpoint":
        previous = tmp_path / "newer.json"
        receipt = capture_checkpoint(store.path, previous)
        source = SQLiteAuditStore(tmp_path / "old.sqlite3")
        asyncio.run(source.save(original))
    elif state == "history_conflict":
        source = SQLiteAuditStore(tmp_path / "other.sqlite3")
        asyncio.run(source.save(initial(7)))
        asyncio.run(source.save(initial(8)))
    before, previous_bytes = source.path.read_bytes(), previous.read_bytes()
    result = inspect_checkpoint(source.path, previous, receipt["checkpoint_sha256"])
    assert result["status"] == state
    safe = state in {"at_checkpoint", "checkpoint_lagging"}
    assert result["minimum_head_satisfied"] is safe
    assert result["checkpoint_refresh_recommended"] is (state == "checkpoint_lagging")
    assert result["uncheckpointed_rows"] == (
        1 if state == "checkpoint_lagging" else 0 if safe else None
    )
    assert datetime.fromisoformat(result["observed_at"]).utcoffset() is not None
    assert not result["automatic_activation_allowed"] and not result["latest_live_state_verified"]
    assert not result["independent_storage_verified"]
    assert source.path.read_bytes() == before and previous.read_bytes() == previous_bytes


def test_matching_chain_in_new_location_is_not_rejected_as_wrong_history(tmp_path):
    _, original, previous, receipt = ready(tmp_path)
    clone = SQLiteAuditStore(tmp_path / "moved.sqlite3")
    asyncio.run(clone.save(original))
    result = inspect_checkpoint(clone.path, previous, receipt["checkpoint_sha256"])
    assert result["minimum_head_satisfied"] and result["status"] == "at_checkpoint"
    assert result["source_locator_matches"] is False


def test_baseline_export_does_not_claim_monotonic_progress(tmp_path):
    _, _, _, receipt = ready(tmp_path)
    assert receipt["progression_check"]["monotonic_head_verified"] is False
    assert receipt["progression_check"]["previous_head"] is None
    assert receipt["progression_check"]["advanced_rows"] is None


def test_empty_previous_head_is_not_claimed_as_nonempty_lineage(tmp_path):
    empty = SQLiteAuditStore(tmp_path / "empty.sqlite3")
    previous = tmp_path / "empty.json"
    receipt = capture_checkpoint(empty.path, previous)
    store = SQLiteAuditStore(tmp_path / "first-nonempty.sqlite3")
    asyncio.run(store.save(initial(9)))
    result = capture_checkpoint(
        store.path,
        tmp_path / "first.json",
        previous_checkpoint=previous,
        previous_checkpoint_sha256=receipt["checkpoint_sha256"],
    )
    assert result["progression_check"]["monotonic_head_verified"]
    assert result["progression_check"]["previous_checkpoint_has_history"] is False
    assert result["progression_check"]["advanced_rows"] == 1


def test_cli_advance_and_status_emit_machine_readable_results(tmp_path, capsys):
    store, _, previous, receipt = ready(tmp_path)
    asyncio.run(store.save(initial(2)))
    status_args = [
        "checkpoint-status",
        "--database",
        str(store.path),
        "--checkpoint",
        str(previous),
        "--checkpoint-sha256",
        receipt["checkpoint_sha256"],
    ]
    audit_storage.main(status_args)
    status = json.loads(capsys.readouterr().out)
    assert status["status"] == "checkpoint_lagging" and status["uncheckpointed_rows"] == 1
    output = tmp_path / "new.json"
    audit_storage.main(
        [
            "checkpoint-advance",
            "--database",
            str(store.path),
            "--destination",
            str(output),
            "--previous-checkpoint",
            str(previous),
            "--previous-checkpoint-sha256",
            receipt["checkpoint_sha256"],
        ]
    )
    advanced = json.loads(capsys.readouterr().out)
    assert advanced["progression_check"]["monotonic_head_verified"]
    assert advanced["head"]["seq"] == 2 and not advanced["automatic_activation_allowed"]


def test_cli_status_prints_unsafe_result_and_exits3_without_changing_data(tmp_path, capsys):
    _, _, previous, receipt = ready(tmp_path)
    other = SQLiteAuditStore(tmp_path / "other.sqlite3")
    asyncio.run(other.save(initial(9)))
    before = other.path.read_bytes()
    with pytest.raises(SystemExit) as stopped:
        audit_storage.main(
            [
                "checkpoint-status",
                "--database",
                str(other.path),
                "--checkpoint",
                str(previous),
                "--checkpoint-sha256",
                receipt["checkpoint_sha256"],
            ]
        )
    result = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 3 and result["status"] == "history_conflict"
    assert not result["minimum_head_satisfied"] and other.path.read_bytes() == before


def test_cli_advance_cannot_silently_start_a_new_baseline(tmp_path, monkeypatch):
    capture = Mock(side_effect=AssertionError("missing previous anchor must not fall back"))
    monkeypatch.setattr(audit_storage, "capture_checkpoint", capture)
    with pytest.raises(SystemExit) as stopped:
        audit_storage.main(
            [
                "checkpoint-advance",
                "--database",
                "not-read.sqlite3",
                "--destination",
                str(tmp_path / "not-created.json"),
            ]
        )
    assert stopped.value.code == 2
    capture.assert_not_called()


def test_changed_previous_file_cannot_seed_a_new_trusted_checkpoint(tmp_path):
    store, _, previous, receipt = ready(tmp_path)
    previous.write_bytes(previous.read_bytes() + b" ")
    output = tmp_path / "new.json"
    with pytest.raises(AuditTransferError, match="pin mismatch"):
        capture_checkpoint(
            store.path,
            output,
            previous_checkpoint=previous,
            previous_checkpoint_sha256=receipt["checkpoint_sha256"],
        )
    assert not output.exists()
