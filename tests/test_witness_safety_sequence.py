"""Model-counted synthetic action ordering; not independently labeled attacks."""

import json
from contextlib import contextmanager
from itertools import pairwise

import pytest

from app.services.audit_transfer import AuditTransferError
from scripts import run_witness_safety_sequence as sequence
from scripts.run_witness_safety_sequence import ACTIONS, run


@pytest.mark.parametrize("seed", [1, 17, 64, 20261120])
def test_mixed_action_order_preserves_external_minima_and_exact_pending_recovery(tmp_path, seed):
    output = tmp_path / "sequence"
    result = run(output, seed=seed)
    assert result["completed"] and result["steps"] == len(ACTIONS)
    assert result["handoffs"] == 2
    assert result["receipts"] == result["anchors"] + 1
    assert result["paid_api_calls"] == 0 and result["detection_metrics_changed"] is False
    trace = [json.loads(row) for row in (output / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {row["action"] for row in trace} == set(ACTIONS)
    assert all(row["passed"] for row in trace)
    assert all(b["receipts"] >= a["receipts"] and b["source_rows"] >= a["source_rows"]
               for a, b in pairwise(trace))
    assert not list(output.glob("private-sequence-*"))
    assert not (output / "failure.json").exists()


@pytest.mark.parametrize("bad", [{"rounds": 0}, {"rounds": 33}, {"seed": True},
                                  {"delay_seconds": float("nan")}, {"delay_seconds": 61},
                                  {"max_seconds": 7201}])
def test_invalid_resource_policy_is_rejected_before_output_creation(tmp_path, bad):
    output = tmp_path / "invalid"
    with pytest.raises(AuditTransferError):
        run(output, **bad)
    assert not output.exists()


def test_deadline_reports_partial_coverage_and_cleans_fixture(tmp_path):
    output = tmp_path / "bounded"
    result = run(output, rounds=32, delay_seconds=1, max_seconds=1)
    assert not result["completed"] and result["stopped_at_deadline"]
    assert result["steps"] < len(ACTIONS) * 32
    assert json.loads((output / "report.json").read_text())["completed"] is False
    assert not list(output.glob("private-sequence-*"))


def test_cleanup_failure_never_leaves_a_completed_report(tmp_path, monkeypatch):
    original = sequence.tempfile.TemporaryDirectory

    @contextmanager
    def cleanup_error(*args, **kwargs):
        with original(*args, **kwargs) as temporary:
            yield temporary
        if kwargs.get("prefix") == "private-sequence-":
            raise OSError("test-owned cleanup failure")

    monkeypatch.setattr(sequence.tempfile, "TemporaryDirectory", cleanup_error)
    output = tmp_path / "failed"
    with pytest.raises(OSError, match="cleanup failure"):
        run(output, seed=17)
    assert not (output / "report.json").exists()
    failed = json.loads((output / "failure.json").read_text())
    assert not failed["completed"] and failed["completed_steps"] == len(ACTIONS)
    assert not list(output.glob("private-sequence-*"))


def test_owned_stop_request_is_partial_and_does_not_claim_full_protocol(tmp_path, monkeypatch):
    original = sequence.tempfile.TemporaryDirectory
    output = tmp_path / "stopped"

    @contextmanager
    def stopped(*args, **kwargs):
        with original(*args, **kwargs) as temporary:
            if kwargs.get("prefix") == "private-sequence-":
                (output / "stop.request").write_text("stop owned lab only")
            yield temporary

    monkeypatch.setattr(sequence.tempfile, "TemporaryDirectory", stopped)
    result = run(output, seed=17)
    assert result["stopped_by_operator"] and not result["completed"] and result["steps"] == 0
    assert not list(output.glob("private-sequence-*"))


def test_a_short_lived_stop_event_is_latched_and_never_reports_all_steps_complete(tmp_path, monkeypatch):
    output = tmp_path / "one-shot-stop"
    original = type(output).exists
    seen = 0

    def one_shot(path):
        nonlocal seen
        if path == output / "stop.request":
            seen += 1
            return seen == 1
        return original(path)

    monkeypatch.setattr(type(output), "exists", one_shot)
    result = run(output)
    assert not result["completed"] and result["stopped_by_operator"] and result["steps"] == 0


def test_private_fixtures_are_separate_from_report_filesystem_and_removed(tmp_path, monkeypatch):
    original = sequence.tempfile.TemporaryDirectory
    output = tmp_path / "reports"
    fixtures = []

    @contextmanager
    def capture(*args, **kwargs):
        with original(*args, **kwargs) as temporary:
            if kwargs.get("prefix") == "private-sequence-":
                assert kwargs.get("dir") is None
                fixtures.append(type(output)(temporary))
                assert not fixtures[-1].is_relative_to(output)
                (output / "stop.request").write_text("inspect fixture separation only")
            yield temporary

    monkeypatch.setattr(sequence.tempfile, "TemporaryDirectory", capture)
    result = run(output)
    assert not result["completed"] and result["steps"] == 0
    assert fixtures and all(not path.exists() for path in fixtures)
