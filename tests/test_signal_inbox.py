import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.services.signal_inbox import (
    InboxConflict,
    InboxFull,
    InboxLeaseLost,
    InboxMissing,
    InboxUnavailable,
    SignalInbox,
)

NOW = datetime(2026, 11, 2, 0, 0, tzinfo=UTC)


def accept(inbox, event="event-1", tenant="tenant-a", *, now=NOW, payload=None):
    payload = payload or {"event_id": event, "signature": "test-signature"}
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    digest = hashlib.sha256(json.dumps(unsigned, sort_keys=True).encode()).hexdigest()
    return inbox.accept(tenant, event, payload, digest, "operator-a", now)


@pytest.fixture
def inbox(tmp_path):
    return SignalInbox(tmp_path / "shared.sqlite3", lease_seconds=10, retry_seconds=2)


def test_ack_is_committed_and_survives_new_instance(inbox):
    receipt = accept(inbox)
    assert receipt["state"] == "pending"
    assert receipt["attempts"] == 0
    assert receipt["duplicate"] is False
    reopened = SignalInbox(inbox.path)
    assert reopened.get("tenant-a", "event-1") == receipt
    with sqlite3.connect(inbox.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM signal_inbox").fetchone()[0] == 1
    assert not ({"payload", "submitted_by", "input_digest", "lease_token"} & receipt.keys())


def test_commit_failure_never_returns_ack_and_rolls_back(inbox, monkeypatch):
    original = sqlite3.connect

    class FailingCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("simulated fsync failure")

    def connect(*args, **kwargs):
        return original(*args, **kwargs, factory=FailingCommit)

    with monkeypatch.context() as context:
        context.setattr("app.services.signal_inbox.sqlite3.connect", connect)
        with pytest.raises(InboxUnavailable):
            accept(inbox)
    with pytest.raises(InboxMissing):
        inbox.get("tenant-a", "event-1")


def test_exact_repeat_is_retained_and_changed_payload_conflicts(inbox):
    original = accept(inbox)
    repeated = accept(inbox, now=NOW + timedelta(hours=1))
    assert repeated == original | {"duplicate": True}
    with pytest.raises(InboxConflict):
        accept(inbox, payload={"event_id": "event-1", "signature": "changed"})
    with pytest.raises(InboxConflict):
        accept(inbox, payload={"event_id": "event-1", "signature": "test", "changed": True})
    assert inbox.metrics("tenant-a")["total"] == 1


def test_tenant_scoped_identity_and_status(inbox):
    accept(inbox)
    accept(inbox, tenant="tenant-b")
    assert inbox.metrics("tenant-a")["total"] == 1
    assert inbox.metrics("tenant-c")["total"] == 0
    with pytest.raises(InboxMissing):
        inbox.get("tenant-c", "event-1")


def test_processing_completion_and_status_hide_raw_signal(inbox):
    accept(inbox)
    item = inbox.claim(now=NOW)
    assert item["state"] == "processing"
    assert item["attempts"] == 1
    assert item["payload"]["signature"] == "test-signature"
    assert item["submitted_by"] == "operator-a"
    assert inbox.claim(now=NOW + timedelta(seconds=1)) is None
    receipt = inbox.complete("tenant-a", "event-1", item["lease_token"], {"revoked": 2}, NOW)
    assert receipt["state"] == "completed"
    assert receipt["result"] == {"revoked": 2}
    assert inbox.metrics("tenant-a")["completed"] == 1
    assert inbox.claim(now=NOW + timedelta(days=1)) is None
    assert accept(inbox)["duplicate"] is True
    assert "test-signature" not in json.dumps(receipt)


def test_restart_recovers_expired_lease_and_fences_old_worker(inbox):
    accept(inbox)
    first = inbox.claim(now=NOW)
    reopened = SignalInbox(inbox.path, lease_seconds=10)
    assert reopened.claim(now=NOW + timedelta(seconds=9)) is None
    second = reopened.claim(now=NOW + timedelta(seconds=10))
    assert second["attempts"] == 2
    assert second["lease_token"] != first["lease_token"]
    for method, value in ((inbox.complete, {}), (inbox.fail, "worker_failed")):
        with pytest.raises(InboxLeaseLost):
            method("tenant-a", "event-1", first["lease_token"], value,
                   NOW + timedelta(seconds=11))
    reopened.complete("tenant-a", "event-1", second["lease_token"], {},
                      NOW + timedelta(seconds=11))
    assert inbox.get("tenant-a", "event-1")["state"] == "completed"


@pytest.mark.parametrize("method,value", [("complete", {}), ("fail", "worker_failed")])
def test_expired_lease_cannot_mutate_even_before_reclaim(inbox, method, value):
    accept(inbox)
    item = inbox.claim(now=NOW)
    with pytest.raises(InboxLeaseLost):
        getattr(inbox, method)("tenant-a", "event-1", item["lease_token"], value,
                               NOW + timedelta(seconds=10))
    assert inbox.get("tenant-a", "event-1")["state"] == "processing"


def test_backoff_retries_and_dead_letter_are_durable(inbox):
    accept(inbox)
    first = inbox.claim(now=NOW)
    failed = inbox.fail("tenant-a", "event-1", first["lease_token"], "policy_unavailable", NOW)
    assert failed["state"] == "pending"
    assert inbox.claim(now=NOW + timedelta(seconds=1)) is None
    second = inbox.claim(now=NOW + timedelta(seconds=2))
    inbox.fail("tenant-a", "event-1", second["lease_token"], "policy_unavailable",
               NOW + timedelta(seconds=2))
    assert inbox.claim(now=NOW + timedelta(seconds=5)) is None
    third = inbox.claim(now=NOW + timedelta(seconds=6))
    failed = inbox.fail("tenant-a", "event-1", third["lease_token"], "policy_unavailable",
                        NOW + timedelta(seconds=6))
    assert failed["state"] == "failed"
    assert failed["attempts"] == 3
    assert SignalInbox(inbox.path).get("tenant-a", "event-1") == failed
    assert inbox.claim(now=NOW + timedelta(days=1)) is None


def test_abandoned_final_attempt_goes_to_failed_then_claims_next(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_attempts=1, lease_seconds=1)
    accept(inbox)
    accept(inbox, event="event-2", now=NOW + timedelta(microseconds=1))
    inbox.claim(now=NOW)
    next_item = inbox.claim(now=NOW + timedelta(seconds=1))
    assert next_item["event_id"] == "event-2"
    failed = inbox.get("tenant-a", "event-1")
    assert failed["state"] == "failed"
    assert failed["last_error"] == "lease_expired"


def test_claim_uses_oldest_eligible_record_without_head_of_line_blocking(inbox):
    accept(inbox)
    first = inbox.claim(now=NOW)
    inbox.fail("tenant-a", "event-1", first["lease_token"], "temporary", NOW)
    accept(inbox, event="event-2", now=NOW + timedelta(seconds=1))
    assert inbox.claim(now=NOW + timedelta(seconds=1))["event_id"] == "event-2"


def test_global_pending_capacity_counts_processing_but_preserves_duplicates(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_pending=1)
    accept(inbox)
    first = inbox.claim(now=NOW)
    assert accept(inbox)["duplicate"] is True
    with pytest.raises(InboxFull):
        accept(inbox, tenant="tenant-b")
    inbox.complete("tenant-a", "event-1", first["lease_token"], {}, NOW)
    accept(inbox, tenant="tenant-b")


def test_per_tenant_pending_capacity_allows_other_tenant(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_pending=3, max_pending_per_tenant=1)
    accept(inbox)
    with pytest.raises(InboxFull):
        accept(inbox, event="event-2")
    accept(inbox, tenant="tenant-b")


@pytest.mark.parametrize("limit", ["global", "tenant"])
def test_terminal_retention_never_silently_forgets_event_ids(tmp_path, limit):
    options = {"max_records": 1} if limit == "global" else {"max_records_per_tenant": 1}
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", **options)
    accept(inbox)
    item = inbox.claim(now=NOW)
    inbox.complete("tenant-a", "event-1", item["lease_token"], {}, NOW)
    assert accept(inbox)["duplicate"] is True
    with pytest.raises(InboxFull):
        accept(inbox, event="event-2")
    if limit == "tenant":
        accept(inbox, tenant="tenant-b")


def test_concurrent_duplicate_accept_creates_one_receipt(inbox):
    def submit(_):
        return accept(SignalInbox(inbox.path))

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(submit, range(16)))
    assert sum(not receipt["duplicate"] for receipt in receipts) == 1
    assert inbox.metrics("tenant-a")["total"] == 1


def test_competing_workers_get_exclusive_claims(inbox):
    for number in range(8):
        accept(inbox, event=f"event-{number}")

    def take(_):
        return SignalInbox(inbox.path).claim(now=NOW)

    with ThreadPoolExecutor(max_workers=8) as pool:
        items = list(pool.map(take, range(16)))
    claimed = [item for item in items if item]
    assert len(claimed) == 8
    assert len({item["event_id"] for item in claimed}) == 8
    assert all(item["attempts"] == 1 for item in claimed)


@pytest.mark.parametrize("sql", [
    "UPDATE signal_inbox SET payload='{}'",
    "UPDATE signal_inbox SET payload='not-json'",
    "UPDATE signal_inbox SET received_at='not-a-time'",
    "UPDATE signal_inbox SET state='processing'",
    "UPDATE signal_inbox SET last_error='secret error with spaces'",
    "UPDATE signal_inbox SET input_digest='bad'",
])
def test_corrupt_rows_fail_closed_in_status_claim_metrics_and_restart(inbox, sql):
    accept(inbox)
    with sqlite3.connect(inbox.path) as connection:
        connection.execute(sql)
    for operation in (
        lambda: inbox.get("tenant-a", "event-1"),
        lambda: inbox.claim(now=NOW),
        lambda: inbox.metrics("tenant-a"),
        lambda: SignalInbox(inbox.path),
        lambda: accept(inbox, event="event-2"),
    ):
        with pytest.raises(InboxUnavailable):
            operation()


def test_table_can_share_session_database_without_touching_journal(tmp_path):
    path = tmp_path / "shared.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE journal (seq INTEGER PRIMARY KEY,payload TEXT)")
        connection.execute("INSERT INTO journal VALUES (1,'session state')")
    inbox = SignalInbox(path)
    accept(inbox)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT * FROM journal").fetchall() == [(1, "session state")]


def test_insertion_failure_rolls_back_and_allows_recovery(inbox):
    with sqlite3.connect(inbox.path) as connection:
        connection.execute("CREATE TRIGGER reject_signal BEFORE INSERT ON signal_inbox "
                           "BEGIN SELECT RAISE(ABORT,'disk unavailable'); END")
    with pytest.raises(InboxUnavailable):
        accept(inbox)
    with sqlite3.connect(inbox.path) as connection:
        connection.execute("DROP TRIGGER reject_signal")
    assert accept(inbox)["duplicate"] is False


def test_malformed_input_and_exception_details_are_not_accepted(inbox):
    with pytest.raises(ValueError):
        accept(inbox, now=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        accept(inbox, payload={"invalid": float("nan")})
    accept(inbox)
    item = inbox.claim(now=NOW)
    with pytest.raises(ValueError):
        inbox.fail("tenant-a", "event-1", item["lease_token"], "secret details here", NOW)
    assert inbox.get("tenant-a", "event-1")["state"] == "processing"


def test_metrics_measure_retained_acceptance_to_completion_per_tenant(inbox):
    accept(inbox)
    accept(inbox, event="event-2", now=NOW + timedelta(seconds=2))
    accept(inbox, tenant="tenant-b")
    first = inbox.claim(now=NOW)
    inbox.complete("tenant-a", "event-1", first["lease_token"], {},
                   NOW + timedelta(seconds=4))
    metrics = inbox.metrics("tenant-a", now=NOW + timedelta(seconds=6))
    assert metrics["total"] == 2
    assert metrics["oldest_pending_age_seconds"] == 4
    assert metrics["oldest_processing_age_seconds"] is None
    assert metrics["completion_latency_samples"] == 1
    assert metrics["mean_completion_latency_seconds"] == 4
    assert metrics["max_completion_latency_seconds"] == 4
    empty = inbox.metrics("tenant-c", now=NOW)
    assert empty["mean_completion_latency_seconds"] is None
    assert empty["completion_latency_samples"] == 0


def test_concurrent_accept_obeys_global_capacity(inbox):
    bounded = SignalInbox(inbox.path, max_pending=3)

    def submit(number):
        try:
            accept(bounded, event=f"event-{number}")
            return True
        except InboxFull:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(submit, range(16)))
    assert sum(admitted) == 3
    assert bounded.metrics("tenant-a")["pending"] == 3


def test_integrity_reports_corruption_without_disclosing_signal_or_tenant(inbox):
    accept(inbox)
    assert inbox.integrity() == {
        "ok": True, "backend": "sqlite", "mode": "local", "verified_records": 1,
    }
    with sqlite3.connect(inbox.path) as connection:
        connection.execute("UPDATE signal_inbox SET payload='{}'")
    assert inbox.integrity() == {"ok": False, "backend": "sqlite", "mode": "local"}


def test_exhausted_delivery_can_reconcile_ack_without_another_policy_attempt(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_attempts=1, lease_seconds=1)
    accept(inbox)
    first = inbox.claim(now=NOW, reconcile_exhausted=True)
    assert first["reconcile_only"] is False
    assert inbox.claim(now=NOW, reconcile_exhausted=True) is None
    second = inbox.claim(now=NOW + timedelta(seconds=1), reconcile_exhausted=True)
    assert second["reconcile_only"] is True
    assert second["attempts"] == first["attempts"] == 1
    assert second["lease_token"] != first["lease_token"]
    with pytest.raises(InboxLeaseLost):
        inbox.complete("tenant-a", "event-1", first["lease_token"], {},
                       NOW + timedelta(seconds=1))
    result = inbox.complete("tenant-a", "event-1", second["lease_token"],
                            {"duplicate": True}, NOW + timedelta(seconds=1))
    assert result["state"] == "completed" and result["attempts"] == 1
    assert inbox.claim(now=NOW + timedelta(days=1), reconcile_exhausted=True) is None


def test_exhausted_reconciliation_without_effects_can_fail_terminally(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_attempts=1, lease_seconds=1)
    accept(inbox)
    inbox.claim(now=NOW)
    final = inbox.claim(now=NOW + timedelta(seconds=1), reconcile_exhausted=True)
    result = inbox.fail("tenant-a", "event-1", final["lease_token"],
                        "PROCESSING_EXHAUSTED", NOW + timedelta(seconds=1))
    assert result["state"] == "failed"
    assert result["last_error"] == "PROCESSING_EXHAUSTED"
    assert result["attempts"] == 1
    assert inbox.claim(now=NOW + timedelta(days=1), reconcile_exhausted=True) is None


def test_reconciliation_crash_can_retry_read_only_with_new_fence(tmp_path):
    inbox = SignalInbox(tmp_path / "inbox.sqlite3", max_attempts=1, lease_seconds=1)
    accept(inbox)
    inbox.claim(now=NOW)
    old = inbox.claim(now=NOW + timedelta(seconds=1), reconcile_exhausted=True)
    reopened = SignalInbox(inbox.path, max_attempts=1, lease_seconds=1)
    new = reopened.claim(now=NOW + timedelta(seconds=2), reconcile_exhausted=True)
    assert new["reconcile_only"] and new["attempts"] == 1
    assert new["lease_token"] != old["lease_token"]
    with pytest.raises(InboxLeaseLost):
        inbox.fail("tenant-a", "event-1", old["lease_token"], "PROCESSING_EXHAUSTED",
                   NOW + timedelta(seconds=2))
    reopened.complete("tenant-a", "event-1", new["lease_token"], {},
                      NOW + timedelta(seconds=2))
