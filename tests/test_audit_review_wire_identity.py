"""Review-only changes cannot replace immutable JSON booleans with numbers."""

import asyncio
import sqlite3
from datetime import timedelta

import pytest
from test_sqlite_audit import initial, review

from app.services.audit import AuditStore, _record_hash
from app.services.federated_audit import AuditQueryUnavailable, FederatedAuditStore
from app.services.sqlite_audit import AuditReviewConflict, SQLiteAuditStore


def pair(old_value, new_value):
    first = initial(1).model_copy(update={"llm_trace": {"evidence_reads": old_value}})
    changed = review(first).model_copy(
        update={
            "llm_trace": {"evidence_reads": new_value},
            "review_updated_at": first.analyzed_at + timedelta(seconds=1),
        }
    )
    return first, changed


@pytest.mark.parametrize("old_value,new_value", [(1, True), (False, 0)])
def test_review_writer_rejects_type_changes_to_immutable_trace(tmp_path, old_value, new_value):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first, changed = pair(old_value, new_value)
    asyncio.run(store.save(first))
    before = store.path.read_bytes()
    with pytest.raises(AuditReviewConflict):
        asyncio.run(store.save_review(changed, first))
    assert store.path.read_bytes() == before


@pytest.mark.parametrize("old_value,new_value", [(1, True), (False, 0)])
def test_validly_rehashed_sqlite_review_cannot_change_immutable_trace(
    tmp_path, old_value, new_value
):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first, changed = pair(old_value, new_value)
    asyncio.run(store.save(first))
    payload = changed.model_dump_json()
    with sqlite3.connect(store.path) as con:
        seq, previous = con.execute("SELECT seq,digest FROM audit_head").fetchone()
        digest = _record_hash(previous, payload)
        con.execute(
            "INSERT INTO audit_entries VALUES (?,?,?,?)", (seq + 1, previous, digest, payload)
        )
        con.execute("UPDATE audit_head SET seq=?,digest=?", (seq + 1, digest))
    assert store.integrity()["ok"] is False


@pytest.mark.parametrize("old_value,new_value", [(1, True), (False, 0)])
def test_jsonl_review_revalidation_rejects_immutable_type_changes(tmp_path, old_value, new_value):
    store = AuditStore(tmp_path / "audit.jsonl")
    first, changed = pair(old_value, new_value)
    asyncio.run(store.save(first))
    asyncio.run(store.save(changed))
    assert store.writer_integrity()["ok"] is False


@pytest.mark.parametrize("old_value,new_value", [(1, True), (False, 0)])
def test_federation_cannot_merge_type_changed_trace_as_same_analysis(
    tmp_path, old_value, new_value
):
    base = tmp_path / "audit.jsonl"
    one = FederatedAuditStore(tmp_path / "audit.worker-one.jsonl", base)
    two = FederatedAuditStore(tmp_path / "audit.worker-two.jsonl", base)
    first, changed = pair(old_value, new_value)
    asyncio.run(one.save(first))
    asyncio.run(two.save(changed))
    with pytest.raises(AuditQueryUnavailable):
        one.recent()


@pytest.mark.parametrize("old_value,new_value", [(1, True), (False, 0)])
def test_sqlite_cannot_treat_type_changed_resubmission_as_idempotent(
    tmp_path, old_value, new_value
):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first, _ = pair(old_value, new_value)
    asyncio.run(store.save(first))
    changed = first.model_copy(update={"llm_trace": {"evidence_reads": new_value}})
    with pytest.raises(AuditReviewConflict):
        asyncio.run(store.save(changed))
    assert store.integrity()["verified_lines"] == 1


def test_sqlite_expected_review_version_uses_json_types_not_python_equality(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first, _ = pair(1, True)
    asyncio.run(store.save(first))
    expected = first.model_copy(update={"llm_trace": {"evidence_reads": True}})
    updated = review(first).model_copy(
        update={
            "review_updated_at": first.analyzed_at + timedelta(seconds=1),
        }
    )
    with pytest.raises(AuditReviewConflict):
        asyncio.run(store.save_review(updated, expected))
    assert store.integrity()["verified_lines"] == 1


def test_equivalent_serialized_trace_keeps_idempotence_and_legitimate_review(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1).model_copy(update={"llm_trace": {"tools": ("a",), "counts": {1: 2}}})
    asyncio.run(store.save(first))
    asyncio.run(store.save(first))
    updated = review(first).model_copy(
        update={
            "review_updated_at": first.analyzed_at + timedelta(seconds=1),
        }
    )
    asyncio.run(store.save_review(updated, first))
    assert store.integrity()["verified_lines"] == 2
    assert store.get(first.event_id).review_note == updated.review_note
