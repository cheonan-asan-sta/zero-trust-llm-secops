"""Compact validation must reject every malformed row and preserve review semantics."""

import asyncio
import json
from datetime import timedelta

import pytest
from test_sqlite_audit import initial, review

from app.models import ReviewStatus
from app.services.audit import _record_hash
from app.services.federated_audit import AuditQueryUnavailable
from app.services.sqlite_audit import AuditReviewConflict, SQLiteAuditStore


def later_review(original):
    return review(original).model_copy(
        update={
            "review_updated_at": (original.review_updated_at or original.analyzed_at)
            + timedelta(seconds=1),
        }
    )


def append_payload(store, payload):
    with store._transaction(write=True) as con:
        seq, parent = con.execute("SELECT seq,digest FROM audit_head WHERE id=1").fetchone()
        digest = _record_hash(parent, payload)
        con.execute(
            "INSERT INTO audit_entries VALUES (?,?,?,?)", (seq + 1, parent, digest, payload)
        )
        con.execute("UPDATE audit_head SET seq=?,digest=? WHERE id=1", (seq + 1, digest))


def summaries(store):
    values = []
    for retained in (True, False):
        with store._transaction() as con:
            entries, *head = store._read(con, retain_records=retained)
            values.append((set(entries), head))
    return values


def test_compact_scan_follows_interleaved_review_reopen_history_and_preserves_source(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first, second = initial(1), initial(2)
    resolved = later_review(first)
    reopened = resolved.model_copy(
        update={
            "review_status": ReviewStatus.IN_REVIEW,
            "review_updated_at": resolved.review_updated_at + timedelta(seconds=1),
        }
    )
    finished = later_review(reopened).model_copy(
        update={
            "review_updated_at": reopened.review_updated_at + timedelta(seconds=1),
        }
    )

    async def write():
        await store.save(first)
        await store.save(second)
        await store.save_review(resolved, first)
        await store.save_review(later_review(second), second)
        await store.save_review(reopened, resolved)
        await store.save_review(finished, reopened)

    asyncio.run(write())
    before = store.path.read_bytes()
    materialized, compact = summaries(store)
    assert materialized == compact
    assert store.integrity()["ok"] and store.integrity()["verified_lines"] == 6
    assert SQLiteAuditStore.open_existing(store.path).get(first.event_id) == finished
    assert store.path.read_bytes() == before


def test_compact_review_validation_preserves_existing_dictionary_and_numeric_equality(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1).model_copy(update={"verification_context": {"a": 1, "b": [True, "value"]}})
    asyncio.run(store.save(first))
    # JSON numbers remain numerically equal and property order is irrelevant.
    # Boolean/numeric substitution is separately rejected by the review tests.
    updated = later_review(first).model_copy(
        update={
            "verification_context": {"b": [True, "value"], "a": 1.0},
        }
    )
    asyncio.run(store.save_review(updated, first))
    assert summaries(store)[0] == summaries(store)[1]
    assert store.integrity()["ok"] and store.get(first.event_id) == updated


def test_compact_review_validation_rejects_nested_boolean_numeric_substitution(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1).model_copy(update={"verification_context": {"a": 1, "b": [True, "value"]}})
    asyncio.run(store.save(first))
    before = store.path.read_bytes()
    changed = later_review(first).model_copy(
        update={
            "verification_context": {"b": [1.0, "value"], "a": 1.0},
        }
    )
    with pytest.raises(AuditReviewConflict):
        asyncio.run(store.save_review(changed, first))
    assert store.path.read_bytes() == before and store.integrity()["verified_lines"] == 1


@pytest.mark.parametrize(
    "kind",
    [
        "orphan_review",
        "immutable_review",
        "stale_review",
        "repeat_resolve",
        "bad_head",
        "bad_chain",
        "invalid_model",
        "capacity",
    ],
)
def test_compact_and_materialized_verifiers_reject_identical_corruptions(tmp_path, kind):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1)
    asyncio.run(store.save(first))
    changed = later_review(first)
    if kind == "orphan_review":
        changed = later_review(initial(9))
    elif kind == "immutable_review":
        changed = changed.model_copy(update={"actor_id": "forged-actor"})
    elif kind == "stale_review":
        changed = changed.model_copy(update={"review_updated_at": first.analyzed_at})
    elif kind == "repeat_resolve":
        asyncio.run(store.save_review(changed, first))
        changed = changed.model_copy(
            update={
                "review_updated_at": changed.review_updated_at + timedelta(seconds=1),
            }
        )
    if kind in {"orphan_review", "immutable_review", "stale_review", "repeat_resolve"}:
        append_payload(store, changed.model_dump_json())
    elif kind == "invalid_model":
        payload = json.loads(first.model_dump_json())
        payload["latency_ms"] = -1
        append_payload(store, json.dumps(payload))
    elif kind == "capacity":
        asyncio.run(store.save(initial(2)))
        store.MAX_ROWS = 1
    else:
        with store._transaction(write=True) as con:
            if kind == "bad_head":
                con.execute("UPDATE audit_head SET seq=0,digest=? WHERE id=1", ("0" * 64,))
            else:
                con.execute("UPDATE audit_entries SET digest=? WHERE seq=1", ("f" * 64,))
    before = store.path.read_bytes()
    for retained in (True, False):
        with pytest.raises(AuditQueryUnavailable), store._transaction() as con:
            store._read(con, retain_records=retained)
    assert store.integrity()["ok"] is False
    assert store.path.read_bytes() == before
