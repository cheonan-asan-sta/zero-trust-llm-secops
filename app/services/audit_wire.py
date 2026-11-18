"""Strict JSON value equality for a persisted analysis response contract."""

import json

MUTABLE_REVIEW = {"review_status", "reviewer", "review_note", "review_updated_at"}


def analysis_wire(record, *, exclude=None):
    return json.dumps(
        record.model_dump(mode="json", exclude=exclude),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def analysis_core_wire(record):
    return analysis_wire(record, exclude=MUTABLE_REVIEW)
