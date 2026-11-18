"""Strict JSON value equality for a persisted analysis response contract."""

import json


def analysis_wire(record):
    return json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
