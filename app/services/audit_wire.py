"""Typed JSON value equality and exact serialized response contracts."""

import json
import math

MUTABLE_REVIEW = {"review_status", "reviewer", "review_note", "review_updated_at"}


def analysis_wire(record, *, exclude=None):
    return json.dumps(
        record.model_dump(mode="json", exclude=exclude),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _json_value_equal(left, right):
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if left is None or right is None:
        return left is right
    if type(left) in {int, float} and type(right) in {int, float}:
        if (type(left) is float and not math.isfinite(left)) or (
            type(right) is float and not math.isfinite(right)
        ):
            return False
        return left == right
    if type(left) is str and type(right) is str:
        return left == right
    if type(left) is list and type(right) is list:
        return len(left) == len(right) and all(
            _json_value_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if type(left) is dict and type(right) is dict:
        return (
            all(type(key) is str for key in left)
            and all(type(key) is str for key in right)
            and left.keys() == right.keys()
            and all(_json_value_equal(left[key], right[key]) for key in left)
        )
    return False


def analysis_values_equal(left, right, *, exclude=None):
    # JSON has a numeric value type, distinct from boolean. Preserve legitimate
    # 1/1.0 and property-order equivalence without Python's True == 1 shortcut.
    try:
        return _json_value_equal(
            left.model_dump(mode="json", exclude=exclude),
            right.model_dump(mode="json", exclude=exclude),
        )
    except (ValueError, TypeError, RecursionError):
        return False


def analysis_core_equal(left, right):
    return analysis_values_equal(left, right, exclude=MUTABLE_REVIEW)
