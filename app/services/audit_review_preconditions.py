"""Representation preconditions for opt-in transactional human review clients."""

import hashlib
import hmac
import re

from fastapi import HTTPException

from app.services.audit_wire import analysis_wire

_STRONG_REVIEW_TAG = re.compile(r'"r1-[a-f0-9]{64}"')


def review_etag(record):
    payload = b"zero-trust-review-v1\x00" + analysis_wire(record).encode("utf-8")
    return '"r1-' + hashlib.sha256(payload).hexdigest() + '"'


def parse_review_if_match(values):
    if not values:
        return None
    if len(values) != 1 or not isinstance(values[0], str) or len(values[0]) > 256:
        raise HTTPException(400, "Provide one explicit strong review ETag")
    tag = values[0].strip(" \t")
    if _STRONG_REVIEW_TAG.fullmatch(tag) is None:
        raise HTTPException(400, "Provide one explicit strong review ETag")
    return tag


def require_review_match(record, tag, *, required, transactional):
    if tag is None:
        if required:
            raise HTTPException(428, "Read the current result and provide its review ETag")
        return
    if not transactional:
        raise HTTPException(503, "Conditional review requires transactional SQLite audit")
    if not hmac.compare_digest(review_etag(record), tag):
        raise HTTPException(412, "Review version changed; reload the current result")
