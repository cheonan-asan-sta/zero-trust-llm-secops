"""Representation preconditions for opt-in transactional human review clients."""

import hashlib
import hmac
import json
import re

from fastapi import HTTPException

from app.services.audit_wire import analysis_wire

_STRONG_REVIEW_TAG = re.compile(r'"r1-[a-f0-9]{64}"')
_REVIEW_IDENTITY = re.compile(r"[a-f0-9]{64}")


def review_identity(principal):
    """Intent binding, not an authentication token or proof of human reading."""
    payload = json.dumps(
        [principal.tenant_id, principal.subject, principal.auth_method],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(b"zero-trust-review-caller-v1\x00" + payload).hexdigest()


def parse_review_identity(values):
    if not values:
        return None
    if len(values) != 1 or _REVIEW_IDENTITY.fullmatch(values[0]) is None:
        raise HTTPException(400, "Provide one review caller binding")
    return values[0]


def require_review_identity(principal, expected, tag, *, required=False):
    if required and (expected is None or tag is None):
        raise HTTPException(428, "Read the result and provide its review ETag and caller binding")
    if expected is None:
        return
    if tag is None:
        raise HTTPException(400, "Caller-bound review requires an explicit review ETag")
    if principal.auth_method not in {"api_key", "oidc"} or not hmac.compare_digest(
        expected, review_identity(principal)
    ):
        raise HTTPException(
            403, "Review caller changed; read the result under the current identity"
        )


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
