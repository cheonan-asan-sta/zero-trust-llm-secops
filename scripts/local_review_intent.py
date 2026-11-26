"""Reuse operator snapshot checks in owned synchronous local HTTP harnesses.

The supplied transport and credentials belong to the caller. No credential is
persisted and no failed write is retried or downgraded to an unbound review.
"""

import ipaddress
from email.message import Message
from urllib.parse import urlsplit

from scripts.audit_review_client import AuditReviewClient, decode, require


class LocalReviewClient(AuditReviewClient):
    def __init__(self, client, headers):
        self.url = str(client.base_url).rstrip("/")
        origin = urlsplit(self.url)
        try:
            local = ipaddress.ip_address(origin.hostname).is_loopback
        except ValueError:
            local = origin.hostname in {"localhost", "testserver"}
        require(local and origin.scheme == "http", "Owned local HTTP transport required")
        self.client = client
        self.headers = dict(headers)
        self.last_response = None

    def _request(self, method, path, payload=None, *, etag=None, caller_binding=None):
        headers = dict(self.headers)
        if etag is not None:
            headers["If-Match"] = etag
        if caller_binding is not None:
            headers["X-Review-Identity"] = caller_binding
        response = self.client.request(
            method, path, headers=headers, json=payload, follow_redirects=False
        )
        self.last_response = response
        require(
            response.status_code == 200, f"HTTP {response.status_code}; request was not retried"
        )
        metadata = Message()
        for key, value in response.headers.multi_items():
            metadata[key] = value
        return decode(response.content), metadata


def review_observed(client, headers, expected, *, status, note):
    """A harness inspects its expected record before submitting bound intent."""
    operator = LocalReviewClient(client, headers)
    snapshot = operator.prepare(expected["event_id"])
    require(snapshot["result"] == expected, "Observed record changed; inspect before reviewing")
    operator.review(snapshot, status, note)
    return operator.last_response
