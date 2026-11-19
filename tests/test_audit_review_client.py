"""Operator intent stays tied to the observed result, origin and caller."""

import io
import json
import os
from email.message import Message
from http.client import IncompleteRead
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest
from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from scripts.audit_review_client import (
    AuditReviewClient,
    ReviewClientError,
    base_url,
    decode,
    load_snapshot,
    save_snapshot,
)


class AppOpener:
    def __init__(self, api):
        self.api = api
        self.calls = []
        self.transform = lambda response: response

    def open(self, request, timeout):
        headers = dict(request.header_items())
        self.calls.append((request.get_method(), request.full_url, headers.get("If-match")))
        response = self.api.client.request(
            request.get_method(), request.full_url, headers=headers, content=request.data
        )
        response = self.transform(response)
        parsed = Message()
        for key, value in response.headers.multi_items():
            parsed.add_header(key, value)
        body = io.BytesIO(response.content)
        if response.status_code != 200:
            raise HTTPError(request.full_url, response.status_code, "Not successful", parsed, body)
        body.status = 200
        body.headers = parsed
        return body


@pytest.fixture
def operator(api):
    client = AuditReviewClient("http://127.0.0.1:9999", api.headers["X-API-Key"])
    opener = AppOpener(api)
    client._opener = opener
    return SimpleNamespace(client=client, opener=opener, api=api)


def snapshot(operator):
    return operator.client.prepare("audit-cancel-1")


def test_snapshot_keeps_exact_result_and_identity_without_credentials(operator, tmp_path):
    observed = snapshot(operator)
    path = tmp_path / "observed.json"
    save_snapshot(path, observed)
    assert load_snapshot(path) == observed
    assert observed["identity"] == {
        "subject": "local-auditor",
        "tenant_id": "local",
        "auth_method": "api_key",
    }
    assert operator.api.headers["X-API-Key"] not in path.read_text(encoding="utf-8")
    assert len(operator.opener.calls) == 3 and all(
        method == "GET" for method, _, _ in operator.opener.calls
    )
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_strict_server_accepts_only_observed_intent_and_server_reviewer(operator):
    main.settings.audit_review_require_if_match = True
    observed = snapshot(operator)
    updated = operator.client.review(observed, "IN_REVIEW", "Verified current evidence")
    assert updated.reviewer == "local-auditor"
    assert updated.review_status.value == "IN_REVIEW"
    assert operator.opener.calls[-1] == (
        "PATCH",
        "http://127.0.0.1:9999/results/audit-cancel-1/review",
        observed["etag"],
    )


def test_stale_review_is_not_refetched_or_retried(operator):
    observed = snapshot(operator)
    response = operator.api.client.patch(
        "/results/audit-cancel-1/review",
        headers=operator.api.headers,
        json={"status": "IN_REVIEW", "note": "Another operator reviewed"},
    )
    assert response.status_code == 200
    before = operator.api.store.integrity()["verified_lines"]
    calls = len(operator.opener.calls)
    with pytest.raises(ReviewClientError, match="HTTP 412"):
        operator.client.review(observed, "RESOLVED", "An outdated screen must not win")
    assert [v[0] for v in operator.opener.calls[calls:]] == ["GET", "PATCH"]
    assert operator.api.store.integrity()["verified_lines"] == before


def test_successful_snapshot_cannot_be_replayed(operator):
    observed = snapshot(operator)
    operator.client.review(observed, "IN_REVIEW", "First deliberate review")
    with pytest.raises(ReviewClientError, match="HTTP 412"):
        operator.client.review(observed, "IN_REVIEW", "Attempted replay review")


def test_identity_change_during_prepare_cannot_issue_a_snapshot(operator):
    def change(response):
        if "/results/" in str(response.url):
            main.settings.api_key_subject = "changed-during-read"
        return response

    operator.opener.transform = change
    with pytest.raises(ReviewClientError, match="identity changed"):
        snapshot(operator)


def test_duplicate_etag_headers_cannot_issue_a_snapshot(operator):
    def duplicate(response):
        if "/results/" in str(response.url):
            response.headers = type(response.headers)(
                [*response.headers.multi_items(), ("etag", response.headers["etag"])]
            )
        return response

    operator.opener.transform = duplicate
    with pytest.raises(ReviewClientError, match="One strong"):
        snapshot(operator)


@pytest.mark.parametrize("failure_kind", ["network", "short-http-body"])
def test_lost_response_after_commit_never_retries_or_erases_history(operator, failure_kind):
    observed = snapshot(operator)

    def lose(response):
        if response.request.method == "PATCH":
            if failure_kind == "short-http-body":
                raise IncompleteRead(operator.api.headers["X-API-Key"].encode(), 100)
            raise URLError(operator.api.headers["X-API-Key"])
        return response

    operator.opener.transform = lose
    with pytest.raises(ReviewClientError, match="not retried") as failure:
        operator.client.review(observed, "IN_REVIEW", "Committed before response loss")
    assert operator.api.headers["X-API-Key"] not in str(failure.value)
    assert operator.api.store.integrity()["verified_lines"] == 3
    assert sum(v[0] == "PATCH" for v in operator.opener.calls) == 1
    operator.opener.transform = lambda response: response
    with pytest.raises(ReviewClientError, match="HTTP 412"):
        operator.client.review(observed, "IN_REVIEW", "Committed before response loss")
    assert operator.api.store.integrity()["verified_lines"] == 3


def test_success_body_with_a_different_review_note_is_not_reported_as_intended_success(operator):
    observed = snapshot(operator)

    def change(response):
        if response.request.method == "PATCH":
            altered = response.json()
            altered["review_note"] = "Different from submitted intent"
            response._content = json.dumps(altered).encode()
        return response

    operator.opener.transform = change
    with pytest.raises(ReviewClientError, match="submitted intent"):
        operator.client.review(observed, "IN_REVIEW", "Operator selected this note")
    assert operator.api.store.get("audit-cancel-1").review_note == "Operator selected this note"


@pytest.mark.parametrize(
    "field,value", [("api_key_subject", "another-operator"), ("api_key_tenant_id", "other")]
)
def test_changed_caller_or_tenant_never_submits_snapshot(operator, field, value):
    observed = snapshot(operator)
    setattr(main.settings, field, value)
    before = len(operator.opener.calls)
    with pytest.raises(ReviewClientError, match="caller"):
        operator.client.review(observed, "IN_REVIEW", "Do not send under another identity")
    assert [v[0] for v in operator.opener.calls[before:]] == ["GET"]


def test_withdrawn_key_is_not_used_for_a_review(operator):
    observed = snapshot(operator)
    operator.api.withdraw()
    before = len(operator.opener.calls)
    with pytest.raises(ReviewClientError, match="HTTP 401"):
        operator.client.review(observed, "IN_REVIEW", "Withdrawn caller must stop")
    assert [v[0] for v in operator.opener.calls[before:]] == ["GET"]


@pytest.mark.parametrize("mutation", ["origin", "record", "tag", "extra", "identity"])
def test_tampered_snapshot_is_rejected_before_network(operator, mutation):
    observed = snapshot(operator)
    if mutation == "origin":
        observed["base_url"] = "https://untrusted.example.test"
    elif mutation == "record":
        observed["result"]["assessment"]["rationale"] = "Edited local explanation"
    elif mutation == "tag":
        observed["etag"] = "*"
    elif mutation == "extra":
        observed["unexpected"] = True
    else:
        observed["identity"]["tenant_id"] = "other"
    calls = len(operator.opener.calls)
    with pytest.raises(ReviewClientError):
        operator.client.review(observed, "IN_REVIEW", "Check original intent first")
    assert len(operator.opener.calls) == calls


@pytest.mark.parametrize("etag", [None, "*", 'W/"weak"', '"r1-' + "0" * 64 + '"'])
def test_missing_weak_or_wrong_response_etag_cannot_create_snapshot(operator, etag):
    def change(response):
        if "/results/" in str(response.url):
            response.headers.pop("etag", None)
            if etag is not None:
                response.headers["etag"] = etag
        return response

    operator.opener.transform = change
    with pytest.raises(ReviewClientError):
        snapshot(operator)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test",
        "https://user:secret@example.test",
        "https://example.test/path",
        "https://example.test?q=secret",
        "https://example.test#part",
        "https://example.test\n",
        "file:///etc/passwd",
        "http://127.0.0.1.evil.test",
        "https://example.test:99999",
    ],
)
def test_invalid_or_insecure_origin_is_rejected(url):
    with pytest.raises((ReviewClientError, ValueError)):
        base_url(url)


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:1234", "http://[::1]:1234", "http://localhost:1234", "https://example.test"],
)
def test_explicit_supported_origins(url):
    assert base_url(url + "/") == url


@pytest.mark.parametrize(
    "raw", [b'{"status":1,"status":2}', b'{"value":NaN}', b'{"value":Infinity}']
)
def test_ambiguous_snapshot_json_is_rejected(raw):
    with pytest.raises(ReviewClientError):
        decode(raw)


def test_snapshot_save_never_overwrites_existing_file(operator, tmp_path):
    path = tmp_path / "existing.json"
    path.write_bytes(b"preserved")
    with pytest.raises(FileExistsError):
        save_snapshot(path, snapshot(operator))
    assert path.read_bytes() == b"preserved"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink/FIFO file contract")
def test_snapshot_symlink_and_fifo_are_rejected_without_read(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"private")
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises(ReviewClientError):
        load_snapshot(link)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ReviewClientError, match="regular"):
        load_snapshot(fifo)
