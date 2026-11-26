"""Read a review snapshot, then explicitly submit its strong HTTP precondition.

Uses verified HTTPS (optional mTLS), or literal loopback HTTP for local tests.
Snapshots are local operator records, not independent evidence or proof of reading.
"""

import argparse
import hmac
import ipaddress
import json
import os
import re
import ssl
import stat
from datetime import UTC, datetime
from http.client import HTTPException
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from app.models import AnalysisResult, ReviewUpdateRequest
from app.services.audit_review_preconditions import review_etag, review_identity
from app.services.audit_wire import analysis_core_equal

MAX_BYTES = 2 * 1024 * 1024
SCHEMA = "operator-audit-review-snapshot-2"
TAG = re.compile(r'"r1-[a-f0-9]{64}"')
BINDING = re.compile(r"[a-f0-9]{64}")


class ReviewClientError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ReviewClientError(message)


def identity_binding(identity):
    require(
        type(identity) is dict
        and set(identity) == {"subject", "tenant_id", "auth_method"}
        and all(isinstance(value, str) and value for value in identity.values())
        and identity["auth_method"] in {"api_key", "oidc"},
        "Invalid snapshot identity",
    )
    return review_identity(SimpleNamespace(**identity))


def base_url(value):
    require(
        isinstance(value, str) and not any(ord(c) <= 32 or ord(c) == 127 for c in value),
        "Use an explicit HTTP(S) origin without whitespace",
    )
    parts = urlsplit(value)
    require(
        parts.scheme in {"https", "http"}
        and parts.hostname
        and not parts.username
        and not parts.password
        and not parts.query
        and not parts.fragment
        and parts.path in {"", "/"},
        "Use an origin without credentials, path or query",
    )
    require("%" not in parts.netloc and "\\" not in parts.netloc, "Invalid origin")
    # Evaluate the port before any request; do not resolve names to broaden HTTP.
    require(parts.port is None or 0 < parts.port < 65536, "Invalid origin port")
    if parts.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            loopback = parts.hostname.lower() == "localhost"
        require(loopback, "Plain HTTP is allowed only for literal loopback or localhost")
    return urlunsplit((parts.scheme, parts.netloc.lower(), "", "", ""))


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "Duplicate JSON field")
            value[key] = item
        return value

    def constant(_):
        raise ReviewClientError("Non-finite JSON value")

    require(len(raw) <= MAX_BYTES, "JSON exceeds local byte limit")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class AuditReviewClient:
    def __init__(
        self, url, credential, *, bearer=False, ca_file=None, cert_file=None, key_file=None
    ):
        self.url = base_url(url)
        require(
            isinstance(credential, str)
            and credential
            and not any(ord(c) <= 32 or ord(c) == 127 for c in credential),
            "Supply a non-empty credential through the selected environment variable",
        )
        require(bool(cert_file) == bool(key_file), "Supply both client certificate and key")
        require(
            self.url.startswith("https:") or not any((ca_file, cert_file, key_file)),
            "TLS configuration requires HTTPS",
        )
        context = ssl.create_default_context(cafile=ca_file)
        if cert_file:
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        self._headers = (
            {"Authorization": "Bearer " + credential} if bearer else {"X-API-Key": credential}
        )
        self._opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))

    def _request(self, method, path, payload=None, *, etag=None, caller_binding=None):
        data = None if payload is None else json.dumps(payload, allow_nan=False).encode()
        headers = self._headers | {"Accept": "application/json", "Content-Type": "application/json"}
        if etag is not None:
            require(isinstance(etag, str) and TAG.fullmatch(etag), "Invalid review ETag")
            headers["If-Match"] = etag
        if caller_binding is not None:
            require(
                isinstance(caller_binding, str) and BINDING.fullmatch(caller_binding),
                "Invalid review caller binding",
            )
            headers["X-Review-Identity"] = caller_binding
        request = Request(
            self.url + path,
            data=data,
            method=method,
            headers=headers,
        )
        try:
            with self._opener.open(request, timeout=10) as response:
                require(response.status == 200, "Unexpected success response")
                raw = response.read(MAX_BYTES + 1)
                return decode(raw), response.headers
        except HTTPError as error:
            error.close()
            raise ReviewClientError(f"HTTP {error.code}; request was not retried") from None
        except (URLError, OSError, HTTPException) as error:
            raise ReviewClientError("HTTP/TLS request failed; request was not retried") from error

    def _identity(self):
        value, _headers = self._request("GET", "/auth/me")
        require(type(value) is dict, "Invalid identity response")
        identity = {key: value.get(key) for key in ("subject", "tenant_id", "auth_method")}
        require(
            all(isinstance(v, str) and v for v in identity.values())
            and identity["auth_method"] in {"api_key", "oidc"},
            "Authenticated identity required",
        )
        return identity

    @staticmethod
    def _event(value):
        require(
            isinstance(value, str)
            and 0 < len(value) <= 256
            and value not in {".", ".."}
            and not any(ord(c) < 32 or ord(c) == 127 for c in value),
            "Invalid event identifier",
        )
        return quote(value, safe="")

    def prepare(self, event_id):
        path = "/results/" + self._event(event_id)
        identity = self._identity()
        value, headers = self._request("GET", path)
        tags = headers.get_all("ETag", [])
        require(len(tags) == 1 and TAG.fullmatch(tags[0]), "One strong review ETag is required")
        bindings = headers.get_all("X-Review-Identity", [])
        require(
            len(bindings) == 1
            and BINDING.fullmatch(bindings[0])
            and hmac.compare_digest(bindings[0], identity_binding(identity)),
            "One matching review caller binding is required",
        )
        modes = headers.get_all("X-Review-Mode", [])
        require(modes == ["conditional"], "Conditional review backend is required")
        record = AnalysisResult.model_validate(value)
        require(
            record.event_id == event_id and record.tenant_id == identity["tenant_id"],
            "Result identity does not match requested scope",
        )
        require(hmac.compare_digest(tags[0], review_etag(record)), "Result does not match its ETag")
        require(identity == self._identity(), "Caller identity changed during read")
        return {
            "schema": SCHEMA,
            "base_url": self.url,
            "identity": identity,
            "etag": tags[0],
            "review_identity": bindings[0],
            "review_mode": modes[0],
            "observed_at": datetime.now(UTC).isoformat(),
            "result": record.model_dump(mode="json"),
        }

    def review(self, snapshot, status, note):
        require(type(snapshot) is dict, "Invalid snapshot fields")
        require(
            snapshot.get("schema") == SCHEMA,
            "Unsupported snapshot version; prepare and inspect a new snapshot",
        )
        require(
            set(snapshot)
            == {
                "schema",
                "base_url",
                "identity",
                "etag",
                "observed_at",
                "result",
                "review_identity",
                "review_mode",
            },
            "Invalid snapshot fields",
        )
        require(
            snapshot["base_url"] == self.url,
            "Snapshot origin does not match the explicit target",
        )
        record = AnalysisResult.model_validate(snapshot["result"])
        tag = snapshot["etag"]
        require(
            isinstance(tag, str)
            and TAG.fullmatch(tag)
            and hmac.compare_digest(tag, review_etag(record)),
            "Snapshot result or ETag was changed",
        )
        identity = snapshot["identity"]
        binding = identity_binding(identity)
        require(
            identity["tenant_id"] == record.tenant_id,
            "Invalid snapshot identity",
        )
        require(snapshot["review_mode"] == "conditional", "Conditional review snapshot is required")
        require(
            isinstance(snapshot["review_identity"], str)
            and BINDING.fullmatch(snapshot["review_identity"])
            and hmac.compare_digest(snapshot["review_identity"], binding),
            "Snapshot caller binding was changed",
        )
        # Validate everything locally before contacting the configured service.
        require(
            status in {"IN_REVIEW", "RESOLVED", "DISMISSED"} and isinstance(note, str),
            "Choose a review transition and provide a note",
        )
        payload = ReviewUpdateRequest(status=status, note=note).model_dump(
            mode="json", exclude_none=True
        )
        path = "/results/" + self._event(record.event_id) + "/review"
        require(identity == self._identity(), "Current caller does not match snapshot identity")
        # No refetch/retry: a stale version is a conflict for the operator to review.
        result, headers = self._request("PATCH", path, payload, etag=tag, caller_binding=binding)
        updated = AnalysisResult.model_validate(result)
        require(
            updated.analysis_id == record.analysis_id
            and updated.tenant_id == record.tenant_id
            and updated.event_id == record.event_id,
            "Review response scope mismatch",
        )
        require(
            analysis_core_equal(record, updated)
            and updated.review_status.value == payload["status"]
            and updated.reviewer == identity["subject"]
            and updated.review_note == payload["note"],
            "Review response does not match submitted intent",
        )
        tags = headers.get_all("ETag", [])
        require(len(tags) == 1 and tags[0] == review_etag(updated), "Review response ETag mismatch")
        bindings = headers.get_all("X-Review-Identity", [])
        require(
            len(bindings) == 1 and bindings[0] == binding,
            "Review response caller binding mismatch; inspect current history before another review",
        )
        return updated


def save_snapshot(path, snapshot):
    raw = json.dumps(snapshot, ensure_ascii=False, allow_nan=False, indent=2).encode()
    require(len(raw) <= MAX_BYTES, "Snapshot exceeds local byte limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def load_snapshot(path):
    require(not Path(path).is_symlink(), "Snapshot symlink rejected")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Snapshot must be a regular file")
        return decode(stream.read(MAX_BYTES + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", required=True, help="Explicit target origin; never read from snapshot"
    )
    parser.add_argument("--credential-env", default="SECOPS_API_KEY")
    parser.add_argument("--bearer", action="store_true")
    parser.add_argument("--ca-file")
    parser.add_argument("--cert-file")
    parser.add_argument("--key-file")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--event-id", required=True)
    prepare.add_argument("--snapshot", required=True, type=Path)
    review = commands.add_parser("review")
    review.add_argument("--snapshot", required=True, type=Path)
    review.add_argument("--status", required=True, choices=("IN_REVIEW", "RESOLVED", "DISMISSED"))
    review.add_argument("--note", required=True)
    args = parser.parse_args()
    try:
        snapshot = load_snapshot(args.snapshot) if args.command == "review" else None
        client = AuditReviewClient(
            args.base_url,
            os.environ.get(args.credential_env),
            bearer=args.bearer,
            ca_file=args.ca_file,
            cert_file=args.cert_file,
            key_file=args.key_file,
        )
        if args.command == "prepare":
            save_snapshot(args.snapshot, client.prepare(args.event_id))
            print("Snapshot saved. Inspect it before submitting a separate review command.")
        else:
            result = client.review(snapshot, args.status, args.note)
            print(
                json.dumps(
                    {"review_status": result.review_status.value, "reviewer": result.reviewer}
                )
            )
    except ReviewClientError as error:
        parser.exit(1, f"Review operation failed: {error}.\n")
    except (OSError, ValueError, TypeError, KeyError):
        # Do not echo URLs, server bodies, credentials or TLS key locations.
        parser.exit(
            1,
            "Review operation failed; no automatic retry. Check scope, version and service availability.\n",
        )


if __name__ == "__main__":
    main()
