"""Read-only, authenticated aggregate exporter for the existing tenant inbox API.

Does not import the application, read its database, or grant/revoke permissions.
Use a viewer credential and a separate scrape token. HTTP is for isolated local labs;
production transport, credentials and endpoint protection need separate validation.
"""

import argparse
import hmac
import json
import math
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

STATES = ("pending", "processing", "completed", "failed")
MAX_BODY = 65536


def validate_upstream(url):
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path != "/zero-trust/signals/inbox"):
        raise ValueError("invalid_fixed_inbox_url")
    return url


def render_summary(summary):
    if not isinstance(summary, dict):
        raise TypeError("invalid_summary")
    counts = []
    for state in STATES:
        value = summary.get(state)
        if type(value) is not int or not 0 <= value <= 100000:
            raise ValueError("invalid_count")
        counts.append(value)
    if (type(summary.get("total")) is not int or not 0 <= summary["total"] <= 100000
            or sum(counts) != summary["total"]):
        raise ValueError("inconsistent_total")
    rows = ["# TYPE secops_signal_inbox_records gauge"]
    rows += [f'secops_signal_inbox_records{{state="{state}"}} {value}'
             for state, value in zip(STATES, counts, strict=True)]
    for state in ("pending", "processing"):
        value = summary.get("oldest_" + state + "_age_seconds")
        if value is None and summary[state] == 0:
            value = 0
        if (type(value) not in {int, float} or not math.isfinite(value) or value < 0
                or (summary[state] > 0 and value is None)):
            raise ValueError("invalid_age")
        name = f"secops_signal_inbox_oldest_{state}_age_seconds"
        rows += [f"# TYPE {name} gauge", f"{name} {value}"]
    return "\n".join(rows) + "\n"


def authorized(header, token):
    if not isinstance(header, str) or len(header) > 512:
        return False
    return hmac.compare_digest(header.encode("utf-8"), ("Bearer " + token).encode("utf-8"))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_summary(url, key, *, timeout=.5):
    request = Request(validate_upstream(url), headers={"X-API-Key": key, "Accept": "application/json"})
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise ValueError("upstream_response_too_large")
    return render_summary(json.loads(raw))


def metrics(url, key, fetch=fetch_summary):
    try:
        result = fetch(url, key)
    except (OSError, ValueError, TypeError):
        # No stale queue values and no server payload/URL/credential in the error surface.
        return "# TYPE secops_signal_collection_success gauge\nsecops_signal_collection_success 0\n"
    return ("# TYPE secops_signal_collection_success gauge\nsecops_signal_collection_success 1\n"
            + result)


def handler(url, key, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if not authorized(self.headers.get("Authorization"), token):
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path != "/metrics":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = metrics(url, key).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9101)
    args = parser.parse_args()
    token = args.token_file.read_text(encoding="utf-8").strip()
    key = os.environ.get("C01_UPSTREAM_API_KEY", "")
    if not 32 <= len(token) <= 128 or not key:
        raise ValueError("credentials_required")
    server = ThreadingHTTPServer((args.listen, args.port), handler(validate_upstream(args.upstream), key, token))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
