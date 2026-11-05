"""Container-only wrappers and trusted local probes; never print credentials."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlencode

from scripts import mtls_transport as tls
from scripts.continuous_mtls_assets import _credential


def service(role):
    if os.environ.get("APP_ENVIRONMENT", "local") not in {"local", "test"}:
        raise ValueError("monitoring_local_test_only")
    os.environ["ANALYZER_MODE"] = "rule"
    if role == "reader":
        os.environ.update(AUTH_MODE="api_key", API_KEY_SHA256=_credential("api-key.sha256", digest=True),
                          API_KEY_SUBJECT="monitor-reader", API_KEY_TENANT_ID="local", API_KEY_ROLES="viewer")
        argv = ["-m", "scripts.mtls_native", "api", "--profile", "/tls/server.json"]
    elif role == "exporter":
        os.environ["C01_UPSTREAM_API_KEY"] = _credential("api-key.txt")
        argv = ["-m", "scripts.signal_metrics_exporter", "--upstream", "https://reader:8000/zero-trust/signals/inbox",
                "--token-file", "/auth/scrape.token", "--listen", "0.0.0.0", "--server-tls-profile", "/tls/server.json",
                "--upstream-tls-profile", "/tls/reader.json"]
    else:
        raise ValueError("monitoring_role")
    os.execv(sys.executable, [sys.executable, *argv])


def probe(data):
    name = data.get("profile")
    if name not in {"prometheus", "alertmanager", "exporter", "sink"}:
        raise ValueError("monitoring_probe_profile")
    path = data.get("path", "/metrics")
    if not isinstance(path, str) or not path.startswith("/") or any(c in path for c in "\r\n") or len(path) > 4096:
        raise ValueError("monitoring_probe_path")
    if name == "prometheus" and "query" in data:
        path = "/api/v1/query?" + urlencode({"query": data["query"]} | ({"time": data["time"]} if "time" in data else {}))
    headers = data.get("headers", {})
    if not isinstance(headers, dict):
        raise TypeError("monitoring_probe_headers")
    observed = {}
    status, raw = tls.request(Path("/monitor-tls") / (name + ".json"), path, data.get("body"), headers,
                              method=data.get("method", "GET"), observed=observed)
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeError):
        body = raw.decode("utf-8", errors="replace")
    return {"status": status, "body": body, "body_sha256": hashlib.sha256(raw).hexdigest(),
            "tls_version": observed.get("tls_version")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("service", "probe"))
    parser.add_argument("role", nargs="?")
    args = parser.parse_args()
    if args.mode == "service":
        service(args.role)
    else:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError("monitoring_probe_size")
        print(json.dumps(probe(json.loads(raw))))


if __name__ == "__main__":
    main()
