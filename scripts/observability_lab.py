"""Local-only C01 notification receiver and bounded in-network query probe."""

import argparse
import json
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from scripts.signal_metrics_exporter import NoRedirect, authorized


def notification_seen(events, name, status, first_index, binding=None):
    """A prior startup/fault notification cannot satisfy a new fault episode."""
    if type(first_index) is not int or first_index < 0:
        raise ValueError("invalid_notification_epoch")
    return any(event["alertname"] == name and event["status"] == status
               and all(event.get(key) == value for key, value in (binding or {}).items())
               for event in events[first_index:])


def receiver(token):
    events = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def permitted(self):
            if not authorized(self.headers.get("Authorization"), token):
                self.reply(401, {})
                return False
            if self.path != "/events":
                self.reply(404, {})
                return False
            return True

        def do_GET(self):
            if self.permitted():
                with lock:
                    self.reply(200, {"events": events[:]})

        def do_POST(self):
            if not self.permitted():
                return
            length = self.headers.get("Content-Length", "")
            if not length.isdigit() or not 0 < int(length) <= 262144:
                self.reply(413, {})
                return
            try:
                payload = json.loads(self.rfile.read(int(length)))
                extracted = []
                for alert in payload["alerts"]:
                    name, status = alert["labels"]["alertname"], alert["status"]
                    if not name.startswith("C01") or len(name) > 80 or status not in {"firing", "resolved"}:
                        raise ValueError("unsupported_alert")
                    extracted.append({"alertname": name, "status": status,
                                      "instance": alert["labels"].get("instance"),
                                      "job": alert["labels"].get("job"),
                                      "fingerprint": alert["fingerprint"], "starts_at": alert["startsAt"],
                                      "received_at": datetime.now(UTC).isoformat()})
                with lock:
                    if len(events) + len(extracted) > 1000:
                        self.reply(503, {})
                        return
                    events.extend(extracted)
            except (KeyError, ValueError, TypeError):
                self.reply(400, {})
                return
            self.reply(200, {})
    return Handler


def probe():
    request = json.loads(sys.stdin.buffer.read(8192))
    parsed = urlsplit(request["url"])
    if (parsed.scheme != "http" or parsed.hostname not in {"storage", "evaluator", "am"}
            or parsed.username or parsed.password or parsed.port not in {9090, 8428, 8880, 9093}):
        raise ValueError("lab_probe_target_rejected")
    with build_opener(ProxyHandler({}), NoRedirect()).open(request["url"], timeout=3) as response:
        raw = response.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("lab_probe_body_too_large")
    print(json.dumps(json.loads(raw)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["receiver", "probe", "local-http"])
    parser.add_argument("--token-file", type=Path)
    args = parser.parse_args()
    if args.mode == "probe":
        probe()
        return
    if args.mode == "local-http":
        data = json.loads(sys.stdin.buffer.read(262145))
        if data["port"] not in {8000, 9101, 9001} or data["path"] not in {
                "/metrics", "/events", "/zero-trust/signals/inbox"}:
            raise ValueError("lab_local_target_rejected")
        request = Request(f"http://127.0.0.1:{data['port']}{data['path']}",
            headers=data.get("headers", {}),
            data=json.dumps(data["payload"]).encode() if data.get("payload") is not None else None)
        try:
            response = build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=2)
        except HTTPError as exc:
            response = exc
        with response:
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise ValueError("lab_response_too_large")
            print(json.dumps({"status": response.code, "body": raw.decode()}))
        return
    token = args.token_file.read_text(encoding="utf-8").strip()
    server = ThreadingHTTPServer(("0.0.0.0", 9001), receiver(token))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
