"""Per-service ephemeral monitoring material, extending the existing single lab CA."""

import hashlib
import secrets
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SERVERS = ("reader", "exporter", "prometheus", "alertmanager", "sink")
CLIENTS = ("metrics-reader", "scrape-agent", "monitor-alert", "alert-manager", "monitor-query",
           "am-control", "sink-auditor", "scrape-control")


def outgoing(client, server):
    return {"ca_file": "/tls/ca.pem", "cert_file": f"/tls/{client}.pem", "key_file": f"/tls/{client}.key",
            "server_name": server, "min_version": "TLS12", "insecure_skip_verify": False}


def web(server, clients):
    return {"tls_server_config": {"cert_file": f"/tls/{server}.pem", "key_file": f"/tls/{server}.key",
        "client_auth_type": "RequireAndVerifyClientCert", "client_ca_file": "/tls/ca.pem",
        "client_allowed_sans": clients, "min_version": "TLS12"}, "http_server_config": {"http2": False}}


def configurations():
    prom = {"global": {"scrape_interval": "1s", "scrape_timeout": "800ms", "evaluation_interval": "1s"},
        "scrape_configs": [{"job_name": "zt-signals", "scheme": "https", "metrics_path": "/metrics",
            "authorization": {"type": "Bearer", "credentials_file": "/tls/scrape.token"},
            "tls_config": outgoing("scrape-agent", "exporter"),
            "static_configs": [{"targets": ["exporter:9101"]}]}],
        "rule_files": ["/tls/alerts.yaml"], "alerting": {"alertmanagers": [{"scheme": "https",
            "tls_config": outgoing("monitor-alert", "alertmanager"),
            "static_configs": [{"targets": ["alertmanager:9093"]}]}]}}
    am = {"route": {"receiver": "local", "group_by": ["alertname"], "group_wait": "0s",
                    "group_interval": "1s", "repeat_interval": "1h"},
        "receivers": [{"name": "local", "webhook_configs": [{"url": "https://sink:9001/events",
            "send_resolved": True, "http_config": {"tls_config": outgoing("alert-manager", "sink"),
                "authorization": {"type": "Bearer", "credentials_file": "/tls/notify.token"}}}]}]}
    return {"prometheus-tls": {"config.yml": yaml.safe_dump(prom),
                "web.yml": yaml.safe_dump(web("prometheus", ["monitor-query"])),
                "alerts.yaml": (ROOT / "infra/observability/alerts.yaml").read_text(encoding="utf-8")},
            "alertmanager-tls": {"config.yml": yaml.safe_dump(am),
                "web.yml": yaml.safe_dump(web("alertmanager", ["monitor-alert", "am-control"]))}}


def assets(server, client, credentials):
    viewer, scrape, notify = [secrets.token_urlsafe(32) for _ in range(3)]
    config = configurations()
    return {
        "reader-tls": server("server.json", "reader", {"metrics-reader": "metrics-reader"}),
        "reader-auth": {"api-key.sha256": hashlib.sha256(viewer.encode()).hexdigest()},
        "exporter-tls": server("server.json", "exporter", {
            "scrape-agent": "scrape-agent", "scrape-control": "scrape-agent"})
            | client("reader.json", "metrics-reader", "reader", "reader", 8000),
        "exporter-auth": {"api-key.txt": viewer, "scrape.token": scrape},
        "prometheus-tls": credentials("prometheus", "scrape-agent", "monitor-alert")
            | config["prometheus-tls"] | {"scrape.token": scrape},
        "alertmanager-tls": credentials("alertmanager", "alert-manager")
            | config["alertmanager-tls"] | {"notify.token": notify},
        "sink-tls": server("server.json", "sink", {"alert-manager": "alert-manager", "sink-auditor": "sink-auditor"})
            | {"notify.token": notify},
        "monitor-operator-tls": client("prometheus.json", "monitor-query", "prometheus", "prometheus", 9090)
            | client("alertmanager.json", "am-control", "alertmanager", "alertmanager", 9093)
            | client("exporter.json", "scrape-control", "exporter", "exporter", 9101)
            | client("sink.json", "sink-auditor", "sink", "sink", 9001),
    }
