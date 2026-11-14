"""Read-only signed observation freshness with a bounded local monitor ledger."""

import argparse
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from scripts.f1_lab.collector_freshness import CollectorMonitor, CollectorScope
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "tenant",
        "server",
        "unit",
        "source",
        "key-id",
        "capture",
        "registry",
        "registry-sha256",
        "ledger",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        scope = CollectorScope(
            tenant_id=args.tenant,
            server_id=args.server,
            unit=args.unit,
            source_id=args.source,
            key_id=args.key_id,
        )
        monitor = CollectorMonitor(
            scope, PinnedServiceRegistry(args.registry, args.registry_sha256), Path(args.ledger)
        )
        result = monitor.check(Path(args.capture))
        body = asdict(result)
        if body["observed_at"] is not None:
            body["observed_at"] = body["observed_at"].isoformat()
        body.update(
            scope="signed_collector_observation_freshness",
            authorization_checked=False,
            automatic_enforcement_allowed=False,
        )
    except (ValueError, OSError, sqlite3.Error):
        body = {
            "state": "unavailable",
            "reason": "monitor_configuration_or_storage_unavailable",
            "authorization_checked": False,
            "automatic_enforcement_allowed": False,
        }
    print(json.dumps(body))
    return 0 if body["state"] == "fresh" else 2


if __name__ == "__main__":
    raise SystemExit(main())
