"""Periodically restrict local signed sessions without requiring a new observation."""

import argparse
import json
import signal
import sqlite3
import sys
from threading import Event

from app.config import get_settings
from app.services.trusted_signals import SignalRegistryUnavailable, SignalVerifier
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations


def build_service(settings) -> ZeroTrustOperations:
    if settings.app_environment not in {"local", "test"}:
        raise ValueError("session watchdog is local/test only")
    return ZeroTrustOperations(
        settings.zero_trust_db_path,
        signal_verifier=SignalVerifier(settings.trusted_signal_sources_path),
    )


def _summary(result):
    summary = {name: result[name] for name in ("checked", "changed", "held", "revoked")}
    if any(type(value) is not int or value < 0 for value in summary.values()):
        raise ValueError("invalid watchdog summary")
    return summary


def _error_code(error):
    if isinstance(error, SignalRegistryUnavailable):
        return "SIGNAL_REGISTRY_UNAVAILABLE"
    if isinstance(error, JournalUnavailable):
        return "JOURNAL_UNAVAILABLE"
    return "CONFIG_OR_STORAGE_UNAVAILABLE"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Run one revalidation pass, then exit")
    parser.add_argument("--interval-seconds", type=float, default=5)
    args = parser.parse_args(argv)
    if not 0.01 <= args.interval_seconds <= 60:
        parser.error("--interval-seconds must be finite and between 0.01 and 60")
    stopped = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    failures = (SignalRegistryUnavailable, JournalUnavailable, sqlite3.Error, OSError,
                ValueError, TypeError, KeyError)
    try:
        service = build_service(get_settings())
    except failures as error:
        print(json.dumps({"watchdog": "unavailable", "error": _error_code(error)}),
              file=sys.stderr, flush=True)
        return 1
    while not stopped.is_set():
        try:
            summary = _summary(service.revalidate_sessions())
            print(json.dumps({"watchdog": "revalidated", **summary}), flush=True)
        except failures as error:
            # Codes and aggregate counts only: never emit an exception, tenant,
            # subject, certificate, signed input or grant in watchdog output.
            print(json.dumps({"watchdog": "unavailable", "error": _error_code(error)}),
                  file=sys.stderr, flush=True)
            if args.once:
                return 1
        if args.once:
            return 0
        stopped.wait(args.interval_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
