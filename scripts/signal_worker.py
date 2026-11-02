"""Run the local durable observation worker separately from the HTTP server."""

import argparse
import json
import signal
import sys
from threading import Event

from app.config import get_settings
from app.services.continuous_signals import ContinuousSignalService
from app.services.signal_inbox import InboxUnavailable, SignalInbox
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations


def build_service(settings) -> ContinuousSignalService:
    if settings.app_environment == "production":
        raise ValueError("Continuous signal worker is local/test only")
    operations = ZeroTrustOperations(
        settings.zero_trust_db_path,
        signal_verifier=SignalVerifier(settings.trusted_signal_sources_path),
    )
    inbox = SignalInbox(
        settings.zero_trust_db_path,
        max_pending=settings.signal_inbox_max_pending,
        max_records=settings.signal_inbox_max_records,
        max_attempts=settings.signal_inbox_max_attempts,
        lease_seconds=settings.signal_inbox_lease_seconds,
        retry_seconds=settings.signal_inbox_retry_seconds,
    )
    return ContinuousSignalService(operations, inbox)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Attempt one delivery, then exit")
    parser.add_argument("--poll-seconds", type=float, default=0.5)
    args = parser.parse_args(argv)
    if not 0.01 <= args.poll_seconds <= 60:
        parser.error("--poll-seconds must be between 0.01 and 60")
    try:
        service = build_service(get_settings())
    except (ValueError, InboxUnavailable, JournalUnavailable):
        print(json.dumps({"worker": "unavailable"}), file=sys.stderr)
        return 1
    stopped = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    while not stopped.is_set():
        try:
            receipt = service.process_one()
            if receipt:
                # Print state only, never signatures, subject IDs or grants.
                print(json.dumps({"worker": "delivery", "state": receipt["state"],
                                  "attempts": receipt["attempts"]}), flush=True)
        except InboxUnavailable:
            print(json.dumps({"worker": "storage_unavailable"}), file=sys.stderr, flush=True)
            if args.once:
                return 1
            receipt = None
        if args.once:
            return 1 if receipt and receipt["state"] == "failed" else 0
        if receipt is None or receipt["state"] != "completed":
            stopped.wait(args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
