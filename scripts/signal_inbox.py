"""Inspect or archive terminal receipts in the shared local signal inbox."""

import argparse
import json
import sys
from pathlib import Path

from app.config import get_settings
from app.services.signal_inbox import InboxFull, InboxUnavailable, SignalInbox


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["status", "compact"])
    parser.add_argument("--database", type=Path)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)
    if args.limit is not None and not 1 <= args.limit <= 10000:
        parser.error("--limit must be between 1 and 10000")
    try:
        settings = get_settings()
        if settings.app_environment not in {"local", "test"}:
            raise ValueError("signal inbox maintenance is local/test only")
        inbox = SignalInbox(
            args.database or settings.zero_trust_db_path,
            max_pending=settings.signal_inbox_max_pending,
            max_records=settings.signal_inbox_max_records,
            max_attempts=settings.signal_inbox_max_attempts,
            lease_seconds=settings.signal_inbox_lease_seconds,
            retry_seconds=settings.signal_inbox_retry_seconds,
        )
        result = inbox.storage_status() if args.operation == "status" else inbox.compact(limit=args.limit)
        print(json.dumps({"inbox": args.operation, **result}), flush=True)
        return 0
    except (InboxFull, InboxUnavailable, OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"inbox": "unavailable", "error": "CONFIG_OR_STORAGE_UNAVAILABLE"}),
              file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
