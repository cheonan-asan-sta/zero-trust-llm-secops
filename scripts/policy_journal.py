"""Inspect or compact the local policy journal while preserving its complete history."""

import argparse
import json
import sys
from pathlib import Path

from app.config import get_settings
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations


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
            raise ValueError("policy journal maintenance is local/test only")
        operations = ZeroTrustOperations(args.database or settings.zero_trust_db_path)
        result = (operations.journal_status() if args.operation == "status"
                  else operations.compact_journal(limit=args.limit))
        print(json.dumps({"journal": args.operation, **result}), flush=True)
        return 0
    except (JournalUnavailable, OSError, ValueError, TypeError, KeyError):
        # Counts and a fixed error code only; no payload, token, path or exception.
        print(json.dumps({"journal": "unavailable", "error": "CONFIG_OR_STORAGE_UNAVAILABLE"}),
              file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
