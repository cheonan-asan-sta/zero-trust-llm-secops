"""Local console maintenance of an existing behavior context database.

No HTTP route or new credentials. SQLite serializes this with existing writers.
"""

import argparse
import json
from pathlib import Path

from app.config import get_settings
from app.services.behavior_context_store import BehaviorContextStore, ContextStoreUnavailable


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "compact"))
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args(argv)
    try:
        if get_settings().app_environment not in {"local", "test"}:
            raise ValueError("context maintenance is local only")
        if args.database.is_symlink() or not args.database.is_file():
            raise ValueError("existing context database required")
        store = BehaviorContextStore(args.database)
        result = store.compact(limit=args.limit) if args.command == "compact" else {}
        print(json.dumps(result | store.storage_status()))
        return 0
    except (OSError, ValueError, ContextStoreUnavailable):
        print(json.dumps({"status": "unavailable"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
