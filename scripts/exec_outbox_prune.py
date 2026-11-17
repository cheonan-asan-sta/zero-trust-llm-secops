"""Preview or prune old published records backed by a pinned isolated restore."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.exec_outbox import prune_outbox


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tenant", "server", "unit", "source", "receipt-sha256", "checkpoint-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("root", "outbox", "review", "checkpoint"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--min-age-seconds", type=int, default=86400)
    parser.add_argument("--limit", type=int, default=64)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    scope = ArchiveScope(
        tenant_id=args.tenant, server_id=args.server, unit=args.unit, source_id=args.source
    )
    print(
        json.dumps(
            prune_outbox(
                args.outbox,
                args.root,
                scope,
                args.review,
                args.receipt_sha256,
                args.checkpoint,
                args.checkpoint_sha256,
                min_age_seconds=args.min_age_seconds,
                limit=args.limit,
                apply=args.apply,
            )
        )
    )


if __name__ == "__main__":
    main()
