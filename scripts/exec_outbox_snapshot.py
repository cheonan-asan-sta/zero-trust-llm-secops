"""Create a private full sealed-outbox mirror for existing encrypted backups."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.exec_outbox import snapshot_outbox


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tenant", "server", "unit", "source"):
        parser.add_argument("--" + name, required=True)
    for name in ("root", "outbox", "mirror"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    scope = ArchiveScope(
        tenant_id=args.tenant, server_id=args.server, unit=args.unit, source_id=args.source
    )
    print(json.dumps(snapshot_outbox(args.outbox, args.root, scope, args.mirror)))


if __name__ == "__main__":
    main()
