"""Owned real-systemd capture pipeline measurement with generated fixture keys."""

import argparse
import json
from pathlib import Path

from scripts.run_systemd_collector_runtime import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--seconds", type=int, default=180)
    args = parser.parse_args()
    result = run(
        args.directory,
        freshness=True,
        archival=True,
        scheduling=True,
        reporting=True,
        backups=True,
        load_seconds=args.seconds,
    )
    print(json.dumps({"completed": result["completed"], "cases": len(result["cases"])}))


if __name__ == "__main__":
    main()
