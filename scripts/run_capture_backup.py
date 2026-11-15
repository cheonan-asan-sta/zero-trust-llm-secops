"""Actual systemd encrypted cold backup, isolated restore and prior controls."""

import argparse
import json
from pathlib import Path

from scripts.run_systemd_collector_runtime import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    result = run(
        parser.parse_args().directory,
        freshness=True,
        archival=True,
        scheduling=True,
        reporting=True,
        backups=True,
    )
    print(json.dumps({"completed": result["completed"], "cases": len(result["cases"])}))


if __name__ == "__main__":
    main()
