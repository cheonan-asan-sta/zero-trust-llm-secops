"""Real systemd lossless capture archival and freshness-preserving restoration."""

import argparse
import json
from pathlib import Path

from scripts.run_systemd_collector_runtime import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    result = run(parser.parse_args().directory, freshness=True, archival=True)
    print(
        json.dumps(
            {
                "completed": result["completed"],
                "cases": len(result["cases"]),
                "normal_added_alerts": result["normal_added_alerts"],
            }
        )
    )


if __name__ == "__main__":
    main()
