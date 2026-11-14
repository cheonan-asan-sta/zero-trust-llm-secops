"""Local-only bounded signed capture storage workload and fault checks."""

import argparse
from pathlib import Path

from app.config import get_settings
from scripts.f1_lab.capture_load import run
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--cycles", type=int, default=128)
    parser.add_argument("--batch", type=int, default=4)
    parser.add_argument("--interval", type=float, default=0)
    parser.add_argument("--pressure-root", type=Path)
    args = parser.parse_args()
    require(get_settings().app_environment in {"local", "test"}, "load_local_test_only")
    result = run(
        args.directory,
        cycles=args.cycles,
        batch=args.batch,
        interval=args.interval,
        pressure_root=args.pressure_root,
    )
    print(
        canonical(
            {
                k: result[k]
                for k in (
                    "completed",
                    "pipeline_captures",
                    "pipeline_elapsed_seconds",
                    "long_soak_8h_completed",
                )
            }
        ).decode()
    )


if __name__ == "__main__":
    main()
