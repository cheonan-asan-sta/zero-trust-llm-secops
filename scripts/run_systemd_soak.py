"""Explicit local real-systemd soak; no resuming interrupted time as continuous time."""

import argparse
import json
import signal
from pathlib import Path

from scripts.f1_lab.native_soak import SoakProfile
from scripts.run_systemd_collector_runtime import run


def interrupted(signum, frame):
    raise InterruptedError("native_soak_interrupted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hours", type=int, choices=(8, 12))
    mode.add_argument("--preflight-seconds", type=int)
    args = parser.parse_args()
    profile = SoakProfile("soak", args.hours * 3600) if args.hours else SoakProfile("preflight", args.preflight_seconds)
    old = signal.signal(signal.SIGTERM, interrupted)
    try:
        result = run(args.directory, freshness=True, archival=True, scheduling=True,
                     reporting=True, backups=True, soak_profile=profile)
        print(json.dumps({"completed": result["completed"], "mode": profile.mode,
                          "long_soak_8h_completed": result["load_controls"]["long_soak_8h_completed"]}))
    finally:
        signal.signal(signal.SIGTERM, old)


if __name__ == "__main__":
    main()
