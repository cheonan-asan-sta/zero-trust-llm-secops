"""Bounded local resource controls; allocate only after reading this unit's limit."""

import json
import os
import sys
import time

from scripts.systemd_resources import snapshot

PREFIX = "SECOPS_RESOURCE_CONTROL_V1 "


def emit(mode, stage, metrics):
    print(PREFIX + json.dumps({"schema": "systemd-resource-control-1", "mode": mode,
        "stage": stage, "invocation_id": os.environ.get("INVOCATION_ID"),
        "metrics": metrics}, allow_nan=False), flush=True)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1 or argv[0] not in {"cpu", "memory", "observe"}:
        return 2
    mode = os.environ.get("SECOPS_RESOURCE_MODE")
    if mode not in {"cpu", "memory"}:
        return 2
    metrics = snapshot()
    if argv[0] == "observe":
        emit(mode, "stop", metrics)
        return 0
    if (mode != argv[0] or metrics["memory_limit_bytes"] != 64 * 1024 * 1024
            or metrics["cpu_quota_percent"] != 25 or metrics["tasks_limit"] != 8):
        return 77  # No pressure is applied to an unsupported/unbounded host.
    emit(mode, "ready", metrics)
    if mode == "cpu":
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            pass
    else:
        data = bytearray(128 * 1024 * 1024)
        for offset in range(0, len(data), 4096):
            data[offset] = 1
    emit(mode, "complete", snapshot())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
