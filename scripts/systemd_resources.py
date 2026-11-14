"""Read only the current process's non-root cgroups; never borrow host totals."""

import json
import os
import re
import stat
from pathlib import Path

PREFIX = "SECOPS_RESOURCE_V1 "
KINDS = {"scripts.collect_shared_execution": "collector",
         "scripts.archive_service_captures": "archive",
         "scripts.service_capture_status": "health"}
EMPTY = {"cpu_usage_nsec": None, "cpu_source": None, "memory_peak_bytes": None,
         "memory_source": None, "memory_limit_bytes": None, "cpu_quota_percent": None,
         "throttled_periods": None, "memory_limit_hits": None, "memory_oom_kills": None,
         "tasks_limit": None}


def group_path(value):
    if (type(value) is not str or len(value) > 1024 or not value.startswith("/")
            or any(p in {"", ".", ".."} for p in value.split("/")[1:])
            or not re.fullmatch(r"/[A-Za-z0-9_.@\\:/-]+", value)):
        raise ValueError("resource_group_scope")
    return value.lstrip("/")


def number(value):
    if type(value) is not str or not re.fullmatch(r"[0-9]{1,20}", value):
        return None
    result = int(value)
    return result if result < 2**64 - 1 else None


def read(root, group, controller, name):
    try:
        base = root.resolve(strict=True)
        path = root / controller / group_path(group) / name
        if not path.parent.resolve(strict=True).is_relative_to(base):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            raw = stream.read(4097)
        return raw.decode("ascii").strip() if len(raw) <= 4096 else None
    except (OSError, ValueError, UnicodeError):
        return None


def keyed(value):
    pairs = [line.split() for line in (value or "").splitlines()]
    if any(len(p) != 2 for p in pairs) or len({p[0] for p in pairs}) != len(pairs):
        return {}
    return {k: number(v) for k, v in pairs}


def snapshot(cgroups=None, *, root=Path("/sys/fs/cgroup")):
    cgroups = Path("/proc/self/cgroup").read_text() if cgroups is None else cgroups
    groups = {}
    for line in cgroups.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        try:
            group_path(parts[2])
        except ValueError:
            continue  # Empty or root groups must never become machine totals.
        for controller in parts[1].split(","):
            if controller in groups:
                raise ValueError("resource_duplicate_controller")
            groups[controller] = parts[2]
    result = EMPTY.copy()
    unified = groups.get("")
    for controller in ("", "unified"):
        if not unified:
            break
        data = keyed(read(root, unified, controller, "cpu.stat"))
        if data.get("usage_usec") is not None:
            result.update(cpu_usage_nsec=data["usage_usec"] * 1000, cpu_source="cgroup2_cpu_stat")
        peak = number(read(root, unified, controller, "memory.peak"))
        if peak is not None:
            result.update(memory_peak_bytes=peak, memory_source="cgroup2_memory_peak",
                          memory_limit_bytes=number(read(root, unified, controller, "memory.max")))
        events = keyed(read(root, unified, controller, "memory.events"))
        if events.get("oom_kill") is not None:
            result["memory_oom_kills"] = events["oom_kill"]
        quota = (read(root, unified, controller, "cpu.max") or "").split()
        if len(quota) == 2 and number(quota[0]) is not None and number(quota[1]):
            result.update(cpu_quota_percent=100 * int(quota[0]) / int(quota[1]),
                          throttled_periods=data.get("nr_throttled"))
        limit = number(read(root, unified, controller, "pids.max"))
        if limit is not None:
            result["tasks_limit"] = limit
    if result["cpu_usage_nsec"] is None and groups.get("cpuacct"):
        for controller in ("cpuacct", "cpu,cpuacct"):
            usage = number(read(root, groups["cpuacct"], controller, "cpuacct.usage"))
            if usage is not None:
                result.update(cpu_usage_nsec=usage, cpu_source="cgroup1_cpuacct")
                break
    if result["memory_peak_bytes"] is None and groups.get("memory"):
        peak = number(read(root, groups["memory"], "memory", "memory.max_usage_in_bytes"))
        if peak is not None:
            result.update(memory_peak_bytes=peak, memory_source="cgroup1_memory_peak",
                          memory_limit_bytes=number(read(root, groups["memory"], "memory", "memory.limit_in_bytes")))
    if groups.get("memory"):
        result["memory_limit_hits"] = number(read(root, groups["memory"], "memory", "memory.failcnt"))
        events = keyed(read(root, groups["memory"], "memory", "memory.oom_control"))
        if events.get("oom_kill") is not None:
            result["memory_oom_kills"] = events["oom_kill"]
    if result["cpu_quota_percent"] is None and groups.get("cpu"):
        for controller in ("cpu", "cpu,cpuacct"):
            quota = number(read(root, groups["cpu"], controller, "cpu.cfs_quota_us"))
            period = number(read(root, groups["cpu"], controller, "cpu.cfs_period_us"))
            if quota is not None and period:
                data = keyed(read(root, groups["cpu"], controller, "cpu.stat"))
                result.update(cpu_quota_percent=100 * quota / period,
                              throttled_periods=data.get("nr_throttled"))
                break
    if result["tasks_limit"] is None and groups.get("pids"):
        result["tasks_limit"] = number(read(root, groups["pids"], "pids", "pids.max"))
    return result


def receipt(kind, succeeded):
    invocation = os.environ.get("INVOCATION_ID", "")
    if kind not in KINDS.values() or not re.fullmatch(r"[a-f0-9]{32}", invocation):
        return None
    try:
        metrics = snapshot()
    except (OSError, ValueError):
        metrics = None
    return {"schema": "systemd-worker-resource-1", "kind": kind, "invocation_id": invocation,
            "worker_succeeded": succeeded, "metrics": metrics}


def validate(value, *, kind, invocation):
    if (type(value) is not dict or set(value) != {"schema", "kind", "invocation_id", "worker_succeeded", "metrics"}
            or value["schema"] != "systemd-worker-resource-1" or value["kind"] != kind
            or value["invocation_id"] != invocation or value["worker_succeeded"] is not True
            or type(invocation) is not str or not re.fullmatch(r"[a-f0-9]{32}", invocation)):
        raise ValueError("resource_receipt_binding")
    metrics = value["metrics"]
    if type(metrics) is not dict or set(metrics) != set(EMPTY):
        raise ValueError("resource_metrics_shape")
    for name, item in metrics.items():
        if name.endswith("_source"):
            allowed = ({None, "cgroup2_cpu_stat", "cgroup1_cpuacct"} if name == "cpu_source"
                       else {None, "cgroup2_memory_peak", "cgroup1_memory_peak"})
            if (item is not None and type(item) is not str) or item not in allowed:
                raise ValueError("resource_source")
        elif name == "cpu_quota_percent":
            if item is not None and (type(item) not in {int, float} or not 0 <= item <= 1e12):
                raise ValueError("resource_quota")
        elif item is not None and (type(item) is not int or not 0 <= item < 2**80):
            raise ValueError("resource_counter")
    for metric, source in [("cpu_usage_nsec", "cpu_source"), ("memory_peak_bytes", "memory_source")]:
        if (metrics[metric] is None) != (metrics[source] is None):
            raise ValueError("resource_missing_source")
    return metrics


def emit(kind, succeeded):
    value = receipt(kind, succeeded)
    if value is not None:
        print(PREFIX + json.dumps(value, allow_nan=False), flush=True)
