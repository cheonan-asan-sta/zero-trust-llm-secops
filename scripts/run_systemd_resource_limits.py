"""Exercise only UUID-owned, nonroot, bounded transient systemd units."""

import argparse
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.systemd_resource_load import PREFIX
from scripts.systemd_resources import validate


def command(args):
    return subprocess.run(args, capture_output=True, timeout=25, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"})


def controls(directory):
    require(os.geteuid() == 0 and Path("/proc/1/comm").read_text().strip() == "systemd", "resource_systemd_root")
    source = Path(__file__).resolve().parents[1]
    require(source.parent == Path("/run") and source.name.startswith("zt-resource-v79-"), "resource_owned_source")
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    report = {"completed": False, "global_configuration_changed": False,
              "paid_api_calls": 0, "aws_calls": 0, "cases": []}
    try:
        for mode in ("cpu", "memory"):
            unit = "zt79-limit-" + uuid.uuid4().hex[:12] + "-" + mode + ".service"
            row = {"mode": mode, "unit": unit, "passed": False}
            report["cases"].append(row)
            try:
                properties = {"Type": "oneshot", "RemainAfterExit": "yes", "User": "daemon",
                    "WorkingDirectory": str(source), "CPUAccounting": "yes", "MemoryAccounting": "yes",
                    "CPUQuota": "25%", "MemoryMax": "64M", "MemorySwapMax": "0", "TasksMax": "8",
                    "TimeoutStartSec": "10", "TimeoutStopSec": "5", "NoNewPrivileges": "yes",
                    "PrivateNetwork": "yes", "PrivateTmp": "yes", "ProtectSystem": "strict",
                    "ProtectHome": "yes", "ProtectControlGroups": "yes", "PrivateDevices": "yes",
                    "CapabilityBoundingSet": "", "OOMPolicy": "stop",
                    "ExecStopPost": "/usr/bin/python3 -m scripts.systemd_resource_load observe"}
                args = ["/usr/bin/systemd-run", "--unit=" + unit,
                    "--setenv=PYTHONDONTWRITEBYTECODE=1", "--setenv=SECOPS_RESOURCE_MODE=" + mode]
                args += ["--property=" + k + "=" + v for k, v in properties.items()]
                launched = command([*args, "/usr/bin/python3", "-m", "scripts.systemd_resource_load", mode])
                row["launch_exit_code"] = launched.returncode
                raw = command(["/usr/bin/systemctl", "show", unit,
                    "--property=InvocationID,Result,ExecMainCode,ExecMainStatus,MemoryMax,CPUQuotaPerSecUSec,TasksMax"])
                require(raw.returncode == 0, "resource_unit_unavailable")
                props = dict(line.split("=", 1) for line in raw.stdout.decode().splitlines() if "=" in line)
                row["properties"] = props
                invocation = props.get("InvocationID", "")
                require(bool(re.fullmatch(r"[0-9a-f]{32}", invocation)), "resource_invocation_missing")
                command(["/usr/bin/systemctl", "stop", unit])
                logs = command(["/usr/bin/journalctl", "--no-pager", "--lines=16", "--output=json",
                    "--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID", "--unit=" + unit,
                    "_SYSTEMD_INVOCATION_ID=" + invocation])
                require(logs.returncode == 0, "resource_control_journal")
                receipts = []
                for line in logs.stdout.splitlines():
                    message = decode(line)
                    text = message.get("MESSAGE", "")
                    if (message.get("_SYSTEMD_INVOCATION_ID") != invocation or type(text) is not str
                            or not text.startswith(PREFIX)):
                        continue
                    value = decode(text[len(PREFIX):].encode())
                    require(set(value) == {"schema", "mode", "stage", "invocation_id", "metrics"}
                        and value["schema"] == "systemd-resource-control-1" and value["mode"] == mode
                        and value["invocation_id"] == invocation and value["stage"] in {"ready", "complete", "stop"},
                        "resource_control_receipt")
                    validate({"schema": "systemd-worker-resource-1", "kind": "collector",
                        "invocation_id": invocation, "worker_succeeded": True, "metrics": value["metrics"]},
                        kind="collector", invocation=invocation)
                    receipts.append(value)
                row["receipts"] = receipts
                require(len({v["stage"] for v in receipts}) == len(receipts), "resource_duplicate_stage")
                ready = [v for v in receipts if v["stage"] == "ready"]
                require(len(ready) == 1, "resource_control_ready_missing")
                before = ready[0]["metrics"]
                require(before["memory_limit_bytes"] == 64 * 1024 * 1024
                    and before["cpu_quota_percent"] == 25 and before["tasks_limit"] == 8,
                    "resource_control_limits_not_active")
                if mode == "cpu":
                    final = [v for v in receipts if v["stage"] == "complete"]
                    require(launched.returncode == 0 and len(final) == 1 and props["Result"] == "success",
                            "resource_cpu_work_failed")
                    after = final[0]["metrics"]
                    require(after["throttled_periods"] is not None and before["throttled_periods"] is not None
                        and after["throttled_periods"] > before["throttled_periods"]
                        and after["cpu_usage_nsec"] is not None and before["cpu_usage_nsec"] is not None
                        and after["cpu_usage_nsec"] > before["cpu_usage_nsec"], "resource_cpu_not_throttled")
                    row["evidence"] = "kernel_quota_and_throttled_counter_increase"
                else:
                    kills = [v["metrics"]["memory_oom_kills"] for v in receipts
                             if v["metrics"]["memory_oom_kills"] is not None]
                    completed = [v for v in receipts if v["stage"] == "complete"]
                    oom = (props["Result"] == "oom-kill" and props["ExecMainStatus"] == "9"
                           and before["memory_oom_kills"] is not None and max(kills, default=0) > before["memory_oom_kills"])
                    reclaim = (props["Result"] == "success" and before["memory_limit_hits"] is not None
                               and len(completed) == 1
                               and completed[0]["metrics"]["memory_limit_hits"] is not None
                               and completed[0]["metrics"]["memory_limit_hits"] > before["memory_limit_hits"])
                    require(oom or reclaim, "resource_memory_pressure_not_confirmed")
                    row["evidence"] = "unit_oom_kill_and_kernel_counter" if oom else "kernel_memory_limit_reclaim_counter"
                row["passed"] = True
            finally:
                require(unit.startswith("zt79-limit-"), "resource_cleanup_scope")
                command(["/usr/bin/systemctl", "stop", unit])
                command(["/usr/bin/systemctl", "reset-failed", unit])
                state = command(["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"])
                row["owned_unit_removed"] = state.stdout.strip() == b"not-found"
                require(row["owned_unit_removed"], "resource_unit_cleanup")
        report["completed"] = True
    finally:
        (output / "limits.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    result = controls(args.directory)
    print(json.dumps({"completed": result["completed"], "cases": len(result["cases"])}))


if __name__ == "__main__":
    main()
