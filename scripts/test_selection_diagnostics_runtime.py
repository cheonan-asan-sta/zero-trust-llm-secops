"""Owned mTLS baseline plus deliberate transport/command diagnostic controls."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.continuous_mtls_runtime import RuntimeFailure, command
from scripts.infra_probe_diagnostics import execute_probe
from scripts.monitoring_diagnostics import collect
from scripts.test_infra_selection_runtime import SelectionChecks


def run(directory):
    checks = SelectionChecks(directory)
    report = {
        "schema": "selection-diagnostics-acceptance-1",
        "completed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "historical_CI_failure_root_cause_confirmed": False,
    }
    output = checks.path.parent / "diagnostics-acceptance.json"
    try:
        checks.run()
        checks.require(
            checks.report["completed"] and len(checks.report["checks"]) == 37,
            "selection_diagnostics_baseline",
        )
        report["baseline_checks"] = 37
        before = checks.served()
        proxy = checks.runtime.container("proxy")
        forced = object.__new__(SelectionChecks)
        forced.runtime, forced.scrape = checks.runtime, checks.scrape
        forced.report = {
            "schema": "selection-deliberate-transport-failure-1",
            "completed": False,
            "checks": [],
            "workloads": [],
        }
        forced.path = checks.path.parent / "deliberate-transport-failure.json"
        command(["docker", "stop", "--time", "2", proxy])
        try:
            try:
                forced.workload(1, 8, "missing")
            except RuntimeFailure:
                pass
            else:
                raise ValueError("selection_deliberate_failure_accepted")
            row = forced.report["workloads"][0]
            checks.require(
                row["passed"] is False
                and row["probe_exit_code"] == 1
                and row["probe_failure"]["stage"] == "request"
                and len(row["rows"]) == 16
                and all(r["error"] for r in row["rows"])
                and row["delivered"] == 0
                and checks.served() == before,
                "selection_transport_failure_diagnostic_incomplete",
            )
            report["transport_failure"] = {
                "expected_failure_recorded": True,
                "actual_error_rows": 16,
                "outage_deliveries": 0,
                "automatic_retries": 0,
            }
        finally:
            command(["docker", "start", proxy])
        checks.wait(
            lambda: (
                checks.runtime.probe({"profile": "frontend", "path": "/documents", "headers": {}})[
                    "status"
                ]
                == 403
            ),
            "selection_proxy_not_recovered",
        )
        operator = checks.runtime.container("operator")
        command(["docker", "stop", "--time", "2", operator])
        try:
            result = execute_probe(checks.runtime, "missing", 8)
            checks.require(
                result["exit_code"] != 0
                and result["report"] is None
                and result["failure"]["stage"] == "command"
                and result["failure"]["code"] == "command_exit",
                "selection_command_failure_not_recorded",
            )
            states = collect(checks.runtime, "selection_deliberate_operator_stop")
            checks.require(
                any(
                    r["service"] == "operator" and r.get("running") is False
                    for r in states["services"]
                ),
                "selection_stopped_operator_not_observed",
            )
            report["command_failure"] = result | {"public_runtime_state": states}
        finally:
            command(["docker", "start", operator])
        checks.wait(
            lambda: (
                checks.runtime.probe({"profile": "core", "path": "/health/live"})["status"] == 200
            ),
            "selection_operator_not_recovered",
        )
        checks.require(checks.served() == before, "selection_diagnostics_unexpected_delivery")
        report.update(
            completed=True,
            actual_fault_controls=2,
            baseline_normal_denial_recovered=True,
            no_resource_delivery_under_faults=True,
        )
    finally:
        checks.cleanup()
        report["cleanup"] = checks.report.get("cleanup")
        report["baseline_report_sha256"] = hashlib.sha256(checks.path.read_bytes()).hexdigest()
        output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    result = run(parser.parse_args().directory)
    print(
        json.dumps(
            {
                "completed": result["completed"],
                "baseline_checks": result["baseline_checks"],
                "actual_fault_controls": result["actual_fault_controls"],
            }
        )
    )


if __name__ == "__main__":
    main()
