"""Repeat the isolated M3 functional workload and collect bounded local measurements.

No cloud, model API, host-wide container cleanup, or detector tuning is performed.
Use: python -m scripts.measure_signal_infrastructure --repeats 3
"""

import argparse
import hashlib
import json
import math
import platform
import re
import subprocess
import threading
import time
import uuid
from datetime import datetime

import yaml

from scripts import test_signal_compose as flow

UNITS = {"B": 1, "kB": 1000, "KB": 1000, "MB": 1000**2, "GB": 1000**3,
         "TB": 1000**4, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}


def size_estimate(value):
    """Docker CLI values are rounded display values, not precise byte counters."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([A-Za-z]+)", value.strip())
    if not match or match[2] not in UNITS:
        raise ValueError("unsupported_size")
    size = float(match[1]) * UNITS[match[2]]
    if not math.isfinite(size):
        raise ValueError("nonfinite_size")
    return round(size)


def percent(value):
    if not re.fullmatch(r"\d+(?:\.\d+)?%", value):
        raise ValueError("unsupported_percentage")
    result = float(value[:-1])
    if not math.isfinite(result):
        raise ValueError("nonfinite_percentage")
    return result


def distribution(values):
    if not values:
        return {"n": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("invalid_duration")
    ordered = sorted(values)
    return {"n": len(values), "p50_ms": ordered[math.ceil(len(values) * .5) - 1],
            "p95_ms": ordered[math.ceil(len(values) * .95) - 1], "max_ms": ordered[-1]}


def docker(*args, timeout=15):
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout, check=False)
    if result.returncode:
        raise flow.CheckFailed("docker_" + args[0] + "_exit_" + str(result.returncode))
    return result.stdout


def parse_stats(row, containers):
    if not re.fullmatch(r"[a-f0-9]{12,64}", row["ID"]):
        raise ValueError("invalid_container_id")
    matches = [service for ident, service in containers.items() if ident.startswith(row["ID"])]
    if len(matches) != 1:
        raise ValueError("unowned_container")
    memory = row["MemUsage"].split(" / ")
    network = row["NetIO"].split(" / ")
    block = row["BlockIO"].split(" / ")
    if any(len(pair) != 2 for pair in (memory, network, block)):
        raise ValueError("invalid_counter_pair")
    if not str(row["PIDs"]).isdigit():
        raise ValueError("invalid_pids")
    return {"at": flow.timestamp(), "service": matches[0], "cpu_percent": percent(row["CPUPerc"]),
            "memory_bytes_estimate": size_estimate(memory[0]),
            "memory_limit_bytes_estimate": size_estimate(memory[1]),
            "network_rx_bytes_estimate": size_estimate(network[0]),
            "network_tx_bytes_estimate": size_estimate(network[1]),
            "block_read_bytes_estimate": size_estimate(block[0]),
            "block_written_bytes_estimate": size_estimate(block[1]),
            "pids": int(row["PIDs"])}


class Sampler:
    def __init__(self, containers, destination, interval):
        self.containers, self.destination, self.interval = containers, destination, interval
        self.rows, self.errors = [], []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.collect, daemon=True)

    def collect(self):
        while not self.stopped.is_set():
            try:
                raw = docker("stats", "--no-stream", "--no-trunc", "--format", "{{json .}}",
                             *self.containers, timeout=12)
                rows = [parse_stats(json.loads(line), self.containers)
                        for line in raw.splitlines() if line.strip()]
                with self.destination.open("a", encoding="utf-8") as handle:
                    for row in rows:
                        handle.write(json.dumps(row) + "\n")
                self.rows.extend(rows)
            except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, flow.CheckFailed) as exc:
                self.errors.append({"at": flow.timestamp(), "error_type": type(exc).__name__})
            self.stopped.wait(self.interval)

    def stop(self):
        self.stopped.set()
        self.thread.join(timeout=20)
        flow.require(not self.thread.is_alive(), "sampler_did_not_stop")


class MeasuredApi(flow.Api):
    def __init__(self, port, report):
        super().__init__(port, report)
        self.starts = {}

    def request(self, method, path, payload=None, *, label="request", expected=None, record=True):
        groups = {"risk_intake": "normal_worker", "risk_while_worker_stopped": "worker_outage"}
        endings = {"access_m3-first-a": "normal_worker", "access_m3-second-a": "worker_outage"}
        started = time.perf_counter()
        if label in groups:
            self.starts[groups[label]] = started
        previous_rows = len(self.report["http"])
        try:
            status, body = super().request(method, path, payload, label=label, expected=expected, record=record)
        finally:
            # Python 3.12 monotonic() on Windows can have ~15.6 ms resolution.
            # Keep the functional runner unchanged; use QPC/perf_counter here.
            finished = time.perf_counter()
            if record and len(self.report["http"]) > previous_rows:
                self.report["http"][-1]["elapsed_ms"] = round((finished - started) * 1000, 3)
        if label in endings and status == 403 and body.get("reason_code") == "SESSION_NOT_AUTHORIZED":
            group = endings[label]
            self.report["denial_latency"].append({"group": group, "at": flow.timestamp(),
                "client_post_start_to_first_confirmed_denial_ms":
                    round((finished - self.starts[group]) * 1000, 3)})
        return status, body


def install_profile(assets, image):
    profile = yaml.safe_load(assets["override"].read_text("utf-8"))
    for service in ("app", "signal-worker"):
        profile["services"][service].update(image=image, cpus=1.0, mem_limit="256m", pids_limit=128)
    assets["override"].write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")


def describe_containers(compose):
    ids = compose.run("ps", "--all", "--quiet", "app", "signal-worker").split()
    flow.require(len(ids) == 2, "two_own_containers_required")
    descriptions = json.loads(docker("inspect", *ids))
    containers, security = {}, []
    for item in descriptions:
        service = item["Config"]["Labels"]["com.docker.compose.service"]
        flow.require(service in {"app", "signal-worker"}, "unexpected_service")
        host = item["HostConfig"]
        flow.require(host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
                     and host["NanoCpus"] == 1000000000 and host["Memory"] == 268435456,
                     "container_security_or_resource_limits")
        if service == "signal-worker":
            flow.require(host["NetworkMode"] == "none" and not host["PortBindings"],
                         "worker_network_or_port_boundary")
        flow.require(all(not m["RW"] for m in item["Mounts"]
                         if m["Destination"] == "/signals/sources.json"), "registry_not_read_only")
        containers[item["Id"]] = service
        security.append({"service": service, "network_mode": host["NetworkMode"],
                         "read_only_rootfs": host["ReadonlyRootfs"], "user": item["Config"]["User"],
                         "cap_drop": host["CapDrop"], "security_options": host["SecurityOpt"],
                         "nano_cpus": host["NanoCpus"], "memory_limit_bytes": host["Memory"],
                         "published_ports": host["PortBindings"],
                         "mounts": [{"destination": m["Destination"], "writable": m["RW"],
                                     "type": m["Type"]} for m in item["Mounts"]]})
    return containers, security


def run_repeat(number, directory, image, interval, timeout, command, build):
    report = {"repeat": number, "status": "failed", "checks": [], "http": [],
              "sessions": {}, "receipts": {}, "denial_latency": [], "started_at": flow.timestamp()}
    project = "secops-m3check-infra-" + uuid.uuid4().hex[:12]
    assets = flow.initialize_assets(directory)
    install_profile(assets, image)
    port = flow.available_port()
    compose = flow.Compose(command, project, port, assets)
    sampler = None
    report["project"] = project
    try:
        if build:
            started = time.perf_counter()
            compose.run("build", "app", timeout=1200)
            report["image_build_ms"] = round((time.perf_counter() - started) * 1000, 3)
        report["image_id"] = json.loads(docker("image", "inspect", image))[0]["Id"]
        started = time.perf_counter()
        compose.run("up", "-d", "--no-build", "app", "signal-worker")
        api = MeasuredApi(port, report)
        api.wait_ready(timeout)
        report["compose_start_to_first_live_ms"] = round((time.perf_counter() - started) * 1000, 3)
        containers, report["container_security"] = describe_containers(compose)
        sampler = Sampler(containers, directory / "resource-samples.jsonl", interval)
        sampler.thread.start()
        flow.check_container_boundaries(compose, report)
        interfaces = json.loads(compose.run("exec", "-T", "signal-worker", "python", "-c",
            "import json,socket; print(json.dumps([name for _,name in socket.if_nameindex()]))"))
        flow.require(interfaces == ["lo"], "worker_network_not_isolated")
        report["checks"].append({"label": "worker_loopback_only", "status": "passed",
                                 "at": flow.timestamp()})
        flow.run_checks(api, compose, assets, report, timeout)
        report["status"] = "passed"
    except flow.CheckFailed as exc:
        report["error_code"] = str(exc)
    except Exception as exc:  # noqa: BLE001 -- never serialize response bodies or credentials
        report["error_code"] = "unexpected_" + type(exc).__name__
    finally:
        if sampler:
            try:
                sampler.stop()
            except flow.CheckFailed:
                report["status"] = "failed"
                report["measurement_error"] = "sampler_shutdown_failed"
            report["resource_samples"] = sampler.rows
            report["sampling_errors"] = sampler.errors
            if sampler.errors or {r["service"] for r in sampler.rows} != {"app", "signal-worker"}:
                report["status"] = "failed"
                report["measurement_error"] = "incomplete_resource_sampling"
        try:
            compose.cleanup()
            report["cleanup"] = {"containers_removed": True, "volume_removed": True}
        except flow.CheckFailed as exc:
            report["cleanup"] = {"containers_removed": False, "error_code": str(exc)}
            report["status"] = "failed"
        report["finished_at"] = flow.timestamp()
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def summarize(reports):
    http = {}
    for report in reports:
        for row in report["http"]:
            # Polling/session IDs must not create extra independent revocation samples.
            group = f"{row['method']} {row['label']} HTTP{row['status']}"
            http.setdefault(group, []).append(row["elapsed_ms"])
    denial, completion = {}, {}
    for report in reports:
        for row in report["denial_latency"]:
            denial.setdefault(row["group"], []).append(row["client_post_start_to_first_confirmed_denial_ms"])
        for name, group in (("first_completed", "normal_worker"), ("resumed_completed", "worker_outage")):
            receipt = report["receipts"].get(name)
            if receipt:
                elapsed = (datetime.fromisoformat(receipt["completed_at"])
                           - datetime.fromisoformat(receipt["received_at"])).total_seconds() * 1000
                completion.setdefault(group, []).append(round(elapsed, 3))
    return {"http_by_operation": {k: distribution(v) for k, v in http.items()},
            "client_post_start_to_denial": {k: distribution(v) for k, v in denial.items()},
            "server_received_to_completed": {k: distribution(v) for k, v in completion.items()},
            "resource_sample_count": sum(len(r.get("resource_samples", [])) for r in reports),
            "functional_checks_passed": sum(c["status"] == "passed" for r in reports for c in r["checks"])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--sample-seconds", type=float, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args(argv)
    if not 1 <= args.repeats <= 10 or not 0.5 <= args.sample_seconds <= 10 or not 5 <= args.timeout_seconds <= 120:
        parser.error("repeats 1..10, sampling 0.5..10 seconds, timeout 5..120 seconds required")
    suffix = uuid.uuid4().hex[:12]
    directory = flow.ROOT / "runtime/m3-validation" / ("infra-" + suffix)
    directory.mkdir(parents=True, exist_ok=False)
    image = "zero-trust-llm-secops:m3-infra-" + suffix
    metadata = {"schema": "m3-infra-measurement-1", "started_at": flow.timestamp(),
                "image_tag": image, "host": platform.platform(), "requested_repeats": args.repeats,
                "resource_sampling_requested_seconds": args.sample_seconds, "limits": {
                    "cpus_per_service": 1, "memory_bytes_per_service": 268435456, "pids_per_service": 128},
                "scope": "synthetic functional workload, not throughput/SLO/RTO/RPO evidence",
                "percentile_method": "nearest rank; small samples do not establish population P95",
                "resource_units": "rounded Docker CLI display values; Linux memory excludes cache",
                "status": "failed", "repeats": []}
    clock = time.get_clock_info("perf_counter")
    metadata["client_duration_clock"] = {"name": "perf_counter", "implementation": clock.implementation,
                                        "resolution_seconds": clock.resolution, "monotonic": clock.monotonic}
    try:
        metadata["base_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=flow.ROOT, text=True, encoding="utf-8").strip()
        sources = [*sorted((flow.ROOT / "app").rglob("*.py")), flow.ROOT / "Dockerfile",
                   flow.ROOT / "compose.yaml", flow.ROOT / "compose.signals.yaml",
                   flow.ROOT / "scripts/signal_worker.py", flow.ROOT / "scripts/test_signal_compose.py",
                   flow.ROOT / "scripts/measure_signal_infrastructure.py"]
        metadata["source_sha256"] = {p.relative_to(flow.ROOT).as_posix():
                                     hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        info = json.loads(docker("info", "--format", "{{json .}}"))
        metadata["engine"] = {k: info.get(k) for k in (
            "ServerVersion", "OSType", "Architecture", "NCPU", "MemTotal", "OperatingSystem")}
        command = flow.detect_compose()
        for number in range(1, args.repeats + 1):
            report = run_repeat(number, directory / f"repeat-{number:02}", image, args.sample_seconds,
                                args.timeout_seconds, command, build=number == 1)
            metadata["repeats"].append(report)
            print(json.dumps({"repeat": number, "status": report["status"], "project": report["project"]}), flush=True)
            if report["status"] != "passed":
                break
        metadata["summary"] = summarize(metadata["repeats"])
        if len(metadata["repeats"]) == args.repeats and all(r["status"] == "passed" for r in metadata["repeats"]):
            metadata["status"] = "passed"
    except Exception as exc:  # noqa: BLE001 -- redact CLI/environment and unexpected payloads
        metadata["error_code"] = "unexpected_" + type(exc).__name__
    finally:
        try:
            docker("image", "rm", image, timeout=30)
            metadata["image_tag_removed"] = True
        except (OSError, subprocess.TimeoutExpired, flow.CheckFailed):
            metadata["image_tag_removed"] = False
        metadata["finished_at"] = flow.timestamp()
        (directory / "measurement.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": metadata["status"], "report": str(directory / "measurement.json")}))
    return 0 if metadata["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
