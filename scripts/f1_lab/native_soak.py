"""Closed long-test profiles and durable progress; interruptions never count as continuity."""

import hashlib
import math
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.collector_freshness import atomic_capture
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical


@dataclass(frozen=True)
class SoakProfile:
    mode: str
    seconds: int

    def __post_init__(self):
        require(type(self.mode) is str and type(self.seconds) is int and (
            self.mode == "soak" and self.seconds in {8 * 3600, 12 * 3600}
            or self.mode == "preflight" and 60 <= self.seconds <= 600
        ), "soak_profile")

    @property
    def interval(self):
        return 20 if self.mode == "soak" else 5

    @property
    def renewal(self):
        return 1200 if self.mode == "soak" else 15

    @property
    def max_gap(self):
        return 60 if self.mode == "soak" else 30

    @property
    def max_cycles(self):
        return math.ceil(self.seconds / self.interval) + 2


def clocks():
    return time.monotonic(), time.clock_gettime(time.CLOCK_BOOTTIME)


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def verify_samples(path, count, head):
    require(Path(path).stat().st_size <= 32 * 1024**2, "soak_log_size")
    previous = "0" * 64
    observed = 0
    with Path(path).open("rb") as stream:
        for line in stream:
            require(len(line) <= 65536, "soak_log_line")
            row = decode(line)
            require(type(row) is dict and set(row) == {"payload", "sha256"}, "soak_log_shape")
            payload = row["payload"]
            require(type(payload) is dict and set(payload) == {"previous", "sample"}, "soak_log_payload")
            require(payload["previous"] == previous and payload["sample"]["cycle"] == observed + 1,
                    "soak_log_order")
            require(hashlib.sha256(canonical(payload)).hexdigest() == row["sha256"], "soak_log_digest")
            previous = row["sha256"]
            observed += 1
    require(observed == count and previous == head, "soak_log_final")


class Progress:
    def __init__(self, output, profile):
        self.profile = profile
        self.output = Path(output)
        self.path = self.output / "soak-progress.json"
        self.log = self.output / "soak-samples.jsonl"
        self.fd = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.closed = False
        self.start, boot = clocks()
        self.suspend_offset = boot - self.start
        self.boot_id = boot_id()
        self.previous = self.start
        self.count = 0
        self.head = "0" * 64
        self.maximum_gap = 0.0
        self.write("running", None)

    def elapsed(self):
        now, boot = clocks()
        require(boot_id() == self.boot_id,
                "soak_boot_changed")
        require(abs((boot - now) - self.suspend_offset) <= 5, "soak_suspend_observed")
        require(now >= self.previous, "soak_monotonic_regression")
        return now - self.start

    def add(self, sample):
        elapsed = self.elapsed()
        now = self.start + elapsed
        gap = now - self.previous
        require(gap <= self.profile.max_gap, "soak_observation_gap")
        require(self.count < self.profile.max_cycles, "soak_sample_limit")
        require(sample["cycle"] == self.count + 1, "soak_sample_order")
        require(sample["logical_bytes"] <= 128 * 1024**2
                and sample["allocated_file_bytes"] <= 128 * 1024**2, "soak_capture_capacity")
        for key in ("collector_accounting", "archive", "health"):
            require(type(sample[key]["CPUUsageNSec"]) is int and type(sample[key]["MemoryPeak"]) is int,
                    "soak_resource_missing")
        payload = canonical({"previous": self.head, "sample": sample})
        digest = hashlib.sha256(payload).hexdigest()
        row = canonical({"payload": {"previous": self.head, "sample": sample}, "sha256": digest}) + b"\n"
        with os.fdopen(os.dup(self.fd), "ab") as stream:
            stream.write(row)
            stream.flush()
            os.fsync(stream.fileno())
        self.head = digest
        self.count += 1
        self.previous = now
        self.maximum_gap = max(self.maximum_gap, gap)
        self.write("running", sample)

    def write(self, state, sample):
        atomic_capture(self.path, canonical({
            "schema": "native-soak-progress-1", "state": state, "completed": state == "complete",
            "mode": self.profile.mode, "requested_seconds": self.profile.seconds,
            "elapsed_seconds": round(clocks()[0] - self.start, 3), "cycles": self.count,
            "boot_id_sha256": hashlib.sha256(self.boot_id.encode()).hexdigest(),
            "interval_seconds": self.profile.interval, "maximum_observed_gap_seconds": round(self.maximum_gap, 3),
            "sample_chain_head": self.head, "latest_sample": sample,
            "updated_at": datetime.now(UTC).isoformat(), "paid_api_calls": 0, "aws_calls": 0,
            "long_soak_8h_completed": state == "complete" and self.profile.mode == "soak",
            "resume_supported": False,
        }))

    def finish(self):
        elapsed = self.elapsed()
        require(elapsed >= self.profile.seconds, "soak_duration_short")
        require(self.count >= self.profile.seconds // self.profile.interval - 1, "soak_coverage_short")
        require(self.start + elapsed - self.previous <= self.profile.max_gap, "soak_final_gap")
        verify_samples(self.log, self.count, self.head)
        return {"mode": self.profile.mode, "requested_seconds": self.profile.seconds,
                "observed_seconds": round(elapsed, 3), "cycles": self.count,
                "sample_chain_head": self.head, "maximum_gap_seconds": round(self.maximum_gap, 3),
                "boot_id_sha256": hashlib.sha256(self.boot_id.encode()).hexdigest(),
                "long_soak_8h_completed": self.profile.mode == "soak"}

    def close(self, completed):
        if self.closed:
            return
        try:
            self.write("complete" if completed else "interrupted_or_failed", None)
        finally:
            os.close(self.fd)
            self.closed = True
