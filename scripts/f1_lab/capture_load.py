"""Bounded, synthetic signed storage workload; never production collection."""

import errno
import hashlib
import math
import multiprocessing
import os
import sqlite3
import stat
import time
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.capture_archive import ArchiveFull, ArchivePolicy, ArchiveScope, CaptureArchive
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import CollectorMonitor, CollectorScope, atomic_capture
from scripts.f1_lab.collector_status_bridge import health_report, publish, read_public, validate
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    ProcessObservation,
    ServiceEvent,
)
from scripts.run_shared_execution_controls import setup


def distribution(values):
    require(bool(values) and all(math.isfinite(v) and v >= 0 for v in values), "load_samples")
    ordered = sorted(values)
    return {
        "samples": len(values),
        "min": round(ordered[0], 3),
        "p50": round(ordered[math.ceil(len(values) * 0.50) - 1], 3),
        "p95": round(ordered[math.ceil(len(values) * 0.95) - 1], 3),
        "max": round(ordered[-1], 3),
    }


def footprint(root):
    """Regular-file bytes, not directory metadata, quota, or physical free space."""
    logical = allocated = files = 0
    for parent, directories, names in os.walk(root, followlinks=False):
        for name in directories + names:
            path = Path(parent) / name
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), "load_unexpected_link")
            if stat.S_ISREG(info.st_mode):
                files += 1
                logical += info.st_size
                allocated += info.st_blocks * 512
    return {"regular_files": files, "logical_bytes": logical, "allocated_file_bytes": allocated}


def inventory(root):
    """Verify every compressed row and detect conflicting hot/cold duplicates."""
    values = {}
    database = root / "archive.sqlite3"
    if database.exists():
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as con:
            for rid, size, packed, expected in con.execute(
                "SELECT run_id,raw_bytes,payload,raw_sha FROM captures"
            ):
                raw = CaptureArchive.unpack(packed, size, expected)
                values[rid] = hashlib.sha256(raw).hexdigest()
    for path in root.glob("*/capture.json"):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(
            path.parent.name not in values or values[path.parent.name] == digest, "load_conflict"
        )
        values[path.parent.name] = digest
    return values


def inventory_sha(values):
    return hashlib.sha256(canonical(sorted(values.items()))).hexdigest()


def resource_sample():
    import resource

    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss = next(
        line.split()[1]
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith("VmRSS:")
    )
    return {
        "self_cpu_seconds": usage.ru_utime + usage.ru_stime,
        "self_peak_rss_bytes": usage.ru_maxrss * 1024,
        "self_rss_bytes": int(rss) * 1024,
    }


class SignedStorageLab:
    def __init__(self, output):
        self.output = Path(output)
        keys, registry, _ = setup(self.output / "public-trust")
        self.key = keys["runtime"]
        now = datetime.now(UTC)
        registry = registry.model_copy(
            update={
                "expires_at": now + timedelta(hours=12),
                "authorities": [
                    a.model_copy(
                        update={"mode": "systemd", "expires_at": now + timedelta(hours=12)}
                    )
                    for a in registry.authorities
                ],
            }
        )
        path = self.output / "public-trust/registry.json"
        path.write_bytes(canonical(registry.model_dump(mode="json")))
        self.pinned = PinnedServiceRegistry(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.scope = CollectorScope(
            tenant_id="local-lab",
            server_id="shared-lab",
            unit="shared-fixture.service",
            source_id="local-proc",
            key_id="proc-1",
        )
        self.root = self.output / "store"
        self.root.mkdir(mode=0o700)
        self.archive_scope = ArchiveScope.model_validate(self.scope.model_dump(exclude={"key_id"}))
        self.policy = ArchivePolicy(max_hot_records=8, max_records=4096)
        self.archive = CaptureArchive(self.root, self.archive_scope, policy=self.policy)
        self.monitor = CollectorMonitor(self.scope, self.pinned, self.output / "monitor.sqlite3")
        self.expected = {}

    def write(self):
        now = datetime.now(UTC)
        rid = uuid.uuid4().hex
        event = ServiceEvent(
            tenant_id=self.scope.tenant_id,
            server_id=self.scope.server_id,
            unit=self.scope.unit,
            boot_id="1" * 32,
            invocation_id="2" * 32,
            process_id=42,
            event_id=hashlib.sha256(rid.encode()).hexdigest(),
            raw_sha256="d" * 64,
            observed_at=now,
            mode="systemd",
            collection_basis="manager_snapshot",
        )
        observation = ProcessObservation(
            pid=42,
            start_ticks=1,
            parent_pid=1,
            real_uid=65534,
            effective_uid=65534,
            login_uid=None,
            audit_session_id=None,
            executable_sha256="a" * 64,
            command_sha256="b" * 64,
            argument_count=1,
            parent_ref_sha256=None,
        )
        proof = runtime_proof(
            event,
            observation,
            self.key,
            source_id=self.scope.source_id,
            key_id=self.scope.key_id,
            observed_at=now,
        )
        raw = (
            canonical(
                {
                    "schema": "zt-service-capture-1",
                    "event": event.model_dump(mode="json"),
                    "runtime_proof": proof.model_dump(mode="json"),
                    "authorization_proof_included": False,
                }
            )
            + b"\n"
        )
        with capture_store_lock(self.root):
            target = self.root / rid
            target.mkdir(mode=0o700)
            atomic_capture(target / "capture.json", raw)
            atomic_capture(self.root / "latest.json", raw)
        self.expected[rid] = hashlib.sha256(raw).hexdigest()

    def health(self):
        latest = self.root / "latest.json"
        result = self.monitor.check(latest)
        require(result.state == "fresh", "load_health_not_fresh")
        status = health_report(self.scope, result, latest, self.pinned)
        destination = self.output / "health.json"
        publish(destination, status)
        validate(read_public(destination), "health", status["scope_sha256"])

    def reopen(self):
        self.archive = CaptureArchive(self.root, self.archive_scope, policy=self.policy)
        self.monitor = CollectorMonitor(self.scope, self.pinned, self.output / "monitor.sqlite3")

    def fault_controls(self):
        latest = self.root / "latest.json"
        original = latest.read_bytes()
        before = inventory(self.root)
        with self.archive.connection() as con:
            records = len(self.archive.load(con)[0])
        limited = CaptureArchive(
            self.root,
            self.archive_scope,
            policy=self.policy.model_copy(
                update={"max_hot_records": 1, "max_records": max(1, records)}
            ),
        )
        try:
            limited.compact(apply=True)
        except ArchiveFull:
            pass
        else:
            raise ValueError("load_capacity_not_reached")
        require(
            inventory(self.root) == before and latest.read_bytes() == original, "load_capacity_loss"
        )
        ledger = self.monitor.path
        ledger.chmod(0o400)
        try:
            require(os.geteuid() != 0, "load_storage_fault_nonroot_required")
            require(self.monitor.check(latest).state == "unavailable", "load_monitor_not_closed")
        finally:
            ledger.chmod(0o600)
        require(latest.read_bytes() == original, "load_ledger_fault_changed_latest")
        self.reopen()
        self.health()
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe(duplex=False)

        def hold():
            with capture_store_lock(self.root):
                child.send(True)
                time.sleep(15)

        worker = context.Process(target=hold)
        worker.start()
        waited = time.monotonic()
        try:
            require(parent.poll(5) and parent.recv(), "load_lock_worker_not_ready")
            waited = time.monotonic()
            try:
                self.archive.compact(apply=True)
            except ValueError as error:
                require(
                    str(error) == "native_source_capture_store_lock_busy", "load_wrong_lock_failure"
                )
            else:
                raise ValueError("load_lock_not_exclusive")
            waited = time.monotonic() - waited
        finally:
            worker.terminate()
            worker.join(5)
            parent.close()
            child.close()
        require(
            not worker.is_alive()
            and latest.read_bytes() == original
            and inventory(self.root) == before,
            "load_lock_failure_changed_data",
        )
        self.write()
        latest_before_crash = latest.read_bytes()

        def crash_after_commit():
            archive = CaptureArchive(
                self.root,
                self.archive_scope,
                policy=self.policy.model_copy(update={"max_hot_records": 1}),
            )
            archive.after_archive_commit = lambda: os._exit(73)
            archive.compact(apply=True)

        worker = context.Process(target=crash_after_commit)
        worker.start()
        try:
            worker.join(15)
            require(worker.exitcode == 73, "load_commit_crash_not_reached")
        finally:
            if worker.is_alive():
                worker.terminate()
                worker.join(5)
        require(
            inventory(self.root) == self.expected and latest.read_bytes() == latest_before_crash,
            "load_commit_crash_lost_data",
        )
        self.reopen()
        self.archive.compact(apply=True)
        self.health()
        require(
            inventory(self.root) == self.expected and latest.read_bytes() == latest_before_crash,
            "load_restart_lost_data",
        )
        return {
            "archive_capacity_preserves_all_bytes": True,
            "read_only_monitor_storage_fails_closed": True,
            "reopened_workers_recover": True,
            "actual_lock_contention_preserves_all_bytes": True,
            "lock_wait_seconds": round(waited, 3),
            "actual_worker_exit_after_commit": 73,
            "committed_cleanup_recovers_after_worker_exit": True,
        }


def disk_pressure(mount):
    """Fill only a dedicated <=4MiB empty tmpfs, never an ordinary host filesystem."""
    mount = Path(mount)
    require(
        mount.is_absolute() and mount.resolve() == mount and not mount.is_symlink(),
        "load_pressure_path",
    )
    mounts = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    require(
        any(row[4] == str(mount) and row[row.index("-") + 1] == "tmpfs" for row in mounts),
        "load_pressure_tmpfs",
    )
    size = os.statvfs(mount)
    require(
        0 < size.f_blocks * size.f_frsize <= 4 * 1024**2 and not any(mount.iterdir()),
        "load_pressure_dedicated_small_mount",
    )
    owned = mount / ("zt-load-" + uuid.uuid4().hex)
    owned.mkdir(mode=0o700)
    latest, filler = owned / "latest.json", owned / "fill"
    before = b'{"previous":true}\n'
    atomic_capture(latest, before)
    filled = 0
    try:
        try:
            with filler.open("xb", buffering=0) as stream:
                for _ in range(1025):
                    filled += stream.write(b"x" * 4096)
                raise ValueError("load_pressure_not_full")
        except OSError as error:
            require(error.errno == errno.ENOSPC, "load_pressure_wrong_error")
        try:
            atomic_capture(latest, b"replacement" * 1024)
        except OSError as error:
            require(error.errno == errno.ENOSPC, "load_publication_wrong_error")
        else:
            raise ValueError("load_publication_did_not_fail")
        require(latest.read_bytes() == before, "load_full_disk_replaced_latest")
        require(set(owned.iterdir()) == {latest, filler}, "load_full_disk_temp_left")
        return {"actual_ENOSPC": True, "latest_bytes_preserved": True, "filled_bytes": filled}
    finally:
        for path in (filler, latest):
            path.unlink(missing_ok=True)
        owned.rmdir()


def run(output, *, cycles=128, batch=4, interval=0, pressure_root=None):
    require(os.name == "posix" and os.geteuid() != 0, "load_nonroot_linux_required")
    require(
        type(cycles) is int
        and 3 <= cycles <= 4096
        and type(batch) is int
        and 1 <= batch <= 64
        and 9 <= cycles * batch <= 4096,
        "load_cycle_bounds",
    )
    require(
        type(interval) in {float, int} and math.isfinite(interval) and 0 <= interval <= 60,
        "load_interval",
    )
    output = Path(output)
    require(output.is_absolute() and not output.is_symlink(), "load_output_absolute")
    output.mkdir(mode=0o700, exist_ok=False)
    lab = SignedStorageLab(output)
    durations = {
        name: []
        for name in (
            "write_ms",
            "health_ms",
            "archive_ms",
            "cycle_ms",
            "start_gap_ms",
            "schedule_lag_ms",
        )
    }
    samples = []
    started = time.monotonic()
    initial = resource_sample()
    previous = None
    for index in range(cycles):
        scheduled = started + index * interval if interval else time.monotonic()
        time.sleep(max(0, scheduled - time.monotonic()))
        began = time.monotonic()
        durations["schedule_lag_ms"].append(max(0, began - scheduled) * 1000)
        if previous is not None:
            durations["start_gap_ms"].append((began - previous) * 1000)
        previous = began
        for name, operation in (
            ("write_ms", lambda: [lab.write() for _ in range(batch)]),
            ("health_ms", lab.health),
            ("archive_ms", lambda: lab.archive.compact(apply=True)),
        ):
            at = time.monotonic()
            operation()
            durations[name].append((time.monotonic() - at) * 1000)
        durations["cycle_ms"].append((time.monotonic() - began) * 1000)
        samples.append(
            {
                "cycle": index + 1,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                **resource_sample(),
                **footprint(lab.root),
            }
        )
        atomic_capture(
            output / "progress.json",
            canonical(
                {
                    "completed": False,
                    "cycles": index + 1,
                    "requested_cycles": cycles,
                    "pipeline_captures": (index + 1) * batch,
                    "latest_sample": samples[-1],
                }
            ),
        )
        if index == cycles // 2:
            lab.reopen()
        if index % 64 == 0:
            print(canonical({"load_progress_cycles": index + 1, "of": cycles}).decode(), flush=True)
    elapsed = time.monotonic() - started
    faults = lab.fault_controls()
    actual = inventory(lab.root)
    require(actual == lab.expected, "load_capture_loss_or_change")
    final = resource_sample()
    result = {
        "schema": "zt-capture-storage-load-1",
        "completed": True,
        "workload": "synthetic signed fixtures through storage/health/archive APIs, not native collection",
        "cycles": cycles,
        "batch": batch,
        "pipeline_captures": cycles * batch,
        "captures_including_fault_probe": len(actual),
        "interval_seconds": interval,
        "pipeline_elapsed_seconds": round(elapsed, 3),
        "long_soak_8h_completed": elapsed >= 8 * 3600,
        "captures_per_second": round(cycles * batch / elapsed, 3),
        "duration_ms": {name: distribution(values) for name, values in durations.items()},
        "self_cpu_seconds": round(final["self_cpu_seconds"] - initial["self_cpu_seconds"], 3),
        "self_peak_rss_bytes": final["self_peak_rss_bytes"],
        "first_sample": samples[0],
        "last_sample": samples[-1],
        "samples": samples,
        "all_original_bytes_preserved": True,
        "expected_inventory_sha256": inventory_sha(lab.expected),
        "actual_inventory_sha256": inventory_sha(actual),
        "fault_controls": faults,
        "disk_pressure": disk_pressure(pressure_root) if pressure_root else {"executed": False},
        "paid_api_calls": 0,
        "aws_calls": 0,
        "independent_detection_evaluation": False,
        "authorization_checked": False,
        "automatic_enforcement_allowed": False,
        "host_quota_or_production_SLO_proven": False,
    }
    (output / "run.json").write_bytes(canonical(result) + b"\n")
    atomic_capture(
        output / "progress.json",
        canonical(
            {
                "completed": True,
                "run_sha256": hashlib.sha256((output / "run.json").read_bytes()).hexdigest(),
            }
        ),
    )
    return result
