"""Do not count host totals, stale invocations or unavailable metrics as zero."""

import json
import sys
from types import SimpleNamespace

import pytest

from scripts import measure_systemd_worker as worker
from scripts import systemd_resources as resource
from scripts.f1_lab import capture_load_runtime as parent

ID = "a" * 32
GROUP = "/system.slice/owned.service"


def write(root, controller, name, value, group=GROUP):
    path = root / controller / group.lstrip("/") / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    return path


def valid():
    return {"schema": "systemd-worker-resource-1", "kind": "collector", "invocation_id": ID,
            "worker_succeeded": True, "metrics": resource.EMPTY | {
                "cpu_usage_nsec": 5000, "cpu_source": "cgroup2_cpu_stat",
                "memory_peak_bytes": 8192, "memory_source": "cgroup1_memory_peak"}}


def test_hybrid_cpu_and_legacy_peak_preserve_units(tmp_path):
    write(tmp_path, "unified", "cpu.stat", "usage_usec 123\nnr_throttled 2\n")
    write(tmp_path, "cpu", "cpu.cfs_quota_us", "25000")
    write(tmp_path, "cpu", "cpu.cfs_period_us", "100000")
    write(tmp_path, "cpu", "cpu.stat", "nr_throttled 4")
    write(tmp_path, "memory", "memory.max_usage_in_bytes", "8192")
    write(tmp_path, "memory", "memory.limit_in_bytes", "67108864")
    write(tmp_path, "memory", "memory.failcnt", "9")
    write(tmp_path, "pids", "pids.max", "8")
    # An unrelated host-wide cpuacct total must not be used.
    (tmp_path / "cpuacct").mkdir()
    (tmp_path / "cpuacct/cpuacct.usage").write_text("999999999")
    result = resource.snapshot("0::" + GROUP + "\n1:cpu:" + GROUP + "\n2:cpuacct:/\n3:memory:" + GROUP + "\n4:pids:" + GROUP,
                               root=tmp_path)
    assert result["cpu_usage_nsec"] == 123000 and result["cpu_source"] == "cgroup2_cpu_stat"
    assert result["memory_peak_bytes"] == 8192 and result["memory_source"] == "cgroup1_memory_peak"
    assert result["cpu_quota_percent"] == 25 and result["throttled_periods"] == 4
    assert result["memory_limit_hits"] == 9 and result["tasks_limit"] == 8


def test_unified_memory_and_cpuacct_fallback(tmp_path):
    write(tmp_path, "", "memory.peak", "4096")
    write(tmp_path, "", "memory.max", "65536")
    write(tmp_path, "", "memory.events", "oom_kill 1")
    write(tmp_path, "cpuacct", "cpuacct.usage", "999")
    value = resource.snapshot("0::" + GROUP + "\n2:cpuacct:" + GROUP, root=tmp_path)
    assert value["cpu_usage_nsec"] == 999 and value["cpu_source"] == "cgroup1_cpuacct"
    assert value["memory_peak_bytes"] == 4096 and value["memory_source"] == "cgroup2_memory_peak"
    assert value["memory_oom_kills"] == 1


@pytest.mark.parametrize("value", ["/", "", "relative", "/../secret", "/a/../b", "/a//b", "/a/./b", "/a\x00b"])
def test_bad_paths_never_read_host_or_private_files(tmp_path, value):
    with pytest.raises(ValueError):
        resource.group_path(value)
    assert resource.snapshot("0::" + value, root=tmp_path) == resource.EMPTY


@pytest.mark.parametrize("value", ["[not set]", "max", "-1", "1e3", "NaN", "18446744073709551615", "5\nsecret"])
def test_invalid_and_unlimited_numbers_remain_missing(value):
    assert resource.number(value) is None


def test_zero_is_observed_but_missing_is_not_zero(tmp_path):
    write(tmp_path, "unified", "cpu.stat", "usage_usec 0")
    result = resource.snapshot("0::" + GROUP, root=tmp_path)
    assert result["cpu_usage_nsec"] == 0 and result["memory_peak_bytes"] is None
    assert resource.snapshot("", root=tmp_path) == resource.EMPTY


def test_final_link_oversize_and_duplicate_stats_are_not_observations(tmp_path):
    private = tmp_path / "private"
    private.write_text("123456")
    path = write(tmp_path, "unified", "cpu.stat", "x")
    path.unlink()
    path.symlink_to(private)
    assert resource.snapshot("0::" + GROUP, root=tmp_path)["cpu_usage_nsec"] is None
    path.unlink()
    path.write_text("usage_usec 5\nusage_usec 6")
    assert resource.snapshot("0::" + GROUP, root=tmp_path)["cpu_usage_nsec"] is None
    path.write_text("x" * 4097)
    assert resource.snapshot("0::" + GROUP, root=tmp_path)["cpu_usage_nsec"] is None


@pytest.mark.parametrize("change", [
    {"invocation_id": "b" * 32}, {"kind": "health"}, {"worker_succeeded": "true"},
    {"worker_succeeded": False}, {"stderr": "private"}, {"schema": "old"},
    {"metrics": resource.EMPTY | {"cpu_usage_nsec": 1}},
    {"metrics": resource.EMPTY | {"memory_peak_bytes": True, "memory_source": "cgroup1_memory_peak"}},
    {"metrics": resource.EMPTY | {"cpu_quota_percent": float("nan")}},
])
def test_receipt_scope_types_and_provenance(change):
    with pytest.raises(ValueError):
        resource.validate(valid() | change, kind="collector", invocation=ID)


@pytest.mark.parametrize("exit_code", [None, 0, 73, "private"])
def test_wrapper_keeps_output_exit_and_argv_without_echoing_arguments(monkeypatch, capsys, exit_code):
    original = sys.argv
    observed = []
    def run(module, **kwargs):
        assert sys.argv == ["scripts.collect_shared_execution", "private-key-argument"]
        print("original worker output")
        raise SystemExit(exit_code)
    monkeypatch.setattr(worker.runpy, "run_module", run)
    monkeypatch.setattr(worker, "emit", lambda kind, ok: observed.append((kind, ok)))
    with pytest.raises(SystemExit) as error:
        worker.main(["scripts.collect_shared_execution", "private-key-argument"])
    assert error.value.code == exit_code and sys.argv is original
    assert observed == [("collector", exit_code in (None, 0))]
    assert capsys.readouterr().out == "original worker output\n"


def test_metric_failure_does_not_replace_worker_failure(monkeypatch):
    def run(*args, **kwargs):
        raise SystemExit(73)
    def emit(*args):
        raise OSError("private")
    monkeypatch.setattr(worker.runpy, "run_module", run)
    monkeypatch.setattr(worker, "emit", emit)
    with pytest.raises(SystemExit) as error:
        worker.main(["scripts.collect_shared_execution"])
    assert error.value.code == 73


def test_journal_must_bind_current_invocation_and_exactly_one_receipt(monkeypatch):
    monkeypatch.setattr(parent, "property_value", lambda unit, name: ID if name == "InvocationID" else "[not set]")
    rows = [{"_SYSTEMD_INVOCATION_ID": "b" * 32, "MESSAGE": resource.PREFIX + json.dumps(valid())},
            {"_SYSTEMD_INVOCATION_ID": ID, "MESSAGE": resource.PREFIX + json.dumps(valid())}]
    def run(*args, **kwargs):
        return SimpleNamespace(stdout=b"\n".join(json.dumps(r).encode() for r in rows))
    monkeypatch.setattr(parent.subprocess, "run", run)
    observed = parent.accounting("owned.service", "collector")
    assert observed["CPUUsageNSec"] == 5000 and observed["MemoryPeak"] == 8192
    rows.append(rows[-1])
    with pytest.raises(ValueError, match="missing_or_duplicate"):
        parent.accounting("owned.service", "collector")
