"""Short tests exercise qualification rules; never substitute for eight real hours."""

import json
from types import SimpleNamespace

import pytest

from scripts.f1_lab import native_soak as module
from scripts.run_systemd_collector_runtime import run


@pytest.mark.parametrize("mode,seconds", [("soak", 1), ("soak", 3600), ("soak", True),
    ("soak", 8.0 * 3600), ("preflight", 59), ("preflight", 601), ("unknown", 28800)])
def test_closed_profiles(mode, seconds):
    with pytest.raises(ValueError, match="soak_profile"):
        module.SoakProfile(mode, seconds)


@pytest.mark.parametrize("seconds", [601, 28800, True])
def test_original_short_mode_limits_are_not_widened(tmp_path, seconds):
    path = tmp_path / "never-created"
    with pytest.raises(ValueError, match="load_duration"):
        run(path, load_seconds=seconds)
    assert not path.exists()


@pytest.fixture
def clock(monkeypatch):
    value = SimpleNamespace(now=0.0, suspend=0.0, boot="same")
    monkeypatch.setattr(module, "clocks", lambda: (value.now, value.now + value.suspend))
    monkeypatch.setattr(module, "boot_id", lambda: value.boot)
    return value


def sample(cycle):
    return {"cycle": cycle, "logical_bytes": 4096, "allocated_file_bytes": 8192,
        **{name: {"CPUUsageNSec": 10, "MemoryPeak": 4096}
           for name in ("collector_accounting", "archive", "health")}}


def test_preflight_can_complete_but_never_claims_real_eight_hours(tmp_path, clock):
    progress = module.Progress(tmp_path, module.SoakProfile("preflight", 60))
    try:
        for index in range(12):
            clock.now = index * 5 + 1
            progress.add(sample(index + 1))
        clock.now = 60
        result = progress.finish()
        assert result["long_soak_8h_completed"] is False and result["cycles"] == 12
        progress.close(True)
        state = json.loads(progress.path.read_bytes())
        assert state["completed"] is True and state["long_soak_8h_completed"] is False
        rows = [json.loads(row) for row in progress.log.read_bytes().splitlines()]
        assert rows[-1]["sha256"] == result["sample_chain_head"]
        assert rows[0]["payload"]["previous"] == "0" * 64
        assert rows[-1]["payload"]["previous"] == rows[-2]["sha256"]
        module.verify_samples(progress.log, 12, result["sample_chain_head"])
        progress.log.write_bytes(progress.log.read_bytes().replace(b'"CPUUsageNSec":10', b'"CPUUsageNSec":11', 1))
        with pytest.raises(ValueError, match="log_digest"):
            module.verify_samples(progress.log, 12, result["sample_chain_head"])
    except BaseException:
        progress.close(False)
        raise


@pytest.mark.parametrize("failure", ["gap", "suspend", "boot", "regression", "capacity", "metric", "order"])
def test_interruption_or_missing_evidence_cannot_qualify(tmp_path, clock, failure):
    progress = module.Progress(tmp_path, module.SoakProfile("soak", 28800))
    row = sample(1)
    if failure == "gap": clock.now = 61
    elif failure == "suspend": clock.suspend = 6
    elif failure == "boot": clock.boot = "different"
    elif failure == "regression": clock.now = -1
    elif failure == "capacity": row["logical_bytes"] = 129 * 1024**2
    elif failure == "metric": row["health"]["MemoryPeak"] = None
    elif failure == "order": row["cycle"] = 2
    with pytest.raises(ValueError):
        progress.add(row)
    progress.close(False)
    state = json.loads(progress.path.read_bytes())
    assert state["state"] == "interrupted_or_failed" and state["completed"] is False
    assert state["long_soak_8h_completed"] is False and state["resume_supported"] is False


def test_elapsed_time_alone_cannot_replace_sample_coverage(tmp_path, clock):
    progress = module.Progress(tmp_path, module.SoakProfile("soak", 28800))
    clock.now = 28800
    with pytest.raises(ValueError, match="coverage_short"):
        progress.finish()
    progress.close(False)


def test_evidence_paths_cannot_be_reused_as_a_resume(tmp_path, clock):
    progress = module.Progress(tmp_path, module.SoakProfile("preflight", 60))
    progress.close(False)
    with pytest.raises(FileExistsError):
        module.Progress(tmp_path, module.SoakProfile("preflight", 60))
