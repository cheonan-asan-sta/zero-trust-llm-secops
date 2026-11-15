import math
import os
import sys

import pytest

from scripts.f1_lab.capture_load import (
    SignedStorageLab,
    disk_pressure,
    distribution,
    footprint,
    inventory,
    run,
)
from scripts.f1_lab.native_jsonl import decode

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() == 0,
    reason="Linux nonroot worker, cooperative locks and readonly storage faults",
)


def test_real_pipeline_faults_and_worker_exit_preserve_every_original(tmp_path):
    result = run(tmp_path / "lab", cycles=6, batch=2)
    assert result["completed"] and result["pipeline_captures"] == 12
    assert result["captures_including_fault_probe"] == 13
    assert result["expected_inventory_sha256"] == result["actual_inventory_sha256"]
    assert result["fault_controls"]["actual_worker_exit_after_commit"] == 73
    assert result["fault_controls"]["lock_wait_seconds"] >= 4.5
    assert not result["long_soak_8h_completed"]
    assert not result["authorization_checked"] and not result["automatic_enforcement_allowed"]
    assert len(inventory(tmp_path / "lab/store")) == 13
    assert decode((tmp_path / "lab/run.json").read_bytes())["completed"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"cycles": 2},
        {"cycles": True},
        {"cycles": 4097},
        {"cycles": 3, "batch": 1},
        {"batch": 0},
        {"batch": 65},
        {"cycles": 4096, "batch": 2},
        {"interval": math.inf},
        {"interval": math.nan},
        {"interval": -1},
        {"interval": True},
    ],
)
def test_bad_workload_never_creates_runtime(tmp_path, arguments):
    destination = tmp_path / "not-created"
    with pytest.raises(ValueError):
        run(destination, **arguments)
    assert not destination.exists()


def test_existing_output_and_ordinary_filesystem_are_never_filled(tmp_path):
    marker = tmp_path / "keep"
    marker.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        run(tmp_path)
    with pytest.raises(ValueError, match="load_pressure_tmpfs"):
        disk_pressure(tmp_path)
    assert marker.read_bytes() == b"existing" and set(tmp_path.iterdir()) == {marker}


def test_footprint_refuses_link_instead_of_following_external_file(tmp_path):
    (tmp_path / "link").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="load_unexpected_link"):
        footprint(tmp_path)


def test_changed_signature_cannot_be_counted_as_healthy_work(tmp_path):
    lab = SignedStorageLab(tmp_path)
    lab.write()
    latest = lab.root / "latest.json"
    payload = decode(latest.read_bytes())
    payload["runtime_proof"]["signature"] = "A" * 86
    from scripts.f1_lab.operation_context import canonical

    latest.write_bytes(canonical(payload))
    with pytest.raises(ValueError, match="load_health_not_fresh"):
        lab.health()


def test_latency_uses_nearest_rank_without_hiding_tail():
    result = distribution(list(range(1, 21)))
    assert result == {"samples": 20, "min": 1, "p50": 10, "p95": 19, "max": 20}
    with pytest.raises(ValueError):
        distribution([1, math.nan])
