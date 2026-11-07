import json

import pytest

from scripts.app_state_recovery import RecoveryError
from scripts.continuous_mtls_runtime import compose_spec
from scripts.mtls_app_recovery import WRITERS, fence, phase
from scripts.recoverable_mtls_runtime import RECOVERY_VOLUMES, recovery_spec


def test_recovery_topologies_reuse_mtls_and_isolate_the_approved_copy():
    identity = ("kmtls-000000000000", "sha256:" + "0" * 64, "sha256:" + "1" * 64)
    base = compose_spec(*identity)
    original = recovery_spec(*identity, restored=False)
    approved = recovery_spec(*identity, restored=True)
    assert original["networks"] == approved["networks"] == base["networks"]
    assert original["volumes"] == approved["volumes"]
    assert set(approved["volumes"]) - set(base["volumes"]) == set(RECOVERY_VOLUMES)
    for role, service in base["services"].items():
        initial, recovered = original["services"][role], approved["services"][role]
        if role not in WRITERS:
            assert initial == recovered == service
            continue
        assert initial["entrypoint"][-2:] == [role, "original"]
        assert recovered["entrypoint"][-2:] == [role, "approved"]
        for definition in (initial, recovered):
            assert definition["volumes"].count("recovery-public:/admission:ro") == 1
            assert all(not mount.startswith("recovery-authority:") for mount in definition["volumes"])
        if role != "collector":
            assert "data:/data" in initial["volumes"]
            assert "data:/data" not in recovered["volumes"]
            assert "recovered-data:/data" in recovered["volumes"]
            assert recovered["environment"]["ZERO_TRUST_DB_PATH"] == "/data/active/app.sqlite3"


def test_maintenance_is_one_way_and_approval_requires_matching_pin(tmp_path):
    marker = tmp_path / "phase.json"
    marker.write_text(json.dumps({"phase": "original"}))
    assert fence(tmp_path) == phase(tmp_path) == {"phase": "maintenance"}
    with pytest.raises(RecoveryError, match="mtls_recovery_already_fenced"):
        fence(tmp_path)

    approved = {"phase": "approved", "restore_id": "0" * 32}
    marker.write_text(json.dumps(approved))
    pin = tmp_path / "current.json"
    with pytest.raises(RecoveryError, match="regular_file_required"):
        phase(tmp_path)
    pin.write_text(json.dumps({"restore_id": "1" * 32}))
    with pytest.raises(RecoveryError, match="mtls_recovery_pin"):
        phase(tmp_path)
    pin.write_text(json.dumps({"restore_id": approved["restore_id"]}))
    assert phase(tmp_path) == approved
