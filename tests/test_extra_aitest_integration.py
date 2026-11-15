"""Integration preserves canonical approval quorum and optional legacy backup data."""

import shutil
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.services.behavior_context_store import BehaviorContextStore
from app.services.response_actions import ResponseConflict, ResponseService
from scripts import app_state_recovery as recovery
from scripts import behavior_context_recovery as context_storage
from scripts import response_storage_contract as legacy_storage
from scripts.app_recovery_fixture import prepare
from scripts.app_storage_fixture import seed_logs
from tests import test_response_actions as canonical_cases
from tests.test_response_actions import approved, command
from tests.test_response_storage_recovery import seed as seed_legacy


def test_main_exposes_canonical_response_api_without_legacy_approval_bypass():
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/response/requests" in paths
    assert not any(path.startswith("/response/plans") for path in paths)


@pytest.fixture
def combined_recovery(tmp_path, monkeypatch):
    env = canonical_cases.response_lab.__wrapped__(tmp_path, monkeypatch)
    pending = approved(env, "canonical-pending")
    original = env.lab.store.read("tenant-a")
    root = tmp_path / "combined-recovery"
    source = root / "data"
    source.mkdir(parents=True)
    for original_path, name in ((env.lab.operations_path, "app.sqlite3"),
                                (env.lab.store_path, context_storage.NAME),
                                (env.lab.registry_path, "sources.json")):
        shutil.copyfile(original_path, source / name)
    seed_logs(source)
    legacy = seed_legacy(source)
    env.lab.clock.now = env.lab.at(6)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            instant = env.lab.clock.now
            return instant.astimezone(tz) if tz else instant.replace(tzinfo=None)

    monkeypatch.setattr(recovery, "datetime", Clock)
    store = recovery.Store(root)
    store.initialize(full_state=True, response_state=True)
    store.checkpoint()
    saved = store.backup()
    return SimpleNamespace(env=env, pending=pending, original=original, root=root,
                           source=source, legacy=legacy, store=store, saved=saved)


def test_combined_restore_preserves_canonical_quorum_and_fences_legacy_plans(combined_recovery):
    lab = combined_recovery
    result = lab.store.restore(lab.saved["backup_id"])
    stage = lab.root / "restores" / result["restore_id"]
    context = BehaviorContextStore(stage / context_storage.NAME)
    canonical = ResponseService(context, recovery.operations(stage))
    view = canonical.get(lab.pending["request_id"], lab.env.requester)
    assert view["required_approvals"] == 2
    assert view["approved_by"] == ["reviewer-a", "reviewer-b"]
    assert view["status"] == "STALE"
    with pytest.raises(ResponseConflict):
        canonical.execute(view["request_id"], command(view), lab.env.requester)
    assert context.read("tenant-a") == lab.original
    assert result["context_preserved"] and result["response_plans_fenced"] == 4
    assert legacy_storage.inspect(stage)["count"] == len(lab.legacy)
    assert recovery.verify_admission(stage, lab.store.public)["admission_verified"]


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_aggregate_backup_limit_includes_both_context_and_legacy_database(
    combined_recovery, monkeypatch, operation,
):
    lab = combined_recovery
    limit = lab.saved["component_bytes"] - (lab.source / legacy_storage.FILE).stat().st_size
    assert limit > (lab.source / context_storage.NAME).stat().st_size
    monkeypatch.setattr(recovery, "MAX_BACKUP_COMPONENT_BYTES", limit)
    with pytest.raises(recovery.RecoveryError, match="backup_components_size_limit"):
        if operation == "backup":
            lab.store.backup()
        else:
            lab.store.restore(lab.saved["backup_id"])
    assert recovery.read_json(lab.store.public / "current.json")["restore_id"] is None


@pytest.mark.parametrize("full_state,response_state", [(False, False), (True, False), (True, True)])
def test_modified_legacy_inspector_invalidates_checkpoint_even_without_legacy_database(
    tmp_path, monkeypatch, recovery_clock, full_state, response_state,
):
    code = tmp_path / "code"
    (code / "scripts").mkdir(parents=True)
    for name in ("app_state_recovery.py", "app_storage_contract.py", "serve_recovered_app.py",
                 "behavior_context_recovery.py", "response_storage_contract.py"):
        shutil.copyfile(recovery.ROOT / "scripts" / name, code / "scripts" / name)
    application_digest = recovery.app_digest()
    monkeypatch.setattr(recovery, "ROOT", code)
    monkeypatch.setattr(recovery, "app_digest", lambda: application_digest)
    root = tmp_path / "lab"
    source = root / "data"
    prepare(source)
    if full_state:
        seed_logs(source)
    if response_state:
        seed_legacy(source)
    store = recovery.Store(root)
    store.initialize(full_state=full_state, response_state=response_state)
    store.checkpoint()
    inspector = code / "scripts/response_storage_contract.py"
    inspector.write_bytes(inspector.read_bytes() + b"\n# changed admission implementation\n")
    with pytest.raises(recovery.RecoveryError, match="application_version_mismatch"):
        store.backup()
