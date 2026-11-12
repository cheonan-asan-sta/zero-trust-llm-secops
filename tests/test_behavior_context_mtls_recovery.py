"""Exercise the stopped Docker job logic locally, without starting containers."""

import json

import pytest

from app.services.behavior_context_store import BehaviorContextStore, ContextStoreUnavailable
from scripts import app_state_recovery as recovery
from scripts import behavior_context_recovery as context
from scripts import mtls_app_recovery as manager
from scripts.app_recovery_fixture import prepare, verify
from scripts.app_storage_fixture import seed_behavior_context, seed_logs


def test_frozen_source_preserves_nonempty_context_and_never_writes_source(tmp_path):
    source, frozen = tmp_path / "source", tmp_path / "frozen"
    prepare(source)
    seed_logs(source)
    rows = seed_behavior_context(source)
    frozen.mkdir()
    before = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    manager.frozen_source(source, frozen)
    assert BehaviorContextStore(frozen / context.NAME).read("recovery-tenant") == rows
    assert context.inspect(frozen) == context.inspect(source)
    assert {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()} == before
    assert recovery.storage.inspect(frozen) == recovery.storage.inspect(source)


def test_frozen_missing_context_becomes_empty_only_in_private_copy(tmp_path):
    source, frozen = tmp_path / "source", tmp_path / "frozen"
    prepare(source)
    frozen.mkdir()
    manager.frozen_source(source, frozen)
    assert not (source / context.NAME).exists()
    assert context.inspect(frozen)["records"] == 0


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_frozen_context_refuses_unclean_source_instead_of_ignoring_sidecars(tmp_path, suffix):
    source, frozen = tmp_path / "source", tmp_path / "frozen"
    prepare(source)
    seed_behavior_context(source)
    (source / (context.NAME + suffix)).write_bytes(b"unrecovered SQLite state")
    frozen.mkdir()
    before = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    with pytest.raises(ContextStoreUnavailable, match="sidecars"):
        manager.frozen_source(source, frozen)
    assert not list(frozen.iterdir())
    assert {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()} == before


def test_mtls_job_retries_same_backup_and_preserves_context_after_publication_failure(
    tmp_path, recovery_clock, monkeypatch,
):
    source = tmp_path / "source"
    prepare(source)
    seed_logs(source)
    rows = seed_behavior_context(source)
    authority, public, destination = (tmp_path / name for name in ("authority", "public", "restored"))
    for path in (authority, public, destination):
        path.mkdir()
    (public / "phase.json").write_text(json.dumps({"phase": "maintenance"}))
    original = manager.atomic

    def interrupt(path, body):
        if path == public / "phase.json":
            raise OSError("injected approval publication failure")
        original(path, body)

    monkeypatch.setattr(manager, "atomic", interrupt)
    arguments = {"authority": authority, "source": source, "registry": source / "sources.json",
                 "public": public, "destination": destination}
    with pytest.raises(OSError, match="publication failure"):
        manager.restore(**arguments)
    backup = (authority / "backup.json").read_bytes()
    assert manager.phase(public) == {"phase": "maintenance"}
    monkeypatch.setattr(manager, "atomic", original)
    result = manager.restore(**arguments)
    active = destination / "active"
    assert result == manager.phase(public)
    assert result["phase"] == "approved"
    assert (authority / "backup.json").read_bytes() == backup
    assert BehaviorContextStore(active / context.NAME).read("recovery-tenant") == rows
    assert BehaviorContextStore(source / context.NAME).read("recovery-tenant") == rows
    assert recovery.verify_admission(active, public)["admission_verified"]
    assert verify(active, source)["old_grants_denied"] == 3

