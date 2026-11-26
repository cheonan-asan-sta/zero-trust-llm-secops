"""Unsupported native guarantees must reject before accessing or changing state."""

import os
from types import SimpleNamespace

import pytest

from scripts import behavior_execution_collector as collector
from scripts import mtls_app_recovery as recovery
from scripts.app_state_recovery import RecoveryError
from scripts.f1_lab import capture_backup, credential_peer_service, exec_history


def test_native_exec_refuses_non_linux_without_fork(monkeypatch):
    monkeypatch.setattr(exec_history.sys, "platform", "win32")
    with pytest.raises(ValueError, match="exec_history_linux_configuration"):
        exec_history.collect_owned_exec(None, [], None, source_id="local", key_id="local")


def test_kernel_peer_cannot_authenticate_without_peer_credentials(monkeypatch):
    monkeypatch.setattr(credential_peer_service, "socket", SimpleNamespace())
    with pytest.raises(ValueError, match="credential_peer_kernel_identity"):
        credential_peer_service.peer_service(None, "fixture.service")


@pytest.mark.parametrize("operation", ["file", "directory"])
def test_private_archive_requires_posix_identity_before_file_access(monkeypatch, operation):
    with monkeypatch.context() as patch:
        patch.delattr(os, "geteuid", raising=False)
        with pytest.raises(ValueError, match="capture_backup_posix_required"):
            if operation == "file":
                capture_backup.private_file("missing-not-created", 100)
            else:
                capture_backup.private_directory("missing-not-created")


@pytest.mark.parametrize("operation", ["restore", "sync"])
def test_mtls_recovery_requires_directory_durability_before_state_access(monkeypatch, operation):
    with monkeypatch.context() as patch:
        patch.delattr(os, "O_DIRECTORY", raising=False)
        with pytest.raises(RecoveryError, match="mtls_recovery_posix_required"):
            if operation == "restore":
                recovery.restore()
            else:
                recovery.sync_directory("missing-not-created")


@pytest.mark.skipif(os.name == "posix", reason="Actual non-POSIX durability rejection")
def test_durable_input_is_not_silently_accepted_on_windows(tmp_path):
    path = tmp_path / "must-remain-missing"
    with pytest.raises(ValueError, match="durable_input_requires_posix"):
        collector.read_private(path, durable=True)
    assert not path.exists()
