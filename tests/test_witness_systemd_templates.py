"""Optional Linux service contracts; no host installation in unit tests."""

import configparser
from pathlib import Path

import pytest

from app.services.audit_transfer import AuditTransferError
from scripts import run_witness_systemd_controls as controls
from scripts import witness_systemd_probe as probe

ROOT = Path(__file__).resolve().parents[1] / "infra/systemd"


def unit(name):
    # systemd permits repeated Environment=; keep parsing of repeated keys local
    # to this static contract rather than modifying production templates.
    result = configparser.RawConfigParser(strict=False)
    result.optionxform = str
    result.read(ROOT / name, encoding="utf-8")
    return result


@pytest.mark.parametrize("name,memory", [("secops-audit-witness@.service", "512M"),
                                        ("secops-audit-witness-restore-status@.service", "256M")])
def test_service_runs_without_network_capabilities_or_extra_process_inspection(name, memory):
    service = unit(name)["Service"]
    for key, expected in {"User": "secops-witness", "Group": "secops-witness", "NoNewPrivileges": "yes",
                          "CapabilityBoundingSet": "", "AmbientCapabilities": "", "PrivateNetwork": "yes",
                          "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateDevices": "yes",
                          "StandardInput": "null", "TasksMax": "8", "MemoryMax": memory,
                          "RestrictAddressFamilies": "AF_UNIX", "RestrictNamespaces": "yes"}.items():
        assert service[key] == expected
    assert "ptrace" in service["SystemCallFilter"] and "pidfd_getfd" in service["SystemCallFilter"]
    assert service["SystemCallErrorNumber"] == "EPERM"
    assert "/proc" in service["InaccessiblePaths"].split()
    assert not any(word in service["ExecStart"] for word in ("/bin/sh", "curl ", "init ", "latest", "restore --"))


def test_collector_reuses_pinned_pending_state_and_protects_source_and_signing_key_writes():
    service = unit("secops-audit-witness@.service")["Service"]
    assert service["Type"] == "simple" and service["Restart"] == "on-failure"
    assert "scripts.audit_witness_observer watch" in service["ExecStart"]
    assert "${WITNESS_PROFILE_SHA256}" in service["ExecStart"]
    assert "${WITNESS_MINIMUM_RECEIPT}" in service["ExecStart"]
    assert "--status-file" in service["ExecStart"]
    assert "/var/lib/secops-audit" in service["ReadOnlyPaths"].split()
    assert "/var/lib/secops-audit-witness/%i/signer/private.key" in service["ReadOnlyPaths"].split()
    assert service["ReadWritePaths"].split() == ["/var/lib/secops-audit-witness/%i/control",
                                                "/var/lib/secops-audit-witness/%i/signer",
                                                "/var/cache/secops-audit-witness/%i"]


def test_keyless_checker_can_write_only_aggregate_cache_and_has_no_key_argument():
    service = unit("secops-audit-witness-restore-status@.service")["Service"]
    assert service["Type"] == "oneshot" and "scripts.witness_restore_status" in service["ExecStart"]
    assert "--key-file" not in service["ExecStart"] and "LoadCredential" not in service
    assert "${WITNESS_RESTORE_RECEIPT_SHA256}" in service["ExecStart"]
    assert "${WITNESS_BACKUP_SHA256}" in service["ExecStart"]
    assert service["ReadWritePaths"] == "/var/cache/secops-audit-witness-restore/%i"
    assert "-/var/lib/secops-audit-witness" in service["InaccessiblePaths"].split()
    assert "-/var/lib/secops-audit" in service["InaccessiblePaths"].split()


def test_timer_is_finite_cadence_and_never_replays_missed_checks_as_fresh():
    timer = unit("secops-audit-witness-restore-status@.timer")["Timer"]
    assert timer["OnUnitInactiveSec"] == "15s" and timer["Persistent"] == "no"
    assert timer["Unit"] == "secops-audit-witness-restore-status@%i.service"


def test_controller_rejects_unsupported_identity_before_creating_output(tmp_path, monkeypatch):
    if controls.os.name == "posix":
        monkeypatch.setattr(controls.os, "geteuid", lambda: 1000)
    output = tmp_path / "not-created"
    with pytest.raises(AuditTransferError, match="root_required"):
        controls.run(output)
    assert not output.exists()


def test_nonlinux_probe_rejects_before_opening_any_file(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.os, "name", "nt")
    with pytest.raises(ValueError, match="Linux"):
        probe.probe(str(tmp_path / "audit"), str(tmp_path / "key"), str(tmp_path / "cache"))
