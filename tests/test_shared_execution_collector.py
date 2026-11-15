import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from scripts.f1_lab import shared_execution_collector as collector
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_shared_execution_controls import setup
from tests.test_shared_execution_evidence import bundle


def stat_blob(pid=42, start=100, parent=0):
    fields = ["S", str(parent)] + ["0"] * 17 + [str(start)]
    return (f"{pid} (odd ) process name) " + " ".join(fields)).encode()


def test_proc_stat_uses_start_time_not_pid_alone_and_handles_parentheses():
    assert collector.process_tag(stat_blob(), 42) == (0, 100)
    with pytest.raises(ValueError):
        collector.process_tag(stat_blob(pid=43), 42)
    with pytest.raises(ValueError):
        collector.process_tag(stat_blob(start=0), 42)
    with pytest.raises(ValueError):
        collector.process_tag(b"42 (name) Z 0", 42)


@pytest.mark.parametrize(
    "value,expected", [(b"4294967295\n", None), (b"0\n", 0), (b"1001\n", 1001)]
)
def test_audit_login_identity_does_not_default_unknown_to_root(tmp_path, value, expected):
    path = tmp_path / "loginuid"
    path.write_bytes(value)
    assert collector.optional_audit_id(path) == expected
    assert collector.optional_audit_id(tmp_path / "missing") is None


@pytest.mark.parametrize(
    "body", [b"Uid:\t0 0 0\n", b"Uid:\t0 0 0 0\nUid:\t1 1 1 1\n", b"Uid:\t-1 0 0 0\n"]
)
def test_incomplete_or_conflicting_uid_values_are_rejected(body):
    with pytest.raises(ValueError):
        collector.process_uids(body)


def native_record():
    return {
        "_BOOT_ID": "1" * 32,
        "_SYSTEMD_INVOCATION_ID": "2" * 32,
        "_SYSTEMD_UNIT": "shared-fixture.service",
        "_PID": "42",
        "__CURSOR": "native-cursor-1",
        "__REALTIME_TIMESTAMP": "1794628800000000",
    }


def test_native_journal_fields_bind_boot_invocation_pid_and_exact_raw_bytes():
    raw = canonical(native_record()) + b"\n"
    event = collector.journal_event(raw, tenant_id="tenant", server_id="server")
    assert event and event.process_id == 42 and event.mode == "systemd" and event.raw_sha256
    assert event.boot_id == "1" * 32 and event.invocation_id == "2" * 32
    assert (
        collector.journal_event(
            b"type=SERVICE_START unit=unknown", tenant_id="tenant", server_id="server"
        )
        is None
    )


@pytest.mark.parametrize(
    "field",
    [
        "_BOOT_ID",
        "_SYSTEMD_INVOCATION_ID",
        "_SYSTEMD_UNIT",
        "_PID",
        "__CURSOR",
        "__REALTIME_TIMESTAMP",
    ],
)
@pytest.mark.parametrize("mode", ["missing", "duplicate_array", "null"])
def test_native_fields_are_not_guessed_from_untrusted_aliases(field, mode):
    data = native_record()
    value = data.pop(field)
    data[field.removeprefix("_")] = value
    if mode == "duplicate_array":
        data[field] = [value, value]
    elif mode == "null":
        data[field] = None
    assert collector.journal_event(canonical(data), tenant_id="tenant", server_id="server") is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("_BOOT_ID", "0" * 32),
        ("_SYSTEMD_INVOCATION_ID", "0" * 32),
        ("_PID", "0"),
        ("_SYSTEMD_UNIT", "init.scope"),
        ("_SYSTEMD_UNIT", "--evil.service"),
        ("__CURSOR", ""),
    ],
)
def test_unusable_native_values_do_not_become_valid_events(field, value):
    data = {**native_record(), field: value}
    assert collector.journal_event(canonical(data), tenant_id="tenant", server_id="server") is None


@pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc reader")
@pytest.mark.parametrize("mode", ["pid_reuse", "uid_change", "command_change", "truncated_command"])
def test_proc_snapshot_rejects_process_changes_during_capture(monkeypatch, mode):
    calls = {}

    def read(path, maximum):
        name = Path(path).name
        calls[name] = calls.get(name, 0) + 1
        if name == "stat":
            return stat_blob(start=101 if mode == "pid_reuse" and calls[name] > 1 else 100)
        if name == "status":
            return (
                b"Uid:\t1 1 1 1\n"
                if mode == "uid_change" and calls[name] > 1
                else b"Uid:\t10001 10001 10001 10001\n"
            )
        if name == "cmdline":
            if mode == "truncated_command":
                return b"unterminated"
            return (
                b"changed\0"
                if mode == "command_change" and calls[name] > 1
                else b"python\0fixture\0"
            )
        return b"4294967295\n"

    monkeypatch.setattr(collector, "bounded", read)
    monkeypatch.setattr(collector, "boot_id", lambda: "1" * 32)
    monkeypatch.setattr(collector, "executable_hash", lambda _: "a" * 64)
    with pytest.raises(ValueError):
        collector.snapshot_process(42)


def test_executable_read_has_a_bound_and_does_not_execute_the_file(tmp_path):
    binary = tmp_path / "data"
    binary.write_bytes(b"not an executable; only hashed")
    assert len(collector.executable_hash(binary)) == 64
    with binary.open("wb") as stream:
        stream.truncate(128 * 1024**2 + 1)
    with pytest.raises(ValueError):
        collector.executable_hash(binary)


def test_systemctl_collector_exposes_only_fixed_read_operations(monkeypatch):
    def run(argv, **kwargs):
        assert argv == [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=Id,MainPID,InvocationID",
            "--",
            "shared-fixture.service",
        ]
        assert "shell" not in kwargs and kwargs["timeout"] == 5
        assert not any(name.startswith(("DBUS_", "LD_")) for name in kwargs["env"])
        return SimpleNamespace(
            returncode=0,
            stdout=b"Id=shared-fixture.service\nMainPID=42\nInvocationID=" + b"2" * 32 + b"\n",
        )

    monkeypatch.setattr(collector.subprocess, "run", run)
    assert collector.manager_state("shared-fixture.service") == (42, "2" * 32)
    for unit in ["--bad.service", "../bad.service", "bad.service;id", "bad\n.service"]:
        with pytest.raises(ValueError):
            collector.manager_state(unit)


@pytest.mark.parametrize("mode", ["restart", "pid", "boot", "mode"])
def test_manager_and_proc_must_agree_before_signing(tmp_path, monkeypatch, mode):
    keys, _, _, event, proofs, _, _ = bundle(tmp_path)
    event = event.model_copy(
        update={
            "mode": "systemd" if mode != "mode" else "local_process_lab",
            "collection_basis": "manager_snapshot" if mode != "mode" else "local_process_lab",
        }
    )
    states = iter(
        [(43 if mode == "pid" else 42, "2" * 32), (42, "3" * 32 if mode == "restart" else "2" * 32)]
    )
    monkeypatch.setattr(collector, "manager_state", lambda _: next(states))
    monkeypatch.setattr(
        collector,
        "snapshot_process",
        lambda _: ("3" * 32 if mode == "boot" else "1" * 32, proofs[0].observation),
    )
    monkeypatch.setattr(
        collector, "runtime_proof", lambda *a, **kw: pytest.fail("must not sign unbound facts")
    )
    with pytest.raises(ValueError):
        collector.collect_systemd(event, keys["runtime"], source_id="local-proc", key_id="proc-1")


def test_quiet_service_can_be_collected_as_a_new_manager_snapshot(tmp_path, monkeypatch):
    keys, _, _, _, proofs, _, _ = bundle(tmp_path)
    monkeypatch.setattr(collector, "manager_state", lambda _: (42, "2" * 32))
    monkeypatch.setattr(collector, "boot_id", lambda: "1" * 32)
    monkeypatch.setattr(collector, "snapshot_process", lambda _: ("1" * 32, proofs[0].observation))
    marker = object()
    monkeypatch.setattr(collector, "runtime_proof", lambda *a, **kw: marker)
    event, proof = collector.collect_current_systemd(
        "shared-fixture.service",
        keys["runtime"],
        tenant_id="local-lab",
        server_id="shared-lab",
        source_id="local-proc",
        key_id="proc-1",
    )
    assert (
        event.collection_basis == "manager_snapshot" and event.mode == "systemd" and proof is marker
    )
    assert event.process_id == 42 and event.invocation_id == "2" * 32


def test_cli_rejects_lab_key_for_production_capture_without_persisting_private_key(tmp_path):
    keys, _, pinned = setup(tmp_path / "keys")
    key = keys["runtime"].private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.collect_shared_execution",
            "--tenant",
            "local-lab",
            "--server",
            "shared-lab",
            "--unit",
            "shared-fixture.service",
            "--source",
            "local-proc",
            "--key-id",
            "proc-1",
            "--registry",
            str(pinned.path),
            "--registry-sha256",
            sha(pinned.path),
            "--output",
            str(tmp_path / "capture"),
        ],
        input=key,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 1 and json.loads(result.stdout)["completed"] is False
    assert key not in result.stdout + result.stderr and not (tmp_path / "capture").exists()
