import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from scripts.f1_lab.systemd_request_launcher import SystemdUnitLauncher, UnitTarget
from scripts.run_systemd_caller_controls import setup_broker


def fixture(tmp_path):
    keys, _, _, broker = setup_broker(tmp_path / "evidence", "fixture.service")
    target = UnitTarget("local-lab", "shared-lab", "fixture.service", "a" * 64, "b" * 64)
    launcher = SystemdUnitLauncher(
        [target], keys["runtime"], source_id="local-proc", key_id="proc-1"
    )
    request = broker.issue(
        tenant_id="local-lab",
        server_id="shared-lab",
        unit="fixture.service",
        executable_sha256="a" * 64,
        command_sha256="b" * 64,
        now=datetime.now(UTC),
    )
    return launcher, request


@pytest.mark.parametrize(
    "state",
    [
        b"Id=fixture.service\nLoadState=loaded\nActiveState=active\nMainPID=42\nInvocationID=111\nJob=\n",
        b"Id=fixture.service\nLoadState=not-found\nActiveState=inactive\nMainPID=0\nInvocationID=\nJob=\n",
        b"Id=fixture.service\nLoadState=loaded\nActiveState=activating\nMainPID=0\nInvocationID=\nJob=\n",
        b"Id=other.service\nLoadState=loaded\nActiveState=inactive\nMainPID=0\nInvocationID=\nJob=\n",
        b"Id=fixture.service\nId=fixture.service\nLoadState=loaded\nActiveState=inactive\nMainPID=0\nInvocationID=\nJob=\n",
    ],
)
def test_never_starts_existing_unknown_or_ambiguous_unit(tmp_path, monkeypatch, state):
    launcher, request = fixture(tmp_path)
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=state)

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ValueError):
        launcher.launch(request)
    assert len(calls) == 1 and calls[0][1] == "show"


def test_only_exact_allowlisted_unit_is_started_without_shell(tmp_path, monkeypatch):
    launcher, request = fixture(tmp_path)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=b"Id=fixture.service\nLoadState=loaded\nActiveState=inactive\nMainPID=0\nInvocationID=\nJob=\n",
        )

    monkeypatch.setattr(subprocess, "run", run)
    launcher.launch(request)
    assert calls[1][0] == ["/usr/bin/systemctl", "start", "--", "fixture.service"]
    assert not calls[1][1].get("shell") and "LD_PRELOAD" not in calls[1][1]["env"]
    for field, value in [
        ("unit", "other.service"),
        ("unit", "--help"),
        ("command_sha256", "c" * 64),
    ]:
        with pytest.raises(ValueError):
            launcher.launch(request.model_copy(update={field: value}))
    assert len(calls) == 2


def test_timeout_is_not_retried_by_launcher(tmp_path, monkeypatch):
    launcher, request = fixture(tmp_path)
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "start":
            raise subprocess.TimeoutExpired(argv, 10)
        return SimpleNamespace(
            returncode=0,
            stdout=b"Id=fixture.service\nLoadState=loaded\nActiveState=inactive\nMainPID=0\nInvocationID=\nJob=\n",
        )

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(subprocess.TimeoutExpired):
        launcher.launch(request)
    assert len(calls) == 2
