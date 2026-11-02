"""Driver safety contracts; real Docker/HTTP checks run explicitly through its CLI."""

import json
import stat
import subprocess
from datetime import UTC, datetime

from app.security import Principal, Role
from app.services.trusted_signals import SignalVerifier
from app.zero_trust_models import SignedSessionSignal
from scripts import test_signal_compose as runner


def test_generated_registry_has_separate_authorities_and_private_keys_stay_host_only(tmp_path):
    assets = runner.initialize_assets(tmp_path / "compose-unique")
    registry = json.loads(assets["registry"].read_text("utf-8"))
    session, identity = registry["sources"]
    assert session["observation_kinds"] == [] and identity["observation_kinds"] == ["identity"]
    assert session["keys"][0]["public_key_pem"] != identity["keys"][0]["public_key_pem"]
    assert "PRIVATE KEY" not in assets["registry"].read_text("utf-8")
    assert stat.S_IMODE(assets["registry"].stat().st_mode) == 0o644
    for kind in ("session", "identity"):
        path = assets["directory"] / f"private-{kind}.pem"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.name not in assets["override"].read_text("utf-8")
    verifier = SignalVerifier(assets["registry"])
    principal = Principal("local-operator", "local", frozenset({Role.ADMIN}), "disabled")
    signed = SignedSessionSignal.model_validate(runner.signed_session(
        "session-test", runner.USERS[0], runner.DEVICES[0], assets["keys"]["session"],
    ))
    assert verifier.verify(signed, principal, datetime.now(UTC)).source_id == "m3check-session"
    observation = runner.signed_observation("event-test", runner.USERS[0], assets["keys"]["identity"])
    assert verifier.verify_observation(observation, principal, datetime.now(UTC)).source_id == "m3check-identity"


def test_optional_share_receives_only_public_registry_and_keeps_private_assets_at_home(tmp_path):
    home = tmp_path / "host-only" / "compose-unique"
    shared = tmp_path / "ascii-shared"
    assets = runner.initialize_assets(home, shared, "secops-m3check-test")
    public_directory = shared / "secops-m3check-test"
    assert assets["registry"] == public_directory / "public-sources.json"
    assert sorted(path.name for path in public_directory.iterdir()) == ["public-sources.json"]
    assert stat.S_IMODE(public_directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(assets["registry"].stat().st_mode) == 0o644
    assert "PRIVATE KEY" not in assets["registry"].read_text("utf-8")
    assert (home / "private-session.pem").is_file()
    assert (home / "private-identity.pem").is_file()
    assert assets["override"].parent == home


def test_compose_inherits_selected_engine_and_cleanup_only_targets_its_project(tmp_path, monkeypatch):
    assets = runner.initialize_assets(tmp_path / "compose-unique")
    calls = []
    monkeypatch.setenv("DOCKER_HOST", "unix:///task-engine/docker.sock")
    monkeypatch.setenv("DOCKER_CONFIG", "/task-local/docker-config")

    def fake_run(command, **options):
        calls.append((command, options))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    compose = runner.Compose(["docker", "compose"], "secops-m3check-test", 43121, assets)
    compose.run("up", "-d", "--no-build", "app", "signal-worker")
    compose.cleanup()
    for command, options in calls:
        assert "--project-name" in command and "secops-m3check-test" in command
        assert str(runner.ROOT / "compose.yaml") in command
        assert str(runner.ROOT / "compose.signals.yaml") in command
        assert options["env"]["DOCKER_HOST"] == "unix:///task-engine/docker.sock"
        assert options["env"]["DOCKER_CONFIG"] == "/task-local/docker-config"
        assert options["env"]["SIGNAL_REGISTRY_PATH"] == str(assets["registry"])
        assert options["env"]["SECOPS_PORT"] == "43121"
    assert calls[-1][0][-3:] == ["down", "--remove-orphans", "--volumes"]
    assert not any("prune" in command for command, _ in calls)
    assert len(compose.log_paths) == 2
    assert json.loads(compose.log_paths[-1].read_text("utf-8"))["returncode"] == 0


def test_compose_failure_preserves_cli_diagnostics_in_artifact_log(tmp_path, monkeypatch):
    assets = runner.initialize_assets(tmp_path / "compose-unique")
    monkeypatch.setattr(runner.subprocess, "run", lambda command, **options:
                        subprocess.CompletedProcess(command, 1, stdout="", stderr="bind source missing"))
    compose = runner.Compose(["docker-compose"], "secops-m3check-test", 43121, assets)
    try:
        compose.run("up", "-d", "--no-build", "app", "signal-worker")
    except runner.CheckFailed as exc:
        assert str(exc) == "compose_up_exit_1"
    else:
        raise AssertionError("A failed Docker command must fail the driver")
    log = json.loads(compose.log_paths[0].read_text("utf-8"))
    assert log["returncode"] == 1 and log["stderr"] == "bind source missing"


def test_receipt_report_excludes_payloads_signatures_grants_and_unexpected_result_fields():
    safe = runner.safe_receipt({
        "event_id": "safe-id", "state": "completed", "payload": {"signature": "private-proof"},
        "result": {"matched_sessions": 2, "changed_sessions": 2, "stale": False,
                   "duplicate": False, "grant_token": "private-grant"},
        "signature": "private-proof", "grant_token": "private-grant",
    })
    serialized = json.dumps(safe)
    assert "private-proof" not in serialized and "private-grant" not in serialized
    assert "payload" not in safe and safe["result"]["changed_sessions"] == 2


def test_failure_writes_redacted_evidence_and_cleans_own_stack(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(runner, "detect_compose", lambda: ["docker-compose"])
    monkeypatch.setattr(runner, "available_port", lambda: 43122)
    cleanup = []

    class FailedCompose:
        def __init__(self, command, project, port, assets):
            self.project = project

        def run(self, *args, **options):
            raise RuntimeError("DO NOT PRINT PRIVATE TOKEN")

        def cleanup(self, preserve_data=False):
            cleanup.append((self.project, preserve_data))

    monkeypatch.setattr(runner, "Compose", FailedCompose)
    report = tmp_path / "evidence.json"
    assert runner.main(["--report", str(report), "--no-build"]) == 1
    content = report.read_text("utf-8")
    assert "DO NOT PRINT PRIVATE TOKEN" not in content + capsys.readouterr().out
    parsed = json.loads(content)
    assert parsed["error_code"] == "unexpected_RuntimeError"
    assert parsed["cleanup"]["containers_removed"]
    assert cleanup == [(parsed["project"], False)]
