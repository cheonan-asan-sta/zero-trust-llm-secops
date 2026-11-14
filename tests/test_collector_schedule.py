import json
import os
import subprocess
import sys
from datetime import UTC, datetime

import pytest

from scripts.f1_lab.collector_freshness import atomic_capture
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import runtime_proof
from tests.test_collector_freshness import envelope, fixture

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux worker self-observation")


@pytest.mark.parametrize("mode", ["fresh", "missing", "wrong_pin"])
def test_health_security_report_does_not_change_freshness_or_allow_enforcement(tmp_path, mode):
    keys, _, pinned, scope, event, proof, _, latest, _ = fixture(tmp_path)
    at = datetime.now(UTC)
    event = event.model_copy(update={"observed_at": at})
    proof = runtime_proof(
        event,
        proof.observation,
        keys["runtime"],
        source_id=scope.source_id,
        key_id=scope.key_id,
        observed_at=at,
    )
    atomic_capture(latest, canonical(envelope(event, proof)))
    if mode == "missing":
        latest.unlink()
    args = [sys.executable, "-m", "scripts.service_capture_status", "--observe-worker-security"]
    values = {
        "tenant": scope.tenant_id,
        "server": scope.server_id,
        "unit": scope.unit,
        "source": scope.source_id,
        "key-id": scope.key_id,
        "capture": str(latest),
        "registry": str(pinned.path),
        "registry-sha256": "0" * 64 if mode == "wrong_pin" else pinned.expected_sha256,
        "ledger": str(tmp_path / "health.sqlite3"),
    }
    for name, value in values.items():
        args.extend(["--" + name, value])
    result = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
    body = json.loads(result.stdout)
    assert result.returncode == (0 if mode == "fresh" else 2)
    assert body["state"] == ("fresh" if mode == "fresh" else "unavailable")
    assert not body["authorization_checked"] and not body["automatic_enforcement_allowed"]
    assert body["worker_security"]["effective_uid"] == os.geteuid()


def test_security_observation_failure_cannot_report_fresh(tmp_path, monkeypatch, capsys):
    from scripts import service_capture_status as cli

    def unavailable():
        raise OSError("controlled worker self-observation failure")

    # The independent freshness result can be fresh, but a requested security
    # report that cannot be observed must not be claimed complete.
    from scripts.f1_lab.collector_freshness import CaptureStatus

    monkeypatch.setattr(cli.CollectorMonitor, "check", lambda *_: CaptureStatus("fresh", "test"))
    monkeypatch.setattr(cli, "current_security_status", unavailable)
    _, _, pinned, scope, _, _, _, latest, _ = fixture(tmp_path)
    args = ["status", "--observe-worker-security"]
    for name, value in {
        "tenant": scope.tenant_id,
        "server": scope.server_id,
        "unit": scope.unit,
        "source": scope.source_id,
        "key-id": scope.key_id,
        "capture": str(latest),
        "registry": str(pinned.path),
        "registry-sha256": pinned.expected_sha256,
        "ledger": str(tmp_path / "security-failure.sqlite3"),
    }.items():
        args.extend(["--" + name, value])
    monkeypatch.setattr(sys, "argv", args)
    assert cli.main() == 2
    body = json.loads(capsys.readouterr().out)
    assert body["state"] == "unavailable" and not body["automatic_enforcement_allowed"]
