"""Real owned loopback HTTP process, registry withdrawal during an admitted model."""

import hashlib
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

from test_service_analysis_evidence import executed as executed  # noqa: PLC0414

from app.scenarios import synthetic_events
from app.services.sqlite_audit import SQLiteAuditStore
from scripts.f1_lab.http_worker_controls import owned_worker
from scripts.f1_lab.shared_native_controls import configure


def test_actual_http_account_withdrawal_during_provider_denies_before_audit(executed, tmp_path):
    lab, _, _ = executed
    config, pin, _ = configure(lab, tmp_path / "shared")
    caller, legacy = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    registry = tmp_path / "accounts.json"
    entry = {
        "subject": "owned-loopback-caller",
        "tenant_id": lab.principal.tenant_id,
        "sha256": hashlib.sha256(caller.encode()).hexdigest(),
        "roles": ["analyst"],
        "enabled": True,
    }

    def save(enabled):
        registry.write_text(
            json.dumps(
                {"schema": "api-key-accounts-1", "accounts": [{**entry, "enabled": enabled}]}
            ),
            encoding="utf-8",
        )
        registry.chmod(0o600)

    save(True)
    directory = tmp_path / "worker"
    gate = directory / "provider-gate"
    audit = tmp_path / "audit.sqlite3"
    with owned_worker(
        lab, (config, pin), audit, directory, legacy, accounts_path=registry, provider_gate=gate
    ) as (process, client, stats):
        with ThreadPoolExecutor(max_workers=1) as pool:
            request = pool.submit(
                client.post,
                "/analysis",
                headers={"X-API-Key": caller},
                json=synthetic_events()[0].model_dump(mode="json"),
            )
            deadline = time.monotonic() + 4
            while not (gate / "entered.json").exists():
                assert time.monotonic() < deadline and process.poll() is None
                time.sleep(0.02)
            marker = json.loads((gate / "entered.json").read_text(encoding="utf-8"))
            assert marker == {"pid": process.pid, "calls": 1}
            assert client.get("/health/live").status_code == 200
            save(False)
            (gate / "release").touch()
            response = request.result(timeout=4)
        assert response.status_code == 401 and "assessment" not in response.json()
        observed = json.loads(stats.read_text(encoding="utf-8"))
        assert observed["provider_stub_calls"] == 1 and observed["paid_api_calls"] == 0
        assert SQLiteAuditStore.open_existing(audit).integrity()["verified_lines"] == 0
        process.kill()
        assert process.wait(timeout=10) != 0
