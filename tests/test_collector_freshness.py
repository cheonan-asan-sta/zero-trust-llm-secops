import base64
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts import collect_shared_execution as cli
from scripts.f1_lab.collector_freshness import (
    CollectorMonitor,
    CollectorScope,
    atomic_capture,
    inspect_capture,
)
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    ProcessObservation,
    ServiceEvent,
    proof_bytes,
)
from scripts.run_shared_execution_controls import setup


def fixture(tmp_path):
    keys, registry, _ = setup(tmp_path / "trust")
    registry = registry.model_copy(
        update={
            "authorities": [a.model_copy(update={"mode": "systemd"}) for a in registry.authorities]
        }
    )
    pinned = repin(tmp_path / "trust/registry.json", registry)
    now = registry.issued_at + timedelta(seconds=10)
    scope = CollectorScope(
        tenant_id="local-lab",
        server_id="shared-lab",
        unit="shared-fixture.service",
        source_id="local-proc",
        key_id="proc-1",
    )
    event = ServiceEvent(
        tenant_id=scope.tenant_id,
        server_id=scope.server_id,
        unit=scope.unit,
        boot_id="1" * 32,
        invocation_id="2" * 32,
        process_id=42,
        event_id="e" * 64,
        raw_sha256="d" * 64,
        observed_at=now,
        mode="systemd",
        collection_basis="manager_snapshot",
    )
    observation = ProcessObservation(
        pid=42,
        start_ticks=1,
        parent_pid=1,
        real_uid=65534,
        effective_uid=65534,
        login_uid=None,
        audit_session_id=None,
        executable_sha256="a" * 64,
        command_sha256="b" * 64,
        argument_count=4,
        parent_ref_sha256=None,
    )
    proof = runtime_proof(
        event,
        observation,
        keys["runtime"],
        source_id=scope.source_id,
        key_id=scope.key_id,
        observed_at=now,
    )
    payload = envelope(event, proof)
    latest = tmp_path / "latest.json"
    atomic_capture(latest, canonical(payload))
    return keys, registry, pinned, scope, event, proof, payload, latest, now


def repin(path, registry):
    path.write_bytes(canonical(registry.model_dump(mode="json")))
    return PinnedServiceRegistry(path, hashlib.sha256(path.read_bytes()).hexdigest())


def envelope(event, proof):
    return {
        "schema": "zt-service-capture-1",
        "event": event.model_dump(mode="json"),
        "runtime_proof": proof.model_dump(mode="json"),
        "authorization_proof_included": False,
    }


def resign(proof, key):
    return proof.model_copy(
        update={
            "signature": base64.urlsafe_b64encode(key.sign(proof_bytes(proof))).decode().rstrip("=")
        }
    )


@pytest.mark.parametrize(
    "seconds,state", [(0, "fresh"), (29, "fresh"), (30, "stale"), (31, "stale")]
)
def test_freshness_expires_without_changing_a_threat_decision(tmp_path, seconds, state):
    _, _, pinned, scope, _, _, payload, _, now = fixture(tmp_path)
    result = inspect_capture(payload, scope, pinned, now=now + timedelta(seconds=seconds))
    assert result.state == state and result.event_sha256
    assert not hasattr(result, "alert") and not hasattr(result, "grant")


@pytest.mark.parametrize(
    "mutation",
    [
        "signature",
        "tenant",
        "server",
        "unit",
        "invocation",
        "pid",
        "source",
        "key",
        "lab",
        "authorization",
        "extra",
        "truth",
    ],
)
def test_unsigned_wrong_scope_or_wrong_role_never_becomes_fresh(tmp_path, mutation):
    _, _, pinned, scope, _, _, payload, _, now = fixture(tmp_path)
    if mutation == "signature":
        payload["runtime_proof"]["signature"] = "A" * 86
    elif mutation in {"tenant", "server", "unit", "invocation", "pid"}:
        field, value = {
            "tenant": ("tenant_id", "other"),
            "server": ("server_id", "other"),
            "unit": ("unit", "other.service"),
            "invocation": ("invocation_id", "3" * 32),
            "pid": ("process_id", 43),
        }[mutation]
        payload["event"][field] = value
    elif mutation in {"source", "key"}:
        payload["runtime_proof"][mutation + "_id"] = "other"
    elif mutation == "lab":
        payload["event"].update(mode="local_process_lab", collection_basis="local_process_lab")
    elif mutation == "authorization":
        payload["authorization_proof_included"] = True
    elif mutation == "extra":
        payload["trusted"] = True
    else:
        payload["event"]["ground_truth"] = "normal"
    assert inspect_capture(payload, scope, pinned, now=now).state == "unavailable"


@pytest.mark.parametrize("change", ["expired", "future", "disabled", "wrong_key"])
def test_producer_rejects_inactive_authority_before_target_collection(
    tmp_path, monkeypatch, change
):
    keys, registry, pinned, scope, _, _, _, _, now = fixture(tmp_path)
    wrong_public = (
        base64.urlsafe_b64encode(
            Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        .decode()
        .rstrip("=")
    )

    def authority(a):
        if a.kind != "runtime":
            return a
        return a.model_copy(
            update={"expires_at": now - timedelta(seconds=1)}
            if change == "expired"
            else {"issued_at": now + timedelta(seconds=1)}
            if change == "future"
            else {"enabled": False}
            if change == "disabled"
            else {"public_key": wrong_public}
        )

    registry = registry.model_copy(
        update={"authorities": [authority(a) for a in registry.authorities]}
    )
    pinned = repin(pinned.path, registry)
    monkeypatch.setattr(
        cli,
        "collect_current_systemd",
        lambda *a, **kw: pytest.fail("must reject before collecting target"),
    )
    with pytest.raises(ValueError):
        cli.collect_payload(arguments(scope, pinned), keys["runtime"], clock=lambda: now)


def arguments(scope, pinned):
    return SimpleNamespace(
        tenant=scope.tenant_id,
        server=scope.server_id,
        unit=scope.unit,
        source=scope.source_id,
        key_id=scope.key_id,
        registry=pinned.path,
        registry_sha256=pinned.expected_sha256,
        collection_basis="manager_snapshot",
    )


def test_short_lived_key_clips_and_resigns_the_proof(tmp_path, monkeypatch):
    keys, registry, pinned, scope, event, proof, _, _, now = fixture(tmp_path)
    expiry = now + timedelta(seconds=3)
    registry = registry.model_copy(
        update={
            "authorities": [
                a.model_copy(update={"expires_at": expiry}) if a.kind == "runtime" else a
                for a in registry.authorities
            ]
        }
    )
    pinned = repin(pinned.path, registry)
    monkeypatch.setattr(cli, "current_security_status", lambda: {"effective_uid": 1})
    monkeypatch.setattr(cli, "collect_current_systemd", lambda *a, **kw: (event, proof))
    payload, _ = cli.collect_payload(arguments(scope, pinned), keys["runtime"], clock=lambda: now)
    assert payload["runtime_proof"]["expires_at"] != proof.model_dump(mode="json")["expires_at"]
    assert inspect_capture(payload, scope, pinned, now=now).state == "fresh"
    assert inspect_capture(payload, scope, pinned, now=expiry).state == "unavailable"


@pytest.mark.parametrize("change", ["revoked", "expires_during_collection"])
def test_authority_is_rechecked_after_collection_and_latest_is_preserved(
    tmp_path, monkeypatch, change
):
    keys, registry, pinned, scope, event, proof, _, latest, now = fixture(tmp_path)
    original = latest.read_bytes()
    monkeypatch.setattr(cli, "current_security_status", lambda: {"effective_uid": 1})
    if change == "expires_during_collection":
        registry = registry.model_copy(
            update={
                "authorities": [
                    a.model_copy(update={"expires_at": now + timedelta(seconds=1)})
                    if a.kind == "runtime"
                    else a
                    for a in registry.authorities
                ]
            }
        )
        pinned = repin(pinned.path, registry)
    calls = []

    def collect(*a, **kw):
        calls.append(True)
        if change == "revoked":
            data = registry.model_dump(mode="json")
            data["authorities"][0]["enabled"] = False
            pinned.path.write_bytes(canonical(data))
        return event, proof

    monkeypatch.setattr(cli, "collect_current_systemd", collect)
    with pytest.raises(ValueError):
        cli.collect_payload(
            arguments(scope, pinned),
            keys["runtime"],
            clock=lambda: now + timedelta(seconds=2 if calls else 0),
        )
    assert calls and latest.read_bytes() == original


def test_latest_publication_is_atomic_and_failure_preserves_old_file(tmp_path, monkeypatch):
    *_, latest, _ = fixture(tmp_path)
    original = latest.read_bytes()

    def fail(*a, **kw):
        raise OSError("controlled filesystem failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        atomic_capture(latest, b'{"new":"payload"}')
    assert latest.read_bytes() == original and not list(tmp_path.glob(".secops-capture-*"))


@pytest.mark.parametrize("mode", ["missing", "oversize", "duplicate_json", "directory", "symlink"])
def test_invalid_capture_files_do_not_become_fresh(tmp_path, mode):
    _, _, pinned, scope, _, _, _, latest, now = fixture(tmp_path)
    if mode == "missing":
        latest.unlink()
    elif mode == "oversize":
        latest.write_bytes(b"x" * 65537)
    elif mode == "duplicate_json":
        latest.write_bytes(b'{"schema":1,"schema":2}')
    elif mode == "directory":
        latest.unlink()
        latest.mkdir()
    else:
        if sys.platform != "linux":
            pytest.skip("Linux symlink fixture")
        target = tmp_path / "target.json"
        latest.rename(target)
        latest.symlink_to(target)
    monitor = CollectorMonitor(scope, pinned, tmp_path / "monitor.sqlite3")
    assert monitor.check(latest, now=now).state == "unavailable"


def test_restart_rejects_clock_and_capture_rollback_and_accepts_new_observation(tmp_path):
    keys, _, pinned, scope, event, proof, payload, latest, now = fixture(tmp_path)
    ledger = tmp_path / "monitor.sqlite3"
    monitor = CollectorMonitor(scope, pinned, ledger)
    assert monitor.check(latest, now=now).state == "fresh"
    newer = event.model_copy(
        update={"observed_at": now + timedelta(seconds=2), "event_id": "f" * 64}
    )
    newproof = runtime_proof(
        newer,
        proof.observation,
        keys["runtime"],
        source_id=scope.source_id,
        key_id=scope.key_id,
        observed_at=newer.observed_at,
    )
    atomic_capture(latest, canonical(envelope(newer, newproof)))
    assert monitor.check(latest, now=now + timedelta(seconds=2)).state == "fresh"
    restarted = CollectorMonitor(scope, pinned, ledger)
    assert restarted.check(latest, now=now + timedelta(seconds=1)).reason == "clock_regression"
    atomic_capture(latest, canonical(payload))
    assert restarted.check(latest, now=now + timedelta(seconds=3)).reason == "capture_regression"
    atomic_capture(latest, canonical(envelope(newer, newproof)))
    assert restarted.check(latest, now=now + timedelta(seconds=4)).state == "fresh"


def test_concurrent_duplicate_reads_keep_one_durable_progress_record(tmp_path):
    _, _, pinned, scope, _, _, _, latest, now = fixture(tmp_path)
    monitor = CollectorMonitor(scope, pinned, tmp_path / "monitor.sqlite3")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: monitor.check(latest, now=now), range(8)))
    assert all(r.state == "fresh" for r in results)
    with monitor.connect() as con:
        assert con.execute("SELECT count(*) FROM latest").fetchone()[0] == 1


def test_current_registry_is_rechecked_on_duplicate_reads(tmp_path):
    _, registry, pinned, scope, _, _, _, latest, now = fixture(tmp_path)
    monitor = CollectorMonitor(scope, pinned, tmp_path / "monitor.sqlite3")
    assert monitor.check(latest, now=now).state == "fresh"
    registry = registry.model_copy(
        update={
            "authorities": [
                a.model_copy(update={"enabled": False}) if a.kind == "runtime" else a
                for a in registry.authorities
            ]
        }
    )
    monitor.registry = repin(pinned.path, registry)
    assert monitor.check(latest, now=now).state == "unavailable"


@pytest.mark.parametrize("mode", ["future", "excess_ttl", "naive"])
def test_signed_future_or_excess_lifetime_is_not_fresh(tmp_path, mode):
    keys, _, pinned, scope, event, proof, payload, _, now = fixture(tmp_path)
    if mode == "future":
        event = event.model_copy(update={"observed_at": now + timedelta(seconds=1)})
        proof = runtime_proof(
            event,
            proof.observation,
            keys["runtime"],
            source_id=scope.source_id,
            key_id=scope.key_id,
            observed_at=event.observed_at,
        )
    elif mode == "excess_ttl":
        proof = resign(
            proof.model_copy(update={"expires_at": now + timedelta(seconds=31)}), keys["runtime"]
        )
    else:
        now = now.replace(tzinfo=None)
    payload = envelope(event, proof)
    assert inspect_capture(payload, scope, pinned, now=now).state == "unavailable"


def test_capacity_and_corrupt_ledger_do_not_emit_fresh_status(tmp_path):
    keys, registry, pinned, scope, event, proof, _, latest, now = fixture(tmp_path)
    ledger = tmp_path / "monitor.sqlite3"
    monitor = CollectorMonitor(scope, pinned, ledger, capacity=1)
    assert monitor.check(latest, now=now).state == "fresh"
    scope2 = scope.model_copy(update={"unit": "second.service"})
    registry = registry.model_copy(
        update={
            "authorities": [
                a.model_copy(update={"units": [scope.unit, scope2.unit]})
                if a.kind == "runtime"
                else a
                for a in registry.authorities
            ]
        }
    )
    pinned = repin(pinned.path, registry)
    event2 = event.model_copy(update={"unit": scope2.unit})
    proof2 = resign(proof.model_copy(update={"event_sha256": event2.sha256}), keys["runtime"])
    atomic_capture(latest, canonical(envelope(event2, proof2)))
    other = CollectorMonitor(scope2, pinned, ledger, capacity=1)
    assert other.check(latest, now=now).reason == "monitor_capacity"
    ledger.write_bytes(b"corrupt")
    assert monitor.check(latest, now=now).state == "unavailable"


def test_status_cli_reports_only_freshness_and_fails_closed_for_missing_file(tmp_path):
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
    args = [
        sys.executable,
        "-m",
        "scripts.service_capture_status",
        "--tenant",
        scope.tenant_id,
        "--server",
        scope.server_id,
        "--unit",
        scope.unit,
        "--source",
        scope.source_id,
        "--key-id",
        scope.key_id,
        "--capture",
        str(latest),
        "--registry",
        str(pinned.path),
        "--registry-sha256",
        pinned.expected_sha256,
        "--ledger",
        str(tmp_path / "cli.sqlite3"),
    ]
    first = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
    body = json.loads(first.stdout)
    assert first.returncode == 0 and body["state"] == "fresh"
    assert body["authorization_checked"] is False and body["automatic_enforcement_allowed"] is False
    latest.unlink()
    second = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
    assert second.returncode == 2 and json.loads(second.stdout)["state"] == "unavailable"
