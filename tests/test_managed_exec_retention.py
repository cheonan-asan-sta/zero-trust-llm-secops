"""Signed retention contracts. Native systemd and monitoring run separately."""

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature

from scripts.f1_lab import managed_exec_retention as retention
from scripts.f1_lab.capture_archive import ArchivePolicy, ArchiveScope, CaptureArchive
from scripts.f1_lab.collector_freshness import CollectorMonitor, CollectorScope, inspect_capture
from scripts.f1_lab.managed_exec_capture import ManagedExecCapture, capture_parts
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.service_caller_identity import PinnedCallerRegistry
from scripts.f1_lab.shared_execution_collector import runtime_proof
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    ProcessObservation,
    ServiceEvent,
    digest,
)
from scripts.run_exec_history_controls import setup_app

# The sealed outbox uses POSIX UID/mode/no-follow and directory durability.
# Windows must reject this native storage contract, never emulate it as trusted.
pytestmark = pytest.mark.skipif(os.name != "posix", reason="Native POSIX sealed-outbox storage")


def fixture(tmp_path):
    lab = setup_app(tmp_path / "control", "fixture.service")
    root, outbox, worker, intents = [tmp_path / n for n in ("store", "outbox", "worker", "intents")]
    for path in (root, outbox, worker, intents):
        path.mkdir(mode=0o700)
    launches = []

    def collect(request):
        event = ServiceEvent(
            tenant_id=request.tenant_id,
            server_id=request.server_id,
            unit=request.unit,
            boot_id="1" * 32,
            invocation_id=request.request_id,
            process_id=42,
            observed_at=datetime.now(UTC),
            mode="systemd",
            collection_basis="ptrace_exec",
            event_id=digest([request.authentication_nonce, "d" * 64]),
            raw_sha256="d" * 64,
        )
        process = ProcessObservation(
            pid=42,
            start_ticks=1,
            parent_pid=1,
            real_uid=65534,
            effective_uid=65534,
            login_uid=None,
            audit_session_id=None,
            executable_sha256=request.executable_sha256,
            command_sha256=request.command_sha256,
            argument_count=1,
            parent_ref_sha256=None,
        )
        proof = runtime_proof(
            event, process, lab.keys["runtime"], source_id="local-proc", key_id="proc-1"
        )
        capture = {
            "request_sha256": request.authentication_nonce,
            "event": event.model_dump(mode="json"),
            "proof": proof.model_dump(mode="json"),
            "exit_code": 0,
        }
        (worker / "capture.json").write_bytes(canonical(capture))
        (worker / "capture.json").chmod(0o600)
        return event, proof

    launcher = SimpleNamespace(
        directory=worker, launch=lambda r: launches.append(r.request_id), collect=collect
    )
    scope = CollectorScope(
        tenant_id=lab.target.tenant_id,
        server_id=lab.target.server_id,
        unit=lab.target.unit,
        source_id="local-proc",
        key_id="proc-1",
    )
    archive_scope = ArchiveScope.model_validate(scope.model_dump(exclude={"key_id"}))

    def execute():
        gate = lab.gate(lab.new_request(), lab.new_access())
        result, publication = retention.dispatch_and_retain(
            gate, launcher, lab.permission, root, outbox, intent_root=intents
        )
        raw = (outbox / (gate.request.request_id + ".json")).read_bytes()
        return gate, result, publication, raw

    return SimpleNamespace(
        lab=lab,
        root=root,
        outbox=outbox,
        intents=intents,
        launcher=launcher,
        scope=scope,
        archive_scope=archive_scope,
        execute=execute,
        launches=launches,
    )


def status(f, raw, **kwargs):
    return inspect_capture(
        json.loads(raw),
        f.scope,
        f.lab.broker.joiner.registry,
        caller_registry=f.lab.broker.registry,
        **kwargs,
    )


def test_complete_private_record_and_idempotent_publication(tmp_path):
    f = fixture(tmp_path)
    gate, result, published, raw = f.execute()
    value = ManagedExecCapture.model_validate_json(raw)
    assert value.caller_receipt == result[0]
    assert value.app_use.request_sha256 == gate.request.authentication_nonce
    assert published["completed"] and status(f, raw).state == "fresh"
    assert (f.root / "latest.json").read_bytes() == raw
    assert gate.token.encode() not in raw and gate.access.grant_token.encode() not in raw
    assert gate.principal.subject.encode() not in raw
    assert gate.access.session_id.encode() not in raw
    assert "private_key" not in raw.decode() and value.exit_code == 0
    for _ in range(2):
        retention.publish_sealed(raw, f.root, f.lab.broker.joiner.registry, f.lab.broker.registry)
    assert len(f.launches) == 1
    with pytest.raises(ValueError):
        retention.dispatch_and_retain(gate, f.launcher, f.lab.permission, f.root, f.outbox,
                                     intent_root=f.intents)
    assert len(f.launches) == 1


@pytest.mark.parametrize(
    "field",
    [
        "exit_code",
        "sealed_at",
        "signature",
        "app_use.access_record_sha256",
        "app_use.policy_sha256",
        "app_use.caller_ref_sha256",
        "app_use.session_ref_sha256",
        "app_use.session_version",
        "app_use.resource_id",
        "app_use.request_sha256",
        "caller_receipt.signature",
        "caller_receipt.service_evidence_sha256",
        "authorization_proof.signature",
        "runtime_proof.signature",
        "request.nonce",
        "request.command_sha256",
        "event.event_id",
        "event.collection_basis",
    ],
)
def test_tampering_never_reports_fresh_or_publishes(tmp_path, field):
    f = fixture(tmp_path)
    _, _, _, raw = f.execute()
    value = json.loads(raw)
    parent = value
    parts = field.split(".")
    for name in parts[:-1]:
        parent = parent[name]
    name = parts[-1]
    old = parent[name]
    parent[name] = (
        old + 1
        if type(old) is int
        else (
            "manager_snapshot"
            if name == "collection_basis"
            else "2030-01-01T00:00:00Z"
            if name == "sealed_at"
            else (
                ("a" if old[0] != "a" else "b")
                if len(old) == 64
                else ("B" if old[0] != "B" else "C")
            )
            + old[1:]
        )
    )
    changed = canonical(value)
    assert status(f, changed).state == "unavailable"
    with pytest.raises((ValueError, InvalidSignature)) as error:
        retention.publish_sealed(
            changed, f.root, f.lab.broker.joiner.registry, f.lab.broker.registry
        )
    assert error.value is not None and (f.root / "latest.json").read_bytes() == raw


def test_no_pin_stale_restore_and_clock_regression(tmp_path):
    f = fixture(tmp_path)
    _, _, _, raw = f.execute()
    capture = ManagedExecCapture.model_validate_json(raw)
    assert (
        inspect_capture(json.loads(raw), f.scope, f.lab.broker.joiner.registry).state
        == "unavailable"
    )
    later = capture.sealed_at + timedelta(seconds=65)
    assert status(f, raw, now=later).state == "stale"
    monitor = CollectorMonitor(
        f.scope,
        f.lab.broker.joiner.registry,
        tmp_path / "health.db",
        caller_registry=f.lab.broker.registry,
    )
    assert monitor.check(f.root / "latest.json", now=later).state == "stale"
    assert (
        monitor.check(f.root / "latest.json", now=later - timedelta(seconds=1)).reason
        == "clock_regression"
    )
    assert (f.root / "latest.json").read_bytes() == raw


def test_stripping_managed_seal_cannot_downgrade_to_legacy_capture(tmp_path):
    f = fixture(tmp_path)
    _, _, _, raw = f.execute()
    original = json.loads(raw)
    legacy = {
        "schema": "zt-service-capture-1",
        "event": original["event"],
        "runtime_proof": original["runtime_proof"],
        "authorization_proof_included": False,
    }
    assert inspect_capture(legacy, f.scope, f.lab.broker.joiner.registry).state == "unavailable"
    assert status(f, canonical(legacy)).state == "unavailable"
    with pytest.raises(ValueError, match="legacy_downgrade"):
        CaptureArchive(f.root, f.archive_scope).shape(canonical(legacy))


@pytest.mark.parametrize("point", ["before_run", "before_latest"])
def test_durable_outbox_resumes_without_execution_or_resigning(tmp_path, monkeypatch, point):
    f = fixture(tmp_path)
    original = retention.atomic_capture

    def fail(path, body):
        if path.name == ("capture.json" if point == "before_run" else "latest.json"):
            raise OSError("owned injected publication interruption: " + path.name)
        original(path, body)

    monkeypatch.setattr(retention, "atomic_capture", fail)
    with pytest.raises(OSError):
        f.execute()
    pending = list(f.outbox.glob("*.json"))
    assert len(pending) == len(f.launches) == 1
    raw = pending[0].read_bytes()
    monkeypatch.setattr(retention, "atomic_capture", original)
    retention.publish_sealed(raw, f.root, f.lab.broker.joiner.registry, f.lab.broker.registry)
    assert (f.root / "latest.json").read_bytes() == raw and len(f.launches) == 1


def test_archive_restore_is_byte_exact_and_never_rolls_latest_back(tmp_path):
    f = fixture(tmp_path)
    records = [f.execute() for _ in range(3)]
    latest = (f.root / "latest.json").read_bytes()
    archive = CaptureArchive(f.root, f.archive_scope, policy=ArchivePolicy(max_hot_records=1))
    result = archive.compact(apply=True)
    assert result["archive_records"] == 2
    run_id = records[0][0].request.request_id
    archive.restore(run_id, tmp_path / "review")
    assert (tmp_path / "review/capture.json").read_bytes() == records[0][3]
    assert (f.root / "latest.json").read_bytes() == latest
    retention.publish_sealed(
        records[0][3], f.root, f.lab.broker.joiner.registry, f.lab.broker.registry
    )
    assert (f.root / "latest.json").read_bytes() == latest
    capture_parts(json.loads(records[0][3]))


def test_refuse_wrong_worker_before_sealing(tmp_path):
    f = fixture(tmp_path)
    gate, result, _, _ = f.execute()
    raw = json.loads((f.launcher.directory / "capture.json").read_bytes())
    raw["exit_code"] = True
    with pytest.raises(ValueError):
        retention.seal_completed(gate, result, raw)
    raw["exit_code"] = 0
    raw["request_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        retention.seal_completed(gate, result, raw)


@pytest.mark.parametrize(
    "change",
    [
        "runtime_disabled",
        "authorization_disabled",
        "caller_disabled",
        "policy_changed",
        "caller_wrong_pin",
        "service_wrong_pin",
    ],
)
def test_current_revocation_and_pins_override_old_valid_seal(tmp_path, change):
    f = fixture(tmp_path)
    _, _, _, raw = f.execute()
    broker = f.lab.broker
    if change.startswith("caller_"):
        value = json.loads(broker.registry.path.read_bytes())
        if change == "caller_disabled":
            value["subjects"][0]["enabled"] = False
            broker.registry.path.write_bytes(canonical(value))
        broker.registry = PinnedCallerRegistry(
            broker.registry.path,
            "0" * 64
            if change == "caller_wrong_pin"
            else hashlib.sha256(broker.registry.path.read_bytes()).hexdigest(),
            expected_environment="local_oidc",
        )
    else:
        value = json.loads(broker.joiner.registry.path.read_bytes())
        if change == "policy_changed":
            value["policy_sha256"] = "0" * 64
        elif change != "service_wrong_pin":
            kind = change.removesuffix("_disabled")
            for authority in value["authorities"]:
                if authority["kind"] == kind:
                    authority["enabled"] = False
        broker.joiner.registry.path.write_bytes(canonical(value))
        broker.joiner.registry = PinnedServiceRegistry(
            broker.joiner.registry.path,
            "0" * 64
            if change == "service_wrong_pin"
            else hashlib.sha256(broker.joiner.registry.path.read_bytes()).hexdigest(),
        )
    assert status(f, raw).state == "unavailable"
    # Storage can still recover exact bytes; it must not assert current trust.
    assert (
        CaptureArchive(f.root, f.archive_scope).shape(raw).sha256
        == json.loads(raw)["caller_receipt"]["event_sha256"]
    )


@pytest.mark.parametrize(
    "kind",
    [
        "outbox_nested",
        "outbox_same",
        "outbox_link",
        "store_link",
        "run_link",
        "capture_link",
        "latest_link",
        "run_extra_file",
    ],
)
def test_private_paths_reject_links_and_unexpected_files(tmp_path, kind):
    f = fixture(tmp_path)
    if kind.startswith("outbox_") or kind == "store_link":
        root, outbox = f.root, f.outbox
        if kind == "outbox_nested":
            outbox = root / "pending"
            outbox.mkdir(mode=0o700)
        elif kind == "outbox_same":
            outbox = root
        else:
            link = tmp_path / "linked"
            link.symlink_to(outbox if kind == "outbox_link" else root, target_is_directory=True)
            if kind == "outbox_link":
                outbox = link
            else:
                root = link
        gate = f.lab.gate(f.lab.new_request(), f.lab.new_access())
        with pytest.raises(ValueError):
            retention.dispatch_and_retain(gate, f.launcher, f.lab.permission, root, outbox,
                                         intent_root=f.intents)
        assert not f.launches
    else:
        gate, _, _, raw = f.execute()
        run = f.root / gate.request.request_id
        if kind == "run_extra_file":
            (run / "unexpected").write_text("owned fixture")
        elif kind == "run_link":
            moved = tmp_path / "moved-run"
            run.rename(moved)
            run.symlink_to(moved, target_is_directory=True)
        else:
            target = run / "capture.json" if kind == "capture_link" else f.root / "latest.json"
            moved = tmp_path / "moved-capture"
            target.rename(moved)
            target.symlink_to(moved)
        with pytest.raises((ValueError, OSError)):
            retention.publish_sealed(
                raw, f.root, f.lab.broker.joiner.registry, f.lab.broker.registry
            )


def test_operator_retry_cli_cannot_execute_and_health_cli_requires_caller_pin(tmp_path):
    f = fixture(tmp_path)
    gate, _, _, raw = f.execute()
    broker = f.lab.broker
    trust = [
        "--registry",
        str(broker.joiner.registry.path),
        "--registry-sha256",
        broker.joiner.registry.expected_sha256,
    ]
    caller = [
        "--caller-registry",
        str(broker.registry.path),
        "--caller-registry-sha256",
        broker.registry.sha256,
        "--caller-environment",
        "local_oidc",
    ]

    def cli(module, arguments):
        result = subprocess.run(
            [sys.executable, "-m", module, *arguments],
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "AWS_EC2_METADATA_DISABLED": "true"},
            capture_output=True,
            timeout=20,
            check=False,
        )
        return result.returncode, json.loads(result.stdout)

    code, result = cli(
        "scripts.service_capture_retain",
        [
            "--capture",
            str(f.outbox / (gate.request.request_id + ".json")),
            "--root",
            str(f.root),
            *trust,
            *caller,
        ],
    )
    assert code == 0 and result["completed"] and len(f.launches) == 1
    health = [
        "--tenant",
        f.scope.tenant_id,
        "--server",
        f.scope.server_id,
        "--unit",
        f.scope.unit,
        "--source",
        f.scope.source_id,
        "--key-id",
        f.scope.key_id,
        "--capture",
        str(f.root / "latest.json"),
        "--ledger",
        str(tmp_path / "cli-health.db"),
        *trust,
    ]
    code, result = cli("scripts.service_capture_status", health)
    assert code == 2 and result["state"] == "unavailable"
    code, result = cli("scripts.service_capture_status", [*health, *caller])
    assert code == 0 and result["state"] == "fresh"
    assert result["automatic_enforcement_allowed"] is False
    assert (f.root / "latest.json").read_bytes() == raw and len(f.launches) == 1
