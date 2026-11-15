"""Trusted completed-execution to archive adapter, with a private sealed outbox.

Publication retry accepts the same signed bytes only; it never invokes systemd,
refreshes a timestamp or returns a consumed app grant. A crash before the outbox
is durable still requires operator reconciliation, not automatic re-execution.
"""

import base64
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.app_execution_gate import AppExecutionGate
from scripts.f1_lab.capture_archive import MAX_SCAN, raw_capture
from scripts.f1_lab.capture_backup import fresh_file, private_directory, private_file
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import MAX_CAPTURE, atomic_capture
from scripts.f1_lab.managed_exec_capture import (
    AppUseReceipt,
    ManagedExecCapture,
    capture_parts,
    seal_bytes,
    verify_managed,
)
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_evidence import digest


def seal_completed(gate, result, worker_capture):
    """Trusted server-only adapter; all inputs refer to the completed dispatch."""
    require(isinstance(gate, AppExecutionGate) and gate.used, "retention_completed_gate")
    receipt, event, proofs = result
    request = gate.request
    require(
        type(worker_capture) is dict
        and set(worker_capture) == {"request_sha256", "event", "proof", "exit_code"}
        and len(proofs) == 2
        and worker_capture["request_sha256"] == request.authentication_nonce
        and worker_capture["event"] == event.model_dump(mode="json")
        and worker_capture["proof"] == proofs[0].model_dump(mode="json"),
        "retention_worker_binding",
    )
    now = datetime.now(UTC)
    require(
        gate.broker.joiner.check(event, proofs, now=now).state == "consistent",
        "retention_current_evidence",
    )
    with gate.operations._transaction() as (_, entries, _):
        linked = [
            e
            for e in entries
            if e["kind"] == "access"
            and e.get("execution_request_sha256") == request.authentication_nonce
        ]
    require(len(linked) == 1, "retention_app_record_count")
    record = linked[0]
    require(
        record["allowed"] is True
        and record["reason_code"] == "ACCESS_GRANTED"
        and (
            record["tenant_id"],
            record["operator_id"],
            record["session_id"],
            record["resource_id"],
            record["action"],
            record["session_version"],
        )
        == (
            request.tenant_id,
            gate.principal.subject,
            gate.access.session_id,
            gate.target.resource_id,
            gate.target.action,
            gate.authorized_version,
        ),
        "retention_app_record_binding",
    )
    capture = ManagedExecCapture(
        request=request,
        event=event,
        runtime_proof=proofs[0],
        authorization_proof=proofs[1],
        caller_receipt=receipt,
        app_use=AppUseReceipt(
            request_sha256=request.authentication_nonce,
            caller_ref_sha256=receipt.caller_ref_sha256,
            session_ref_sha256=digest([request.tenant_id, gate.access.session_id]),
            resource_id=gate.target.resource_id,
            action=gate.target.action,
            session_version=gate.authorized_version,
            policy_sha256=proofs[1].observation.policy_sha256,
            access_record_sha256=digest(record),
        ),
        exit_code=worker_capture["exit_code"],
        sealed_at=now,
        signature="A" * 86,
    )
    capture = capture.model_copy(
        update={
            "signature": base64.urlsafe_b64encode(gate.broker.key.sign(seal_bytes(capture)))
            .decode()
            .rstrip("=")
        }
    )
    verify_managed(capture, gate.broker.joiner.registry, gate.broker.registry, now=now)
    raw = canonical(capture.model_dump(mode="json")) + b"\n"
    require(len(raw) <= MAX_CAPTURE, "retention_capture_bound")
    return raw


def publish_sealed(raw, root, service_pin, caller_pin, *, now=None):
    """Idempotent locked publication; retains old records without latest rollback."""
    now = datetime.now(UTC) if now is None else now
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CAPTURE, "retention_capture_bytes")
    capture = ManagedExecCapture.model_validate(decode(raw))
    verify_managed(capture, service_pin, caller_pin, now=now)
    root = private_directory(root)
    with capture_store_lock(root):
        latest = root / "latest.json"
        promote = True
        if latest.exists() or latest.is_symlink():
            old, old_proof = capture_parts(decode(raw_capture(latest)))
            require(
                (old.tenant_id, old.server_id, old.unit, old_proof.source_id)
                == (
                    capture.event.tenant_id,
                    capture.event.server_id,
                    capture.event.unit,
                    capture.runtime_proof.source_id,
                ),
                "retention_store_scope",
            )
            if old.observed_at == capture.event.observed_at:
                require(old.sha256 == capture.event.sha256, "retention_latest_collision")
            promote = old.observed_at <= capture.event.observed_at
        run = root / capture.request.request_id
        if not run.exists():
            require(sum(1 for _ in root.iterdir()) < MAX_SCAN - 3, "retention_store_capacity")
            run.mkdir(mode=0o700)
        private_directory(run)
        require({p.name for p in run.iterdir()} <= {"capture.json"}, "retention_run_inventory")
        target = run / "capture.json"
        if target.exists() or target.is_symlink():
            require(private_file(target, MAX_CAPTURE) == raw, "retention_run_collision")
        else:
            atomic_capture(target, raw)
        if promote:
            atomic_capture(latest, raw)
    return {
        "completed": True,
        "run_id": run.name,
        "latest_promoted": promote,
        "event_sha256": capture.event.sha256,
        "automatic_execution_allowed": False,
    }


def dispatch_and_retain(gate, launcher, policy_proof, root, outbox):
    """Execute once, durably seal, then publish. On failure retry outbox only.

    root/outbox are preconfigured private directories, never client paths. The
    outbox is outside the archive root and needs its own operator cleanup after
    a verified backup; archive compaction must not silently delete pending work.
    """
    root, outbox = private_directory(root), private_directory(outbox)
    require(
        root != outbox and root not in outbox.parents and outbox not in root.parents,
        "retention_outbox_separate",
    )
    require(sum(1 for _ in outbox.iterdir()) < MAX_SCAN, "retention_outbox_capacity")
    pending = outbox / (gate.request.request_id + ".json")
    require(not pending.exists() and not pending.is_symlink(), "retention_request_already_sealed")
    result = gate.dispatch(launcher, policy_proof)
    worker = decode(private_file(Path(launcher.directory) / "capture.json", 16384))
    raw = seal_completed(gate, result, worker)
    fresh_file(pending, raw)
    publication = publish_sealed(raw, root, gate.broker.joiner.registry, gate.broker.registry)
    return result, publication
