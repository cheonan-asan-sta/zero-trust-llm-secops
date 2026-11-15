"""Sealed, private execution evidence; archival never renews its authority.

Only the trusted broker seals a completed execution. This is an audit receipt,
not a bearer credential, grant, fresh device signal or permission to execute.
"""

import base64
from datetime import datetime, timedelta
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, field_validator

from app.models import StrictModel
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.service_caller_identity import (
    CallerReceipt,
    PinnedCallerRegistry,
    ServiceRequest,
    verify_receipt,
)
from scripts.f1_lab.shared_execution_evidence import (
    ServiceEvent,
    ServiceProof,
    digest,
    proof_bytes,
)
from scripts.f1_lab.web_verified_context import SHA, Identifier, Window, public_bytes


class AppUseReceipt(StrictModel):
    request_sha256: SHA
    caller_ref_sha256: SHA
    session_ref_sha256: SHA
    resource_id: Identifier
    action: Literal["READ"]
    session_version: int = Field(strict=True, ge=1)
    policy_sha256: SHA
    access_record_sha256: SHA


class ManagedExecCapture(StrictModel):
    schema_version: Literal["zt-managed-exec-capture-1"] = "zt-managed-exec-capture-1"
    request: ServiceRequest
    event: ServiceEvent
    runtime_proof: ServiceProof
    authorization_proof: ServiceProof
    caller_receipt: CallerReceipt
    app_use: AppUseReceipt
    exit_code: int = Field(strict=True, ge=0, le=255)
    sealed_at: datetime
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)

    @field_validator("sealed_at")
    @classmethod
    def aware(cls, value):
        return Window.aware(value)


def seal_bytes(capture):
    return canonical(capture.model_dump(mode="json", exclude={"signature"}))


def capture_parts(payload):
    """Structural checks for lossless storage, without blessing historical trust."""
    require(type(payload) is dict, "capture_envelope")
    if payload.get("schema_version") == "zt-managed-exec-capture-1":
        capture = ManagedExecCapture.model_validate(payload)
        r, e, runtime, auth, receipt, app = (
            capture.request,
            capture.event,
            capture.runtime_proof,
            capture.authorization_proof,
            capture.caller_receipt,
            capture.app_use,
        )
        require(
            e.mode == "systemd"
            and e.collection_basis == "ptrace_exec"
            and e.event_id == digest([r.authentication_nonce, e.raw_sha256])
            and (e.tenant_id, e.server_id, e.unit) == (r.tenant_id, r.server_id, r.unit)
            and runtime.observation.kind == "runtime"
            and auth.observation.kind == "authorization"
            and runtime.event_sha256 == auth.event_sha256 == receipt.event_sha256 == e.sha256
            and runtime.tenant_id == auth.tenant_id == e.tenant_id
            and runtime.observation.pid == e.process_id
            and runtime.observation.executable_sha256
            == auth.observation.executable_sha256
            == r.executable_sha256
            and runtime.observation.command_sha256
            == auth.observation.command_sha256
            == r.command_sha256
            and auth.observation.decision == "allow"
            and auth.observation.policy_sha256 == app.policy_sha256
            and receipt.request_sha256 == app.request_sha256 == r.authentication_nonce
            and receipt.caller_ref_sha256 == app.caller_ref_sha256
            and receipt.service_evidence_sha256
            == digest(
                sorted(
                    [runtime.model_dump(mode="json"), auth.model_dump(mode="json")],
                    key=lambda v: v["observation"]["kind"],
                )
            )
            and r.issued_at
            <= e.observed_at
            <= receipt.bound_at
            <= capture.sealed_at
            < r.expires_at,
            "managed_capture_binding",
        )
        return e, runtime
    require(
        set(payload) == {"schema", "event", "runtime_proof", "authorization_proof_included"}
        and payload["schema"] == "zt-service-capture-1"
        and payload["authorization_proof_included"] is False,
        "capture_legacy_envelope",
    )
    event = ServiceEvent.model_validate(payload["event"])
    require(
        event.collection_basis not in {"ptrace_exec", "ptrace_exec_lab"},
        "managed_capture_legacy_downgrade",
    )
    return event, ServiceProof.model_validate(payload["runtime_proof"])


def verify_managed(capture, service_pin, caller_pin, *, now):
    """Current pins plus original signatures; old bytes can only become stale.

    No journal/grant/replay ledger is written by this read-only status check.
    The broker attests to the application-use digest; it is not a separately
    signed application journal nor protection against a compromised broker.
    """
    require(isinstance(caller_pin, PinnedCallerRegistry), "managed_caller_pin_required")
    capture = ManagedExecCapture.model_validate(capture.model_dump())
    capture_parts(capture.model_dump(mode="json"))
    require(capture.sealed_at <= now, "managed_seal_future")
    registry = caller_pin.current(now)
    require(caller_pin.current(capture.sealed_at) == registry, "managed_caller_current")
    verify_receipt(
        capture.caller_receipt, caller_pin, capture.request, capture.event, now=capture.sealed_at
    )
    signature = base64.urlsafe_b64decode(capture.signature + "==")
    require(
        base64.urlsafe_b64encode(signature).decode().rstrip("=") == capture.signature,
        "managed_seal_encoding",
    )
    Ed25519PublicKey.from_public_bytes(public_bytes(registry.broker_public_key)).verify(
        signature, seal_bytes(capture)
    )
    service = service_pin.current(now)
    materials = set()
    for proof in (capture.runtime_proof, capture.authorization_proof):
        matches = [
            a
            for a in service.authorities
            if (a.tenant_id, a.server_id, a.source_id, a.key_id, a.kind, a.mode)
            == (
                proof.tenant_id,
                capture.event.server_id,
                proof.source_id,
                proof.key_id,
                proof.observation.kind,
                "systemd",
            )
        ]
        require(len(matches) == 1, "managed_proof_authority")
        a = matches[0]
        material = public_bytes(a.public_key)
        require(
            a.enabled
            and capture.event.unit in a.units
            and a.issued_at <= proof.observed_at <= proof.issued_at <= capture.sealed_at
            and proof.issued_at < proof.expires_at <= a.expires_at
            and capture.sealed_at < proof.expires_at
            and now < a.expires_at
            and timedelta(0) < proof.expires_at - proof.issued_at <= timedelta(seconds=30)
            and material not in materials
            and material != public_bytes(registry.broker_public_key),
            "managed_proof_window_or_role",
        )
        materials.add(material)
        signed = base64.urlsafe_b64decode(proof.signature + "==")
        require(
            base64.urlsafe_b64encode(signed).decode().rstrip("=") == proof.signature,
            "managed_proof_encoding",
        )
        Ed25519PublicKey.from_public_bytes(material).verify(signed, proof_bytes(proof))
    e, auth = capture.event, capture.authorization_proof
    require(
        e.observed_at - timedelta(seconds=30) <= auth.observed_at <= e.observed_at
        and auth.observation.policy_sha256 == service.policy_sha256
        and auth.observation.policy_version >= service.minimum_policy_version,
        "managed_current_policy",
    )
    require(
        caller_pin.current(now) == registry and service_pin.current(now) == service,
        "managed_registry_changed",
    )
    return capture
