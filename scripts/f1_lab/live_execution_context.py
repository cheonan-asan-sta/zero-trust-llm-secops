"""Local live evidence ingress. Historical PID/actor gaps are never backfilled.

These functions run inside a trusted collector, not on submitted process JSON.
An allowlisted command is policy context, never permission to suppress an alert.
"""

import base64
import hashlib
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from pydantic import Field

from app.models import StrictModel
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.pam_journal import micros, verify
from scripts.f1_lab.service_caller_identity import verify_receipt
from scripts.f1_lab.shared_execution_collector import collect_current_systemd, snapshot_process
from scripts.f1_lab.shared_execution_evidence import (
    PolicyObservation,
    ServiceEvent,
    ServiceProof,
    Unit,
    digest,
    proof_bytes,
    refine_service,
)
from scripts.f1_lab.web_verified_context import SHA, Identifier, Window


class ExecutionRule(StrictModel):
    tenant_id: Identifier
    server_id: Identifier
    unit: Unit
    executable_sha256: SHA
    command_sha256: SHA
    real_uid: int = Field(strict=True, ge=0, le=4294967294)
    effective_uid: int = Field(strict=True, ge=0, le=4294967294)


class ExecutionPolicy(Window):
    schema_version: Literal['zt-live-execution-policy-1'] = 'zt-live-execution-policy-1'
    version: int = Field(strict=True, ge=1)
    rules: list[ExecutionRule] = Field(max_length=1000)


class PinnedExecutionPolicy:
    def __init__(self, path, sha256, *, minimum_version=1):
        require(type(sha256) is str and len(sha256) == 64 and set(sha256) <= set('0123456789abcdef')
                and type(minimum_version) is int and minimum_version > 0, 'execution_policy_pin')
        self.path, self.sha256, self.minimum_version = Path(path), sha256, minimum_version

    def current(self, now):
        require(self.path.is_file() and not self.path.is_symlink(), 'execution_policy_file')
        with self.path.open('rb') as stream:
            body = stream.read(256001)
        require(len(body) <= 256000 and hashlib.sha256(body).hexdigest() == self.sha256,
                'execution_policy_hash')
        policy = ExecutionPolicy.model_validate(decode(body))
        require(policy.version >= self.minimum_version and policy.issued_at <= now < policy.expires_at
                and timedelta(0) < policy.expires_at-policy.issued_at <= timedelta(hours=24),
                'execution_policy_window')
        rules = [digest(r.model_dump(mode='json')) for r in policy.rules]
        require(len(rules) == len(set(rules)), 'execution_policy_duplicates')
        return policy


def collect_service(joiner, policy, runtime_key, policy_key, *, tenant_id, server_id, unit,
                    runtime_source_id, runtime_key_id, policy_source_id, policy_key_id):
    """Read actual MainPID/boot/invocation/proc, evaluate a pinned exact allowlist.

    A missing command in a valid complete allowlist is deny. An unavailable or
    changed policy raises; it must never be converted into an allow or deny.
    Signing keys belong to separately configured authority roles.
    """
    observed = datetime.now(UTC)
    rules = policy.current(observed)
    trust = joiner.registry.current(observed)
    require(trust.policy_sha256 == policy.sha256 and rules.version >= trust.minimum_policy_version,
            'execution_policy_registry_binding')
    event, runtime = collect_current_systemd(unit, runtime_key, tenant_id=tenant_id,
        server_id=server_id, source_id=runtime_source_id, key_id=runtime_key_id)
    proc = runtime.observation
    actual = ExecutionRule(tenant_id=tenant_id, server_id=server_id, unit=unit,
        executable_sha256=proc.executable_sha256, command_sha256=proc.command_sha256,
        real_uid=proc.real_uid, effective_uid=proc.effective_uid)
    issued = datetime.now(UTC)
    permission = ServiceProof(tenant_id=tenant_id, source_id=policy_source_id, key_id=policy_key_id,
        event_sha256=event.sha256, observed_at=observed, issued_at=issued,
        expires_at=min(issued+timedelta(seconds=30), rules.expires_at), signature='A'*86,
        observation=PolicyObservation(decision='allow' if actual in rules.rules else 'deny',
            policy_sha256=policy.sha256, policy_version=rules.version,
            executable_sha256=proc.executable_sha256, command_sha256=proc.command_sha256))
    permission = permission.model_copy(update={'signature': base64.urlsafe_b64encode(
        policy_key.sign(proof_bytes(permission))).decode().rstrip('=')})
    finished = datetime.now(UTC)
    require(policy.current(finished) == rules and joiner.registry.current(finished) == trust,
            'execution_collection_trust_changed')
    facts = joiner.check(event, [runtime, permission], now=finished)
    require(facts.state != 'unavailable', 'execution_collection_rejected')
    return event, [runtime, permission], facts


@dataclass(frozen=True)
class PamExecutionContext:
    state: str
    evidence_sha256: str | None = None
    caller_state: str = 'unavailable'
    caller_ref_sha256: str | None = None
    policy_basis: str = 'current_running_process'
    organization_identity_verified: bool = False
    automatic_enforcement_allowed: bool = False


def collect_pam_context(capture, scope, joiner, event, proofs, *, cursor_sha256,
                        caller_registry=None, request=None, receipt=None, now=None):
    """Join a signed native PAM record to the *same still-live* process only.

    Never attach a child/neighbor PID to a caller by adjacency. Comparing journal
    monotonic time with boot-based proc start time is conservative after suspend:
    evidence can become unavailable, never assigned to a later process lifetime.
    """
    real_clock = now is None
    now = datetime.now(UTC) if real_clock else now
    try:
        event = ServiceEvent.model_validate(event.model_dump())
        require(event.mode == 'systemd' and joiner.mode == 'systemd'
                and (scope.tenant_id, scope.server_id, scope.unit)
                == (event.tenant_id, event.server_id, event.unit), 'pam_execution_scope')
        verified = verify(capture, scope, joiner.registry, boot=event.boot_id,
                          invocation=event.invocation_id, now=now)
        facts = joiner.check(event, proofs, now=now)
        require(facts.state in {'consistent', 'adverse', 'review'}, 'pam_execution_proofs')
        found = [r for r in verified.records if r.cursor_sha256 == cursor_sha256]
        require(len(found) == 1 and found[0].event == 'opened', 'pam_execution_exact_record')
        record = found[0]
        runtime = next(p.observation for p in proofs if p.observation.kind == 'runtime')
        boot, live = snapshot_process(record.reported_process_id)
        ticks = os.sysconf('SC_CLK_TCK')
        require(type(ticks) is int and 1 <= ticks <= 1000000, 'pam_execution_clock_ticks')
        fields = ('pid', 'start_ticks', 'real_uid', 'effective_uid', 'login_uid',
                  'audit_session_id', 'executable_sha256', 'command_sha256')
        require(boot == event.boot_id and record.reported_process_id == event.process_id
                and all(getattr(live, f) == getattr(runtime, f) for f in fields)
                and record.sender_uid == live.real_uid
                and (record.audit_login_uid is None or record.audit_login_uid == live.login_uid)
                and (record.audit_session_id is None or record.audit_session_id == live.audit_session_id)
                and (live.start_ticks+1)*1000000 <= record.monotonic_us*ticks
                and record.monotonic_us <= time.monotonic_ns()//1000
                and 0 <= micros(now)-record.recorded_at_us <= 30000000,
                'pam_execution_lifetime_binding')
        caller_state, caller_ref = 'unavailable', None
        if any(v is not None for v in (caller_registry, request, receipt)):
            require(all(v is not None for v in (caller_registry, request, receipt)), 'pam_caller_complete')
            verify_receipt(receipt, caller_registry, request, event, now=now)
            require(receipt.service_evidence_sha256 == facts.evidence_sha256
                    and request.executable_sha256 == live.executable_sha256
                    and request.command_sha256 == live.command_sha256, 'pam_caller_execution_binding')
            caller_state, caller_ref = receipt.environment, receipt.caller_ref_sha256
        finished = datetime.now(UTC) if real_clock else now
        verify(capture, scope, joiner.registry, boot=event.boot_id,
               invocation=event.invocation_id, now=finished)
        require(joiner.check(event, proofs, now=finished).evidence_sha256 == facts.evidence_sha256,
                'pam_execution_completion')
        if caller_registry is not None:
            verify_receipt(receipt, caller_registry, request, event, now=finished)
        evidence = digest([verified.model_dump(mode='json'), cursor_sha256,
                           facts.evidence_sha256, caller_ref])
        return PamExecutionContext(facts.state, evidence, caller_state, caller_ref)
    except (ValueError, TypeError, OSError, AttributeError, KeyError, StopIteration, InvalidSignature):
        return PamExecutionContext('unavailable')


def refine_pam(previous, context):
    """Only exact verified execution denial adds an alert; no alert suppression."""
    from scripts.f1_lab.shared_execution_evidence import ServiceFacts
    require(isinstance(context, PamExecutionContext), 'pam_execution_context_type')
    return refine_service(previous, ServiceFacts(context.state, context.evidence_sha256))
