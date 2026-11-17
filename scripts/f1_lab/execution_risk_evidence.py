"""Use live proof to resolve only attributed identity uncertainty, not threats.

All inputs are trusted internal detector/collector outputs, never client risk
scores. Decisions remain advisory. Local policy controls are not attack labels.
"""

import hashlib
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from pydantic import Field

from app.config import get_settings
from scripts.f1_lab.live_execution_context import collect_pam_context
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.service_caller_identity import verify_receipt
from scripts.f1_lab.shared_execution_collector import snapshot_process
from scripts.f1_lab.shared_execution_evidence import ServiceEvent, digest
from scripts.f1_lab.web_verified_context import SHA, Window

Kind = Literal['audit-share', 'auth']


class CallerRiskPolicy(Window):
    schema_version: Literal['zt-caller-risk-policy-1'] = 'zt-caller-risk-policy-1'
    version: int = Field(strict=True, ge=1)
    authentication_registry_sha256: SHA
    revoked_caller_refs: list[SHA] = Field(max_length=1000)


class PinnedCallerRiskPolicy:
    """Current explicit revocations, independently pinned from receipt trust.

    A receipt stays bound to its exact authentication registry; this file never
    relaxes that binding or imports a receipt from an obsolete/disabled issuer.
    """
    def __init__(self, path, sha256, *, minimum_version=1):
        require(type(sha256) is str and len(sha256) == 64 and set(sha256) <= set('0123456789abcdef')
                and type(minimum_version) is int and minimum_version > 0, 'caller_risk_pin')
        self.path, self.sha256, self.minimum_version = Path(path), sha256, minimum_version

    def current(self, authentication_registry_sha256, now):
        require(self.path.is_file() and not self.path.is_symlink(), 'caller_risk_file')
        with self.path.open('rb') as stream:
            body = stream.read(256001)
        require(len(body) <= 256000 and hashlib.sha256(body).hexdigest() == self.sha256,
                'caller_risk_hash')
        policy = CallerRiskPolicy.model_validate(decode(body))
        require(policy.version >= self.minimum_version
                and policy.authentication_registry_sha256 == authentication_registry_sha256
                and policy.issued_at <= now < policy.expires_at
                and timedelta(0) < policy.expires_at-policy.issued_at <= timedelta(hours=1)
                and len(policy.revoked_caller_refs) == len(set(policy.revoked_caller_refs)),
                'caller_risk_scope_window')
        return policy


@dataclass(frozen=True)
class ContextRiskDecision(OperationDecision):
    event_sha256: str = ''
    kind: str = ''
    independent: OperationDecision | None = None


def add_identity_uncertainty(independent, event, *, kind, uncertainty_score):
    """Attach detector-attributed supplemental risk to one exact live event.

    A generic historical model alert cannot be retroactively described as this
    component. Independent threat findings must be supplied intact by the
    configured detector; callers must not relabel their score as uncertainty.
    """
    require(isinstance(independent, OperationDecision) and not isinstance(independent, ContextRiskDecision)
            and independent.automatic_enforcement_allowed is False
            and type(independent.alert) is bool and type(independent.review) is bool
            and kind in {'audit-share', 'auth'}, 'execution_risk_attribution')
    for score in (independent.baseline_score, independent.score, uncertainty_score):
        require(type(score) in {int, float} and math.isfinite(score) and 0 <= score <= 1,
                'execution_risk_score')
    event = ServiceEvent.model_validate(event.model_dump())
    score = max(independent.score, uncertainty_score)
    return ContextRiskDecision(independent.baseline_score, score,
        independent.alert or score >= .95, independent.review or score >= .9,
        'execution_identity_uncertainty', False, event.sha256, kind, independent)


@dataclass(frozen=True)
class ExecutionRiskEvidence:
    kind: str
    event_sha256: str
    state: str = 'unavailable'
    evidence_sha256: str | None = None


def _caller_state(registry, request, receipt, event, service_sha256, runtime, risk_policy, now):
    verify_receipt(receipt, registry, request, event, now=now)
    require(receipt.service_evidence_sha256 == service_sha256
            and request.command_sha256 == runtime.command_sha256
            and request.executable_sha256 == runtime.executable_sha256, 'risk_caller_execution')
    policy = risk_policy.current(registry.sha256, now)
    return ('adverse' if receipt.caller_ref_sha256 in policy.revoked_caller_refs else 'approved'), policy


def service_evidence(joiner, event, proofs, *, caller_registry=None, request=None,
                     receipt=None, risk_policy=None, now=None):
    real_clock = now is None
    now = datetime.now(UTC) if real_clock else now
    unavailable = ExecutionRiskEvidence('audit-share', '')
    try:
        require(get_settings().app_environment in {'local', 'test'}, 'risk_local_only')
        event = ServiceEvent.model_validate(event.model_dump())
        unavailable = ExecutionRiskEvidence('audit-share', event.sha256)
        facts = joiner.check(event, proofs, now=now)
        require(facts.state in {'consistent', 'adverse'}, 'risk_service_proofs')
        runtime = next(p.observation for p in proofs if p.observation.kind == 'runtime')
        boot, live = snapshot_process(event.process_id)
        fields = ('pid', 'start_ticks', 'real_uid', 'effective_uid', 'login_uid',
                  'audit_session_id', 'executable_sha256', 'command_sha256')
        require(event.mode == joiner.mode == 'systemd' and boot == event.boot_id
                and all(getattr(live, f) == getattr(runtime, f) for f in fields), 'risk_live_process')
        if facts.state == 'adverse':
            return ExecutionRiskEvidence('audit-share', event.sha256, 'adverse', facts.evidence_sha256)
        state, policy = _caller_state(caller_registry, request, receipt, event,
            facts.evidence_sha256, live, risk_policy, now)
        finished = datetime.now(UTC) if real_clock else now
        require(joiner.check(event, proofs, now=finished).evidence_sha256 == facts.evidence_sha256
                and risk_policy.current(caller_registry.sha256, finished) == policy, 'risk_service_completion')
        verify_receipt(receipt, caller_registry, request, event, now=finished)
        completed = datetime.now(UTC) if real_clock else finished
        require(finished <= completed < min(request.expires_at, policy.expires_at,
                *(p.expires_at for p in proofs)), 'risk_service_expired_at_completion')
        return ExecutionRiskEvidence('audit-share', event.sha256, state,
            digest([facts.evidence_sha256, receipt.model_dump(mode='json'), risk_policy.sha256, state]))
    except (ValueError, TypeError, OSError, AttributeError, KeyError, StopIteration, InvalidSignature):
        return unavailable


def pam_evidence(capture, scope, joiner, event, proofs, *, cursor_sha256,
                 caller_registry=None, request=None, receipt=None, risk_policy=None, now=None):
    real_clock = now is None
    unavailable = ExecutionRiskEvidence('auth', '')
    try:
        require(get_settings().app_environment in {'local', 'test'}, 'risk_local_only')
        event = ServiceEvent.model_validate(event.model_dump())
        unavailable = ExecutionRiskEvidence('auth', event.sha256)
        context = collect_pam_context(capture, scope, joiner, event, proofs, cursor_sha256=cursor_sha256,
            caller_registry=caller_registry, request=request, receipt=receipt, now=now)
        now = datetime.now(UTC) if real_clock else now
        if context.state == 'adverse':
            return ExecutionRiskEvidence('auth', event.sha256, 'adverse', context.evidence_sha256)
        require(context.state == 'consistent' and context.caller_ref_sha256 is not None,
                'risk_pam_context')
        facts = joiner.check(event, proofs, now=now)
        runtime = next(p.observation for p in proofs if p.observation.kind == 'runtime')
        state, policy = _caller_state(caller_registry, request, receipt, event,
            facts.evidence_sha256, runtime, risk_policy, now)
        finished = datetime.now(UTC) if real_clock else now
        final = collect_pam_context(capture, scope, joiner, event, proofs, cursor_sha256=cursor_sha256,
            caller_registry=caller_registry, request=request, receipt=receipt, now=finished)
        require(final == context and risk_policy.current(caller_registry.sha256, finished) == policy,
                'risk_pam_completion')
        completed = datetime.now(UTC) if real_clock else finished
        require(finished <= completed < min(capture.expires_at, request.expires_at,
                policy.expires_at, *(p.expires_at for p in proofs)), 'risk_pam_expired_at_completion')
        return ExecutionRiskEvidence('auth', event.sha256, state,
            digest([context.evidence_sha256, risk_policy.sha256, state]))
    except (ValueError, TypeError, OSError, AttributeError, KeyError, StopIteration, InvalidSignature):
        return unavailable


def refine_execution(previous, evidence):
    require(isinstance(previous, ContextRiskDecision) and previous.independent is not None
            and isinstance(evidence, ExecutionRiskEvidence), 'risk_bound_decision')
    if (previous.kind, previous.event_sha256) != (evidence.kind, evidence.event_sha256):
        return previous
    if (evidence.state in {'approved', 'adverse'}
            and (type(evidence.evidence_sha256) is not str or len(evidence.evidence_sha256) != 64
                 or not set(evidence.evidence_sha256) <= set('0123456789abcdef'))):
        return previous
    if evidence.state == 'adverse':
        if previous.alert:
            return previous
        return OperationDecision(previous.baseline_score, 1., True, True,
                                 'verified_current_execution_or_caller_denial')
    base = previous.independent
    if evidence.state == 'approved' and not base.alert and base.score < .9 and base.baseline_score < .9:
        return OperationDecision(base.baseline_score, base.score, False, True,
                                 'verified_caller_resolves_supplemental_identity_risk')
    return previous
