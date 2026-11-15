"""Optional local VPN evidence bridge. No grants, revocation, or production API.

The caller supplies connection facts from its authenticated gateway, not from
VPN usernames or IP-only lookup. Public registries are externally pinned.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from threading import RLock
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from pydantic import Field, field_validator

from app.config import get_settings
from app.continuous_signal_models import SignedContinuousSignal
from app.models import StrictModel
from app.security import Principal, Role
from app.services.trusted_signals import SignalRegistryUnavailable, SignalRejected
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.approvals import ApprovalRejected, SignedApproval
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.vpn_context import PREFIX
from scripts.f1_lab.vpn_risk_retention import RetainedContext

Identifier = Annotated[str, Field(pattern=r'^[A-Za-z0-9._-]{1,64}$')]
SHA = Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
HARD_FLAGS = ('auth_failure', 'tls_failure', 'sql_injection', 'path_traversal', 'shell_payload',
              'command_parameter', 'uploaded_script', 'sensitive_file', 'scanner_agent',
              'privilege_tool', 'service_stop', 'http_forbidden')


class VPNConnection(StrictModel):
    tenant_id: Identifier
    gateway_id: Identifier
    session_id: Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$')]
    session_version: int = Field(strict=True, ge=0, le=200)
    user_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=128)
    action: Literal['REMOTE_ACCESS'] = 'REMOTE_ACCESS'
    peer_ip: IPv4Address
    peer_port: int = Field(strict=True, ge=1, le=65535)
    client_certificate_sha256: SHA
    tls_channel_sha256: SHA
    raw_line_sha256: SHA
    observed_at: datetime

    @field_validator('observed_at')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('vpn_connection_timezone')
        return value


class VPNBinding(StrictModel):
    schema_version: Literal['zt-vpn-binding-1'] = 'zt-vpn-binding-1'
    algorithm: Literal['Ed25519'] = 'Ed25519'
    source_id: Identifier
    key_id: Identifier
    request_nonce: SHA
    request_sha256: SHA
    session_sha256: SHA
    posture_sha256: SHA
    approval_sha256: SHA
    issued_at: datetime
    expires_at: datetime
    signature: str = Field(pattern=r'^[A-Za-z0-9_-]{86}$', repr=False)

    @field_validator('issued_at', 'expires_at')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('vpn_binding_timezone')
        return value


class VPNEvidence(StrictModel):
    binding: VPNBinding
    identity: SignedSessionSignal
    posture: SignedContinuousSignal
    approval: SignedApproval | None = None


@dataclass(frozen=True)
class VPNChallenge:
    request: VPNConnection
    nonce: str
    created_at: datetime
    expires_at: datetime

    @property
    def evidence_sha256(self):
        return hashlib.sha256(canonical({'schema': 'zt-vpn-request-1',
            'connection': self.request.model_dump(mode='json'), 'nonce': self.nonce,
            'created_at': self.created_at.isoformat(), 'expires_at': self.expires_at.isoformat()})).hexdigest()


@dataclass(frozen=True)
class VPNFacts:
    state: str
    reason: str
    evidence_sha256: str | None = None


@dataclass(frozen=True)
class VPNRiskDecision(OperationDecision):
    evidence_state: str = 'unavailable'
    evidence_sha256: str | None = None


def binding_bytes(binding):
    return canonical(binding.model_dump(mode='json', exclude={'signature'}))


def payload_sha(value):
    return hashlib.sha256(canonical(value.model_dump(mode='json') if value is not None else None)).hexdigest()


class VPNTrustBridge:
    def __init__(self, signal_verifier, approval_verifier, resource_policies, enrollments, *,
                 gateways, identity_sources, device_sources, capacity=1000):
        require(type(capacity) is int and 1 <= capacity <= 1000, 'vpn_capacity')
        self.signals, self.approvals, self.policies = signal_verifier, approval_verifier, resource_policies
        self.enrollments = enrollments
        # (tenant, source, key) -> exact gateway IDs. Roles are operator config.
        self.gateways = {key: frozenset(value) for key, value in gateways.items()}
        self.identities, self.devices = frozenset(identity_sources), frozenset(device_sources)
        scopes = [set(self.gateways), set(self.identities), set(self.devices)]
        require(all(scopes) and all(len(s) <= 100 for s in scopes)
                and all(len(k) == 3 and all(isinstance(v, str) and v for v in k) for s in scopes for k in s)
                and not (scopes[0] & scopes[1] or scopes[0] & scopes[2] or scopes[1] & scopes[2])
                and all(self.gateways.values()), 'vpn_authority_roles')
        owners = [{k[:2] for k in scope} for scope in scopes]
        require(not (owners[0] & owners[1] or owners[0] & owners[2] or owners[1] & owners[2]),
                'vpn_authority_source_separation')
        self.capacity, self.pending, self.adverse = capacity, {}, {}
        self.lock, self.last_now = RLock(), None

    def _clock(self, now):
        require(get_settings().app_environment in {'local', 'test'}, 'vpn_local_test_only')
        require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None
                and (self.last_now is None or now >= self.last_now), 'vpn_clock')
        self.last_now = now
        self.pending = {k: v for k, v in self.pending.items() if now < v.expires_at}
        self.adverse = {k: v for k, v in self.adverse.items() if now < v}

    @staticmethod
    def _authorize(principal, tenant):
        require(isinstance(principal, Principal) and principal.tenant_id == tenant
                and principal.auth_method in {'api_key', 'oidc'}
                and Role.ANALYST in principal.effective_roles, 'vpn_authenticated_operator')

    @staticmethod
    def _connection_key(request):
        # Exact authenticated channel/session identity; never IP-only identity.
        return (request.tenant_id, request.gateway_id, request.session_id,
                request.client_certificate_sha256, request.tls_channel_sha256)

    def issue(self, request, principal, *, now=None):
        now = datetime.now(UTC) if now is None else now
        request = VPNConnection.model_validate(request.model_dump())
        with self.lock:
            self._clock(now)
            self._authorize(principal, request.tenant_id)
            require(timedelta(0) <= now-request.observed_at <= timedelta(seconds=30), 'vpn_request_freshness')
            require(len(self.pending) < self.capacity, 'vpn_challenge_capacity')
            challenge = VPNChallenge(request, secrets.token_hex(32), now, now+timedelta(seconds=30))
            self.pending[challenge.nonce] = VPNChallenge(request.model_copy(deep=True), challenge.nonce,
                                                        challenge.created_at, challenge.expires_at)
            return challenge

    def check(self, nonce, bundle, raw_line, principal, *, now=None):
        now = datetime.now(UTC) if now is None else now
        try:
            with self.lock:
                self._clock(now)
                challenge = self.pending.get(nonce)
                require(challenge is not None, 'vpn_challenge_unknown_expired_or_consumed')
                request = challenge.request
                self._authorize(principal, request.tenant_id)
                require(isinstance(raw_line, str) and len(raw_line.encode()) <= 2*1024**2
                        and hashlib.sha256(raw_line.encode()).hexdigest() == request.raw_line_sha256,
                        'vpn_raw_binding')
                match = PREFIX.match(raw_line)
                require(match is not None and IPv4Address(match['ip']) == request.peer_ip
                        and int(match['port']) == request.peer_port, 'vpn_endpoint_binding')
                logged = datetime.fromisoformat(raw_line[:19]).replace(tzinfo=UTC)
                require(timedelta(0) <= request.observed_at-logged < timedelta(seconds=1)
                        and timedelta(0) <= now-request.observed_at <= timedelta(seconds=30), 'vpn_log_time_binding')
                del self.pending[nonce]  # One request, even when subsequent verification fails.
                key = self._connection_key(request)
                if key in self.adverse:
                    return VPNFacts('adverse', 'vpn_recent_verified_adverse')
                require(bundle is not None, 'vpn_evidence_missing')
                bundle = VPNEvidence.model_validate(bundle.model_dump())
                binding, identity, posture = bundle.binding, bundle.identity, bundle.posture
                require(binding.request_nonce == nonce and binding.request_sha256 == challenge.evidence_sha256
                        and binding.session_sha256 == payload_sha(identity)
                        and binding.posture_sha256 == payload_sha(posture)
                        and binding.approval_sha256 == payload_sha(bundle.approval), 'vpn_bundle_binding')
                gateway_key = request.tenant_id, binding.source_id, binding.key_id
                require(request.gateway_id in self.gateways.get(gateway_key, ()), 'vpn_gateway_scope')
                sources = self.signals._sources()
                gateway = sources.get(gateway_key[:2])
                require(gateway is not None and gateway.enabled and not gateway.observation_kinds, 'vpn_gateway_authority')
                public_key = next((k for k in gateway.keys if k.key_id == binding.key_id), None)
                require(public_key is not None and public_key.enabled
                        and public_key.not_before <= binding.issued_at <= now < public_key.not_after
                        and binding.expires_at <= public_key.not_after
                        and challenge.created_at <= binding.issued_at < binding.expires_at <= challenge.expires_at
                        and now < binding.expires_at, 'vpn_gateway_freshness')
                signature = base64.urlsafe_b64decode(binding.signature+'==')
                require(base64.urlsafe_b64encode(signature).decode().rstrip('=') == binding.signature, 'vpn_signature_encoding')
                serialization.load_pem_public_key(public_key.public_key_pem.encode()).verify(signature, binding_bytes(binding))
                event = identity.event
                require((identity.tenant_id, identity.source_id, identity.key_id) in self.identities
                        and (posture.tenant_id, posture.source_id, posture.key_id) in self.devices, 'vpn_signal_authority_role')
                self.signals.verify(identity, principal, now)
                self.signals.verify_observation(posture, principal, now)
                for proof in (identity, posture):
                    source = sources[(proof.tenant_id, proof.source_id)]
                    record = next(k for k in source.keys if k.key_id == proof.key_id)
                    require(record.not_before <= proof.issued_at, 'vpn_key_activation')
                require(request.user_id in gateway.user_ids and request.device_id in gateway.device_ids
                        and event.user.role in gateway.roles, 'vpn_gateway_claim_scope')
                require(identity.session_id == request.session_id and identity.expected_version == request.session_version
                        and identity.tenant_id == request.tenant_id == posture.tenant_id
                        and event.user.user_id == request.user_id and event.device.device_id == request.device_id
                        and event.resource.resource_id == request.resource_id and event.action.value == request.action
                        and event.network.access_method == 'vpn' and IPv4Address(event.network.ip) == request.peer_ip
                        and event.timestamp == request.observed_at and event.ground_truth is None,
                        'vpn_identity_binding')
                require(posture.observation.kind == 'device' and posture.observation.subject_id == request.device_id
                        and timedelta(0) <= now-posture.observed_at <= timedelta(seconds=30)
                        and timedelta(0) <= now-event.timestamp <= timedelta(seconds=30), 'vpn_posture_binding')
                enrollment_sha = self.enrollments.verify(request, now=now)
                policy = self.policies.resolve(event, request.tenant_id, now=now)
                unhealthy = (not event.user.active or event.auth_context.authentication_result != 'success'
                    or event.auth_context.mfa != 'success' or event.auth_context.failed_attempts > 0
                    or not event.device.managed or event.device.security_posture != 'healthy'
                    or not posture.observation.managed or posture.observation.security_posture != 'healthy'
                    or not policy.role_and_action_allowed or event.network.location_anomaly
                    or event.behavior.new_device or event.behavior.unusual_time
                    or event.behavior.request_rate != 'normal' or event.behavior.distinct_resources_10m > 1
                    or any(raw_features(event.behavior.event_text or '')[name] for name in HARD_FLAGS))
                if unhealthy:
                    require(key in self.adverse or len(self.adverse) < self.capacity, 'vpn_adverse_capacity')
                    self.adverse[key] = now+timedelta(seconds=60)
                    return VPNFacts('adverse', 'vpn_verified_device_or_permission_risk', payload_sha(bundle))
                require(bundle.approval is not None and
                        bundle.approval.context.window_evidence_sha256 == challenge.evidence_sha256
                        and challenge.created_at <= bundle.approval.context.issued_at, 'vpn_permission_request_binding')
                authority, _ = self.approvals.current()
                approval_key = authority.authorities.get((request.tenant_id, bundle.approval.context.issuer_id,
                                                          bundle.approval.context.key_id))
                require(approval_key is not None, 'vpn_approval_authority')
                approval_public = approval_key.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                require(all(approval_public != serialization.load_pem_public_key(k.public_key_pem.encode()).public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw) for source in sources.values()
                    if source.tenant_id == request.tenant_id for k in source.keys), 'vpn_approval_key_separation')
                require(authority.verify(bundle.approval, event, request.tenant_id, now=now) == frozenset({'remote_access'}),
                        'vpn_approval_deviation_scope')
                # Recheck immutable authority/policy pins before using positive evidence.
                require(self.signals._sources() == sources and self.policies.resolve(event, request.tenant_id, now=now) == policy,
                        'vpn_authority_changed')
                self.approvals.current()
                require(self.enrollments.verify(request, now=now) == enrollment_sha, 'vpn_enrollment_changed')
                return VPNFacts('approved', 'vpn_verified_healthy_authorized_request', payload_sha(bundle))
        except (ValueError, TypeError, OSError, KeyError, StopIteration, InvalidSignature,
                SignalRejected, SignalRegistryUnavailable, ApprovalRejected):
            return VPNFacts('unavailable', 'vpn_evidence_rejected_or_unavailable')


class VerifiedVPNRisk:
    def __init__(self, baseline, bridge):
        self.baseline, self.bridge = baseline, bridge
        self.web_model, self.vpn_model = baseline.web_model, baseline.vpn_model

    def decide(self, features, case_id, context=None, *, nonce=None, evidence=None,
               raw_line=None, principal=None, now=None):
        before = self.baseline.decide(features, case_id, context)
        if nonce is None or self.bridge is None:
            return before
        require(isinstance(context, RetainedContext) and context.base.kind == 'vpn', 'vpn_retained_context_required')
        if not isinstance(raw_line, str) or features != {**core_features(raw_line), **semantic_observations(raw_line)}:
            return before
        facts = self.bridge.check(nonce, evidence, raw_line, principal, now=now)
        result = before
        if facts.state == 'adverse':
            result = OperationDecision(before.baseline_score, 1., True, True, facts.reason)
        elif facts.state == 'approved' and any(features[n] for n in HARD_FLAGS):
            result = OperationDecision(before.baseline_score, 1., True, True, 'vpn_independent_security_signal')
        elif facts.state == 'approved' and context.prior_score < .95 and before.baseline_score < .9:
            # Only supplemental novelty; this decision never authorizes access.
            result = OperationDecision(before.baseline_score, before.baseline_score,
                before.baseline_score >= .95, before.baseline_score >= .9, facts.reason)
        return VPNRiskDecision(**result.__dict__, evidence_state=facts.state, evidence_sha256=facts.evidence_sha256)
