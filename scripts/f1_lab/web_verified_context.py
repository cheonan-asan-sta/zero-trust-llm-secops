"""Optional local, request-bound server facts; never grants or clears alarms."""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StrictBool, field_validator, model_validator

from app.config import get_settings
from app.models import StrictModel
from app.security import Principal, Role
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.web_residual import ACCESS, INTRINSIC_NAMES, encoded_argv_request

Identifier = Annotated[str, Field(pattern=r'^[A-Za-z0-9._-]{1,128}$')]
SHA = Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
KINDS = ('authentication', 'authorization', 'runtime')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class Window(StrictModel):
    issued_at: datetime
    expires_at: datetime

    @field_validator('issued_at', 'expires_at')
    @classmethod
    def aware(cls, value):
        require(value.tzinfo is not None and value.utcoffset() is not None, 'web_context_timezone')
        return value


class WebRequest(StrictModel):
    tenant_id: Identifier
    server_id: Identifier
    request_id: Identifier
    case_id: SHA
    subject_id: Identifier
    session_id: Identifier
    session_version: int = Field(strict=True, ge=0, le=1000000)
    resource_id: Identifier
    method: Literal['GET', 'POST', 'HEAD']
    target_sha256: SHA
    body_sha256: SHA
    raw_line_sha256: SHA
    observed_at: datetime

    @field_validator('observed_at')
    @classmethod
    def aware(cls, value):
        return Window.aware(value)


class Authentication(StrictModel):
    kind: Literal['authentication']
    result: Literal['success', 'failure', 'unknown']
    mfa: Literal['success', 'failure', 'not_used', 'unknown']


class Authorization(StrictModel):
    kind: Literal['authorization']
    decision: Literal['allow', 'deny', 'unknown']
    action: Literal['execute_uploaded_script']
    policy_sha256: SHA
    policy_version: int = Field(strict=True, ge=1)


class Runtime(StrictModel):
    kind: Literal['runtime']
    executed: StrictBool | None
    executable_sha256: SHA | None
    process_ref_sha256: SHA | None

    @model_validator(mode='after')
    def execution_binding(self):
        require((self.executable_sha256 is not None and self.process_ref_sha256 is not None) if self.executed is True
                else self.executable_sha256 is None and self.process_ref_sha256 is None,
                'web_context_execution_observation')
        return self


class ServerProof(Window):
    schema_version: Literal['zt-web-server-proof-1']
    tenant_id: Identifier
    source_id: Identifier
    key_id: Identifier
    request_sha256: SHA
    observed_at: datetime
    observation: Annotated[Authentication | Authorization | Runtime, Field(discriminator='kind')]
    signature: str = Field(pattern=r'^[A-Za-z0-9_-]{86}$', repr=False)

    @field_validator('observed_at')
    @classmethod
    def aware_observation(cls, value):
        return Window.aware(value)


class WebBundle(StrictModel):
    proofs: list[ServerProof] = Field(min_length=3, max_length=3)


class Authority(Window):
    tenant_id: Identifier
    source_id: Identifier
    key_id: Identifier
    kind: Literal['authentication', 'authorization', 'runtime']
    public_key: str = Field(pattern=r'^[A-Za-z0-9_-]{43}$')
    enabled: StrictBool
    server_ids: list[Identifier] = Field(min_length=1, max_length=100)
    subject_ids: list[Identifier] = Field(min_length=1, max_length=100)
    resource_ids: list[Identifier] = Field(min_length=1, max_length=100)


class Resource(StrictModel):
    tenant_id: Identifier
    server_id: Identifier
    resource_id: Identifier
    authorization_policy_sha256: SHA
    minimum_policy_version: int = Field(strict=True, ge=1)


class WebRegistry(Window):
    schema_version: Literal['zt-web-context-registry-1']
    version: int = Field(strict=True, ge=1)
    authorities: list[Authority] = Field(min_length=3, max_length=100)
    resources: list[Resource] = Field(min_length=1, max_length=1000)


def proof_bytes(proof):
    return canonical(proof.model_dump(mode='json', exclude={'signature'}))


def public_bytes(text):
    raw = base64.urlsafe_b64decode(text+'=')
    require(len(raw) == 32 and base64.urlsafe_b64encode(raw).decode().rstrip('=') == text,
            'web_context_public_key_encoding')
    return raw


class PinnedWebRegistry:
    def __init__(self, path, expected_sha256, *, minimum_version):
        require(isinstance(expected_sha256, str) and len(expected_sha256) == 64
                and set(expected_sha256) <= set('0123456789abcdef')
                and type(minimum_version) is int and minimum_version >= 1, 'web_context_registry_pin')
        self.path, self.expected_sha256, self.minimum_version = Path(path), expected_sha256, minimum_version

    def current(self, now):
        require(self.path.is_file() and not self.path.is_symlink() and self.path.stat().st_size <= 256000,
                'web_context_registry_file')
        with self.path.open('rb') as stream:
            body = stream.read(256001)
        require(len(body) <= 256000 and hashlib.sha256(body).hexdigest() == self.expected_sha256,
                'web_context_registry_hash')
        registry = WebRegistry.model_validate(decode(body))
        require(registry.version >= self.minimum_version and registry.issued_at <= now < registry.expires_at
                and timedelta(0) < registry.expires_at-registry.issued_at <= timedelta(hours=24),
                'web_context_registry_window_version')
        identities, sources, keys, roles = set(), {}, set(), set()
        for authority in registry.authorities:
            identity = authority.tenant_id, authority.source_id, authority.key_id
            key = public_bytes(authority.public_key)
            source = authority.tenant_id, authority.source_id
            require(identity not in identities and key not in keys
                    and (source not in sources or sources[source] == authority.kind)
                    and authority.issued_at < authority.expires_at, 'web_context_authority_separation')
            for scope in (authority.server_ids, authority.subject_ids, authority.resource_ids):
                require(len(scope) == len(set(scope)), 'web_context_duplicate_scope')
            identities.add(identity)
            keys.add(key)
            sources[source] = authority.kind
            roles.add(authority.kind)
        require(roles == set(KINDS), 'web_context_authority_roles')
        resources = [(r.tenant_id, r.server_id, r.resource_id) for r in registry.resources]
        require(len(resources) == len(set(resources)), 'web_context_duplicate_resource')
        return registry


@dataclass(frozen=True)
class WebChallenge:
    request: WebRequest
    nonce: str
    owner: str
    created_at: datetime
    expires_at: datetime

    @property
    def sha256(self):
        return digest({'schema': 'zt-web-challenge-1', 'request': self.request.model_dump(mode='json'),
            'nonce': self.nonce, 'owner': self.owner, 'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat()})


@dataclass(frozen=True)
class WebFacts:
    state: str
    reason: str
    evidence_sha256: str | None = None


class WebTrustBridge:
    def __init__(self, registry, *, capacity=1000):
        require(isinstance(registry, PinnedWebRegistry) and type(capacity) is int and 1 <= capacity <= 1000,
                'web_context_capacity')
        self.registry, self.capacity = registry, capacity
        self.pending, self.last_now, self.lock = {}, None, RLock()

    def _clock(self, now):
        require(get_settings().app_environment in {'local', 'test'}, 'web_context_local_test_only')
        require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None
                and (self.last_now is None or self.last_now <= now), 'web_context_clock')
        self.last_now = now
        self.pending = {k: v for k, v in self.pending.items() if now < v.expires_at}

    @staticmethod
    def _authorize(principal, tenant, owner=None):
        require(isinstance(principal, Principal) and principal.tenant_id == tenant
                and principal.auth_method in {'api_key', 'oidc'} and Role.ANALYST in principal.effective_roles
                and (owner is None or owner == principal.subject), 'web_context_operator')

    def issue(self, request, principal, *, now=None):
        now = datetime.now(UTC) if now is None else now
        request = WebRequest.model_validate(request.model_dump())
        with self.lock:
            self._clock(now)
            self._authorize(principal, request.tenant_id)
            require(timedelta(0) <= now-request.observed_at <= timedelta(seconds=30), 'web_context_request_freshness')
            require(len(self.pending) < self.capacity, 'web_context_pending_capacity')
            challenge = WebChallenge(request, secrets.token_hex(32), principal.subject, now, now+timedelta(seconds=30))
            self.pending[challenge.nonce] = WebChallenge(request.model_copy(deep=True), challenge.nonce,
                challenge.owner, challenge.created_at, challenge.expires_at)
            return challenge

    def check(self, nonce, bundle, raw_line, case_id, principal, *, now=None):
        now = datetime.now(UTC) if now is None else now
        try:
            with self.lock:
                self._clock(now)
                challenge = self.pending.get(nonce)
                require(challenge is not None, 'web_context_unknown_expired_or_consumed')
                request = challenge.request
                self._authorize(principal, request.tenant_id, challenge.owner)
                del self.pending[nonce]  # A rejected attempt cannot reuse a challenge either.
                require(case_id == request.case_id and isinstance(raw_line, str)
                        and len(raw_line.encode()) <= MAX_ROW and digest_raw(raw_line) == request.raw_line_sha256,
                        'web_context_raw_case_binding')
                match = ACCESS.fullmatch(raw_line.rstrip('\r\n'))
                require(match is not None and encoded_argv_request(raw_line)
                        and digest_raw(match['target']) == request.target_sha256
                        and raw_line[:match.start('target')].rsplit('"', 1)[-1].strip() == request.method,
                        'web_context_request_binding')
                moment = raw_time(raw_line, int(now.timestamp())-60, int(now.timestamp())+60, source_timezone='UTC')
                require(0 <= request.observed_at.timestamp()-moment < 1
                        and timedelta(0) <= now-request.observed_at <= timedelta(seconds=30), 'web_context_log_time')
                bundle = WebBundle.model_validate(bundle.model_dump())
                registry = self.registry.current(now)
                resources = [r for r in registry.resources if (r.tenant_id, r.server_id, r.resource_id) ==
                             (request.tenant_id, request.server_id, request.resource_id)]
                require(len(resources) == 1, 'web_context_resource_scope')
                observations = {}
                for proof in bundle.proofs:
                    kind = proof.observation.kind
                    require(kind not in observations and proof.tenant_id == request.tenant_id
                            and proof.request_sha256 == challenge.sha256, 'web_context_proof_request_binding')
                    authorities = [a for a in registry.authorities if
                        (a.tenant_id, a.source_id, a.key_id, a.kind) ==
                        (proof.tenant_id, proof.source_id, proof.key_id, kind)]
                    require(len(authorities) == 1, 'web_context_authority_role')
                    authority = authorities[0]
                    require(authority.enabled and request.server_id in authority.server_ids
                            and request.subject_id in authority.subject_ids and request.resource_id in authority.resource_ids,
                            'web_context_authority_scope')
                    require(authority.issued_at <= proof.issued_at <= now < authority.expires_at
                            and challenge.created_at <= proof.issued_at < proof.expires_at <= challenge.expires_at
                            and proof.expires_at <= authority.expires_at and now < proof.expires_at
                            and request.observed_at <= proof.observed_at <= proof.issued_at,
                            'web_context_proof_freshness')
                    signature = base64.urlsafe_b64decode(proof.signature+'==')
                    require(base64.urlsafe_b64encode(signature).decode().rstrip('=') == proof.signature,
                            'web_context_signature_encoding')
                    Ed25519PublicKey.from_public_bytes(public_bytes(authority.public_key)).verify(signature, proof_bytes(proof))
                    observations[kind] = proof.observation
                require(set(observations) == set(KINDS), 'web_context_complete_bundle')
                auth, permission, runtime = (observations[k] for k in KINDS)
                resource = resources[0]
                require(permission.policy_sha256 == resource.authorization_policy_sha256
                        and permission.policy_version >= resource.minimum_policy_version, 'web_context_policy_binding')
                require(self.registry.current(now) == registry, 'web_context_registry_changed')
                evidence_sha = digest(bundle.model_dump(mode='json'))
                if runtime.executed is True and (permission.decision == 'deny' or auth.result == 'failure' or auth.mfa == 'failure'):
                    return WebFacts('adverse', 'web_verified_denial_or_auth_failure_with_execution', evidence_sha)
                if auth.result == 'unknown' or permission.decision == 'unknown' or runtime.executed is None:
                    return WebFacts('incomplete', 'web_verified_observation_incomplete', evidence_sha)
                if auth.result == 'success' and auth.mfa == 'success' and permission.decision == 'allow':
                    return WebFacts('consistent', 'web_verified_request_context_consistent', evidence_sha)
                return WebFacts('review', 'web_verified_context_requires_review', evidence_sha)
        except (ValueError, TypeError, OSError, KeyError, AttributeError, InvalidSignature, RecursionError):
            return WebFacts('unavailable', 'web_context_rejected_or_unavailable')


def digest_raw(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class WebContextDecision(OperationDecision):
    evidence_state: str = 'unavailable'
    evidence_sha256: str | None = None


class VerifiedWebRisk:
    def __init__(self, baseline, bridge):
        self.baseline, self.bridge = baseline, bridge

    def decide(self, features, case_id, context=None, evidence=None, *, nonce=None, bundle=None,
               raw_line=None, principal=None, now=None):
        before = self.baseline.decide(features, case_id, context, evidence)
        if nonce is None or self.bridge is None:
            return before
        facts = self.bridge.check(nonce, bundle, raw_line, case_id, principal, now=now)
        try:
            intrinsic = core_features(raw_line)
            require(all(features[name] == intrinsic[name] for name in INTRINSIC_NAMES), 'web_context_feature_binding')
        except (ValueError, TypeError, KeyError, AttributeError):
            return before
        result = before
        if facts.state == 'adverse':
            result = OperationDecision(before.baseline_score, max(before.score, 1.), True, True, facts.reason)
        return WebContextDecision(**result.__dict__, evidence_state=facts.state, evidence_sha256=facts.evidence_sha256)
