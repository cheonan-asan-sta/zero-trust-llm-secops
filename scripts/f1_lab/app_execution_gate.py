"""Trusted server adapter: request-bound identity AND the existing app grant.

No public API, command input, token minting or approval bypass. Grant consumption
is durable before launch; a later failed/uncertain launch never refunds it.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from app.security import Principal, Role
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import ProtectedAccessRequest
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.service_caller_identity import ServiceCallerBroker, verify_identity
from scripts.f1_lab.shared_execution_evidence import PolicyObservation, digest
from scripts.f1_lab.systemd_request_launcher import UnitTarget


@dataclass(frozen=True)
class AppExecutionTarget:
    execution: UnitTarget
    resource_id: str
    action: str


class AppExecutionGate:
    def __init__(
        self,
        broker,
        operations,
        target,
        request,
        principal,
        access,
        token,
        *,
        policy_version=1,
        allow_demo=False,
    ):
        require(
            isinstance(broker, ServiceCallerBroker)
            and isinstance(operations, ZeroTrustOperations)
            and isinstance(target, AppExecutionTarget)
            and isinstance(principal, Principal)
            and isinstance(access, ProtectedAccessRequest)
            and type(policy_version) is int
            and policy_version > 0
            and type(allow_demo) is bool,
            "app_execution_configuration",
        )
        self.broker, self.operations, self.target = broker, operations, target
        self.request, self.principal = request.model_copy(deep=True), principal
        self.access, self.token = access.model_copy(deep=True), token
        self.policy_version, self.allow_demo = policy_version, allow_demo
        self.used = False
        self.authorized_version = None

    def authorize(self, request):
        now = datetime.now(UTC)
        require(not self.used and request == self.request, "app_execution_request")
        target, principal = self.target, self.principal
        resource = self.operations.resources.get(target.resource_id)
        require(
            resource is not None and resource.sensitivity == "internal" and target.action == "READ",
            "app_execution_low_impact_target_required",
        )
        require(
            (
                request.tenant_id,
                request.server_id,
                request.unit,
                request.executable_sha256,
                request.command_sha256,
            )
            == (
                target.execution.tenant_id,
                target.execution.server_id,
                target.execution.unit,
                target.execution.executable_sha256,
                target.execution.command_sha256,
            )
            and principal.tenant_id == request.tenant_id
            and Role.RESPONDER in principal.effective_roles
            and principal.auth_method in {"api_key", "oidc"}
            and (self.access.resource_id, self.access.action.value)
            == (target.resource_id, target.action),
            "app_execution_scope",
        )
        identity = self.broker.trust(now)
        actor, _ = verify_identity(self.token, request, identity, now)
        require(
            actor == digest([identity.issuer, principal.tenant_id, principal.subject]),
            "app_execution_caller_identity",
        )
        policy = self.broker.joiner.registry.current(now)
        require(
            policy.policy_sha256 == self.operations.policy_digest
            and self.policy_version >= policy.minimum_policy_version,
            "app_execution_current_policy",
        )
        current = self.operations.history(self.access.session_id, principal)[-1]
        require(
            self.allow_demo or current.signal_trust == "verified_source",
            "app_execution_verified_session_required",
        )
        # The app's transaction rechecks owner, exact resource/action, current
        # policy/source, revocation, expiry and prior use before consuming once.
        result = self.operations.access(
            self.access, principal, now=now, execution_request_sha256=request.authentication_nonce
        )
        self.used = True
        require(
            result.allowed and result.reason_code == "ACCESS_GRANTED", "app_execution_grant_denied"
        )
        self.authorized_version = result.session_version
        return PolicyObservation(
            decision="allow",
            policy_sha256=policy.policy_sha256,
            policy_version=self.policy_version,
            executable_sha256=request.executable_sha256,
            command_sha256=request.command_sha256,
        ), datetime.now(UTC)

    def launch(self, request, launcher):
        now = datetime.now(UTC)
        require(self.used and request == self.request, "app_execution_unconsumed_grant")
        policy = self.broker.joiner.registry.current(now)
        self.broker.trust(now)
        current = self.operations.history(self.access.session_id, self.principal)[-1]
        require(
            current.version == self.authorized_version
            and current.operator_id == self.principal.subject
            and current.decision == "ALLOW"
            and current.status == "ACTIVE"
            and current.resource_id == self.target.resource_id
            and current.action.value == self.target.action
            and current.policy_digest_sha256
            == self.operations.policy_digest
            == policy.policy_sha256
            and current.grant_expires_at is not None
            and now < current.grant_expires_at
            and now < request.expires_at,
            "app_execution_changed_before_launch",
        )
        if current.signal_trust == "verified_source":
            require(
                current.signal_expires_at is not None
                and now < current.signal_expires_at
                and current.signal_source_digest
                == self.operations.signal_verifier.source_digest(
                    self.principal.tenant_id, current.signal_source_id, current.signal_key_id, now
                ),
                "app_execution_source_changed_before_launch",
            )
        launcher.launch(request)

    def dispatch(self, launcher, policy_proof):
        return self.broker.dispatch(
            self.request.request_id,
            self.token,
            authorize=self.authorize,
            launch=lambda request: self.launch(request, launcher),
            collect=launcher.collect,
            policy_proof=policy_proof,
        )
