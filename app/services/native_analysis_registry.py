"""Bounded, process-local references published only by a trusted server collector.

No HTTP publication route exists. Records last at most 30 seconds, survive no
restart, and are not capabilities: resolving one also requires the same caller
and tenant, current analyst authentication, and live evidence revalidation.
"""

import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from threading import RLock

from app.security import Principal, Role
from app.services.session_analysis_evidence import VerifiedSessionContext
from app.services.trusted_signals import SignalRejected
from app.zero_trust_models import SignedSessionSignal


class NativeAnalysisMissing(LookupError):
    pass


@dataclass(frozen=True)
class _PublishedExecution:
    signal: SignedSessionSignal
    tenant_id: str
    subject: str
    expires_at: datetime
    collect: Callable[[Principal], VerifiedSessionContext]
    binding_sha256: str | None = None


class NativeAnalysisRegistry:
    def __init__(self, operations, *, capacity: int = 128):
        if operations is None or type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError("native analysis registry configuration rejected")
        self.operations = operations
        self.capacity = capacity
        self._records: dict[str, _PublishedExecution] = {}
        self._lock = RLock()

    def _prune(self, now):
        for ref in [ref for ref, entry in self._records.items() if entry.expires_at <= now]:
            del self._records[ref]

    @staticmethod
    def _authenticated(principal):
        if principal.auth_method not in {"api_key", "oidc"} or (
            Role.ANALYST not in principal.effective_roles
        ):
            raise SignalRejected("authenticated native analysis caller required")

    @staticmethod
    def _snapshot(context, signal):
        if not isinstance(context, VerifiedSessionContext) or context.verify_current is None:
            raise SignalRejected("live native evidence collector required")
        facts = context.for_event(signal.event)
        native = facts.get("native_execution")
        if not isinstance(native, dict) or not (
            native.get("signatures_and_exact_bindings_verified") is True
            and native.get("mode") == "systemd"
            and native.get("collection_basis") == "ptrace_exec"
            and facts.get("tenant_id") == signal.tenant_id
            and facts.get("not_an_access_grant") is True
        ):
            raise SignalRejected("verified native execution snapshot required")
        return facts

    def publish(self, signal, principal, collect):
        """Trusted in-process API. collect must use server-owned stores and pins."""
        self._authenticated(principal)
        signal = SignedSessionSignal.model_validate(signal.model_dump(mode="json"))
        if signal.tenant_id != principal.tenant_id:
            raise SignalRejected("native publication tenant mismatch")
        context = collect(principal)
        self._snapshot(context, signal)
        context.verify_current()
        now = datetime.now(UTC)
        if not timedelta(0) < context.expires_at - now <= timedelta(seconds=30):
            raise SignalRejected("native publication window rejected")
        entry = _PublishedExecution(
            signal, principal.tenant_id, principal.subject, context.expires_at, collect
        )
        with self._lock:
            self._prune(now)
            if len(self._records) >= self.capacity:
                raise ValueError("native analysis registry capacity exhausted")
            ref = secrets.token_hex(32)
            while ref in self._records:
                ref = secrets.token_hex(32)
            self._records[ref] = entry
        return ref

    def revoke(self, execution_ref):
        """Trusted publisher withdrawal; never exposed as a public mutation route."""
        with self._lock:
            self._records.pop(execution_ref, None)

    def _load(self, execution_ref, principal):
        with self._lock:
            self._prune(datetime.now(UTC))
            entry = self._records.get(execution_ref)
            if entry is None or (entry.tenant_id, entry.subject) != (
                principal.tenant_id,
                principal.subject,
            ):
                # Do not disclose whether another tenant/operator owns the reference.
                raise NativeAnalysisMissing("native execution reference unavailable")
            return entry

    def _assert_active(self, execution_ref, entry):
        with self._lock:
            if (
                self._records.get(execution_ref) is not entry
                or datetime.now(UTC) >= entry.expires_at
            ):
                raise SignalRejected("native execution reference expired or withdrawn")

    def resolve(self, execution_ref, principal, *, caller_authority_check=None):
        self._authenticated(principal)
        entry = self._load(execution_ref, principal)

        def active():
            if caller_authority_check is not None:
                caller_authority_check()
            self._assert_active(execution_ref, entry)

        active()
        signal = entry.signal.model_copy(deep=True)
        context = entry.collect(principal)
        facts = self._snapshot(context, signal)
        facts["native_execution"]["analysis_ref_sha256"] = hashlib.sha256(
            execution_ref.encode()
        ).hexdigest()
        expires = min(entry.expires_at, context.expires_at)
        facts["valid_until"] = expires.isoformat()
        encoded = json.dumps(facts, sort_keys=True, ensure_ascii=False).encode()
        if len(encoded) > 16384:
            raise SignalRejected("native analysis evidence exceeds capacity")

        def verify_current():
            active()
            context.verify_current()
            active()

        verify_current()
        return signal, replace(
            context, expires_at=expires, facts_json=encoded, verify_current=verify_current
        )


def create_native_analysis_registry(operations, settings):
    if operations is None:
        return None
    if settings.native_analysis_shared_config_path is None:
        return NativeAnalysisRegistry(operations)
    # The opt-in native collector runtime ships with the source/Docker image.
    # No dynamic import or path is ever supplied by an HTTP client or stored bundle.
    from scripts.f1_lab.shared_service_analysis import open_shared_service_registry

    return open_shared_service_registry(
        operations,
        settings.native_analysis_shared_config_path,
        settings.native_analysis_shared_config_sha256,
    )
