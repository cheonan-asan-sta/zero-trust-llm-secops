"""Authenticated durable intake and at-least-once, restriction-only processing."""

import hashlib
import hmac
from datetime import UTC, datetime

from pydantic import ValidationError

from app.continuous_signal_models import SignedContinuousSignal
from app.security import Principal, Role
from app.services.signal_inbox import (
    InboxLeaseLost,
    InboxMissing,
    SignalInbox,
)
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    canonical_observation,
)
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations


class ContinuousSignalService:
    def __init__(self, operations: ZeroTrustOperations, inbox: SignalInbox):
        self.operations = operations
        self.inbox = inbox

    def accept(self, signal: SignedContinuousSignal, principal: Principal,
               *, now: datetime | None = None) -> dict:
        now = now or datetime.now(UTC)
        # Also enforce this boundary for non-HTTP callers. Source proof does not
        # replace caller authentication or the explicit per-kind collector scope.
        if Role.ANALYST not in principal.effective_roles:
            raise SignalRejected("observation intake requires analyst authority")
        try:
            self.inbox.get(principal.tenant_id, signal.event_id)
            already_received = True
        except InboxMissing:
            already_received = False
        proof = self.operations.signal_verifier.verify_observation(
            signal, principal, now, enforce_freshness=not already_received,
        )
        # Exact acknowledged deliveries remain idempotent after their original
        # freshness window. The stored payload and current signer scope must match.
        return self.inbox.accept(
            signal.tenant_id, signal.event_id, signal.model_dump(mode="json"),
            proof.input_digest, principal.subject, now,
        )

    def receipt(self, event_id: str, principal: Principal) -> dict:
        return self.inbox.get(principal.tenant_id, event_id)

    def summary(self, principal: Principal, *, now: datetime | None = None) -> dict:
        return self.inbox.metrics(principal.tenant_id, now=now or datetime.now(UTC))

    def _failed(self, tenant, event_id, lease, error_code, clock):
        try:
            return self.inbox.fail(tenant, event_id, lease, error_code, clock())
        except InboxLeaseLost:
            return self.inbox.get(tenant, event_id)

    def process_one(self, *, now: datetime | None = None) -> dict | None:
        clock = (lambda: now) if now is not None else (lambda: datetime.now(UTC))
        delivery = self.inbox.claim(now=clock(), reconcile_exhausted=True)
        if delivery is None:
            return None
        tenant = delivery["tenant_id"]
        event_id = delivery["event_id"]
        lease = delivery["lease_token"]
        try:
            signal = SignedContinuousSignal.model_validate(delivery["payload"])
            digest = hashlib.sha256(canonical_observation(signal)).hexdigest()
            if (signal.tenant_id != tenant or signal.event_id != event_id
                    or not hmac.compare_digest(digest, delivery["input_digest"])):
                raise SignalRejected("stored observation binding rejected")
            # Already committed effects can be acknowledged even if their signer
            # was subsequently revoked. This lookup cannot apply new effects.
            result = self.operations.observation_result(tenant, event_id, digest)
            if result is None:
                if delivery["reconcile_only"]:
                    return self._failed(tenant, event_id, lease, "PROCESSING_EXHAUSTED", clock)
                worker_principal = Principal(
                    subject=delivery["submitted_by"], tenant_id=tenant,
                    roles=frozenset({Role.ANALYST}), auth_method="durable_intake",
                )
                # Delayed adverse evidence may restrict access. Every new policy
                # application still checks the current source/key/claim scope.
                self.operations.signal_verifier.verify_observation(
                    signal, worker_principal, clock(), enforce_freshness=False,
                )
                result = self.operations.apply_observation(signal, digest, now=clock())
        except (SignalRejected, ValidationError):
            return self._failed(tenant, event_id, lease, "SIGNAL_REJECTED", clock)
        except SignalRegistryUnavailable:
            return self._failed(tenant, event_id, lease, "REGISTRY_UNAVAILABLE", clock)
        except JournalUnavailable:
            return self._failed(tenant, event_id, lease, "JOURNAL_UNAVAILABLE", clock)
        except Exception:  # noqa: BLE001 -- bounded worker failure boundary; no exception text stored
            # Keep failures bounded and diagnosable without retaining exception
            # messages that could contain payloads or credentials. Process death
            # (BaseException) leaves the lease for another worker to recover.
            return self._failed(tenant, event_id, lease, "PROCESSING_ERROR", clock)
        try:
            # This commit is deliberately separate from journal effects. If it
            # fails, delivery is retried and the atomic journal marker dedupes it.
            return self.inbox.complete(tenant, event_id, lease, result, clock())
        except InboxLeaseLost:
            # Another worker now owns completion; never overwrite its receipt.
            return self.inbox.get(tenant, event_id)
