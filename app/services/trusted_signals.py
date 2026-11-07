"""Local pinned-source verification; no remote key discovery or private keys in the API."""

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.continuous_signal_models import GUARDDUTY_MAX_AGE_SECONDS, SignedContinuousSignal
from app.security import Principal
from app.zero_trust_models import SignedSessionSignal, TrustedSignalRegistry


class SignalRejected(ValueError):
    pass


class SignalRegistryUnavailable(RuntimeError):
    pass


def canonical_signal(signal: SignedSessionSignal) -> bytes:
    # Includes tenant, session, optimistic version, event and challenge binding.
    # Both signer and verifier use the validated v1 model, not arbitrary JSON bytes.
    payload = signal.model_dump(mode="json", exclude={"signature"})
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def canonical_observation(signal: SignedContinuousSignal) -> bytes:
    """Domain-separated by the signed zt-observation-1 schema, not a session proof."""
    payload = signal.model_dump(mode="json", exclude={"signature"})
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


@dataclass(frozen=True)
class VerifiedSignal:
    source_id: str
    key_id: str
    source_digest: str
    expires_at: datetime
    issued_at: datetime
    challenge_id: str | None
    input_digest: str


class SignalVerifier:
    def __init__(self, registry_path: Path | None = None):
        self.registry_path = registry_path

    def _sources(self):
        if self.registry_path is None:
            return {}
        try:
            # Bound file size before parsing; configured registry errors fail closed.
            if self.registry_path.stat().st_size > 256_000:
                raise ValueError("registry too large")
            registry = TrustedSignalRegistry.model_validate_json(self.registry_path.read_bytes())
            sources = {}
            key_owners = {}
            for source in registry.sources:
                key = (source.tenant_id, source.source_id)
                if key in sources or len({k.key_id for k in source.keys}) != len(source.keys):
                    raise ValueError("duplicate source or key")
                for item in source.keys:
                    public = serialization.load_pem_public_key(item.public_key_pem.encode())
                    if not isinstance(public, Ed25519PublicKey):
                        raise TypeError("source key must be Ed25519")
                    # A collector holding a private key can sign a different source
                    # ID. Sharing its public key across source IDs would therefore
                    # alias their authorities, even if the PEM formatting differs.
                    fingerprint = hashlib.sha256(public.public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
                    )).hexdigest()
                    owner_key = (source.tenant_id, fingerprint)
                    owner = key_owners.setdefault(owner_key, source.source_id)
                    if owner != source.source_id:
                        raise ValueError("source public key reused within tenant")
                sources[key] = source
            return sources
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise SignalRegistryUnavailable("configured source registry unavailable") from exc

    def readiness(self, tenant_id: str | None = None):
        try:
            sources = self._sources()
            return {"ok": True, "configured": self.registry_path is not None,
                    "source_count": sum(tenant_id is None or tenant == tenant_id for tenant, _ in sources),
                    "algorithm": "Ed25519"}
        except SignalRegistryUnavailable:
            return {"ok": False, "configured": True}

    def source_digest(self, tenant_id: str, source_id: str, key_id: str, now: datetime):
        source = self._sources().get((tenant_id, source_id))
        if source is None or not source.enabled:
            return None
        key = next((key for key in source.keys if key.key_id == key_id), None)
        if key is None or not key.enabled or not key.not_before <= now < key.not_after:
            return None
        return hashlib.sha256(source.model_dump_json().encode()).hexdigest()

    def current_source_digests(self, now: datetime) -> dict[tuple[str, str, str], str]:
        """Read one validated authority snapshot for a background session scan.

        Use the same complete source digest and key validity boundary as access().
        A malformed registry raises instead of looking like an empty/revoked one.
        """
        digests = {}
        for (tenant_id, source_id), source in self._sources().items():
            if not source.enabled:
                continue
            digest = hashlib.sha256(source.model_dump_json().encode()).hexdigest()
            for key in source.keys:
                if key.enabled and key.not_before <= now < key.not_after:
                    digests[(tenant_id, source_id, key.key_id)] = digest
        return digests

    def verify(self, signal: SignedSessionSignal, principal: Principal, now: datetime) -> VerifiedSignal:
        sources = self._sources()
        source = sources.get((principal.tenant_id, signal.source_id))
        if source is None or not source.enabled or signal.tenant_id != principal.tenant_id:
            raise SignalRejected("source or tenant rejected")
        # Observation collectors have deliberately narrower claim authority. They
        # cannot switch schemas to assert device health, MFA and a complete session.
        if source.observation_kinds:
            raise SignalRejected("observation-only source cannot assert a full session")
        key = next((item for item in source.keys if item.key_id == signal.key_id), None)
        if key is None or not key.enabled or not key.not_before <= now < key.not_after:
            raise SignalRejected("source key rejected")
        if (signal.issued_at > now or (now - signal.issued_at).total_seconds() > 60
                or signal.expires_at <= now or signal.expires_at > key.not_after
                or signal.event.timestamp > signal.issued_at):
            raise SignalRejected("signal freshness rejected")
        if (signal.event.user.user_id not in source.user_ids
                or signal.event.device.device_id not in source.device_ids
                or signal.event.user.role not in source.roles):
            raise SignalRejected("source claim scope rejected")
        payload = canonical_signal(signal)
        try:
            signature = base64.urlsafe_b64decode(signal.signature + "==")
            if base64.urlsafe_b64encode(signature).decode().rstrip("=") != signal.signature:
                raise ValueError("noncanonical signature")
            public = serialization.load_pem_public_key(key.public_key_pem.encode())
            public.verify(signature, payload)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise SignalRejected("signal signature rejected") from exc
        return VerifiedSignal(
            source_id=signal.source_id, key_id=signal.key_id,
            source_digest=hashlib.sha256(source.model_dump_json().encode()).hexdigest(),
            expires_at=signal.expires_at, issued_at=signal.issued_at,
            challenge_id=signal.challenge_id, input_digest=hashlib.sha256(payload).hexdigest(),
        )

    def verify_observation(
        self, signal: SignedContinuousSignal, principal: Principal, now: datetime,
        *, enforce_freshness: bool = True,
    ) -> VerifiedSignal:
        """Recheck current authority on every delivery, including delayed worker retries.

        Only the authenticated durable receiver may skip the original freshness window
        after accepting the signal. Expired observations can still restrict access;
        even fresh positive observations cannot authenticate, grant or restore access.
        """
        sources = self._sources()
        source = sources.get((principal.tenant_id, signal.source_id))
        if source is None or not source.enabled or signal.tenant_id != principal.tenant_id:
            raise SignalRejected("observation source or tenant rejected")
        key = next((item for item in source.keys if item.key_id == signal.key_id), None)
        if key is None or not key.enabled or not key.not_before <= now < key.not_after:
            raise SignalRejected("observation key rejected")
        observation = signal.observation
        subjects = source.device_ids if observation.kind == "device" else source.user_ids
        if observation.kind not in source.observation_kinds or observation.subject_id not in subjects:
            raise SignalRejected("observation kind or subject scope rejected")
        if observation.kind == "guardduty":
            if observation.resource_id not in source.guardduty_resource_ids:
                raise SignalRejected("observation resource scope rejected")
            if enforce_freshness and (now - signal.observed_at).total_seconds() > GUARDDUTY_MAX_AGE_SECONDS:
                raise SignalRejected("GuardDuty finding is too old for first intake")
        if (signal.issued_at > now or signal.issued_at < key.not_before
                or signal.expires_at > key.not_after
                or (enforce_freshness and (
                    (now - signal.issued_at).total_seconds() > 60 or signal.expires_at <= now
                ))):
            raise SignalRejected("observation freshness rejected")
        payload = canonical_observation(signal)
        try:
            signature = base64.urlsafe_b64decode(signal.signature + "==")
            if base64.urlsafe_b64encode(signature).decode().rstrip("=") != signal.signature:
                raise ValueError("noncanonical signature")
            public = serialization.load_pem_public_key(key.public_key_pem.encode())
            public.verify(signature, payload)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise SignalRejected("observation signature rejected") from exc
        return VerifiedSignal(
            source_id=signal.source_id, key_id=signal.key_id,
            source_digest=hashlib.sha256(source.model_dump_json().encode()).hexdigest(),
            expires_at=signal.expires_at, issued_at=signal.issued_at,
            challenge_id=None, input_digest=hashlib.sha256(payload).hexdigest(),
        )
