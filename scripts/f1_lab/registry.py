"""Externally pinned public approval registry; no key discovery or private key loading."""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from app.models import EventAction, StrictModel
from scripts.f1_lab.approvals import (
    ApprovalRejected,
    ApprovalVerifier,
    Authority,
    Identifier,
    require,
)


class AuthorityRecord(StrictModel):
    tenant_id: Identifier
    issuer_id: Identifier
    key_id: Identifier
    public_key_pem: str = Field(min_length=64, max_length=2048)
    allowed_deviations: list[str] = Field(min_length=1, max_length=6)
    user_ids: list[str] = Field(min_length=1, max_length=100)
    device_ids: list[str] = Field(min_length=1, max_length=100)
    resource_ids: list[str] = Field(min_length=1, max_length=100)
    actions: list[EventAction] = Field(min_length=1, max_length=5)
    key_not_before: str = Field(min_length=20, max_length=40)
    key_not_after: str = Field(min_length=20, max_length=40)
    active: bool = Field(default=True, strict=True)


class PublicRegistry(StrictModel):
    schema_version: Literal['zt-business-authorities-1']
    version: int = Field(strict=True, ge=1)
    authorities: list[AuthorityRecord] = Field(max_length=100)
    revoked_approval_ids: list[str] = Field(default_factory=list, max_length=10000)


class PinnedApprovalVerifier:
    def __init__(self, path: Path, expected_sha256: str, *, minimum_version: int):
        require(len(expected_sha256) == 64 and all(c in '0123456789abcdef' for c in expected_sha256)
                and type(minimum_version) is int and minimum_version >= 1, 'approval_registry_anchor_required')
        self.path = Path(path)
        self.expected_sha256 = expected_sha256
        self.minimum_version = minimum_version

    def current(self):
        try:
            require(self.path.is_file() and not self.path.is_symlink() and self.path.stat().st_size <= 256_000,
                    'approval_registry_file')
            with self.path.open('rb') as stream:
                raw = stream.read(256_001)
            require(len(raw) <= 256_000 and hashlib.sha256(raw).hexdigest() == self.expected_sha256,
                    'approval_registry_hash')
            registry = PublicRegistry.model_validate_json(raw)
            require(registry.version >= self.minimum_version, 'approval_registry_version')
            authorities = []
            for row in registry.authorities:
                public = serialization.load_pem_public_key(row.public_key_pem.encode())
                require(isinstance(public, Ed25519PublicKey), 'approval_registry_public_key_type')
                scopes = (row.allowed_deviations, row.user_ids, row.device_ids, row.resource_ids, row.actions)
                require(all(len(set(values)) == len(values) and all(str(v).strip() for v in values)
                            for values in scopes), 'approval_registry_duplicate_or_empty_scope')
                authorities.append(Authority(row.tenant_id, row.issuer_id, row.key_id, public,
                    frozenset(row.allowed_deviations), frozenset(row.user_ids), frozenset(row.device_ids),
                    frozenset(row.resource_ids), frozenset(row.actions), datetime.fromisoformat(row.key_not_before),
                    datetime.fromisoformat(row.key_not_after), row.active))
            require(len(set(registry.revoked_approval_ids)) == len(registry.revoked_approval_ids),
                    'approval_registry_duplicate_revocation')
            verifier = ApprovalVerifier(tuple(authorities), revoked_approval_ids=registry.revoked_approval_ids)
            return verifier, {'version': registry.version, 'sha256': self.expected_sha256}
        except (ValueError, TypeError, OSError):
            raise ApprovalRejected('approval_registry_unavailable') from None

    def verify(self, signed, event, tenant_id, *, now=None):
        # Re-read bounded bytes and recheck the external anchor on every decision.
        # Replacing an old mtime or swapping a public registry cannot retain trust.
        verifier, _ = self.current()
        return verifier.verify(signed, event, tenant_id, now=now)

    def verify_window(self, signed, event, tenant_id, window, *, now=None):
        verifier, _ = self.current()
        return verifier.verify_window(signed, event, tenant_id, window, now=now)
