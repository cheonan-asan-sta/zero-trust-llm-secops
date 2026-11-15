"""Externally pinned certificate enrollment; no identity inferred from VPN names."""

import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import Field

from app.models import StrictModel
from scripts.f1_lab.native_jsonl import decode, require


class Enrollment(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    gateway_id: str = Field(min_length=1, max_length=64)
    user_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    client_certificate_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    enabled: bool = Field(default=True, strict=True)


class EnrollmentRegistry(StrictModel):
    schema_version: Literal['zt-vpn-enrollments-1']
    version: int = Field(strict=True, ge=1)
    issued_at: datetime
    expires_at: datetime
    bindings: list[Enrollment] = Field(max_length=1000)


class PinnedVPNEnrollments:
    def __init__(self, path, expected_sha256, *, minimum_version=1):
        require(isinstance(expected_sha256, str) and len(expected_sha256) == 64
                and all(c in '0123456789abcdef' for c in expected_sha256)
                and type(minimum_version) is int and minimum_version >= 1, 'vpn_enrollment_pin')
        self.path, self.expected_sha256, self.minimum_version = Path(path), expected_sha256, minimum_version

    def verify(self, request, *, now):
        require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
                'vpn_enrollment_clock')
        require(self.path.is_file() and not self.path.is_symlink() and self.path.stat().st_size <= 256000,
                'vpn_enrollment_file')
        with self.path.open('rb') as stream:
            body = stream.read(256001)
        require(len(body) <= 256000 and hashlib.sha256(body).hexdigest() == self.expected_sha256,
                'vpn_enrollment_hash')
        registry = EnrollmentRegistry.model_validate(decode(body))
        require(all(t.tzinfo is not None and t.utcoffset() is not None for t in (registry.issued_at, registry.expires_at))
                and registry.issued_at <= now < registry.expires_at
                and timedelta(0) < registry.expires_at-registry.issued_at <= timedelta(hours=24)
                and registry.version >= self.minimum_version, 'vpn_enrollment_window_version')
        identities, match = set(), None
        for binding in registry.bindings:
            key = binding.tenant_id, binding.gateway_id, binding.client_certificate_sha256
            require(key not in identities, 'vpn_enrollment_duplicate_certificate')
            identities.add(key)
            if key == (request.tenant_id, request.gateway_id, request.client_certificate_sha256):
                match = binding
        require(match is not None and match.enabled and match.user_id == request.user_id
                and match.device_id == request.device_id, 'vpn_enrollment_identity')
        return self.expected_sha256
