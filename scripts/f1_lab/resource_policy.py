"""Pinned operator resource policy for shadow observations; never an access API."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import Field, field_validator

from app.models import EventAction, SecurityEvent, StrictModel
from scripts.f1_lab.approvals import Identifier

RoleName = Annotated[str, Field(min_length=1, max_length=64)]
SENSITIVITY = ('public', 'internal', 'high', 'critical')


class ResourcePolicyUnavailable(ValueError):
    pass


class Permission(StrictModel):
    action: EventAction
    roles: list[RoleName] = Field(min_length=1, max_length=32)

    @field_validator('roles')
    @classmethod
    def role_scope(cls, values):
        if len(set(values)) != len(values) or any(not v.strip() or '*' in v for v in values):
            raise ValueError('resource_policy_exact_role_scope')
        return values


class Resource(StrictModel):
    tenant_id: Identifier
    resource_id: str = Field(min_length=1, max_length=128)
    sensitivity: Literal['public', 'internal', 'high', 'critical']
    permissions: list[Permission] = Field(min_length=1, max_length=5)


class Registry(StrictModel):
    schema_version: Literal['f1-resource-policies-1']
    version: int = Field(strict=True, ge=1)
    issued_at: datetime
    expires_at: datetime
    resources: list[Resource] = Field(max_length=1000)


@dataclass(frozen=True)
class ResourcePolicyDecision:
    role_and_action_allowed: bool
    effective_sensitivity: str
    version: int
    registry_sha256: str


@dataclass(frozen=True)
class ResourcePolicySnapshot:
    resources: MappingProxyType
    version: int
    registry_sha256: str

    def resolve(self, event, tenant_id):
        resource = self.resources.get((tenant_id, event.resource.resource_id))
        if resource is None:
            raise ResourcePolicyUnavailable('resource_policy_unavailable')
        sensitivity, permissions = resource
        allowed = event.user.role in permissions.get(event.action, frozenset())
        sensitivity = max((sensitivity, event.resource.sensitivity), key=SENSITIVITY.index)
        return ResourcePolicyDecision(allowed, sensitivity, self.version, self.registry_sha256)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('resource_policy_duplicate_json_key')
        result[key] = value
    return result


class PinnedResourcePolicies:
    def __init__(self, path: Path, expected_sha256: str, *, minimum_version: int):
        if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
                or any(c not in '0123456789abcdef' for c in expected_sha256)
                or type(minimum_version) is not int or minimum_version < 1):
            raise ResourcePolicyUnavailable('resource_policy_external_anchor_required')
        self.path, self.expected_sha256, self.minimum_version = Path(path), expected_sha256, minimum_version

    @property
    def configuration_binding(self):
        return {'kind': 'pinned-resource-policy-1', 'sha256': self.expected_sha256,
                'minimum_version': self.minimum_version}

    def snapshot(self, *, now=None):
        try:
            now = datetime.now(UTC) if now is None else now
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise ValueError('resource_policy_clock')
            if not self.path.is_file() or self.path.is_symlink() or self.path.stat().st_size > 256_000:
                raise ValueError('resource_policy_file')
            with self.path.open('rb') as stream:
                raw = stream.read(256_001)
            if len(raw) > 256_000 or hashlib.sha256(raw).hexdigest() != self.expected_sha256:
                raise ValueError('resource_policy_hash')
            registry = Registry.model_validate(json.loads(raw, object_pairs_hook=unique_object))
            if (registry.version < self.minimum_version
                    or any(v.tzinfo is None or v.utcoffset() is None for v in (registry.issued_at, registry.expires_at))
                    or not registry.issued_at <= now < registry.expires_at
                    or not timedelta(0) < registry.expires_at-registry.issued_at <= timedelta(hours=24)):
                raise ValueError('resource_policy_version_or_window')
            resources = {}
            for resource in registry.resources:
                identity = resource.tenant_id, resource.resource_id
                if identity in resources or len({p.action for p in resource.permissions}) != len(resource.permissions):
                    raise ValueError('resource_policy_duplicate_scope')
                resources[identity] = (resource.sensitivity,
                    MappingProxyType({p.action: frozenset(p.roles) for p in resource.permissions}))
            return ResourcePolicySnapshot(MappingProxyType(resources), registry.version, self.expected_sha256)
        except (ValueError, TypeError, OSError, RecursionError):
            raise ResourcePolicyUnavailable('resource_policy_unavailable') from None

    def resolve(self, event: SecurityEvent, tenant_id: str, *, now=None):
        # No cross-decision cache. Every new decision rechecks the external pin.
        return self.snapshot(now=now).resolve(event, tenant_id)
