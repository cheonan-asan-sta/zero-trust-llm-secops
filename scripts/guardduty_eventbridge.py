"""Validate and map an EventBridge finding signed by a local forwarder."""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import AwareDatetime, BaseModel, BeforeValidator, Field

from app.continuous_signal_models import GUARDDUTY_MAX_AGE_SECONDS, ResourceIdentifier
from app.models import StrictModel

Account = Annotated[str, Field(pattern=r"^[0-9]{12}$")]
Region = Annotated[str, Field(pattern=r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", max_length=32)]
PrincipalId = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[!-~]+$")]


def _timestamp(value):
    if not isinstance(value, str):
        raise TypeError("expected an ISO timestamp")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise ValueError("expected a timezone-qualified EventBridge timestamp")
    return datetime.fromisoformat(value)


Timestamp = Annotated[AwareDatetime, BeforeValidator(_timestamp)]


class Binding(StrictModel):
    subject_id: str = Field(min_length=1, max_length=128, pattern=r"^[!-~]+$")
    resource_id: ResourceIdentifier


class GuardDutyMapping(StrictModel):
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    account: Account
    region: Region
    forwarder_public_key_pem: str = Field(min_length=1, max_length=1024)
    principals: dict[PrincipalId, Binding] = Field(min_length=1, max_length=100)


# AWS may add fields. Retain their digest while validating only the subset that
# this adapter uses for its restrictive decision.
class AccessKeyDetails(BaseModel):
    principalId: PrincipalId


class FindingResource(BaseModel):
    resourceType: Literal["AccessKey"]
    accessKeyDetails: AccessKeyDetails


class FindingService(BaseModel):
    archived: bool = Field(strict=True)


class Finding(BaseModel):
    accountId: Account
    region: Region
    id: ResourceIdentifier
    arn: str = Field(min_length=1, max_length=512)
    type: str = Field(min_length=1, max_length=160)
    severity: float = Field(strict=True, ge=7, le=10)
    createdAt: Timestamp
    updatedAt: Timestamp
    resource: FindingResource
    service: FindingService


class EventBridgeFinding(BaseModel):
    version: Literal["0"]
    id: UUID
    detail_type: Literal["GuardDuty Finding"] = Field(alias="detail-type")
    source: Literal["aws.guardduty"]
    account: Account
    region: Region
    time: Timestamp
    resources: list[str]
    detail: Finding


def read_local_file(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError("GuardDuty configuration or signature must be a regular file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("GuardDuty configuration or signature exceeds its limit")
    return raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def normalize_finding(raw, signature, mapping, *, tenant_id, now: datetime):
    if mapping.tenant_id != tenant_id:
        raise ValueError("GuardDuty mapping tenant does not match the collector")
    public = serialization.load_pem_public_key(mapping.forwarder_public_key_pem.encode())
    if not isinstance(public, Ed25519PublicKey) or len(signature) != 64:
        raise ValueError("expected a local Ed25519 forwarder signature")
    try:
        public.verify(signature, raw)
    except InvalidSignature as exc:
        raise ValueError("GuardDuty forwarder signature rejected") from exc
    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        event = EventBridgeFinding.model_validate(decoded)
        detail_digest = _digest(decoded["detail"])
    except RecursionError as exc:
        raise ValueError("GuardDuty JSON nesting limit") from exc
    finding = event.detail
    if (event.account != mapping.account or finding.accountId != mapping.account
            or event.region != mapping.region or finding.region != mapping.region):
        raise ValueError("GuardDuty account or region does not match the mapping")
    arn_pattern = (
        rf"arn:aws:guardduty:{mapping.region}:{mapping.account}:"
        rf"detector/[a-zA-Z0-9_-]+/finding/{re.escape(finding.id)}"
    )
    if not re.fullmatch(arn_pattern, finding.arn):
        raise ValueError("GuardDuty finding ARN does not match its identity")
    if finding.service.archived:
        raise ValueError("archived findings are outside the local response scope")
    if (not finding.createdAt <= finding.updatedAt <= event.time <= now
            or now - finding.updatedAt > timedelta(seconds=GUARDDUTY_MAX_AGE_SECONDS)):
        raise ValueError("GuardDuty finding is outside the intake window")
    binding = mapping.principals.get(finding.resource.accessKeyDetails.principalId)
    if binding is None:
        raise ValueError("GuardDuty principal has no local binding")
    observed = finding.updatedAt.astimezone(UTC)
    revision = [mapping.account, mapping.region, finding.id, observed.isoformat()]
    return {
        "event_id": "gd-" + _digest(revision),
        "observed_at": observed,
        "observation": {"kind": "guardduty", **binding.model_dump(), "finding_sha256": detail_digest},
    }
