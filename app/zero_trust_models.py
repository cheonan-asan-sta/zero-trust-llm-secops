from datetime import datetime
from typing import Literal

from pydantic import Field

from app.models import EventAction, SecurityEvent, StrictModel


class ResourcePolicy(StrictModel):
    resource_id: str
    resource_type: str
    sensitivity: Literal["internal", "high", "critical"]
    roles: list[str] = Field(min_length=1)
    actions: list[EventAction] = Field(min_length=1)
    require_mfa: bool = True
    require_managed: bool = True
    max_signal_age_seconds: int = Field(default=300, ge=30, le=3600)
    grant_ttl_seconds: int = Field(default=60, ge=1, le=300)


class ZeroTrustPolicyBundle(StrictModel):
    version: str
    resources: list[ResourcePolicy] = Field(min_length=1)


class SessionEvaluationRequest(StrictModel):
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    expected_version: int = Field(ge=0, le=200)
    event: SecurityEvent


class SessionDecision(StrictModel):
    session_id: str
    tenant_id: str
    operator_id: str
    user_id: str
    device_id: str
    version: int = Field(ge=1, le=200)
    event_id: str
    observed_at: datetime
    evaluated_at: datetime
    source_ip: str
    resource_id: str
    action: EventAction
    decision: Literal["ALLOW", "STEP_UP", "HOLD", "DENY"]
    status: Literal["ACTIVE", "STEP_UP_REQUIRED", "HELD", "REVOKED"]
    risk_score: int = Field(ge=0, le=100)
    reason_codes: list[str]
    evidence: list[str]
    matched_rule_ids: list[str]
    policy_version: str
    policy_digest_sha256: str
    input_digest_sha256: str
    grant_expires_at: datetime | None = None
    enforcement_mode: Literal["local_simulation"] = "local_simulation"


class SessionEvaluationResult(StrictModel):
    session: SessionDecision
    grant_token: str | None = None
    duplicate: bool = False


class SessionRevocationRequest(StrictModel):
    expected_version: int = Field(ge=1, le=199)
    note: str = Field(min_length=3, max_length=300, pattern=r"\S.*")


class ProtectedAccessRequest(StrictModel):
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    resource_id: str = Field(min_length=1, max_length=128)
    action: EventAction
    grant_token: str = Field(min_length=32, max_length=128, repr=False)


class ProtectedAccessResult(StrictModel):
    allowed: bool
    reason_code: str
    session_version: int | None = None
    content: str | None = None
    enforcement_mode: Literal["local_simulation"] = "local_simulation"
