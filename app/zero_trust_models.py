from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.models import EventAction, SecurityEvent, StrictModel

MAX_EVALUATION_VERSION = 200
MAX_SECURITY_VERSION = 204


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
    expected_version: int = Field(ge=0, le=MAX_EVALUATION_VERSION)
    event: SecurityEvent


class SessionDecision(StrictModel):
    session_id: str
    tenant_id: str
    operator_id: str
    user_id: str
    device_id: str
    version: int = Field(ge=1, le=MAX_SECURITY_VERSION)
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
    signal_trust: Literal["demo", "verified_source"] = "demo"
    signal_source_id: str | None = None
    signal_key_id: str | None = None
    signal_source_digest: str | None = None
    signal_expires_at: datetime | None = None
    challenge_id: str | None = None
    challenge_expires_at: datetime | None = None
    enforcement_mode: Literal["local_simulation"] = "local_simulation"

    @model_validator(mode="after")
    def security_versions_never_authorize(self):
        if self.version <= MAX_EVALUATION_VERSION:
            return self  # Preserve existing legacy decisions and synthetic fixtures.
        ranks = {"STEP_UP": 1, "HOLD": 2, "DENY": 3}
        states = {"STEP_UP": "STEP_UP_REQUIRED", "HOLD": "HELD", "DENY": "REVOKED"}
        if (self.decision not in ranks or self.status != states[self.decision]
                or self.grant_expires_at is not None):
            raise ValueError("security-only versions cannot authorize access")
        if ((self.version == 202 and ranks[self.decision] < 2)
                or (self.version == 203 and self.decision == "STEP_UP")
                or (self.version == 203 and self.decision == "HOLD"
                    and "SIGNAL_PROOF_EXPIRED" not in self.reason_codes)
                or (self.version == MAX_SECURITY_VERSION and self.decision != "DENY")):
            raise ValueError("security-only revision budget does not permit this state")
        return self


class SessionEvaluationResult(StrictModel):
    session: SessionDecision
    grant_token: str | None = None
    duplicate: bool = False


class SessionRevocationRequest(StrictModel):
    expected_version: int = Field(ge=1, le=MAX_SECURITY_VERSION)
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


class SignalKey(StrictModel):
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    public_key_pem: str = Field(min_length=50, max_length=1000)
    enabled: bool = True
    not_before: datetime
    not_after: datetime

    @field_validator("not_before", "not_after")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("key validity requires timezone")
        return value

    @model_validator(mode="after")
    def valid_window(self):
        if self.not_after <= self.not_before:
            raise ValueError("invalid key validity window")
        return self


class TrustedSignalSource(StrictModel):
    source_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    enabled: bool = True
    user_ids: list[str] = Field(min_length=1, max_length=100)
    device_ids: list[str] = Field(min_length=1, max_length=100)
    roles: list[str] = Field(min_length=1, max_length=20)
    # Empty preserves legacy full-session-only authority. Nonempty sources are
    # observation-only and cannot use the old full-session proof endpoint.
    observation_kinds: list[Literal["identity", "device"]] = Field(default_factory=list, max_length=2)
    keys: list[SignalKey] = Field(min_length=1, max_length=10)


class TrustedSignalRegistry(StrictModel):
    sources: list[TrustedSignalSource] = Field(max_length=100)


class SignedSessionSignal(SessionEvaluationRequest):
    schema_version: Literal["zt-signal-1"] = "zt-signal-1"
    algorithm: Literal["Ed25519"] = "Ed25519"
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    source_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    issued_at: datetime
    expires_at: datetime
    challenge_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{32,80}$")
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("signal validity requires timezone")
        return value

    @model_validator(mode="after")
    def valid_window(self):
        if not 0 < (self.expires_at - self.issued_at).total_seconds() <= 120:
            raise ValueError("signal lifetime must be at most 120 seconds")
        return self
