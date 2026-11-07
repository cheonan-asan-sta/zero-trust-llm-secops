"""Signed observations can restrict access; they never prove MFA or issue grants."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from app.models import StrictModel

GUARDDUTY_MAX_AGE_SECONDS = 300
ObservationKind = Literal["identity", "device", "guardduty"]
ResourceIdentifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]


class IdentityObservation(StrictModel):
    kind: Literal["identity"] = "identity"
    subject_id: str = Field(min_length=1, max_length=128)
    active: bool
    authentication_result: Literal["success", "failure", "unknown"]


class DeviceObservation(StrictModel):
    kind: Literal["device"] = "device"
    subject_id: str = Field(min_length=1, max_length=128)
    managed: bool
    security_posture: Literal["healthy", "at_risk", "compromised", "unknown"]


class GuardDutyObservation(StrictModel):
    kind: Literal["guardduty"] = "guardduty"
    subject_id: str = Field(min_length=1, max_length=128)
    resource_id: ResourceIdentifier
    finding_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


Observation = Annotated[
    IdentityObservation | DeviceObservation | GuardDutyObservation, Field(discriminator="kind"),
]


class SignedContinuousSignal(StrictModel):
    schema_version: Literal["zt-observation-1"] = "zt-observation-1"
    algorithm: Literal["Ed25519"] = "Ed25519"
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    event_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    source_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    issued_at: datetime
    expires_at: datetime
    observed_at: datetime
    observation: Observation
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)

    @field_validator("issued_at", "expires_at", "observed_at")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observation timestamps require timezone")
        return value

    @model_validator(mode="after")
    def valid_window(self):
        if not 0 < (self.expires_at - self.issued_at).total_seconds() <= 120:
            raise ValueError("observation lifetime must be at most 120 seconds")
        if self.observed_at > self.issued_at:
            raise ValueError("observation cannot follow its issuance")
        return self


class ObservationApplication(StrictModel):
    """Validated journal marker, committed atomically with all affected sessions."""

    kind: Literal["observation"] = "observation"
    tenant_id: str
    event_id: str
    source_id: str
    key_id: str
    input_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime
    recorded_at: datetime
    observation: Observation
    restriction: Literal["STEP_UP", "HOLD", "DENY"] | None
    matched_sessions: int = Field(ge=0)
    changed_sessions: int = Field(ge=0)
    stale: bool
