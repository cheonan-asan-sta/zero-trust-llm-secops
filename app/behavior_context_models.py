"""Authenticated telemetry and server-managed operation context; no caller trust flags."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_serializer, model_validator

from app.behavior_execution_models import BehaviorScope, Digest, ExecutionPolicy, Identifier
from app.models import StrictModel
from app.services.public_detection import PublicSession


class SignedBehaviorCapture(StrictModel):
    schema_version: Literal["zt-behavior-1"] = "zt-behavior-1"
    algorithm: Literal["Ed25519"] = "Ed25519"
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    capture_id: Identifier
    source_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    issued_at: datetime
    expires_at: datetime
    scope: BehaviorScope
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    session_version: int = Field(strict=True, ge=1, le=204)
    session_input_sha256: Digest
    connection_ids: list[Annotated[str, Field(min_length=1, max_length=256)]] = Field(
        min_length=1, max_length=100,
    )
    activity: PublicSession
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware(cls, value):
        if value.utcoffset() is None:
            raise ValueError("capture timestamp requires timezone")
        return value

    @model_validator(mode="after")
    def binding(self):
        if not 0 < (self.expires_at - self.issued_at).total_seconds() <= 120:
            raise ValueError("capture lifetime must be at most 120 seconds")
        if self.scope.source != self.activity.source:
            raise ValueError("capture source mismatch")
        connections = set(self.connection_ids)
        if len(connections) != len(self.connection_ids):
            raise ValueError("duplicate capture connection")
        if {event.connection_id for event in self.activity.events} != connections:
            raise ValueError("capture connection binding mismatch")
        for event in self.activity.events:
            if (event.principal_hash is not None and event.principal_hash != self.scope.principal_hash):
                raise ValueError("capture actor binding mismatch")
            if self.scope.source == "cloudtrail" and event.principal_hash is None:
                raise ValueError("CloudTrail capture requires an observed actor")
            if not 0 <= (self.issued_at - event.timestamp).total_seconds() <= 300:
                raise ValueError("capture observation outside bounded window")
        return self


class ContextWindow(StrictModel):
    valid_from: datetime
    valid_until: datetime
    note: str = Field(min_length=3, max_length=500)

    @field_validator("valid_from", "valid_until")
    @classmethod
    def aware(cls, value):
        if value.utcoffset() is None:
            raise ValueError("context timestamp requires timezone")
        return value

    @model_validator(mode="after")
    def ordered(self):
        if not 0 < (self.valid_until - self.valid_from).total_seconds() <= 7 * 86400:
            raise ValueError("context validity must be positive and at most seven days")
        return self


class BaselineCreate(ContextWindow):
    baseline_id: Identifier
    capture_ids: list[Identifier] = Field(min_length=3, max_length=30)

    @field_validator("capture_ids")
    @classmethod
    def distinct(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("baseline requires distinct reviewed captures")
        return value


class ApprovalCreate(ContextWindow):
    approval_id: Identifier
    baseline_id: Identifier
    max_uses: int = Field(default=1, strict=True, ge=1, le=100)
    execution_policy: ExecutionPolicy | None = None

    @model_serializer(mode="wrap")
    def serialize_approval(self, handler):
        value = handler(self)
        if self.execution_policy is None:
            value.pop("execution_policy", None)
        return value

    @model_validator(mode="after")
    def limited_window(self):
        if (self.valid_until - self.valid_from).total_seconds() > 86400:
            raise ValueError("approval lifetime must be at most one day")
        return self


class ContextRevocation(StrictModel):
    reason: str = Field(min_length=3, max_length=500)


class ContextEvaluationRequest(StrictModel):
    capture_id: Identifier
