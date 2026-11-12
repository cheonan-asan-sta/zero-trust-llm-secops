"""Bounded local requests for simulated high-risk response, never live commands."""

from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator

from app.behavior_execution_models import Digest, Identifier
from app.models import StrictModel


class ResponseCreate(StrictModel):
    request_id: Identifier
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    expected_session_version: int = Field(strict=True, ge=1, le=204)
    action: Literal["disable_account", "isolate_device", "reduce_privilege"]
    expires_at: datetime
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("expires_at")
    @classmethod
    def aware(cls, value):
        if value.utcoffset() is None:
            raise ValueError("response expiry requires a timezone")
        return value.astimezone(UTC)


class ResponseCommand(StrictModel):
    expected_version: int = Field(strict=True, ge=1, le=4)
    request_digest: Digest


class ResponseReview(ResponseCommand):
    reason: str = Field(min_length=3, max_length=500)


class ResponseCancel(ResponseReview):
    pass
