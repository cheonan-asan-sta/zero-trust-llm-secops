"""Signed, capture-bound execution observations and exact approved destinations.

These records attest what a separately registered collector observed. A signature does
not create a process identity or a missing destination observation. Null stays unknown.
"""

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from app.models import EventAction, StrictModel

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class BehaviorScope(StrictModel):
    source: Literal["cowrie", "cloudtrail"]
    user_id: Identifier
    device_id: Identifier
    resource_id: Identifier
    action: EventAction
    principal_hash: str = Field(min_length=1, max_length=256)


class ExecutionActor(StrictModel):
    principal_id: Identifier
    workload_id: Identifier
    executable_sha256: Digest


class ExecutionDestination(StrictModel):
    """Exact endpoint, not a suffix, prefix, wildcard, DNS resolution or URL redirect."""

    kind: Literal["https", "s3"]
    host: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, strict=True, ge=1, le=65535)
    path: str = Field(min_length=1, max_length=1024)

    @field_validator("host")
    @classmethod
    def canonical_host(cls, value):
        if (not value.isascii() or value != value.lower() or value.endswith(".")
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                       for part in value.split("."))):
            raise ValueError("destination host requires a canonical ASCII DNS name or IPv4 address")
        if re.fullmatch(r"[0-9.]+", value):
            try:
                if str(ipaddress.IPv4Address(value)) != value:
                    raise ValueError("noncanonical IPv4 address")
            except ipaddress.AddressValueError as error:
                raise ValueError("destination IPv4 address is not canonical") from error
        return value

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value):
        if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()+,;=:@/-]*", value):
            raise ValueError("destination path requires an exact canonical ASCII path")
        parts = value[1:].split("/")
        if any(part in {".", ".."} for part in parts) or "" in parts[:-1]:
            raise ValueError("destination path aliases are not accepted")
        return value

    @model_validator(mode="after")
    def endpoint(self):
        if self.kind == "https" and self.port is None:
            raise ValueError("HTTPS destination requires an explicit port")
        if self.kind == "s3":
            if self.port is not None or not 3 <= len(self.host) <= 63:
                raise ValueError("S3 destination requires a canonical bucket and no port")
            try:
                ipaddress.IPv4Address(self.host)
            except ipaddress.AddressValueError:
                pass
            else:
                raise ValueError("S3 bucket cannot be an IPv4 address")
        return self


class ExecutionPolicy(StrictModel):
    actor: ExecutionActor
    destinations: list[ExecutionDestination] = Field(min_length=1, max_length=16)

    @field_validator("destinations")
    @classmethod
    def unique_destinations(cls, value):
        if len({item.model_dump_json() for item in value}) != len(value):
            raise ValueError("approved destinations must be distinct")
        return value


class SignedExecutionEvidence(StrictModel):
    schema_version: Literal["zt-execution-1"] = "zt-execution-1"
    algorithm: Literal["Ed25519"] = "Ed25519"
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    evidence_id: Identifier
    source_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    issued_at: datetime
    expires_at: datetime
    observed_at: datetime
    scope: BehaviorScope
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    session_version: int = Field(strict=True, ge=1, le=204)
    session_input_sha256: Digest
    capture_id: Identifier
    capture_input_sha256: Digest
    event_ids: list[Identifier] = Field(min_length=1, max_length=5000)
    connection_ids: list[Annotated[str, Field(min_length=1, max_length=256)]] = Field(
        min_length=1, max_length=100,
    )
    actor: ExecutionActor | None = None
    destinations: list[ExecutionDestination] | None = Field(default=None, min_length=1, max_length=16)
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$", repr=False)

    @field_validator("issued_at", "expires_at", "observed_at")
    @classmethod
    def aware_time(cls, value):
        if value.utcoffset() is None:
            raise ValueError("execution evidence requires timezone")
        return value

    @field_validator("event_ids", "connection_ids")
    @classmethod
    def unique_ids(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("execution evidence identifiers must be distinct")
        return value

    @field_validator("destinations")
    @classmethod
    def unique_destinations(cls, value):
        if value is not None and len({item.model_dump_json() for item in value}) != len(value):
            raise ValueError("observed destinations must be distinct")
        return value

    @model_validator(mode="after")
    def observation_window(self):
        if not 0 < (self.expires_at - self.issued_at).total_seconds() <= 120:
            raise ValueError("execution evidence lifetime must be at most 120 seconds")
        if not 0 <= (self.issued_at - self.observed_at).total_seconds() <= 300:
            raise ValueError("execution observation outside bounded window")
        return self
