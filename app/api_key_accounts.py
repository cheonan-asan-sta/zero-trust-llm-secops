"""Bounded server-owned additional API identities; files contain hashes only."""

import json
import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.models import StrictModel

MAX_BYTES = 131072


class ApiKeyAccount(StrictModel):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$", min_length=64, max_length=64, repr=False)
    subject: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    roles: list[Literal["viewer", "analyst", "responder", "admin"]] = Field(
        min_length=1, max_length=4
    )
    enabled: bool = Field(default=True, strict=True)

    @field_validator("subject")
    @classmethod
    def bounded_subject(cls, value):
        if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("invalid account subject")
        return value

    @field_validator("roles")
    @classmethod
    def unique_roles(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("duplicate account roles")
        return value


class ApiKeyAccounts(StrictModel):
    schema_version: Literal["api-key-accounts-1"] = Field(alias="schema")
    accounts: list[ApiKeyAccount] = Field(max_length=100)

    @model_validator(mode="after")
    def unique_keys(self):
        if len({account.sha256 for account in self.accounts}) != len(self.accounts):
            raise ValueError("duplicate account credentials")
        return self


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate account JSON field")
        result[key] = value
    return result


def load_authentication_json(path: Path):
    # Reopen each time so disabling a credential takes effect on the next call.
    # Never interpret a missing/malformed configured file as a legacy fallback.
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("account source must be a regular file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        live = path.lstat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(live.st_mode)
            or before.st_size > MAX_BYTES
            or signature(before) != signature(live)
        ):
            raise ValueError("account source must be a regular file")
        body = source.read(MAX_BYTES + 1)
        after = os.fstat(source.fileno())
        current = path.lstat()
    if (
        len(body) > MAX_BYTES
        or len(body) != before.st_size
        or not stat.S_ISREG(current.st_mode)
        or signature(before) != signature(after)
        or signature(after) != signature(current)
    ):
        raise ValueError("account source changed or exceeds limit")
    return json.loads(body, object_pairs_hook=unique_object)


def load_accounts(path: Path, legacy_digest: str) -> list[ApiKeyAccount]:
    accounts = ApiKeyAccounts.model_validate(load_authentication_json(path)).accounts
    if any(account.sha256 == legacy_digest for account in accounts):
        raise ValueError("account credential conflicts with legacy identity")
    return accounts
