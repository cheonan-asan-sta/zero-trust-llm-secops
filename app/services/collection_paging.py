"""Caller-bound pages over a verified, unchanged live collection; no grants issued."""

import base64
import hashlib
import hmac
import os
import secrets
import stat
import time
from datetime import UTC, datetime
from typing import Generic, Literal, TypeVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException
from pydantic import Field, ValidationError

from app.models import IncidentCase, StrictModel
from app.services.audit_paging import AuditCursorExpired, AuditCursorInvalid, AuditSnapshotChanged
from app.services.audit_review_preconditions import review_identity
from app.services.audit_transfer import AuditTransferError, canonical, decode
from app.services.cases import CaseStore, _record_hash
from app.services.federated_audit import AuditQueryUnavailable
from app.services.settled_io import settled_io

T = TypeVar("T")
AAD = b"zero-trust-live-collection-page-v1"


class CollectionPage(StrictModel, Generic[T]):
    items: list[T] = Field(max_length=100)
    total_matches: int = Field(ge=0, le=10000)
    page_cursor: str = Field(min_length=1, max_length=2048, pattern=r"^[A-Za-z0-9_-]+$")
    next_cursor: str | None = Field(default=None, max_length=2048, pattern=r"^[A-Za-z0-9_-]+$")
    snapshot_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    snapshot_created_at: datetime
    snapshot_expires_at: datetime
    snapshot_mode: Literal["unchanged_live_view"] = "unchanged_live_view"
    historical_audit_snapshot: Literal[False] = False


class _Cursor(StrictModel):
    version: int = Field(default=1, ge=1, le=1)
    scope: str = Field(pattern=r"^[a-f0-9]{64}$")
    view: str = Field(pattern=r"^[a-f0-9]{64}$")
    offset: int = Field(ge=0, le=10000)
    issued: int = Field(ge=0)
    expires: int = Field(ge=0)


class CollectionPager:
    def __init__(self, master, clock=time.time):
        self.master, self.clock = master, clock

    def _key(self):
        try:
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=AAD).derive(
                self.master()
            )
        except (OSError, ValueError, AuditTransferError) as error:
            raise AuditQueryUnavailable("collection cursor key unavailable") from error

    @staticmethod
    def _seal(state, key):
        nonce = secrets.token_bytes(12)
        return (
            base64.urlsafe_b64encode(
                nonce + AESGCM(key).encrypt(nonce, canonical(state.model_dump()), AAD)
            )
            .decode()
            .rstrip("=")
        )

    def page(self, rows, principal, source, *, limit=12, cursor=None, filters=None):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise AuditCursorInvalid("Invalid collection page size")
        if len(rows) > 10000:
            raise AuditQueryUnavailable("collection exceeds local page budget")
        if any(row.tenant_id != principal.tenant_id for row in rows):
            raise AuditQueryUnavailable("collection tenant mismatch")
        key = self._key()
        scope = hashlib.sha256(
            canonical([source, review_identity(principal), limit, filters or {}])
        ).hexdigest()
        view = hashlib.sha256(canonical([r.model_dump(mode="json") for r in rows])).hexdigest()
        now = int(self.clock())
        state = None
        if cursor is not None:
            try:
                if (
                    not isinstance(cursor, str)
                    or not 1 <= len(cursor) <= 2048
                    or any(
                        c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                        for c in cursor
                    )
                ):
                    raise ValueError("invalid token")
                raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
                state = _Cursor.model_validate(decode(AESGCM(key).decrypt(raw[:12], raw[12:], AAD)))
            except (
                ValueError,
                TypeError,
                InvalidTag,
                ValidationError,
                AuditTransferError,
            ) as error:
                raise AuditCursorInvalid("Invalid collection cursor") from error
            if not hmac.compare_digest(state.scope, scope):
                raise AuditCursorInvalid("Collection scope changed")
            if state.issued > now or state.expires != state.issued + 900 or now >= state.expires:
                raise AuditCursorExpired("Collection view expired")
            if not hmac.compare_digest(state.view, view):
                raise AuditSnapshotChanged("Collection changed; read a new list")
        else:
            state = _Cursor(scope=scope, view=view, offset=0, issued=now, expires=now + 900)
        if state.offset > len(rows) or (state.offset and state.offset == len(rows)):
            raise AuditCursorInvalid("Collection position unavailable")
        if not hmac.compare_digest(key, self._key()):
            raise AuditQueryUnavailable("collection key changed during read")
        items = rows[state.offset : state.offset + limit]
        next_offset = state.offset + len(items)
        snapshot_id = hmac.new(
            key, canonical(state.model_dump(exclude={"offset"})), hashlib.sha256
        ).hexdigest()
        return CollectionPage(
            items=items,
            total_matches=len(rows),
            page_cursor=self._seal(state, key),
            next_cursor=self._seal(state.model_copy(update={"offset": next_offset}), key)
            if next_offset < len(rows)
            else None,
            snapshot_id=snapshot_id,
            snapshot_created_at=datetime.fromtimestamp(state.issued, UTC),
            snapshot_expires_at=datetime.fromtimestamp(state.expires, UTC),
        )


def case_rows(store, tenant):
    if not isinstance(store, CaseStore):
        raise HTTPException(501, "Paged cases require a local case repository")
    if not store._integrity_ok:
        raise AuditQueryUnavailable("case writer integrity failed")
    path = store._path
    if path.is_symlink():
        raise AuditQueryUnavailable("case source link rejected")
    if not path.exists():
        if store._verified_lines or store._records or path.is_symlink():
            raise AuditQueryUnavailable("case source missing")
        return []
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_BINARY", 0),
        )
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 128 * 1024 * 1024:
                raise ValueError("case file budget")
            raw = stream.read(128 * 1024 * 1024 + 1)
            after = os.fstat(stream.fileno())
        live = path.lstat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if (
            path.is_symlink()
            or signature(before) != signature(after)
            or signature(after) != signature(live)
            or len(raw) != before.st_size
        ):
            raise ValueError("case file changed during read")
        latest, previous, count = {}, "0" * 64, 0
        for line in raw.splitlines():
            if not line.strip():
                continue
            count += 1
            if count > 100000 or len(line) > 2 * 1024 * 1024:
                raise ValueError("case row budget")
            value = decode(line)
            if (
                set(value) != {"schema_version", "previous_hash", "record_hash", "payload"}
                or type(value["schema_version"]) is not int
                or value["schema_version"] != 1
            ):
                raise ValueError("case envelope")
            if value["previous_hash"] != previous or not hmac.compare_digest(
                _record_hash(previous, value["payload"]), value["record_hash"]
            ):
                raise ValueError("case chain mismatch")
            row = IncidentCase.model_validate(decode(value["payload"].encode()))
            key = row.tenant_id, row.case_id
            if row.version != (latest[key].version + 1 if key in latest else 1):
                raise ValueError("case version sequence")
            latest[key], previous = row, value["record_hash"]
            if count == store._verified_lines and previous != store._last_hash:
                raise ValueError("known case prefix changed")
        if count < store._verified_lines:
            raise ValueError("known case prefix missing")
        return sorted(
            (r for r in latest.values() if r.tenant_id == tenant),
            key=lambda r: (r.updated_at, r.case_id),
            reverse=True,
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError, AuditTransferError) as error:
        raise AuditQueryUnavailable("case source verification failed") from error


async def read_collection(request, principal, pager, loader, source, is_current, **kwargs):
    async def boundary():
        if not is_current():
            raise AuditQueryUnavailable("collection source changed")
        check = getattr(request.state, "authentication_revalidator", None)
        if check is not None:
            await settled_io(check)
        expiry = principal.authentication_expires_at
        if (principal.auth_method == "oidc" and expiry is None) or (
            expiry is not None and datetime.now(UTC) >= expiry
        ):
            raise HTTPException(401, "Caller authentication expired")
        if not is_current():
            raise AuditQueryUnavailable("collection source changed")

    await boundary()
    result = await settled_io(lambda: pager.page(loader(), principal, source, **kwargs))
    await boundary()
    return result
