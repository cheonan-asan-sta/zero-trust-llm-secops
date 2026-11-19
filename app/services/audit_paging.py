"""Tenant-scoped encrypted cursors over independently verified local audit data.

SQLite pages pin a historical prefix while verifying the whole current chain.
Local JSONL views must remain unchanged between pages; they are not transactions.
"""

import base64
import hashlib
import hmac
import os
import secrets
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import Field, ValidationError

from app.models import AnalysisResult, AuditResultPage, ReviewStatus, RiskLevel, StrictModel
from app.services.audit import AuditStore, _record_hash
from app.services.audit_backup import read_key
from app.services.audit_transfer import AuditTransferError, canonical, decode
from app.services.audit_wire import analysis_values_equal
from app.services.federated_audit import AuditQueryUnavailable, FederatedAuditStore
from app.services.sqlite_audit import SQLiteAuditStore

AAD = b"zero-trust-audit-page-v1"
TTL_SECONDS = 900
MAX_CURSOR_CHARS = 2048
MAX_JSONL_BYTES = 128 * 1024 * 1024


class AuditCursorInvalid(ValueError):
    pass


class AuditCursorExpired(ValueError):
    pass


class AuditSnapshotChanged(RuntimeError):
    pass


class AuditPagingUnsupported(RuntimeError):
    pass


class _Cursor(StrictModel):
    version: Literal[1] = 1
    backend: Literal["sqlite", "jsonl", "federated_jsonl"]
    source: str = Field(pattern=r"^[a-f0-9]{64}$")
    tenant: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    review_status: ReviewStatus | None
    risk_level: RiskLevel | None
    head_seq: int = Field(ge=0, le=100000)
    head_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    offset: int = Field(ge=0, le=100000)
    issued: int = Field(ge=0)
    expires: int = Field(ge=0)


def _keys(master):
    return tuple(
        HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=AAD + b"/" + purpose).derive(
            master
        )
        for purpose in (b"encryption", b"snapshot-id")
    )


def _identity(store):
    if isinstance(store, SQLiteAuditStore):
        backend, path = "sqlite", store.path
    elif isinstance(store, FederatedAuditStore):
        backend, path = "federated_jsonl", store._base_path
    elif isinstance(store, AuditStore):
        backend, path = "jsonl", store._path
    else:
        raise AuditPagingUnsupported("paged reads require a supported local audit backend")
    name = os.path.normcase(str(Path(path).absolute()))
    return backend, hashlib.sha256(canonical([backend, name])).hexdigest()


def _matches(record, tenant, review_status, risk_level):
    return (
        record.tenant_id == tenant
        and (review_status is None or record.review_status == review_status)
        and (risk_level is None or record.assessment.risk_level == risk_level)
    )


def _sort_key(record):
    if record.analyzed_at.utcoffset() is None:
        raise AuditQueryUnavailable("paged audit requires timezone-aware analysis times")
    return record.analyzed_at, record.analysis_id


def _file_signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _jsonl_view(
    store,
    *,
    row_observer=None,
    allow_legacy_prefix=False,
    metadata=None,
    validate_review_transitions=True,
):
    with store._disk_lock:
        return _jsonl_view_locked(
            store,
            row_observer=row_observer,
            allow_legacy_prefix=allow_legacy_prefix,
            metadata=metadata,
            validate_review_transitions=validate_review_transitions,
        )


def _jsonl_view_locked(
    store,
    *,
    row_observer=None,
    allow_legacy_prefix=False,
    metadata=None,
    validate_review_transitions=True,
):
    if not store._integrity_ok:
        raise AuditQueryUnavailable("local audit writer integrity failed")
    path = store._path
    if path.is_symlink():
        raise AuditQueryUnavailable("audit link rejected")
    if not path.exists():
        if (
            store._strict_reads
            or store._page_seen_file
            or store._history
            or store._verified_lines
            or store._legacy_lines
        ):
            raise AuditQueryUnavailable("required audit file missing")
        if metadata is not None:
            metadata.update(
                head="0" * 64,
                verified=0,
                legacy=0,
                size=0,
                fingerprint=hashlib.sha256(b"").hexdigest(),
                signature=None,
            )
        return []
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_JSONL_BYTES:
                raise AuditQueryUnavailable("audit file capacity or type rejected")
            raw = stream.read(MAX_JSONL_BYTES + 1)
            after = os.fstat(stream.fileno())
        live = path.lstat()
        if (
            len(raw) > MAX_JSONL_BYTES
            or len(raw) != before.st_size
            or _file_signature(before) != _file_signature(after)
            or _file_signature(after) != _file_signature(live)
            or not stat.S_ISREG(live.st_mode)
        ):
            raise AuditQueryUnavailable("audit changed during page verification")
        records, previous, count = {}, "0" * 64, 0
        hashed_seen = False
        legacy = 0
        for line in raw.splitlines():
            if not line.strip():
                continue
            count += 1
            if count > SQLiteAuditStore.MAX_ROWS or len(line) > 2 * 1024 * 1024:
                raise AuditQueryUnavailable("audit page row capacity exceeded")
            value = decode(line)
            hashed = type(value) is dict and value.get("schema_version") == 1
            if not hashed and allow_legacy_prefix and not hashed_seen:
                # Compatibility only: legacy rows cannot witness a saved row.
                # A legacy suffix after any hashed row is never accepted here.
                record = AnalysisResult.model_validate(value)
                legacy += 1
                records[record.analysis_id] = record
                if row_observer is not None:
                    row_observer(record, False)
                continue
            if (
                type(value) is not dict
                or set(value) != {"schema_version", "payload", "previous_hash", "record_hash"}
                or value["schema_version"] != 1
                or type(value["schema_version"]) is not int
                or type(value["payload"]) is not str
                or value["previous_hash"] != previous
                or value["record_hash"] != _record_hash(previous, value["payload"])
            ):
                raise AuditQueryUnavailable("paged JSONL requires verified hash-chain rows")
            previous = value["record_hash"]
            hashed_seen = True
            record = AnalysisResult.model_validate(decode(value["payload"]))
            old = records.get(record.analysis_id)
            if validate_review_transitions and old is None and record.review_updated_at is not None:
                raise AuditQueryUnavailable("paged JSONL review lacks original analysis")
            if (
                validate_review_transitions
                and old is not None
                and not analysis_values_equal(old, record)
                and not SQLiteAuditStore._review_fits(old, record)
            ):
                raise AuditQueryUnavailable("paged JSONL review transition rejected")
            records[record.analysis_id] = record
            if row_observer is not None:
                row_observer(record, True)
        final = path.lstat()
        if _file_signature(final) != _file_signature(live) or not stat.S_ISREG(final.st_mode):
            raise AuditQueryUnavailable("audit changed during row validation")
        store._page_seen_file = True
        if metadata is not None:
            metadata.update(
                head=previous,
                verified=count - legacy,
                legacy=legacy,
                size=len(raw),
                fingerprint=hashlib.sha256(raw).hexdigest(),
                signature=_file_signature(final),
            )
        return list(records.values())
    except (OSError, ValueError, TypeError, AuditTransferError) as error:
        raise AuditQueryUnavailable("audit page source unavailable") from error


class AuditPager:
    def __init__(self, key_reader=None, *, clock=None, key_mode=None):
        self._key_mode = key_mode or ("process_local" if key_reader is None else "supplied")
        if key_reader is None:
            ephemeral = secrets.token_bytes(32)
            key_reader = lambda: ephemeral
        self._key_reader = key_reader
        self._clock = clock or time.time

    def readiness(self):
        try:
            self._master()
            ok = True
        except AuditQueryUnavailable:
            ok = False
        return {"ok": ok, "cursor_key_mode": self._key_mode, "cursor_ttl_seconds": TTL_SECONDS}

    def _master(self):
        try:
            key = self._key_reader()
            if type(key) is not bytes or len(key) != 32:
                raise ValueError("invalid cursor key")
            return key
        except (OSError, ValueError, AuditTransferError) as error:
            raise AuditQueryUnavailable("audit cursor key unavailable") from error

    def _open(self, token, key):
        try:
            if type(token) is not str or not 1 <= len(token) <= MAX_CURSOR_CHARS:
                raise ValueError("cursor size")
            raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(raw).decode().rstrip("=") != token or raw[:1] != b"\x01":
                raise ValueError("cursor encoding")
            state = _Cursor.model_validate(decode(AESGCM(key).decrypt(raw[1:13], raw[13:], AAD)))
        except (ValueError, TypeError, InvalidTag, ValidationError, AuditTransferError):
            raise AuditCursorInvalid("Invalid audit cursor") from None
        self._fresh(state)
        return state

    def _fresh(self, state):
        now = int(self._clock())
        if (
            not state.issued <= now < state.expires
            or not 0 < state.expires - state.issued <= TTL_SECONDS
        ):
            raise AuditCursorExpired("Audit cursor expired; restart from the first page")

    @staticmethod
    def _seal(state, key):
        nonce = secrets.token_bytes(12)
        raw = (
            b"\x01"
            + nonce
            + AESGCM(key).encrypt(nonce, canonical(state.model_dump(mode="json")), AAD)
        )
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def page(self, store, tenant, limit=20, cursor=None, review_status=None, risk_level=None):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise AuditCursorInvalid("Page limit must be between1 and100")
        backend, source = _identity(store)
        master = self._master()
        encryption_key, identifier_key = _keys(master)
        state = self._open(cursor, encryption_key) if cursor is not None else None
        scope = backend, source, tenant, review_status, risk_level
        if (
            state
            and (state.backend, state.source, state.tenant, state.review_status, state.risk_level)
            != scope
        ):
            raise AuditCursorInvalid("Audit cursor scope changed")
        now = int(self._clock())
        if isinstance(store, SQLiteAuditStore):
            items, total, seq, digest = self._sqlite(
                store, state, tenant, limit, review_status, risk_level
            )
            mode = "sqlite_prefix"
        else:
            if isinstance(store, FederatedAuditStore):
                records, integrity = store._snapshot()
                if (
                    integrity["legacy_lines"]
                    or integrity["verified_lines"] > SQLiteAuditStore.MAX_ROWS
                ):
                    raise AuditQueryUnavailable("paged federation requires bounded hash-chain rows")
            else:
                records = _jsonl_view(store)
            records = sorted(
                (r for r in records if r.tenant_id == tenant), key=_sort_key, reverse=True
            )
            digest = hashlib.sha256(
                canonical([r.model_dump(mode="json") for r in records])
            ).hexdigest()
            if state and state.head_digest != digest:
                raise AuditSnapshotChanged("Audit view changed; restart from the first page")
            matching = [r for r in records if _matches(r, tenant, review_status, risk_level)]
            total, seq = len(matching), 0
            offset = state.offset if state else 0
            items = matching[offset : offset + limit]
            mode = "unchanged_local_view"
        if state is None:
            state = _Cursor(
                backend=backend,
                source=source,
                tenant=tenant,
                review_status=review_status,
                risk_level=risk_level,
                head_seq=seq,
                head_digest=digest,
                offset=0,
                issued=now,
                expires=now + TTL_SECONDS,
            )
        if state.offset > total:
            raise AuditCursorInvalid("Audit cursor position unavailable")
        self._fresh(state)
        if not hmac.compare_digest(master, self._master()):
            raise AuditQueryUnavailable("audit cursor key changed during query")
        identity = state.model_dump(mode="json", exclude={"offset"})
        snapshot_id = hmac.new(identifier_key, canonical(identity), hashlib.sha256).hexdigest()
        next_offset = state.offset + len(items)
        next_cursor = (
            self._seal(state.model_copy(update={"offset": next_offset}), encryption_key)
            if next_offset < total
            else None
        )
        return AuditResultPage(
            items=items,
            total_matches=total,
            page_cursor=self._seal(state, encryption_key),
            next_cursor=next_cursor,
            snapshot_id=snapshot_id,
            snapshot_created_at=datetime.fromtimestamp(state.issued, UTC),
            snapshot_expires_at=datetime.fromtimestamp(state.expires, UTC),
            snapshot_mode=mode,
        )

    @staticmethod
    def _sqlite(store, state, tenant, limit, review_status, risk_level):
        with store._transaction() as con:
            head = con.execute("SELECT seq,digest FROM audit_head WHERE id=1").fetchone()
            if head is None or type(head[0]) is not int or not 0 <= head[0] <= store.MAX_ROWS:
                raise AuditQueryUnavailable("audit head unavailable")
            seq, digest = (state.head_seq, state.head_digest) if state else head
            selected = {}

            def observe(record, number):
                if number > seq or record.tenant_id != tenant:
                    return
                if _matches(record, tenant, review_status, risk_level):
                    selected[record.analysis_id] = (*_sort_key(record), number)
                else:
                    selected.pop(record.analysis_id, None)

            store._read(con, retain_records=False, row_observer=observe)
            actual = (
                ("0" * 64,)
                if seq == 0
                else con.execute("SELECT digest FROM audit_entries WHERE seq=?", (seq,)).fetchone()
            )
            if actual != (digest,):
                raise AuditSnapshotChanged(
                    "Audit snapshot prefix unavailable; restart from the first page"
                )
            ordered = sorted(selected.values(), reverse=True)
            offset = state.offset if state else 0
            items = [
                AnalysisResult.model_validate_json(
                    con.execute(
                        "SELECT payload FROM audit_entries WHERE seq=?", (number,)
                    ).fetchone()[0]
                )
                for _, _, number in ordered[offset : offset + limit]
            ]
            return items, len(ordered), seq, digest


def create_audit_pager(settings):
    path, pin = settings.audit_cursor_key_path, settings.audit_cursor_key_sha256
    if path is None:
        return AuditPager()
    reader = lambda: read_key(path, pin)
    reader()  # A bad configured key must fail startup, never silently use a new key.
    return AuditPager(reader, key_mode="pinned_file")
