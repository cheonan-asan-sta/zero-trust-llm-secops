"""Dedicated-role signed PAM observations from a trusted local journal reader.

Reported PID is not a process lifetime ID or an authenticated human. These
records are never authorization or existing service execution proofs.
"""

import base64
import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field, field_validator, model_validator

from app.models import StrictModel
from scripts.f1_lab.audit_auth_review import ACCOUNT
from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_evidence import Token, UInt
from scripts.f1_lab.web_verified_context import SHA, Window, public_bytes

DOMAIN = b'zt-pam-journal-capture-1\0'
MAX_RECORDS = 1000
OPEN = re.compile(rf'pam_unix\(sudo:session\): session opened for user (?P<target>{ACCOUNT})'
    rf'(?:\(uid=(?P<target_uid>\d{{1,10}})\))? by (?P<opener>{ACCOUNT})?\(uid=(?P<opener_uid>\d{{1,10}})\)')
CLOSE = re.compile(rf'pam_unix\(sudo:session\): session closed for user (?P<target>{ACCOUNT})')


def now_utc():
    return datetime.now(UTC)


def micros(moment):
    Window.aware(moment)
    delta = moment.astimezone(UTC)-datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days*86400+delta.seconds)*1000000+delta.microseconds


def integer(value, *, positive=False, maximum=4294967294):
    require(type(value) is str and bool(re.fullmatch(r'\d{1,19}', value)), 'pam_numeric_field')
    result = int(value)
    require(int(positive) <= result <= maximum, 'pam_numeric_range')
    return result


def optional_audit(row, name):
    if name not in row:
        return None
    value = integer(row[name], maximum=4294967295)
    return None if value == 4294967295 else value


def account_digest(value):
    return hashlib.sha256(b'pam-reported-account-1\0'+value.encode()).hexdigest() if value else None


class PamRecord(StrictModel):
    event: Literal['opened', 'closed']
    recorded_at_us: int = Field(strict=True, ge=1, le=4102444800000000)
    monotonic_us: int = Field(strict=True, ge=1, le=10**19)
    reported_process_id: int = Field(strict=True, ge=1, le=4294967294)
    sender_uid: UInt
    sender_gid: UInt
    audit_login_uid: UInt | None
    audit_session_id: UInt | None
    sender_program: Literal['sudo'] = 'sudo'
    sender_executable_path: Literal['/usr/bin/sudo', '/bin/sudo']
    transport: Literal['syslog'] = 'syslog'
    reported_target_account_sha256: SHA
    reported_target_uid: UInt | None
    reported_opener_account_sha256: SHA | None
    reported_opener_uid: UInt | None
    cursor_sha256: SHA
    exported_projection_sha256: SHA
    message_sha256: SHA

    @model_validator(mode='after')
    def session_fields(self):
        require(self.event != 'closed' or (self.reported_target_uid is None
            and self.reported_opener_uid is None and self.reported_opener_account_sha256 is None),
            'pam_close_fields')
        require(self.event != 'opened' or self.reported_opener_uid is not None, 'pam_open_uid')
        return self


class Rejections(StrictModel):
    non_pam: int = Field(default=0, strict=True, ge=0, le=MAX_RECORDS)
    untrusted_pam: int = Field(default=0, strict=True, ge=0, le=MAX_RECORDS)
    unavailable_pam: int = Field(default=0, strict=True, ge=0, le=MAX_RECORDS)
    unparseable_message: int = Field(default=0, strict=True, ge=0, le=MAX_RECORDS)


class PamCapture(Window):
    schema_version: Literal['zt-pam-journal-capture-1'] = 'zt-pam-journal-capture-1'
    scope: CollectorScope
    registry_sha256: SHA
    boot_id: Token
    invocation_id: Token
    window_start_us: int = Field(strict=True, ge=1, le=4102444800000000)
    window_end_us: int = Field(strict=True, ge=1, le=4102444800000000)
    journal_rows_seen: int = Field(strict=True, ge=0, le=MAX_RECORDS)
    records: list[PamRecord] = Field(max_length=MAX_RECORDS)
    rejections: Rejections
    process_lifetime_identity_verified: Literal[False] = False
    human_authenticated: Literal[False] = False
    authorization_asserted: Literal[False] = False
    automatic_enforcement_allowed: Literal[False] = False
    signature: str = Field(pattern=r'^[A-Za-z0-9_-]{86}$', repr=False)

    @field_validator('process_lifetime_identity_verified', 'human_authenticated',
                     'authorization_asserted', 'automatic_enforcement_allowed', mode='before')
    @classmethod
    def false_only(cls, value):
        require(type(value) is bool and not value, 'pam_no_identity_or_authority')
        return value

    @field_validator('issued_at', 'expires_at', mode='before')
    @classmethod
    def timestamp_type(cls, value):
        require(type(value) is str or isinstance(value, datetime), 'pam_time_type')
        return value

    @model_validator(mode='after')
    def capture_binding(self):
        require(self.boot_id != '0'*32 and self.invocation_id != '0'*32, 'pam_empty_binding')
        require(0 < self.window_end_us-self.window_start_us <= 600000000
            and 0 <= micros(self.issued_at)-self.window_end_us <= 15000000
            and timedelta(0) < self.expires_at-self.issued_at <= timedelta(seconds=60), 'pam_capture_window')
        require(self.journal_rows_seen == len(self.records)+sum(self.rejections.model_dump().values()),
                'pam_population')
        seen, previous_time, previous_mono = set(), 0, 0
        for record in self.records:
            require(self.window_start_us <= record.recorded_at_us <= self.window_end_us
                and record.cursor_sha256 not in seen and record.recorded_at_us >= previous_time
                and record.monotonic_us >= previous_mono, 'pam_record_order_or_window')
            seen.add(record.cursor_sha256)
            previous_time, previous_mono = record.recorded_at_us, record.monotonic_us
        return self


def authority(registry, scope, now, *, public_key=None):
    Window.aware(now)
    scope = CollectorScope.model_validate(scope.model_dump())
    found = [a for a in registry.authorities if (a.tenant_id, a.server_id, a.source_id, a.key_id, a.kind, a.mode)
        == (scope.tenant_id, scope.server_id, scope.source_id, scope.key_id, 'authentication', 'systemd')]
    require(len(found) == 1, 'pam_authority_role')
    selected = found[0]
    require(selected.enabled and scope.unit in selected.units and selected.issued_at <= now < selected.expires_at
            and (public_key is None or public_bytes(selected.public_key) == public_key), 'pam_authority_scope')
    return selected


def observation(raw, scope, boot, invocation):
    """Parser for an already trusted native reader; client JSON is not a source."""
    require(type(raw) is bytes and 0 < len(raw) <= 16384, 'pam_export_row_bound')
    row = decode(raw)
    require(type(row) is dict, 'pam_export_row_shape')
    message = row.get('MESSAGE')
    if type(message) is not str:
        return None, 'unparseable_message'
    if not message.startswith('pam_unix(sudo:session):'):
        return None, 'non_pam'
    if (row.get('_TRANSPORT') != 'syslog' or row.get('_COMM') != 'sudo'
            or row.get('_EXE') not in {'/usr/bin/sudo', '/bin/sudo'}
            or row.get('_SYSTEMD_UNIT') != scope.unit or row.get('_BOOT_ID') != boot
            or row.get('_SYSTEMD_INVOCATION_ID') != invocation):
        return None, 'untrusted_pam'
    match = OPEN.fullmatch(message) or CLOSE.fullmatch(message)
    if match is None:
        return None, 'unavailable_pam'
    opened = match.re is OPEN
    try:
        cursor = row['__CURSOR']
        require(type(cursor) is str and 0 < len(cursor.encode()) <= 1024
                and not re.search(r'[\x00-\x20\x7f]', cursor), 'pam_cursor')
        record = PamRecord(event='opened' if opened else 'closed',
            recorded_at_us=integer(row['__REALTIME_TIMESTAMP'], positive=True, maximum=4102444800000000),
            monotonic_us=integer(row['__MONOTONIC_TIMESTAMP'], positive=True, maximum=10**19),
            reported_process_id=integer(row['_PID'], positive=True), sender_uid=integer(row['_UID']),
            sender_gid=integer(row['_GID']), audit_login_uid=optional_audit(row, '_AUDIT_LOGINUID'),
            audit_session_id=optional_audit(row, '_AUDIT_SESSION'), sender_executable_path=row['_EXE'],
            reported_target_account_sha256=account_digest(match['target']),
            reported_target_uid=integer(match['target_uid']) if opened and match['target_uid'] else None,
            reported_opener_account_sha256=account_digest(match['opener']) if opened else None,
            reported_opener_uid=integer(match['opener_uid']) if opened else None,
            cursor_sha256=hashlib.sha256(cursor.encode()).hexdigest(),
            exported_projection_sha256=hashlib.sha256(raw).hexdigest(),
            message_sha256=hashlib.sha256(message.encode()).hexdigest())
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None, 'unavailable_pam'
    return record, None


def signed_bytes(capture):
    return DOMAIN+canonical(capture.model_dump(mode='json', exclude={'signature'}))


def build(raws, scope, pinned, key, *, boot, invocation, window_start_us, window_end_us,
          now=None):
    real_clock = now is None
    now = now_utc() if now is None else now
    registry = pinned.current(now)
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signer = authority(registry, scope, now, public_key=public)
    records, rejected, seen, cursors = [], Rejections(), 0, set()
    for raw in raws:
        seen += 1
        require(seen <= MAX_RECORDS, 'pam_journal_truncated')
        record, reason = observation(raw, scope, boot, invocation)
        # Any repeated cursor, including rejected/non-PAM entries, is ambiguous.
        row = decode(raw)
        cursor = row.get('__CURSOR')
        require(type(cursor) is str and 0 < len(cursor.encode()) <= 1024 and cursor not in cursors,
                'pam_export_cursor')
        cursors.add(cursor)
        if record is not None:
            records.append(record)
        else:
            setattr(rejected, reason, getattr(rejected, reason)+1)
    capture = PamCapture(scope=scope, registry_sha256=pinned.expected_sha256, boot_id=boot,
        invocation_id=invocation, window_start_us=window_start_us, window_end_us=window_end_us,
        journal_rows_seen=seen, records=records, rejections=rejected, issued_at=now,
        expires_at=min(now+timedelta(seconds=60), signer.expires_at, registry.expires_at), signature='A'*86)
    finished = now_utc() if real_clock else now
    require(now <= finished < capture.expires_at and pinned.current(finished) == registry, 'pam_signing_completion')
    authority(registry, scope, finished, public_key=public)
    return capture.model_copy(update={'signature': base64.urlsafe_b64encode(key.sign(signed_bytes(capture))).decode().rstrip('=')})


def verify(capture, scope, pinned, *, boot, invocation, now=None):
    real_clock = now is None
    now = now_utc() if now is None else now
    capture = PamCapture.model_validate(capture.model_dump())
    require(capture.scope == scope and capture.boot_id == boot and capture.invocation_id == invocation
            and capture.registry_sha256 == pinned.expected_sha256
            and capture.issued_at <= now < capture.expires_at, 'pam_capture_binding_or_expiry')
    current = pinned.current(now)
    signer = authority(current, scope, now)
    signature = base64.urlsafe_b64decode(capture.signature+'==')
    require(len(signature) == 64 and base64.urlsafe_b64encode(signature).decode().rstrip('=') == capture.signature,
            'pam_signature_encoding')
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes(signer.public_key)).verify(
            signature, signed_bytes(capture))
    except InvalidSignature as error:
        raise ValueError('native_source_pam_signature') from error
    if real_clock:
        finished = now_utc()
        require(now <= finished < capture.expires_at and pinned.current(finished) == current,
                'pam_verification_completion_time')
        authority(current, scope, finished)
    return capture
