"""Pinned two-provider runtime-key selection over private local Unix sockets.

Only unavailable endpoints or currently disabled/expired preapproved keys may
be skipped. Malformed bytes, identity/scope/key mismatch and unsafe filesystem
objects fail closed, without trying the other endpoint. No authorization key
or network credential source is accepted.
"""

import errno
import hashlib
import os
import re
import socket
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field, model_validator

from app.models import StrictModel
from scripts.f1_lab.collector_freshness import CollectorScope, runtime_authority
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.systemd_credentials import peer_uid
from scripts.f1_lab.web_verified_context import SHA, Identifier


class ProviderEndpoint(StrictModel):
    key_id: Identifier
    socket_path: str = Field(min_length=1, max_length=100)
    peer_uid: int = Field(strict=True, ge=0, le=4294967294)


class ProviderProfile(StrictModel):
    schema_version: Literal['zt-collector-provider-ha-1'] = 'zt-collector-provider-ha-1'
    scope: CollectorScope
    registry_sha256: SHA
    endpoints: list[ProviderEndpoint] = Field(min_length=2, max_length=2)

    @model_validator(mode='after')
    def exact_pair(self):
        require(self.endpoints[0].key_id == self.scope.key_id
                and len({e.key_id for e in self.endpoints}) == 2
                and len({e.socket_path for e in self.endpoints}) == 2
                and all(Path(e.socket_path).is_absolute() and len(os.fsencode(e.socket_path)) < 100
                        and '\x00' not in e.socket_path for e in self.endpoints), 'provider_ha_pair')
        return self


def load_profile(path, expected_sha256, scope, registry):
    require(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}', expected_sha256),
            'provider_ha_profile_pin')
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), 'provider_ha_profile_path')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not stat.S_IMODE(before.st_mode) & 0o022 and 0 < before.st_size <= 8192,
                'provider_ha_profile_file')
        raw = stream.read(8193)
        after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                and hashlib.sha256(raw).hexdigest() == expected_sha256, 'provider_ha_profile_changed')
    profile = ProviderProfile.model_validate(decode(raw))
    require(profile.scope == scope and profile.registry_sha256 == registry.expected_sha256,
            'provider_ha_profile_binding')
    current = registry.current(datetime.now(UTC))
    authorities(profile, current)
    return profile


def authorities(profile, registry):
    result = []
    scope = profile.scope
    for endpoint in profile.endpoints:
        matches = [a for a in registry.authorities
                   if (a.tenant_id, a.server_id, a.source_id, a.key_id, a.kind, a.mode)
                   == (scope.tenant_id, scope.server_id, scope.source_id, endpoint.key_id, 'runtime', 'systemd')]
        require(len(matches) == 1 and scope.unit in matches[0].units, 'provider_ha_authority_scope')
        result.append(matches[0])
    return result


class EndpointUnavailable(OSError):
    """Availability failure only; never an invalid or untrusted key response."""


def private_socket(path, expected_uid):
    path = Path(path)
    try:
        parent, info = path.parent.lstat(), path.lstat()
    except FileNotFoundError as error:
        raise EndpointUnavailable('provider endpoint absent') from error
    require(stat.S_ISDIR(parent.st_mode) and not path.parent.is_symlink()
            and parent.st_uid == expected_uid and stat.S_IMODE(parent.st_mode) == 0o700
            and stat.S_ISSOCK(info.st_mode) and not path.is_symlink()
            and info.st_uid == expected_uid and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600, 'provider_ha_private_socket')
    return info


def read_key(endpoint, *, timeout=0.5):
    require(os.name == 'posix' and hasattr(socket, 'SO_PEERCRED') and type(timeout) in {int, float}
            and 0 < timeout <= 0.5, 'provider_ha_local_platform')
    before = private_socket(endpoint.socket_path, endpoint.peer_uid)
    raw = bytearray()
    deadline = time.monotonic()+timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        try:
            connection.settimeout(timeout)
            connection.connect(endpoint.socket_path)
            require(peer_uid(connection) == endpoint.peer_uid, 'provider_ha_peer_uid')
            current = private_socket(endpoint.socket_path, endpoint.peer_uid)
            require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
                    'provider_ha_socket_replaced')
            while len(raw) <= 32:
                remaining = deadline-time.monotonic()
                require(remaining > 0 or not raw, 'provider_ha_partial_response_deadline')
                if remaining <= 0:
                    raise EndpointUnavailable('provider endpoint timeout')
                connection.settimeout(remaining)
                chunk = connection.recv(33-len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= 32, 'provider_ha_key_response_bound')
        except (TimeoutError, ConnectionRefusedError) as error:
            require(not raw, 'provider_ha_partial_key_response')
            raise EndpointUnavailable('provider endpoint unavailable') from error
        except OSError as error:
            if isinstance(error, EndpointUnavailable):
                raise
            if error.errno in {errno.ENOENT, errno.ECONNREFUSED, errno.ETIMEDOUT, errno.ECONNRESET} and not raw:
                raise EndpointUnavailable('provider endpoint disconnected') from error
            raise
    require(len(raw) == 32, 'provider_ha_raw_key_size')
    try:
        final = private_socket(endpoint.socket_path, endpoint.peer_uid)
    except EndpointUnavailable as error:
        raise ValueError('provider endpoint changed during response') from error
    require((final.st_dev, final.st_ino) == (before.st_dev, before.st_ino), 'provider_ha_socket_changed')
    return bytes(raw)


def select_key(profile, registry, *, clock=lambda: datetime.now(UTC)):
    profile = ProviderProfile.model_validate(profile.model_dump())
    now = clock()
    current = registry.current(now)
    approved = authorities(profile, current)
    skipped = []
    for ordinal, (endpoint, authority) in enumerate(zip(profile.endpoints, approved, strict=True)):
        # Revocation/expiry can only remove a preconfigured candidate. The
        # standby must already be independently registered in the same scope.
        if not (authority.enabled and authority.issued_at <= now < authority.expires_at):
            skipped.append({'provider': ordinal, 'reason': 'authority_not_current'})
            continue
        selected_scope = profile.scope.model_copy(update={'key_id': endpoint.key_id})
        runtime_authority(current, selected_scope, now)
        try:
            raw = read_key(endpoint)
        except EndpointUnavailable:
            skipped.append({'provider': ordinal, 'reason': 'endpoint_unavailable'})
            continue
        key = Ed25519PrivateKey.from_private_bytes(raw)
        checked = clock()
        require(checked >= now and registry.current(checked) == current, 'provider_ha_registry_changed')
        runtime_authority(current, selected_scope, checked,
                          public_key=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        return key, selected_scope, {'selected_provider': ordinal, 'selected_key_id': endpoint.key_id,
                                     'skipped': skipped, 'authorization_asserted': False}
    raise EndpointUnavailable('no current preapproved runtime provider available')
