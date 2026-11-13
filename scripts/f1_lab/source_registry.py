"""Frozen public event-authority snapshots for reproducible local experiments.

The pin is trusted operator configuration, never a claim in an event. This is
not a live key-rotation/revocation controller. A changed snapshot fails closed.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from app.services.trusted_signals import SignalRegistryUnavailable, SignalVerifier


@dataclass(frozen=True)
class _RegistryBytes:
    payload: bytes

    def stat(self):
        return SimpleNamespace(st_size=len(self.payload))

    def read_bytes(self):
        return self.payload


class FrozenSignalVerifier(SignalVerifier):
    def __init__(self, registry_path: Path, expected_sha256: str):
        if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
                or any(c not in '0123456789abcdef' for c in expected_sha256)):
            raise ValueError('frozen_source_external_anchor_required')
        super().__init__(Path(registry_path))
        self.expected_sha256 = expected_sha256

    @property
    def configuration_binding(self):
        return {'kind': 'frozen-event-source-registry-1', 'sha256': self.expected_sha256}

    def _sources(self):
        try:
            path = self.registry_path
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 256_000:
                raise ValueError('frozen_source_file')
            with path.open('rb') as stream:
                raw = stream.read(256_001)
            if len(raw) > 256_000 or hashlib.sha256(raw).hexdigest() != self.expected_sha256:
                raise ValueError('frozen_source_hash')
            # Reuse all existing model/key/scope/alias validation on these exact
            # pinned bytes. Reopening the mutable path after hashing is forbidden.
            return SignalVerifier(_RegistryBytes(raw))._sources()
        except (OSError, ValueError, TypeError):
            raise SignalRegistryUnavailable('frozen source registry unavailable') from None
