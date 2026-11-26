"""Encrypted, bounded native references on a local shared SQLite filesystem.

Stores signed inputs, not callbacks or approvals. Every reader must rebuild and
reverify provenance with its own server-owned policy, ledgers, and pinned keys.
This is not host failover, a distributed database, or remote anti-rollback proof.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.native_analysis_registry import (
    NativeAnalysisMissing,
    NativeAnalysisRegistry,
    _PublishedExecution,
)
from app.services.trusted_signals import SignalRegistryUnavailable, SignalRejected

MAX_BUNDLE_BYTES = 65536


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _require(condition):
    if not condition:
        raise ValueError("shared native reference validation failed")


@dataclass(frozen=True)
class StoredNativeReference:
    bundle: bytes
    expires_at: datetime
    binding_sha256: str


class EncryptedNativeReferenceStore:
    def __init__(self, path, key_path, key_sha256, *, capacity=128):
        _require(type(capacity) is int and 1 <= capacity <= 1024)
        _require(
            isinstance(key_sha256, str)
            and len(key_sha256) == 64
            and set(key_sha256) <= set("0123456789abcdef")
        )
        self.path, self.key_path = Path(path), Path(key_path)
        self.key_sha256, self.capacity = key_sha256, capacity
        _require(self.path.parent.is_dir() and self.path.resolve() != self.key_path.resolve())
        self._key()
        with self._connect(write=True) as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS native_reference_meta (id INTEGER PRIMARY KEY CHECK(id=1), store_id TEXT NOT NULL, capacity INTEGER NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS native_references (ref TEXT PRIMARY KEY, owner TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, ciphertext BLOB NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS native_reference_clock (id INTEGER PRIMARY KEY CHECK(id=1), observed TEXT NOT NULL)"
            )
            con.execute(
                "INSERT OR IGNORE INTO native_reference_meta VALUES (1,?,?)",
                (secrets.token_hex(32), capacity),
            )
            row = con.execute(
                "SELECT store_id,capacity FROM native_reference_meta WHERE id=1"
            ).fetchone()
            _require(row is not None and row[1] == capacity and len(row[0]) == 64)
            self.store_id = row[0]

    def _key(self):
        """Reload the pinned key on every read, detecting withdrawal during inference."""
        try:
            _require(not self.key_path.is_symlink())
            fd = os.open(
                self.key_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
            )
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                _require(stat.S_ISREG(info.st_mode) and info.st_size == 32 and info.st_nlink == 1)
                if os.name == "posix":
                    _require(info.st_mode & 0o077 == 0 and info.st_uid in {0, os.geteuid()})
                key = stream.read(33)
            _require(len(key) == 32 and hmac.compare_digest(_sha(key), self.key_sha256))
            return key
        except (OSError, ValueError) as error:
            raise SignalRegistryUnavailable("Shared native reference key unavailable") from error

    @contextmanager
    def _connect(self, *, write=False):
        connection = None
        try:
            _require(not self.path.is_symlink())
            connection = sqlite3.connect(
                self.path if write else self.path.resolve().as_uri() + "?mode=ro",
                uri=not write,
                timeout=5,
            )
            if write:
                connection.execute("PRAGMA synchronous=FULL")
            else:
                connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            with connection:
                yield connection
        except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError, InvalidTag) as error:
            if isinstance(error, (SignalRejected, SignalRegistryUnavailable)):
                raise
            raise SignalRegistryUnavailable("Shared native reference store unavailable") from error
        finally:
            if connection is not None:
                connection.close()

    def _metadata(self, con, now=None):
        row = con.execute(
            "SELECT store_id,capacity FROM native_reference_meta WHERE id=1"
        ).fetchone()
        _require(row == (self.store_id, self.capacity))
        clock = con.execute("SELECT observed FROM native_reference_clock WHERE id=1").fetchone()
        now = datetime.now(UTC) if now is None else now
        _require(now.utcoffset() is not None)
        _require(clock is None or now >= datetime.fromisoformat(clock[0]))
        return now

    @staticmethod
    def _owner(principal):
        return _sha(_canonical([principal.tenant_id, principal.subject]))

    def _aad(self, ref, owner, created, expires):
        return _canonical(["native-reference-1", self.store_id, ref, owner, created, expires])

    def publish(self, bundle, principal, expires_at):
        _require(type(bundle) is bytes and 0 < len(bundle) <= MAX_BUNDLE_BYTES)
        key = self._key()
        owner = self._owner(principal)
        with self._connect(write=True) as con:
            now = self._metadata(con)
            _require(timedelta(0) < expires_at - now <= timedelta(seconds=30))
            created, expires = now.isoformat(), expires_at.astimezone(UTC).isoformat()
            con.execute("DELETE FROM native_references WHERE expires<=?", (created,))
            if con.execute("SELECT count(*) FROM native_references").fetchone()[0] >= self.capacity:
                raise SignalRejected("Shared native reference capacity exhausted")
            ref = secrets.token_hex(32)
            ref_sha = _sha(ref.encode())
            while con.execute("SELECT 1 FROM native_references WHERE ref=?", (ref_sha,)).fetchone():
                ref = secrets.token_hex(32)
                ref_sha = _sha(ref.encode())
            nonce = secrets.token_bytes(12)
            encrypted = nonce + AESGCM(key).encrypt(
                nonce, bundle, self._aad(ref_sha, owner, created, expires)
            )
            con.execute(
                "INSERT INTO native_references VALUES (?,?,?,?,?)",
                (ref_sha, owner, created, expires, encrypted),
            )
            con.execute("INSERT OR REPLACE INTO native_reference_clock VALUES (1,?)", (created,))
        return ref

    def get(self, ref, principal):
        key = self._key()
        _require(isinstance(ref, str) and len(ref) == 64 and set(ref) <= set("0123456789abcdef"))
        ref_sha = _sha(ref.encode())
        with self._connect() as con:
            now = self._metadata(con)
            row = con.execute(
                "SELECT owner,created,expires,ciphertext FROM native_references WHERE ref=?",
                (ref_sha,),
            ).fetchone()
            if row is None or not hmac.compare_digest(row[0], self._owner(principal)):
                raise NativeAnalysisMissing("native execution reference unavailable")
            owner, created, expires, encrypted = row
            _require(type(encrypted) is bytes and 28 <= len(encrypted) <= MAX_BUNDLE_BYTES + 28)
            aad = self._aad(ref_sha, owner, created, expires)
            bundle = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], aad)
            start, end = datetime.fromisoformat(created), datetime.fromisoformat(expires)
            _require(
                start.utcoffset() is not None
                and end.utcoffset() is not None
                and timedelta(0) < end - start <= timedelta(seconds=30)
                and start <= now
            )
            if now >= end:
                raise NativeAnalysisMissing("native execution reference unavailable")
            return StoredNativeReference(bundle, end, _sha(aad + encrypted))

    def revoke(self, ref):
        self._key()
        with self._connect(write=True) as con:
            now = self._metadata(con)
            con.execute("DELETE FROM native_references WHERE ref=?", (_sha(ref.encode()),))
            con.execute(
                "INSERT OR REPLACE INTO native_reference_clock VALUES (1,?)", (now.isoformat(),)
            )


class SharedNativeAnalysisRegistry(NativeAnalysisRegistry):
    """Reconstruct server-verified contexts from encrypted signed bundles per worker."""

    def __init__(self, operations, store, decoder):
        super().__init__(operations, capacity=store.capacity)
        self.store, self.decoder = store, decoder

    def publish(self, signal, principal, collect):
        raise SignalRejected("Shared native analysis requires a signed input bundle")

    def publish_bundle(self, bundle, principal):
        self._authenticated(principal)
        _require(type(bundle) is bytes and len(bundle) <= MAX_BUNDLE_BYTES)
        signal, collect = self.decoder(bundle)
        _require(signal.tenant_id == principal.tenant_id)
        context = collect(principal)
        self._snapshot(context, signal)
        context.verify_current()
        return self.store.publish(bundle, principal, context.expires_at)

    def _load(self, execution_ref, principal):
        row = self.store.get(execution_ref, principal)
        try:
            signal, collect = self.decoder(row.bundle)
        except (ValueError, TypeError, LookupError) as error:
            raise SignalRegistryUnavailable("Shared native signed bundle unavailable") from error
        _require(signal.tenant_id == principal.tenant_id)
        return _PublishedExecution(
            signal,
            principal.tenant_id,
            principal.subject,
            row.expires_at,
            collect,
            row.binding_sha256,
        )

    def _assert_active(self, execution_ref, entry):
        from app.security import Principal, Role

        # Identity is only a DB lookup scope; actual HTTP authentication is checked
        # by the parent registry and the evidence collector, never by this synthetic principal.
        owner = Principal(entry.subject, entry.tenant_id, frozenset({Role.ANALYST}), "unverified")
        try:
            current = self.store.get(execution_ref, owner)
        except NativeAnalysisMissing as error:
            raise SignalRejected(
                "Shared native execution reference expired or withdrawn"
            ) from error
        if current.binding_sha256 != entry.binding_sha256:
            raise SignalRejected("Shared native execution reference changed")

    def revoke(self, execution_ref):
        self.store.revoke(execution_ref)
