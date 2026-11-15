"""Current collector authority and signed observation freshness, never permission.

The local monitor ledger detects ordinary restart/replay/clock regression. The
host, administrator trust pin, collector and ledger remain trusted; restoring
the whole ledger is not prevented. Fresh means recent evidence, not live service,
healthy device, authenticated person, authorization, or a threat classification.
"""

import base64
import os
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.models import StrictModel
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    ServiceEvent,
    ServiceProof,
    Unit,
    digest,
    proof_bytes,
)
from scripts.f1_lab.web_verified_context import Identifier, Window, public_bytes

MAX_CAPTURE = 65536


class CollectorScope(StrictModel):
    tenant_id: Identifier
    server_id: Identifier
    unit: Unit
    source_id: Identifier
    key_id: Identifier

    @property
    def sha256(self):
        return digest(self.model_dump(mode="json"))


def runtime_authority(registry, scope, now, *, public_key=None):
    scope = CollectorScope.model_validate(scope.model_dump())
    Window.aware(now)
    matches = [
        a
        for a in registry.authorities
        if (a.tenant_id, a.server_id, a.source_id, a.key_id, a.kind, a.mode)
        == (scope.tenant_id, scope.server_id, scope.source_id, scope.key_id, "runtime", "systemd")
    ]
    require(len(matches) == 1, "collector_authority_identity")
    a = matches[0]
    require(
        a.enabled and scope.unit in a.units and a.issued_at <= now < a.expires_at,
        "collector_authority_scope_or_window",
    )
    require(
        public_key is None or public_bytes(a.public_key) == public_key, "collector_authority_key"
    )
    return a


@dataclass(frozen=True)
class CaptureStatus:
    state: str
    reason: str
    event_sha256: str | None = None
    observed_at: datetime | None = None


def inspect_capture(payload, scope, pinned, *, now=None):
    now = datetime.now(UTC) if now is None else now
    stage = "envelope"
    try:
        Window.aware(now)
        scope = CollectorScope.model_validate(scope.model_dump())
        require(isinstance(pinned, PinnedServiceRegistry), "collector_registry_type")
        require(
            type(payload) is dict
            and set(payload) == {"schema", "event", "runtime_proof", "authorization_proof_included"}
            and payload["schema"] == "zt-service-capture-1"
            and payload["authorization_proof_included"] is False,
            "collector_envelope",
        )
        event = ServiceEvent.model_validate(payload["event"])
        proof = ServiceProof.model_validate(payload["runtime_proof"])
        stage = "binding"
        require(
            (event.tenant_id, event.server_id, event.unit, event.mode)
            == (scope.tenant_id, scope.server_id, scope.unit, "systemd")
            and proof.observation.kind == "runtime"
            and (proof.tenant_id, proof.source_id, proof.key_id)
            == (scope.tenant_id, scope.source_id, scope.key_id)
            and proof.event_sha256 == event.sha256
            and proof.observation.pid == event.process_id,
            "collector_capture_binding",
        )
        stage = "authority"
        registry = pinned.current(now)
        a = runtime_authority(registry, scope, now)
        stage = "signature"
        signature = base64.urlsafe_b64decode(proof.signature + "==")
        require(
            base64.urlsafe_b64encode(signature).decode().rstrip("=") == proof.signature,
            "collector_signature_encoding",
        )
        Ed25519PublicKey.from_public_bytes(public_bytes(a.public_key)).verify(
            signature, proof_bytes(proof)
        )
        stage = "time"
        require(
            a.issued_at <= proof.observed_at <= proof.issued_at <= now
            and event.observed_at <= proof.observed_at <= event.observed_at + timedelta(seconds=5)
            and proof.issued_at < proof.expires_at <= a.expires_at
            and proof.expires_at - proof.issued_at <= timedelta(seconds=30),
            "collector_capture_window",
        )
        require(pinned.current(now) == registry, "collector_registry_changed")
        fresh = now - event.observed_at <= timedelta(seconds=30) and now < proof.expires_at
        return CaptureStatus(
            "fresh" if fresh else "stale",
            "recent_signed_observation" if fresh else "observation_expired",
            event.sha256,
            event.observed_at,
        )
    except (
        ValueError,
        TypeError,
        AttributeError,
        KeyError,
        OSError,
        InvalidSignature,
        RecursionError,
    ):
        return CaptureStatus("unavailable", "capture_" + stage + "_unavailable")


def read_capture(path):
    path = Path(path)
    require(not path.is_symlink(), "collector_capture_link")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_CAPTURE,
            "collector_capture_file",
        )
        raw = stream.read(MAX_CAPTURE + 1)
        after = os.fstat(stream.fileno())
        require(
            len(raw) <= MAX_CAPTURE
            and (before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns),
            "collector_capture_stable",
        )
    return decode(raw)


def atomic_capture(path, body):
    """One-file replace in a trusted local directory. Not a two-file transaction."""
    path = Path(path)
    require(
        type(body) is bytes
        and 0 < len(body) <= MAX_CAPTURE
        and path.parent.is_dir()
        and not path.parent.is_symlink()
        and not path.is_symlink(),
        "collector_publication_path",
    )
    fd, temporary = tempfile.mkstemp(prefix=".secops-capture-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        require(not path.is_symlink(), "collector_publication_link")
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class CollectorMonitor:
    """Bounded advisory state; no detection score, grant or response side effect."""

    def __init__(self, scope, registry, ledger, *, capacity=1000):
        self.scope = CollectorScope.model_validate(scope.model_dump())
        require(
            isinstance(registry, PinnedServiceRegistry)
            and type(capacity) is int
            and 1 <= capacity <= 10000,
            "collector_monitor_configuration",
        )
        self.registry, self.path, self.capacity = registry, Path(ledger), capacity
        require(self.path.parent.is_dir(), "collector_monitor_parent")
        with self.connect() as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), checked TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS latest (scope TEXT PRIMARY KEY, observed TEXT NOT NULL, event TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self):
        require(not self.path.is_symlink(), "collector_monitor_link")
        con = sqlite3.connect(self.path, timeout=5)
        try:
            with con:
                yield con
        finally:
            con.close()

    def check(self, capture, *, now=None):
        now = datetime.now(UTC) if now is None else now
        try:
            Window.aware(now)
            with self.connect() as con:
                con.execute("BEGIN IMMEDIATE")
                clock = con.execute("SELECT checked FROM clock WHERE id=1").fetchone()
                if clock and now < datetime.fromisoformat(clock[0]):
                    return CaptureStatus("unavailable", "clock_regression")
                con.execute(
                    "INSERT OR REPLACE INTO clock VALUES (1,?)", (now.astimezone(UTC).isoformat(),)
                )
                try:
                    result = inspect_capture(
                        read_capture(capture), self.scope, self.registry, now=now
                    )
                except (ValueError, OSError, RecursionError):
                    return CaptureStatus("unavailable", "capture_file_unavailable")
                if result.state == "unavailable":
                    return result
                old = con.execute(
                    "SELECT observed,event FROM latest WHERE scope=?", (self.scope.sha256,)
                ).fetchone()
                if old and (
                    result.observed_at < datetime.fromisoformat(old[0])
                    or (
                        result.observed_at == datetime.fromisoformat(old[0])
                        and result.event_sha256 != old[1]
                    )
                ):
                    return CaptureStatus("unavailable", "capture_regression")
                if (
                    not old
                    and con.execute("SELECT count(*) FROM latest").fetchone()[0] >= self.capacity
                ):
                    return CaptureStatus("unavailable", "monitor_capacity")
                con.execute(
                    "INSERT OR REPLACE INTO latest VALUES (?,?,?)",
                    (
                        self.scope.sha256,
                        result.observed_at.astimezone(UTC).isoformat(),
                        result.event_sha256,
                    ),
                )
                return result
        except (ValueError, OSError, sqlite3.Error, RecursionError):
            return CaptureStatus("unavailable", "monitor_storage_or_clock_unavailable")
