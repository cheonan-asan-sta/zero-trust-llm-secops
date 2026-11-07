"""Continuously deliver an append-only local observation feed through a durable spool.

This local/test adapter observes JSONL records, not a real IdP or EDR. Capture,
signed transmission and receipt acknowledgement are separate durable boundaries.
"""

import argparse
import base64
import hashlib
import json
import os
import signal
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPException
from pathlib import Path
from threading import Event
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, field_validator, model_serializer, model_validator

from app.config import get_settings
from app.continuous_signal_models import (
    Observation,
    ObservationKind,
    ResourceIdentifier,
    SignedContinuousSignal,
)
from app.models import StrictModel
from app.security import Principal, Role
from app.services.collector_spool import (
    CollectorSpool,
    SpoolBindingMismatch,
    SpoolConflict,
    SpoolFull,
    SpoolUnavailable,
    SpoolVariantLimit,
)
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    SignalVerifier,
    canonical_observation,
)
from scripts.collector_input import (
    JOURNAL,
    MAX_FEED,
    MAX_LINE,
    PREPARATION,
    InputBusy,
    _prefix,
    append_event,
    feed_lock,
    recover_rotation,
    rotate_input,
)
from scripts.guardduty_eventbridge import GuardDutyMapping, normalize_finding, read_local_file
from scripts.local_signal_collector import _NoRedirect, _target

INBOX = "/zero-trust/signals/inbox"


class InputRecord(StrictModel):
    event_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    observed_at: datetime
    observation: Observation

    @field_validator("observed_at")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observation requires timezone")
        return value.astimezone(UTC)


class CollectorConfig(StrictModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    source_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    kind: ObservationKind
    subjects: list[str] = Field(min_length=1, max_length=100)
    resource_ids: list[ResourceIdentifier] = Field(default_factory=list, max_length=100)

    @model_serializer(mode="wrap")
    def serialize_config(self, handler):
        value = handler(self)
        # The spool binds the serialized collector configuration.
        if not self.resource_ids:
            value.pop("resource_ids", None)
        return value

    @model_validator(mode="after")
    def resource_scope(self):
        if bool(self.resource_ids) != (self.kind == "guardduty"):
            raise ValueError("only a GuardDuty collector requires resource scope")
        return self

    @field_validator("subjects")
    @classmethod
    def subject_scope(cls, values):
        if len(set(values)) != len(values) or any(not v.strip() or len(v) > 128 for v in values):
            raise ValueError("invalid collector subjects")
        return values


def _private_file(path, content):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())


def initialize(directory, tenant, source_id, key_id, kind, subjects, *, resource_ids=()):
    config = CollectorConfig(tenant_id=tenant, source_id=source_id, key_id=key_id,
                             kind=kind, subjects=subjects, resource_ids=list(resource_ids))
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    names = ["config.json", "private.pem", "sources.json", "input.jsonl", "state.sqlite3"]
    if any((directory / name).exists() for name in names):
        raise FileExistsError("collector files already exist")
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    now = datetime.now(UTC)
    registry = {"sources": [{
        "tenant_id": tenant, "source_id": source_id, "enabled": True,
        "user_ids": subjects if kind != "device" else ["unused-device-source-user"],
        "device_ids": subjects if kind == "device" else ["unused-identity-source-device"],
        "roles": ["employee"], "observation_kinds": [kind],
        "keys": [{"key_id": key_id, "enabled": True, "public_key_pem": public,
                  "not_before": (now - timedelta(seconds=1)).isoformat(),
                  "not_after": (now + timedelta(days=7)).isoformat()}],
    }]}
    if kind == "guardduty":
        registry["sources"][0]["guardduty_resource_ids"] = config.resource_ids
    _private_file(directory / "private.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    _private_file(directory / "sources.json", json.dumps(registry, indent=2).encode())
    _private_file(directory / "input.jsonl", b"")
    _private_file(directory / "config.json", config.model_dump_json(indent=2).encode())
    return {"collector": "initialized", "schema_version": 1}


@contextmanager
def exclusive_collector(directory):
    """One process owns capture and network delivery for a spool, across platforms."""
    path = Path(directory) / "collector.lock"
    file = os.fdopen(os.open(path, os.O_RDWR | os.O_CREAT, 0o600), "r+b")
    locked = False
    try:
        if os.name == "nt":
            import msvcrt
            if path.stat().st_size == 0:
                file.write(b"0")
                file.flush()
            file.seek(0)
            msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)
        file.close()


def post_observation(base_url, payload, *, tls_profile=None):
    """No proxy, redirects or transport retry; the spool owns every retry."""
    base_url = _target(base_url, tls_profile)
    headers = {}
    api_key = os.environ.get("SIGNAL_COLLECTOR_API_KEY")
    if api_key:
        if len(api_key) > 4096 or any(c in api_key for c in "\r\n"):
            raise ValueError("collector credential format")
        headers["X-API-Key"] = api_key
    wire = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    if tls_profile is not None:
        from scripts.mtls_transport import request
        status, body = request(tls_profile, INBOX, wire, headers)
    else:
        request = Request(base_url + INBOX, data=wire, method="POST",
                          headers={"Content-Type": "application/json", **headers})
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            response = opener.open(request, timeout=3)
        except HTTPError as error:
            response = error
        with response:
            status, body = response.status, response.read(65537)
    if len(body) > 65536:
        raise ValueError("collector response too large")
    return status, json.loads(body)


class ContinuousCollector:
    def __init__(self, directory, base_url, *, tls_profile=None, transport=None,
                 clock=None, max_pending=1000, max_records=10000, max_history=100000,
                 max_rotations=100000, rotate_bytes=MAX_FEED // 2):
        if get_settings().app_environment not in {"local", "test"}:
            raise ValueError("collector is local/test only")
        self.directory = Path(directory).resolve()
        self.input_path = self.directory / "input.jsonl"
        config_path = self.directory / "config.json"
        private_path = self.directory / "private.pem"
        if config_path.stat().st_size > 32768 or private_path.stat().st_size > 16384:
            raise ValueError("collector configuration too large")
        self.config = CollectorConfig.model_validate_json(config_path.read_bytes())
        self.key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(self.key, Ed25519PrivateKey):
            raise TypeError("collector requires Ed25519")
        self.base_url = _target(base_url, tls_profile)
        self.tls_profile = tls_profile
        self.clock = clock or (lambda: datetime.now(UTC))
        self.transport = transport or post_observation
        if type(rotate_bytes) is not int or not 0 <= rotate_bytes <= MAX_FEED:
            raise ValueError("collector rotation threshold invalid")
        self.rotate_bytes = rotate_bytes
        self.verifier = SignalVerifier(self.directory / "sources.json")
        self.principal = Principal("continuous-collector", self.config.tenant_id,
                                   frozenset({Role.ANALYST}), "collector")
        public = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        binding = self.config.model_dump() | {
            "input_path": str(self.input_path), "base_url": self.base_url,
            "tls_profile": str(Path(tls_profile).resolve()) if tls_profile else None,
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
        }
        self.spool = CollectorSpool(self.directory / "state.sqlite3", binding,
                                    max_pending=max_pending, max_records=max_records,
                                    max_history=max_history, max_rotations=max_rotations)

    def capture_one(self):
        with feed_lock(self.directory):
            recover_rotation(self.directory, self.spool)
            return self._capture_locked()

    def _capture_locked(self):
        checkpoint = self.spool.checkpoint()
        prefix, size = _prefix(self.input_path, checkpoint)
        with self.input_path.open("rb") as file:
            file.seek(checkpoint["offset"])
            line = file.readline(MAX_LINE + 1)
        if len(line) > MAX_LINE:
            raise ValueError("collector record size limit")
        if not line or not line.endswith(b"\n"):
            if (not line and self.rotate_bytes and size >= self.rotate_bytes
                    and size == checkpoint["offset"]):
                rotate_input(self.directory, self.spool)
            return False  # Do not checkpoint a writer's partial final line.
        record = InputRecord.model_validate_json(line)
        self._check_record(record)
        event = record.model_dump(mode="json")
        arguments = {"offset": checkpoint["offset"] + len(line),
                     "prefix_sha256": hashlib.sha256(prefix + line).hexdigest()}
        try:
            return self.spool.enqueue(event, **arguments)
        except SpoolFull:
            # Never prune pending or duplicate history. Compact only confirmed
            # receipts, then retry the same event at the same input checkpoint.
            if not self.spool.compact():
                raise
            return self.spool.enqueue(event, **arguments)

    def rotate(self):
        with feed_lock(self.directory):
            return rotate_input(self.directory, self.spool)

    def _check_record(self, record):
        if (record.observation.kind != self.config.kind
                or record.observation.subject_id not in self.config.subjects
                or (record.observation.kind == "guardduty"
                    and record.observation.resource_id not in self.config.resource_ids)
                or record.observed_at > self.clock()):
            raise ValueError("collector input scope or time")

    def append(self, event):
        record = InputRecord.model_validate(event)
        self._check_record(record)
        return append_event(self.directory, record.model_dump(mode="json"))

    def status(self):
        return self.spool.summary() | {
            "storage": self.spool.storage_summary(),
            "input_generation": self.spool.rotation_checkpoint()["generation"],
            "input_rotation_pending": any((self.directory / name).exists()
                                          for name in (JOURNAL, PREPARATION)),
        }

    def _envelope(self, event):
        now = self.clock()
        envelope = SignedContinuousSignal(
            tenant_id=self.config.tenant_id, source_id=self.config.source_id,
            key_id=self.config.key_id, issued_at=now, expires_at=now + timedelta(seconds=90),
            observed_at=event["observed_at"], observation=event["observation"],
            event_id=event["event_id"], signature="A" * 86,
        )
        envelope.signature = base64.urlsafe_b64encode(
            self.key.sign(canonical_observation(envelope)),
        ).decode().rstrip("=")
        self.verifier.verify_observation(envelope, self.principal, now)
        return envelope.model_dump(mode="json")

    def _send(self, envelope):
        # Current local authority is necessary even when replaying an old envelope.
        self.verifier.verify_observation(
            SignedContinuousSignal.model_validate(envelope), self.principal,
            self.clock(), enforce_freshness=False,
        )
        status, receipt = self.transport(self.base_url, envelope, tls_profile=self.tls_profile)
        if status == 202 and (
            not isinstance(receipt, dict) or receipt.get("tenant_id") != self.config.tenant_id
            or receipt.get("event_id") != envelope["event_id"]
            or receipt.get("state") not in {"pending", "processing", "completed", "failed"}
            or type(receipt.get("duplicate")) is not bool
        ):
            raise ValueError("collector receipt binding")
        return status

    def deliver_one(self):
        delivery = self.spool.next_pending(now=self.clock())
        if delivery is None:
            return "idle"
        event_id, envelopes = delivery["event_id"], delivery["envelopes"]
        try:
            if not envelopes:
                envelope = self._envelope(delivery["event"])
                self.spool.stage(event_id, envelope)  # Commit exact bytes before the first POST.
                envelopes = [envelope]
            current = envelopes[-1]
            status = self._send(current)
            if status == 401:
                age = (self.clock() - datetime.fromisoformat(current["issued_at"])).total_seconds()
                if age > 60 or datetime.fromisoformat(current["expires_at"]) <= self.clock():
                    # Preserve all prior variants for an old in-flight POST/ACK-loss race.
                    # The receiver still enforces exact-content conflict checks.
                    current = self._envelope(delivery["event"])
                    self.spool.stage(event_id, current)
                    status = self._send(current)
            if status == 409:
                # Only an exact variant's 202 acknowledges this event. Never infer
                # success from a 409 or invent another event ID to bypass it.
                unresolved = 409
                for previous in envelopes:
                    status = self._send(previous)
                    if status == 202:
                        break
                    if status != 409:
                        unresolved = status
                if status != 202:
                    status = unresolved
            if status == 202:
                self.spool.acknowledge(event_id, now=self.clock())
                return "acknowledged"  # Durable receipt, not policy-application success.
            error = "HTTP_" + str(status) if type(status) is int else "INVALID_RESPONSE"
        except (SignalRejected, SignalRegistryUnavailable):
            error = "AUTHORITY_UNAVAILABLE"
        except SpoolVariantLimit:
            error = "ENVELOPE_LIMIT"
        except (OSError, HTTPException, ValueError, TypeError, KeyError):
            error = "TRANSPORT_OR_RECEIPT_INVALID"
        delay = min(0.5 * 2 ** min(delivery["attempts"], 7), 60)
        self.spool.defer(event_id, error_code=error, now=self.clock(), delay_seconds=delay)
        return "retry"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["init", "run", "status", "compact", "rotate", "append", "append-guardduty"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--tenant", default="local")
    parser.add_argument("--source-id", default="local-identity-observer")
    parser.add_argument("--key-id", default="key-1")
    parser.add_argument("--kind", choices=["identity", "device", "guardduty"], default="identity")
    parser.add_argument("--subject", action="append", default=[])
    parser.add_argument("--resource", action="append", default=[])
    parser.add_argument("--event-signature", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--tls-profile", type=Path)
    parser.add_argument("--poll-seconds", type=float, default=0.5)
    parser.add_argument("--max-pending", type=int, default=1000)
    parser.add_argument("--max-records", type=int, default=10000)
    parser.add_argument("--max-history", type=int, default=100000)
    parser.add_argument("--max-rotations", type=int, default=100000)
    parser.add_argument("--limit", type=int, default=256)
    parser.add_argument("--rotate-bytes", type=int, default=MAX_FEED // 2)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if (args.operation == "append-guardduty") != (args.event_signature is not None):
        parser.error("append-guardduty requires --event-signature")
    if (not 0.01 <= args.poll_seconds <= 60 or not 1 <= args.max_pending <= 10000
            or not 1 <= args.max_records <= 100000
            or not 1 <= args.max_history <= 1000000 or not 1 <= args.limit <= 10000
            or not 1 <= args.max_rotations <= 1000000
            or not 0 <= args.rotate_bytes <= MAX_FEED):
        parser.error("invalid poll interval or capacity")
    stopped = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    try:
        if get_settings().app_environment not in {"local", "test"}:
            raise ValueError("collector is local/test only")
        if args.operation == "init":
            print(json.dumps(initialize(args.directory, args.tenant, args.source_id,
                                        args.key_id, args.kind, args.subject, resource_ids=args.resource)))
            return 0
        def configured_collector():
            return ContinuousCollector(args.directory, args.base_url,
                tls_profile=args.tls_profile, max_pending=args.max_pending, max_records=args.max_records,
                max_history=args.max_history, max_rotations=args.max_rotations,
                rotate_bytes=args.rotate_bytes)

        if args.operation in {"status", "append", "append-guardduty"}:
            collector = configured_collector()
            if args.operation != "status":
                raw = sys.stdin.buffer.read(MAX_LINE + 1)
                if len(raw) > MAX_LINE:
                    raise ValueError("collector input record size limit")
                if args.operation == "append-guardduty":
                    mapping = GuardDutyMapping.model_validate_json(
                        read_local_file(collector.directory / "guardduty-map.json", 32768),
                    )
                    event = normalize_finding(
                        raw, read_local_file(args.event_signature, 64), mapping,
                        tenant_id=collector.config.tenant_id, now=collector.clock(),
                    )
                else:
                    if collector.config.kind == "guardduty":
                        raise ValueError("GuardDuty input requires a signed EventBridge finding")
                    event = json.loads(raw)
                print(json.dumps(collector.append(event)), flush=True)
            else:
                print(json.dumps(collector.status()))
            return 0
        with exclusive_collector(args.directory):
            collector = configured_collector()
            if args.operation == "compact":
                print(json.dumps({"compacted": collector.spool.compact(limit=args.limit),
                                  **collector.status()}), flush=True)
                return 0
            if args.operation == "rotate":
                print(json.dumps(collector.rotate() | collector.status()), flush=True)
                return 0
            while not stopped.is_set():
                full, busy = False, False
                try:
                    captured = collector.capture_one()
                except SpoolFull:
                    captured, full = False, True
                except InputBusy:
                    captured, busy = False, True
                result = collector.deliver_one()
                if captured or full or result != "idle" or args.once:
                    print(json.dumps({"collector": result, "captured": captured,
                                      "backpressure": full, "input_busy": busy}), flush=True)
                if args.once:
                    return 1 if result == "retry" or full or busy else 0
                stopped.wait(args.poll_seconds)
        return 0
    except SpoolFull:
        print(json.dumps({"collector": "backpressure", "error": "STORAGE_CAPACITY_REACHED"}),
              file=sys.stderr, flush=True)
        return 1
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm,
            SpoolUnavailable, SpoolConflict, SpoolBindingMismatch):
        print(json.dumps({"collector": "stopped", "error": "INPUT_CONFIG_OR_STORAGE_INVALID"}),
              file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
