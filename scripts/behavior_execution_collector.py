"""Protected local adapter for execution observations, with exact durable delivery.

The feed must come from a trusted local observer. This adapter signs supplied facts;
it is not an EDR, process attestation engine, or AWS traffic sensor. Missing actor or
destination information stays missing. Signing never derives facts from an approval.
"""

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.behavior_context_models import BehaviorScope
from app.behavior_execution_models import SignedExecutionEvidence
from app.config import get_settings
from app.security import Principal, Role
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    SignalVerifier,
    canonical_execution_evidence,
)
from scripts.continuous_signal_collector import exclusive_collector
from scripts.local_signal_collector import _NoRedirect, _target

ENDPOINT = "/detections/context/execution-evidence"
MAX_RECORD_BYTES = 1_048_576
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 10_000
ENVELOPE_FIELDS = {
    "schema_version", "algorithm", "tenant_id", "source_id", "key_id",
    "issued_at", "expires_at", "signature",
}
STATUSES = {"pending", "acknowledged", "rejected"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _owned(metadata, *, directory=False):
    valid_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not valid_type or (os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    )):
        raise ValueError("execution_collector_requires_owner_only_files")


def read_private(path, maximum=MAX_RECORD_BYTES):
    """Reject symlinks and non-regular input; check permissions on the opened object."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        _owned(metadata)
        if metadata.st_size > maximum:
            raise ValueError("execution_collector_file_too_large")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("execution_collector_file_too_large")
        return raw


def _config(config):
    if (not isinstance(config, dict)
            or set(config) != {"tenant_id", "source_id", "key_id"}
            or any(not isinstance(value, str) or not value for value in config.values())):
        raise ValueError("execution_collector_config")
    return config


def _unsigned(record, config, now, lifetime_seconds=90):
    _config(config)
    if not isinstance(record, dict) or set(record) & ENVELOPE_FIELDS:
        raise ValueError("execution_collector_input_envelope_fields")
    if now.utcoffset() is None:
        raise ValueError("execution_collector_clock_requires_timezone")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 120:
        raise ValueError("execution_collector_lifetime")
    return SignedExecutionEvidence.model_validate({
        **record, **config, "issued_at": now, "expires_at": now + timedelta(seconds=lifetime_seconds),
        "signature": "A" * 86,
    })


def sign_record(record, key, config, verifier, now, *, lifetime_seconds=90):
    """Sign observed fields only, then check current pinned scope and key authority."""
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("execution_collector_key_type")
    envelope = _unsigned(record, config, now, lifetime_seconds)
    signed = base64.urlsafe_b64encode(key.sign(canonical_execution_evidence(envelope))).decode().rstrip("=")
    envelope = envelope.model_copy(update={"signature": signed})
    principal = Principal("execution-collector", config["tenant_id"], frozenset({Role.ANALYST}), "collector")
    verifier.verify_execution_evidence(envelope, principal, now)
    return envelope


def initialize(directory, tenant_id, source_id, key_id, scopes, *, now=None, key=None):
    """Create a local observer identity; registry installation on the server is separate."""
    now = now or datetime.now(UTC)
    config = _config({"tenant_id": tenant_id, "source_id": source_id, "key_id": key_id})
    scopes = [BehaviorScope.model_validate(scope).model_dump(mode="json") for scope in scopes]
    if not scopes:
        raise ValueError("execution_collector_scopes_required")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    _owned(directory.lstat(), directory=True)
    key = key or Ed25519PrivateKey.generate()
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("execution_collector_key_type")
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    registry = {"sources": [{
        "tenant_id": tenant_id, "source_id": source_id, "enabled": True,
        "user_ids": sorted({scope["user_id"] for scope in scopes}),
        "device_ids": sorted({scope["device_id"] for scope in scopes}), "roles": ["employee"],
        "execution_scopes": scopes,
        "keys": [{"key_id": key_id, "enabled": True, "public_key_pem": public,
                  "not_before": (now - timedelta(seconds=1)).isoformat(),
                  "not_after": (now + timedelta(days=7)).isoformat()}],
    }]}
    _private(directory / "private.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    _private(directory / "config.json", _canonical(config))
    _private(directory / "sources.json", _canonical(registry))
    if not SignalVerifier(directory / "sources.json").readiness()["ok"]:
        raise ValueError("execution_collector_registry_invalid")
    return {"status": "initialized", "public_registry": str(directory / "sources.json")}


def post_evidence(base_url, payload, *, tls_profile=None):
    base_url = _target(base_url, tls_profile)
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("EXECUTION_COLLECTOR_API_KEY")
    if token:
        if len(token) > 4096 or any(char in token for char in "\r\n"):
            raise ValueError("execution_collector_credential_format")
        headers["X-API-Key"] = token
    wire = _canonical(payload)
    if tls_profile is not None:
        from scripts.mtls_transport import request
        status, body = request(tls_profile, ENDPOINT, wire, headers)
    else:
        request = Request(base_url + ENDPOINT, data=wire, method="POST", headers=headers)
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            response = opener.open(request, timeout=3)
        except HTTPError as error:
            response = error
        with response:
            status, body = response.status, response.read(65_537)
    if len(body) > 65_536:
        raise ValueError("execution_collector_receipt_too_large")
    return status, json.loads(body)


class ExecutionCollector:
    """Bounded persistent envelope queue; replays never reseal or replace evidence."""

    def __init__(self, directory, base_url, *, tls_profile=None, transport=None, clock=None,
                 lifetime_seconds=90):
        if get_settings().app_environment not in {"local", "test"}:
            raise ValueError("execution_collector_local_only")
        self.directory = Path(directory)
        _owned(self.directory.lstat(), directory=True)
        self.directory = self.directory.resolve()
        self.config = _config(json.loads(read_private(self.directory / "config.json", 32_768)))
        self.key = serialization.load_pem_private_key(read_private(self.directory / "private.pem", 16_384), password=None)
        if not isinstance(self.key, Ed25519PrivateKey):
            raise TypeError("execution_collector_key_type")
        read_private(self.directory / "sources.json", 256_000)
        self.verifier = SignalVerifier(self.directory / "sources.json")
        self.clock = clock or (lambda: datetime.now(UTC))
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 120:
            raise ValueError("execution_collector_lifetime")
        self.lifetime_seconds = lifetime_seconds
        self.base_url = _target(base_url, tls_profile)
        self.tls_profile, self.transport = tls_profile, transport or post_evidence
        public = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.binding = _canonical(self.config | {
            "base_url": self.base_url, "public_key_sha256": _sha(public),
            "tls_profile": str(Path(tls_profile).resolve()) if tls_profile else None,
            "lifetime_seconds": lifetime_seconds,
        }).decode()
        self.database = self.directory / "execution-spool.sqlite3"
        with exclusive_collector(self.directory):
            if not self.database.exists():
                _private(self.database, b"")
                with self._connection() as connection:
                    connection.execute("CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL)")
                    connection.execute(
                        "CREATE TABLE records(seq INTEGER PRIMARY KEY,evidence_id TEXT UNIQUE NOT NULL,"
                        "record_sha256 TEXT NOT NULL,envelope TEXT NOT NULL,envelope_sha256 TEXT NOT NULL,"
                        "input_digest TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL,"
                        "next_attempt TEXT NOT NULL,error_code TEXT)"
                    )
                    connection.execute("INSERT INTO metadata VALUES(1,?)", (self.binding,))
            with self._connection() as connection:
                self._validate(connection)

    @contextmanager
    def _connection(self):
        _owned(self.database.lstat())
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _validate(self, connection):
        binding = connection.execute("SELECT binding FROM metadata WHERE id=1").fetchone()
        if binding is None or binding["binding"] != self.binding:
            raise ValueError("execution_collector_spool_binding")
        rows = connection.execute("SELECT * FROM records ORDER BY seq").fetchall()
        if len(rows) > MAX_RECORDS:
            raise ValueError("execution_collector_spool_capacity")
        size = 0
        for row in rows:
            raw = row["envelope"].encode()
            if len(raw) > MAX_RECORD_BYTES or _sha(raw) != row["envelope_sha256"]:
                raise ValueError("execution_collector_spool_corrupt")
            envelope = SignedExecutionEvidence.model_validate_json(raw)
            record = envelope.model_dump(mode="json", exclude=ENVELOPE_FIELDS)
            if (envelope.evidence_id != row["evidence_id"] or row["record_sha256"] != _sha(_canonical(record))
                    or _sha(canonical_execution_evidence(envelope)) != row["input_digest"]
                    or row["status"] not in STATUSES or type(row["attempts"]) is not int or row["attempts"] < 0
                    or datetime.fromisoformat(row["next_attempt"]).utcoffset() is None):
                raise ValueError("execution_collector_spool_corrupt")
            size += len(raw)
        if size > MAX_TOTAL_BYTES:
            raise ValueError("execution_collector_spool_capacity")
        return rows, size

    def enqueue_file(self, path):
        return self.enqueue(json.loads(read_private(path)))

    def enqueue(self, record):
        """The record comes from a trusted upstream observer, not application users."""
        now = self.clock()
        parsed = _unsigned(record, self.config, now, self.lifetime_seconds)
        normalized = parsed.model_dump(mode="json", exclude=ENVELOPE_FIELDS)
        record_hash = _sha(_canonical(normalized))
        with exclusive_collector(self.directory), self._connection() as connection:
            rows, size = self._validate(connection)
            existing = next((row for row in rows if row["evidence_id"] == parsed.evidence_id), None)
            if existing is not None:
                if existing["record_sha256"] != record_hash:
                    raise ValueError("execution_collector_identifier_conflict")
                return {"evidence_id": parsed.evidence_id, "duplicate": True,
                        "state": existing["status"], "input_digest": existing["input_digest"]}
            envelope = sign_record(record, self.key, self.config, self.verifier, now,
                                   lifetime_seconds=self.lifetime_seconds)
            raw = _canonical(envelope.model_dump(mode="json"))
            if len(rows) >= MAX_RECORDS or len(raw) > MAX_RECORD_BYTES or size + len(raw) > MAX_TOTAL_BYTES:
                raise ValueError("execution_collector_spool_capacity")
            input_digest = _sha(canonical_execution_evidence(envelope))
            connection.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?,?)", (
                len(rows) + 1, envelope.evidence_id, record_hash, raw.decode(), _sha(raw), input_digest,
                "pending", 0, now.isoformat(), None,
            ))
            return {"evidence_id": envelope.evidence_id, "duplicate": False,
                    "state": "pending", "input_digest": input_digest}

    def send_once(self):
        with exclusive_collector(self.directory):
            now = self.clock()
            with self._connection() as connection:
                rows, _ = self._validate(connection)
                pending = next((row for row in rows if row["status"] == "pending"
                                and datetime.fromisoformat(row["next_attempt"]) <= now), None)
                if pending is None:
                    return {"state": "idle"}
                envelope = json.loads(pending["envelope"])
            state, code = "pending", "TRANSPORT_OR_RECEIPT_INVALID"
            try:
                principal = Principal("execution-collector", self.config["tenant_id"],
                                      frozenset({Role.ANALYST}), "collector")
                self.verifier.verify_execution_evidence(
                    SignedExecutionEvidence.model_validate(envelope), principal, now,
                    enforce_freshness=False,
                )
                status, receipt = self.transport(self.base_url, envelope, tls_profile=self.tls_profile)
                if status in {200, 201}:
                    if (not isinstance(receipt, dict) or receipt.get("evidence_id") != pending["evidence_id"]
                            or receipt.get("input_digest") != pending["input_digest"]
                            or type(receipt.get("duplicate")) is not bool):
                        raise ValueError("execution_collector_receipt_binding")
                    state, code = "acknowledged", None
                elif status in {401, 403, 409, 422}:
                    state, code = "rejected", "HTTP_" + str(status)
                elif type(status) is int:
                    code = "HTTP_" + str(status)
            except (SignalRejected, SignalRegistryUnavailable):
                code = "AUTHORITY_UNAVAILABLE"
            except (OSError, HTTPException, ValueError, TypeError, KeyError):
                pass
            with self._connection() as connection:
                self._validate(connection)
                attempts = pending["attempts"] + 1
                due = now + timedelta(seconds=min(2 ** min(attempts, 6), 60))
                connection.execute("UPDATE records SET status=?,attempts=?,next_attempt=?,error_code=? WHERE evidence_id=?",
                                   (state, attempts, due.isoformat(), code, pending["evidence_id"]))
            return {"state": state, "evidence_id": pending["evidence_id"], "attempts": attempts,
                    "error_code": code}

    def status(self):
        with exclusive_collector(self.directory), self._connection() as connection:
            rows, size = self._validate(connection)
            return {"records": len(rows), "bytes": size,
                    **{name: sum(row["status"] == name for row in rows) for name in sorted(STATUSES)}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "enqueue", "send-once", "status"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--tls-profile", type=Path)
    parser.add_argument("--input", type=Path, help="Owner-only upstream JSON observation file")
    parser.add_argument("--tenant")
    parser.add_argument("--source")
    parser.add_argument("--key-id", default="key-1")
    parser.add_argument("--scopes", type=Path, help="Owner-only JSON array of exact behavior scopes")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            if not args.scopes or not args.tenant or not args.source:
                raise ValueError("execution_collector_init_arguments")
            result = initialize(args.directory, args.tenant, args.source, args.key_id,
                                json.loads(read_private(args.scopes)))
        else:
            collector = ExecutionCollector(args.directory, args.base_url, tls_profile=args.tls_profile)
            if args.command == "enqueue":
                if args.input is None:
                    raise ValueError("execution_collector_input_required")
                result = collector.enqueue_file(args.input)
            elif args.command == "send-once":
                result = collector.send_once()
            else:
                result = collector.status()
        print(json.dumps(result, ensure_ascii=False))
    except (OSError, sqlite3.Error, ValueError, TypeError, SignalRegistryUnavailable) as error:
        parser.exit(2, "Execution collector failed: " + type(error).__name__ + "\n")


if __name__ == "__main__":
    main()
