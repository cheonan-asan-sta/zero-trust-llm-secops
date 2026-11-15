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
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.behavior_context_models import BehaviorScope, SignedBehaviorCapture
from app.behavior_execution_models import SignedExecutionEvidence
from app.config import get_settings
from app.security import Principal, Role
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    SignalVerifier,
    canonical_behavior_capture,
    canonical_execution_evidence,
)
from scripts import execution_archive as archive
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


class ContextDeliveryStatus(Exception):
    def __init__(self, status):
        self.status = status if type(status) is int else 0


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


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _owned(metadata, *, directory=False):
    valid_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not valid_type or (os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    )):
        raise ValueError("execution_collector_requires_owner_only_files")


def read_private(path, maximum=MAX_RECORD_BYTES, *, durable=False):
    """Reject symlinks and non-regular input; check permissions on the opened object."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        _owned(metadata)
        if metadata.st_size > maximum:
            raise ValueError("execution_collector_file_too_large")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("execution_collector_file_too_large")
        if durable:
            os.fsync(stream.fileno())
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


def post_context(base_url, endpoint, payload, *, tls_profile=None):
    if endpoint not in {ENDPOINT, "/detections/context/captures", "/detections/context/evaluate"}:
        raise ValueError("execution_collector_endpoint")
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
        status, body = request(tls_profile, endpoint, wire, headers)
    else:
        request = Request(base_url + endpoint, data=wire, method="POST", headers=headers)
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


def post_evidence(base_url, payload, *, tls_profile=None):
    return post_context(base_url, ENDPOINT, payload, tls_profile=tls_profile)


class ExecutionCollector:
    """Bounded persistent envelope queue; replays never reseal or replace evidence."""

    def __init__(self, directory, base_url, *, tls_profile=None, transport=None, clock=None,
                 lifetime_seconds=90, context_transport=None):
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
        self.context_transport = context_transport or post_context
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
                connection.execute("CREATE TABLE IF NOT EXISTS input_files("
                                   "name TEXT PRIMARY KEY,digest TEXT NOT NULL,evidence_id TEXT NOT NULL)")
                connection.execute("CREATE TABLE IF NOT EXISTS bundles("
                                   "evidence_id TEXT PRIMARY KEY,capture TEXT NOT NULL,"
                                   "capture_sha256 TEXT NOT NULL,state TEXT NOT NULL,result TEXT)")
                connection.execute("CREATE TABLE IF NOT EXISTS evaluations("
                                   "evidence_id TEXT PRIMARY KEY,attempts INTEGER NOT NULL,"
                                   "next_attempt TEXT NOT NULL,status TEXT NOT NULL,result TEXT)")
                archive.initialize(connection)
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
        archived = archive.load(connection)
        active_ids = {row["evidence_id"] for row in rows}
        if active_ids & set(archived) or len(rows) + len(archived) > archive.MAX_RECORDS:
            raise ValueError("execution_collector_history_capacity_or_overlap")
        logical_rows = rows + [item["record"] for item in archived.values()]
        sequences = [row["seq"] for row in logical_rows]
        if len(set(sequences)) != len(sequences) or any(type(n) is not int or n < 1 for n in sequences):
            raise ValueError("execution_collector_sequence_corrupt")
        size = 0
        records = {row["evidence_id"]: row for row in logical_rows}
        for row in logical_rows:
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
            if row["evidence_id"] in active_ids:
                size += len(raw)
        bundles = {row["evidence_id"]: row for row in connection.execute("SELECT * FROM bundles")}
        if not set(bundles) <= active_ids:
            raise ValueError("execution_collector_orphan_active_bundle")
        bundles.update({key: item["bundle"] for key, item in archived.items() if item["bundle"] is not None})
        for row in bundles.values():
            raw = row["capture"].encode()
            if (row["evidence_id"] not in records
                    or len(raw) > MAX_RECORD_BYTES or _sha(raw) != row["capture_sha256"]
                    or row["state"] not in {"capture_pending", "captured"}):
                raise ValueError("execution_collector_bundle_corrupt")
            SignedBehaviorCapture.model_validate_json(raw)
            if row["evidence_id"] in active_ids:
                size += len(raw)
        marks = connection.execute("SELECT * FROM input_files").fetchall()
        if len(marks) > archive.MAX_RECORDS:
            raise ValueError("execution_collector_input_capacity")
        for mark in marks:
            if (Path(mark["name"]).name != mark["name"] or not mark["name"].endswith(".json")
                    or re.fullmatch(r"[a-f0-9]{64}", mark["digest"]) is None
                    or mark["evidence_id"] not in records):
                raise ValueError("execution_collector_input_corrupt")
        evaluations = connection.execute("SELECT * FROM evaluations").fetchall()
        if any(row["evidence_id"] not in active_ids for row in evaluations):
            raise ValueError("execution_collector_orphan_active_evaluation")
        evaluations += [item["evaluation"] for item in archived.values() if item["evaluation"] is not None]
        if {row["evidence_id"] for row in evaluations} != set(bundles):
            raise ValueError("execution_collector_evaluation_corrupt")
        for row in evaluations:
            if (row["status"] not in STATUSES or type(row["attempts"]) is not int or row["attempts"] < 0
                    or datetime.fromisoformat(row["next_attempt"]).utcoffset() is None):
                raise ValueError("execution_collector_evaluation_corrupt")
            if row["status"] == "acknowledged":
                receipt = json.loads(row["result"])
                capture = json.loads(bundles[row["evidence_id"]]["capture"])
                if (records[row["evidence_id"]]["status"] != "acknowledged"
                        or bundles[row["evidence_id"]]["state"] != "captured"
                        or receipt.get("capture_id") != capture["capture_id"]
                        or receipt.get("enforcement_eligible") is not False):
                    raise ValueError("execution_collector_evaluation_corrupt")
            if row["result"] is not None and row["evidence_id"] in active_ids:
                size += len(row["result"].encode())
        if size > MAX_TOTAL_BYTES:
            raise ValueError("execution_collector_spool_capacity")
        return rows, size

    def enqueue_file(self, path):
        return self.enqueue(json.loads(read_private(path)))

    def enqueue(self, record, *, input_file=None, capture=None):
        """The record comes from a trusted upstream observer, not application users."""
        now = self.clock()
        with exclusive_collector(self.directory), self._connection() as connection:
            rows, size = self._validate(connection)
            archived = archive.load(connection)
            identifier = record.get("evidence_id") if isinstance(record, dict) else None
            existing = next((row for row in rows if row["evidence_id"] == identifier), None)
            archived_item = archived.get(identifier)
            if archived_item is not None:
                existing = archived_item["record"]
            if existing is None and (len(rows) >= MAX_RECORDS or size >= MAX_TOTAL_BYTES // 2):
                archive.compact(connection, min(MAX_RECORDS, 1000))
                rows, size = self._validate(connection)
                archived = archive.load(connection)
            # An exact replay remains identifiable after the original observation expires.
            # Only a new record is signed at the current time.
            validation_time = (SignedExecutionEvidence.model_validate_json(existing["envelope"]).issued_at
                               if existing is not None else now)
            parsed = _unsigned(record, self.config, validation_time, self.lifetime_seconds)
            normalized = parsed.model_dump(mode="json", exclude=ENVELOPE_FIELDS)
            record_hash = _sha(_canonical(normalized))
            if capture is not None:
                capture = SignedBehaviorCapture.model_validate(capture)
                if (capture.tenant_id != self.config["tenant_id"]
                        or capture.capture_id != parsed.capture_id
                        or _sha(canonical_behavior_capture(capture)) != parsed.capture_input_sha256
                        or capture.scope != parsed.scope
                        or capture.session_id != parsed.session_id
                        or capture.session_version != parsed.session_version
                        or capture.session_input_sha256 != parsed.session_input_sha256
                        or set(capture.connection_ids) != set(parsed.connection_ids)
                        or {event.id for event in capture.activity.events} != set(parsed.event_ids)):
                    raise ValueError("execution_collector_capture_binding")
                capture_raw = _canonical(capture.model_dump(mode="json"))
                if len(capture_raw) > MAX_RECORD_BYTES:
                    raise ValueError("execution_collector_file_too_large")
                previous = connection.execute("SELECT capture_sha256 FROM bundles WHERE evidence_id=?",
                                              (parsed.evidence_id,)).fetchone()
                if archived_item is not None:
                    previous = archived_item["bundle"]
                if previous is not None and previous["capture_sha256"] != _sha(capture_raw):
                    raise ValueError("execution_collector_capture_conflict")
                if existing is not None and previous is None:
                    raise ValueError("execution_collector_bundle_changed")
                if previous is None and size + len(capture_raw) > MAX_TOTAL_BYTES:
                    raise ValueError("execution_collector_spool_capacity")
                if archived_item is None:
                    connection.execute("INSERT OR IGNORE INTO bundles VALUES(?,?,?,?,NULL)",
                                   (parsed.evidence_id, capture_raw.decode(), _sha(capture_raw), "capture_pending"))
                if archived_item is None:
                    connection.execute("INSERT OR IGNORE INTO evaluations VALUES(?,?,?,'pending',NULL)",
                                   (parsed.evidence_id, 0, now.isoformat()))
                if previous is None:
                    size += len(capture_raw)
            if input_file is not None:
                name, digest = input_file
                mark = connection.execute("SELECT digest FROM input_files WHERE name=?", (name,)).fetchone()
                if mark is not None and mark["digest"] != digest:
                    raise ValueError("execution_collector_input_replaced")
                count = connection.execute("SELECT COUNT(*) FROM input_files").fetchone()[0]
                if mark is None and count >= archive.MAX_RECORDS:
                    raise ValueError("execution_collector_input_capacity")
                connection.execute("INSERT OR IGNORE INTO input_files VALUES(?,?,?)",
                                   (name, digest, parsed.evidence_id))
            if existing is not None:
                if existing["record_sha256"] != record_hash:
                    raise ValueError("execution_collector_identifier_conflict")
                return {"evidence_id": parsed.evidence_id, "duplicate": True,
                        "state": existing["status"], "input_digest": existing["input_digest"]}
            if len(rows) + len(archived) >= archive.MAX_RECORDS:
                raise ValueError("execution_collector_history_capacity")
            envelope = sign_record(record, self.key, self.config, self.verifier, now,
                                   lifetime_seconds=self.lifetime_seconds)
            raw = _canonical(envelope.model_dump(mode="json"))
            if len(rows) >= MAX_RECORDS or len(raw) > MAX_RECORD_BYTES or size + len(raw) > MAX_TOTAL_BYTES:
                raise ValueError("execution_collector_spool_capacity")
            input_digest = _sha(canonical_execution_evidence(envelope))
            connection.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?,?)", (
                max([row["seq"] for row in rows] + [item["record"]["seq"] for item in archived.values()] + [0]) + 1, envelope.evidence_id, record_hash, raw.decode(), _sha(raw), input_digest,
                "pending", 0, now.isoformat(), None,
            ))
            return {"evidence_id": envelope.evidence_id, "duplicate": False,
                    "state": "pending", "input_digest": input_digest}

    def capture_one(self, directory):
        """Ingest immutable owner-only JSON files; marking and enqueue commit together.

        Producers publish complete files with an atomic rename in this directory.
        Rotation is a new filename, never a replacement. No file is removed here.
        """
        directory = Path(directory)
        _owned(directory.lstat(), directory=True)
        with os.scandir(directory) as entries:
            names = []
            for entry in entries:
                if entry.name.endswith(".json"):
                    names.append(entry.name)
                    if len(names) > MAX_RECORDS:
                        raise ValueError("execution_collector_input_capacity")
        with exclusive_collector(self.directory), self._connection() as connection:
            marks = {row["name"]: row["digest"] for row in connection.execute("SELECT name,digest FROM input_files")}
        invalid = 0
        for name in sorted(names):
            try:
                raw = read_private(directory / name)
            except (OSError, ValueError):
                invalid += 1
                continue
            digest = _sha(raw)
            if name in marks:
                if marks[name] != digest:
                    raise ValueError("execution_collector_input_replaced")
                continue
            try:
                record = json.loads(raw)
                capture = None
                if isinstance(record, dict) and set(record) == {"capture", "execution"}:
                    capture, record = record["capture"], record["execution"]
                result = self.enqueue(record, input_file=(name, digest), capture=capture)
                return result | {"invalid_files_skipped": invalid}
            except (ValueError, TypeError, RecursionError, SignalRejected, SignalRegistryUnavailable):
                # Preserve the bad file for diagnosis; it cannot starve a later
                # independently valid observation or become an accepted input mark.
                invalid += 1
        if invalid:
            return {"state": "input_error", "error_code": "INPUT_UNAVAILABLE_OR_INVALID",
                    "invalid_files": invalid}
        return {"state": "idle"}

    def tick(self, directory):
        """A broken upstream input must not stop already durable delivery."""
        retention = {"state": "idle"}
        try:
            retention = self.maintain(directory)
        except (OSError, ValueError, TypeError, sqlite3.Error):
            retention = {"state": "maintenance_error"}
        try:
            captured = self.capture_one(directory)
        except (OSError, ValueError, TypeError, SignalRejected, SignalRegistryUnavailable):
            captured = {"state": "input_error", "error_code": "INPUT_UNAVAILABLE_OR_INVALID"}
        return {"input": captured, "delivery": self.send_once(), "evaluation": self.evaluate_once(),
                "retention": retention}

    def evaluate_once(self):
        """Persist advisory results only after both receiver receipts are verified."""
        with exclusive_collector(self.directory):
            now = self.clock()
            with self._connection() as connection:
                self._validate(connection)
                candidates = connection.execute(
                    "SELECT e.*,b.capture FROM evaluations e JOIN records r USING(evidence_id) "
                    "JOIN bundles b USING(evidence_id) WHERE e.status='pending' AND r.status='acknowledged' "
                    "AND b.state='captured' ORDER BY r.seq",
                ).fetchall()
                pending = next((row for row in candidates
                                if datetime.fromisoformat(row['next_attempt']) <= now), None)
            if pending is None:
                return {"state": "idle"}
            capture_id = json.loads(pending["capture"])["capture_id"]
            state, result = "pending", None
            try:
                status, receipt = self.context_transport(
                    self.base_url, "/detections/context/evaluate", {"capture_id": capture_id},
                    tls_profile=self.tls_profile,
                )
                if status == 200:
                    if (not isinstance(receipt, dict) or receipt.get("capture_id") != capture_id
                            or receipt.get("verdict") not in {"normal", "threat", "unknown"}
                            or receipt.get("enforcement_eligible") is not False
                            or type(receipt.get("duplicate")) is not bool
                            or len(_canonical(receipt)) > 65_536):
                        raise ValueError("execution_collector_evaluation_receipt")
                    state, result = "acknowledged", _canonical(receipt).decode()
                elif status in {401, 403, 409, 422}:
                    state = "rejected"
            except (OSError, HTTPException, ValueError, TypeError, KeyError):
                pass
            with self._connection() as connection:
                _, size = self._validate(connection)
                if result is not None and size + len(result.encode()) > MAX_TOTAL_BYTES:
                    state, result = "pending", None
                attempts = pending["attempts"] + 1
                due = now + timedelta(seconds=min(2 ** min(attempts, 6), 60))
                connection.execute("UPDATE evaluations SET status=?,result=?,attempts=?,next_attempt=? WHERE evidence_id=?",
                                   (state, result, attempts, due.isoformat(), pending["evidence_id"]))
            return {"state": state, "evidence_id": pending["evidence_id"], "attempts": attempts}

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
                bundle = connection.execute("SELECT * FROM bundles WHERE evidence_id=?",
                                            (pending["evidence_id"],)).fetchone()
            state, code = "pending", "TRANSPORT_OR_RECEIPT_INVALID"
            try:
                principal = Principal("execution-collector", self.config["tenant_id"],
                                      frozenset({Role.ANALYST}), "collector")
                self.verifier.verify_execution_evidence(
                    SignedExecutionEvidence.model_validate(envelope), principal, now,
                    enforce_freshness=False,
                )
                if bundle is not None and bundle["state"] == "capture_pending":
                    raw = bundle["capture"].encode()
                    if _sha(raw) != bundle["capture_sha256"]:
                        raise ValueError("execution_collector_capture_corrupt")
                    capture = SignedBehaviorCapture.model_validate_json(raw)
                    status, receipt = self.context_transport(
                        self.base_url, "/detections/context/captures", json.loads(raw), tls_profile=self.tls_profile,
                    )
                    if status in {200, 201}:
                        if (not isinstance(receipt, dict) or receipt.get("capture_id") != capture.capture_id
                                or receipt.get("input_digest") != _sha(canonical_behavior_capture(capture))
                                or type(receipt.get("duplicate")) is not bool):
                            raise ValueError("execution_collector_capture_receipt")
                        with self._connection() as connection:
                            connection.execute("UPDATE bundles SET state='captured' WHERE evidence_id=?",
                                               (pending["evidence_id"],))
                    else:
                        raise ContextDeliveryStatus(status)
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
            except ContextDeliveryStatus as error:
                if error.status in {401, 403, 409, 422}:
                    state = "rejected"
                code = "CAPTURE_HTTP_" + str(error.status)
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

    def compact(self, *, limit=1000):
        if type(limit) is not int or not 1 <= limit <= MAX_RECORDS:
            raise ValueError("execution_collector_archive_batch")
        with exclusive_collector(self.directory), self._connection() as connection:
            self._validate(connection)
            moved = archive.compact(connection, limit)
            self._validate(connection)
        return {"compacted": moved}

    def retire_inputs(self, directory, *, limit=1000):
        """Move only archived, unchanged feed files; their durable marks remain forever.

        A hard link is published without overwrite before unlinking the input. Both
        directories are synced. A crash between the two leaves two identical copies
        and the next attempt finishes; no cross-filesystem copy or data loss.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("execution_collector_retirement_batch")
        directory = Path(directory)
        _owned(directory.lstat(), directory=True)
        retired = directory / ".retired"
        retired_bytes = 0
        if retired.exists() or retired.is_symlink():
            _owned(retired.lstat(), directory=True)
            with os.scandir(retired) as files:
                for entry in files:
                    metadata = entry.stat(follow_symlinks=False)
                    _owned(metadata)
                    retired_bytes += metadata.st_size
                    if retired_bytes > archive.MAX_BYTES:
                        raise ValueError("execution_collector_retired_input_capacity")
        with exclusive_collector(self.directory), self._connection() as connection:
            self._validate(connection)
            marks = connection.execute(
                "SELECT f.* FROM input_files f JOIN execution_archive a USING(evidence_id) ORDER BY f.name",
            ).fetchall()
            moved = 0
            for mark in marks:
                source = directory / mark["name"]
                if not source.exists() and not source.is_symlink():
                    continue
                if _sha(read_private(source)) != mark["digest"]:
                    raise ValueError("execution_collector_input_replaced")
                retired.mkdir(mode=0o700, exist_ok=True)
                _owned(retired.lstat(), directory=True)
                target = retired / mark["name"]
                source_size = source.lstat().st_size
                if not target.exists() and retired_bytes + source_size > archive.MAX_BYTES:
                    raise ValueError("execution_collector_retired_input_capacity")
                try:
                    os.link(source, target, follow_symlinks=False)
                    retired_bytes += source_size
                except FileExistsError:
                    pass
                if _sha(read_private(target, durable=True)) != mark["digest"]:
                    raise ValueError("execution_collector_retired_input_conflict")
                _sync_directory(retired)
                if _sha(read_private(source)) != mark["digest"]:
                    raise ValueError("execution_collector_input_replaced")
                source.unlink()
                _sync_directory(directory)
                moved += 1
                if moved >= limit:
                    break
        return moved

    def maintain(self, directory):
        with exclusive_collector(self.directory), self._connection() as connection:
            rows, size = self._validate(connection)
            moved = 0
            if len(rows) >= min(1000, MAX_RECORDS) or size >= MAX_TOTAL_BYTES // 2:
                moved = archive.compact(connection, min(1000, MAX_RECORDS))
        retired = self.retire_inputs(directory)
        return {"state": "maintained" if moved or retired else "idle", "compacted": moved,
                "retired_inputs": retired}

    def status(self):
        with exclusive_collector(self.directory), self._connection() as connection:
            rows, size = self._validate(connection)
            archived = archive.load(connection)
            history = list(rows) + [item["record"] for item in archived.values()]
            return {"records": len(history), "active_records": len(rows), "archived_records": len(archived), "bytes": size,
                    **{name: sum(row["status"] == name for row in history) for name in sorted(STATUSES)},
                    "evaluations": {name: connection.execute(
                        "SELECT COUNT(*) FROM evaluations WHERE status=?", (name,),
                    ).fetchone()[0] + sum(item["evaluation"] is not None and item["evaluation"]["status"] == name
                                             for item in archived.values()) for name in sorted(STATUSES)}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "enqueue", "send-once", "status", "compact", "run"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--tls-profile", type=Path)
    parser.add_argument("--input", type=Path, help="Owner-only upstream JSON observation file")
    parser.add_argument("--input-directory", type=Path, help="Immutable owner-only JSON observation feed")
    parser.add_argument("--poll-seconds", type=float, default=1)
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
            elif args.command == "compact":
                result = collector.compact()
                if args.input_directory is not None:
                    result["retired_inputs"] = collector.retire_inputs(args.input_directory)
            elif args.command == "run":
                if args.input_directory is None or not 0.05 <= args.poll_seconds <= 60:
                    raise ValueError("execution_collector_run_arguments")
                previous = None
                while True:
                    current = json.dumps(collector.tick(args.input_directory), ensure_ascii=False)
                    if current != previous:
                        print(current, flush=True)
                        previous = current
                    time.sleep(args.poll_seconds)
            else:
                result = collector.status()
        print(json.dumps(result, ensure_ascii=False))
    except (OSError, sqlite3.Error, ValueError, TypeError, SignalRegistryUnavailable) as error:
        parser.exit(2, "Execution collector failed: " + type(error).__name__ + "\n")


if __name__ == "__main__":
    main()
