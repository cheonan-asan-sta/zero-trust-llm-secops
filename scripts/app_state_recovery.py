"""Local/test maintenance backup and quarantined recovery of the shared app DB.

The caller must stop all source writers and fence old workloads. Control keys
and the latest checkpoint live outside the untrusted backup and app data. This
is not an online backup scheduler or protection against a privileged operator
rolling back the entire control store. No application policy is modified.
"""

import argparse
import base64
import hashlib
import json
import math
import re
import secrets
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.config import get_settings
from app.security import Principal, Role
from app.services import policy_journal
from app.services.behavior_context_store import ContextStoreUnavailable
from app.services.signal_inbox import InboxUnavailable, SignalInbox
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations
from app.zero_trust_models import SessionRevocationRequest
from scripts import app_storage_contract as storage
from scripts import behavior_context_recovery as context_storage
from scripts import response_storage_contract as response_storage
from scripts.ca_recovery_state import atomic, canonical, locked, opened, sealed
from scripts.certificate_controller import LifecycleError

ROOT = Path(__file__).resolve().parents[1]
MAX_DATABASE = 32 * 1024**2
MAX_ENVELOPE = 64 * 1024**2
# Bound aggregate raw data before base64 and authenticated-envelope expansion.
MAX_BACKUP_COMPONENT_BYTES = 32 * 1024**2
IDENT = re.compile(r"[a-f0-9]{32}\Z")


class RecoveryError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise RecoveryError(code)


def local_only():
    require(get_settings().app_environment in {"local", "test"}, "local_test_only")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, limit=MAX_ENVELOPE):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular_file_required")
    require(path.stat().st_size <= limit, "artifact_size_limit")
    with path.open("rb") as stream:
        result = stream.read(limit + 1)
    require(len(result) <= limit, "artifact_size_limit")
    return result


def read_json(path):
    return json.loads(read_file(path))


def app_digest():
    paths = [p for p in (ROOT / "app").rglob("*") if p.is_file() and
             p.suffix in {".py", ".json", ".yaml", ".yml"} and "__pycache__" not in p.parts]
    return sha(canonical({p.relative_to(ROOT / "app").as_posix(): sha(p.read_bytes().replace(b"\r\n", b"\n"))
                          for p in sorted(paths)}))


def schema(connection):
    return connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()


def recovery_digest(full_state, response_state=False):
    # Pin every admission mode, including canonical context and optional legacy fixtures.
    paths = ("app_state_recovery.py", "app_storage_contract.py", "serve_recovered_app.py",
             "behavior_context_recovery.py", "response_storage_contract.py")
    return sha(canonical({"application": app_digest(), "full_state": full_state,
                          "response_state": response_state, "storage": {
        name: sha((ROOT / "scripts" / name).read_bytes().replace(b"\r\n", b"\n")) for name in paths}}))


def expected_schema(inbox):
    with tempfile.TemporaryDirectory(prefix="secops-schema-") as scratch:
        path = Path(scratch) / "expected.db"
        ZeroTrustOperations(path)
        if inbox:
            SignalInbox(path)
        with closing(sqlite3.connect(path)) as db:
            return schema(db)


def value(item):
    if isinstance(item, bytes):
        return {"blob": base64.b64encode(item).decode()}
    require(item is None or isinstance(item, (str, int, float)), "unsupported_sqlite_value")
    require(not isinstance(item, float) or math.isfinite(item), "unsupported_sqlite_value")
    return item


def operations(directory):
    registry = directory / "sources.json"
    verifier = SignalVerifier(registry) if registry.exists() else SignalVerifier()
    require(verifier.readiness()["ok"], "registry_unavailable")
    return ZeroTrustOperations(directory / "app.sqlite3", signal_verifier=verifier)


def guard_behavior_context(directory, *, configured_path=None):
    """Validate the stopped canonical source without creating or migrating it."""
    expected = Path(directory) / context_storage.NAME
    require(configured_path is None or Path(configured_path).resolve() == expected.resolve(),
            "behavior_context_path_mismatch")
    try:
        return context_storage.inspect(directory, allow_missing=True)
    except ContextStoreUnavailable:
        raise RecoveryError("behavior_context_unavailable") from None


def inspect_state(directory):
    """Validate a private copy; never initialize/migrate the original live DB."""
    directory = Path(directory)
    context = guard_behavior_context(directory)
    database = directory / "app.sqlite3"
    read_file(database, MAX_DATABASE)
    with closing(sqlite3.connect(database)) as db:
        require(db.execute("PRAGMA user_version").fetchone()[0] == 2, "unsupported_journal_format")
        require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "sqlite_integrity_failed")
        actual = schema(db)
        has_inbox = any(row[1] == "signal_inbox" for row in actual)
        require(actual == expected_schema(has_inbox), "unsupported_database_schema")
    service = operations(directory)
    with service._transaction() as transaction:
        latest = {}
        for entry in transaction[1]:
            if entry["kind"] == "decision":
                row = entry["session"]
                latest[(row["tenant_id"], row["session_id"])] = row
        head = {"sequence": transaction.metadata["last_seq"], "hash": transaction[2]}
        records = len(transaction[1])
    if has_inbox:
        require(SignalInbox(database).integrity()["ok"], "inbox_integrity_failed")
    tables = {}
    with closing(sqlite3.connect(database)) as db:
        for kind, name, _, _sql in actual:
            if kind != "table":
                continue
            quoted = '"' + name.replace('"', '""') + '"'
            digest = hashlib.sha256()
            for row in db.execute("SELECT * FROM " + quoted + " ORDER BY rowid"):
                digest.update(canonical([value(cell) for cell in row]) + b"\n")
            tables[name] = digest.hexdigest()
    registry = directory / "sources.json"
    state = {"schema_sha256": sha(canonical(actual)), "tables": tables, "head": head,
             "registry_sha256": sha(read_file(registry, 1024**2)) if registry.exists() else None,
             "application_sha256": recovery_digest(False), "policy_sha256": service.policy_digest,
             "behavior_context": context}
    jsonl = storage.inspect(directory)
    if jsonl is not None:
        state["jsonl"] = jsonl
        state["application_sha256"] = recovery_digest(True)
    response = response_storage.inspect(directory)
    if response is not None:
        require(jsonl is not None, "response_requires_full_storage")
        state["response"] = response
        state["application_sha256"] = recovery_digest(True, True)
    return {"state": state, "state_sha256": sha(canonical(state)), "records": records,
            "sessions": latest, "has_inbox": has_inbox}


def snapshot(source, target, *, timeout=15, registry_path=None):
    source, target = Path(source), Path(target)
    require(not target.exists(), "fresh_snapshot_required")
    context_path = getattr(get_settings(), "behavior_context_db_path", None)
    context_before = guard_behavior_context(source, configured_path=context_path)
    target.mkdir(parents=True)
    database = source / "app.sqlite3"
    read_file(database, MAX_DATABASE)
    registry = Path(registry_path) if registry_path is not None else source / "sources.json"
    before = read_file(registry, 1024**2) if registry_path is not None or registry.exists() else None
    logs = storage.capture(source)
    response_storage.snapshot(source, target)
    started = time.monotonic()

    def progress(_status, _remaining, _total):
        require(time.monotonic() - started <= timeout, "backup_deadline")

    uri = database.resolve().as_uri() + "?mode=ro"
    with (closing(sqlite3.connect(uri, uri=True, timeout=1)) as db,
          closing(sqlite3.connect(target / "app.sqlite3")) as destination):
        db.backup(destination, pages=256, progress=progress, sleep=.05)
    try:
        context_copy = context_storage.capture(source, target, timeout=timeout)
    except ContextStoreUnavailable:
        raise RecoveryError("behavior_context_unavailable") from None
    after = read_file(registry, 1024**2) if registry.exists() else None
    require(before == after, "registry_changed_during_snapshot")
    require(storage.capture(source) == logs, "storage_changed_during_snapshot")
    require(context_before == context_copy == guard_behavior_context(source, configured_path=context_path),
            "behavior_context_changed_during_snapshot")
    if before is not None:
        (target / "sources.json").write_bytes(before)
    for name, raw in logs.items():
        atomic(target / name, raw)
    return inspect_state(target)


def unseal(envelope, key, purpose):
    try:
        require(envelope["manifest"]["purpose"] == purpose, "artifact_purpose")
        return opened(envelope, key)
    except LifecycleError:
        raise RecoveryError("artifact_authentication_failed") from None


class Store:
    def __init__(self, directory, *, source=None, registry_path=None):
        local_only()
        self.root = Path(directory).resolve()
        require(not Path(directory).is_symlink(), "directory_symlink")
        for name in ("control", "public", "backups", "restores", "data"):
            path = self.root / name
            require(not path.is_symlink() and path.resolve().is_relative_to(self.root), "directory_scope")
        self.control, self.public = self.root / "control", self.root / "public"
        self.data = self.root / "data" if source is None else Path(source)
        self.registry_path = registry_path

    def initialize(self, *, full_state=False, response_state=False):
        local_only()
        guard_behavior_context(self.data, configured_path=getattr(get_settings(), "behavior_context_db_path", None))
        logs = storage.inspect(self.data)
        require(type(full_state) is bool and (logs is not None) == full_state,
                "explicit_full_storage_required")
        response = response_storage.inspect(self.data)
        require(type(response_state) is bool and (response is not None) == response_state
                and (not response_state or full_state), "explicit_response_storage_required")
        require(all(not path.exists() or (path.is_dir() and not any(path.iterdir()))
                    for path in (self.control, self.public)), "authority_already_initialized")
        self.control.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.public.mkdir(mode=0o700, exist_ok=True)
        for name in ("backups", "restores"):
            (self.root / name).mkdir(exist_ok=True, mode=0o700)
        for name in ("backup.key", "checkpoint.key"):
            atomic(self.control / name, secrets.token_bytes(32))
        signing = Ed25519PrivateKey.generate()
        atomic(self.control / "signing.key", signing.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        public = signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        source = secrets.token_hex(16)
        atomic(self.public / "trust.json", canonical({"source": source, "public_key": base64.b64encode(public).decode()}))
        atomic(self.control / "anchor.json", canonical({"source": source, "generation": 0,
            "checkpoint_sha256": None, "storage_mode": "full-jsonl" if full_state else "sqlite",
            "response_storage": response_state}))
        return {"initialized": True, "source": source}

    def checkpoint(self):
        """Caller must quiesce all writers before sealing the recovery witness."""
        local_only()
        with locked(self.control), tempfile.TemporaryDirectory(prefix="secops-checkpoint-") as temp:
            anchor = read_json(self.control / "anchor.json")
            # Persist invalidation before inspecting/copying the newer source.
            # If snapshot/seal/anchor publication fails, the old checkpoint must
            # not become usable again merely because its own files still match.
            generation = anchor["generation"] + 1
            atomic(self.public / "current.json", canonical({"source": anchor["source"],
                "generation": generation, "restore_id": None, "release_sha256": None}))
            state = snapshot(self.data, Path(temp) / "snapshot", registry_path=self.registry_path)
            mode = anchor.get("storage_mode", "sqlite")
            require(mode in {"sqlite", "full-jsonl"} and ("jsonl" in state["state"]) == (mode == "full-jsonl"),
                    "checkpoint_storage_mode")
            require(("response" in state["state"]) == anchor.get("response_storage", False),
                    "checkpoint_response_mode")
            manifest = {"purpose": "app-checkpoint-1", "source": anchor["source"],
                        "generation": generation, "created_at": datetime.now(UTC).isoformat()}
            envelope = sealed(state["state"], read_file(self.control / "checkpoint.key", 32), manifest)
            atomic(self.control / "checkpoint.json", canonical(envelope))
            atomic(self.control / "anchor.json", canonical({"source": anchor["source"],
                "generation": manifest["generation"], "checkpoint_sha256": sha(canonical(envelope)),
                "storage_mode": mode, "response_storage": anchor.get("response_storage", False)}))
            return {"checkpointed": True, "generation": manifest["generation"], "records": state["records"],
                    "context_records": state["state"]["behavior_context"]["records"]}

    def _checkpoint(self, max_age):
        require(type(max_age) is int and 1 <= max_age <= 3600, "checkpoint_age_limit")
        anchor = read_json(self.control / "anchor.json")
        current = read_json(self.public / "current.json")
        require(current["source"] == anchor["source"] and current["generation"] == anchor["generation"],
                "checkpoint_publication_incomplete")
        envelope = read_json(self.control / "checkpoint.json")
        require(anchor["checkpoint_sha256"] == sha(canonical(envelope)), "checkpoint_replay_or_tamper")
        state = unseal(envelope, read_file(self.control / "checkpoint.key", 32), "app-checkpoint-1")
        require("behavior_context" in state, "checkpoint_context_missing")
        mode = anchor.get("storage_mode", "sqlite")
        require(mode in {"sqlite", "full-jsonl"} and ("jsonl" in state) == (mode == "full-jsonl"),
                "checkpoint_storage_mode")
        require(("response" in state) == anchor.get("response_storage", False), "checkpoint_response_mode")
        m = envelope["manifest"]
        require(m["source"] == anchor["source"] and m["generation"] == anchor["generation"], "checkpoint_generation")
        age = (datetime.now(UTC) - datetime.fromisoformat(m["created_at"])).total_seconds()
        require(0 <= age <= max_age, "checkpoint_expired_or_future")
        require(state["application_sha256"] == recovery_digest("jsonl" in state, "response" in state),
                "application_version_mismatch")
        return anchor, state

    def backup(self, *, max_age=300):
        local_only()
        with locked(self.control), tempfile.TemporaryDirectory(prefix="secops-backup-") as temp:
            anchor, expected = self._checkpoint(max_age)
            path = Path(temp) / "snapshot"
            result = snapshot(self.data, path, registry_path=self.registry_path)
            require(result["state"] == expected, "source_advanced_since_checkpoint")
            components = [path / "app.sqlite3", path / context_storage.NAME]
            if (path / "sources.json").exists():
                components.append(path / "sources.json")
            if "jsonl" in expected:
                components.extend(path / name for name in ("storage.json", *storage.FILES.values()))
            if "response" in expected:
                components.append(path / response_storage.FILE)
            component_bytes = sum(item.stat().st_size for item in components)
            require(component_bytes <= MAX_BACKUP_COMPONENT_BYTES, "backup_components_size_limit")
            database = read_file(path / "app.sqlite3", MAX_DATABASE)
            context_database = read_file(path / context_storage.NAME, context_storage.MAX_DATABASE)
            registry = path / "sources.json"
            ident = secrets.token_hex(16)
            manifest = {"purpose": "app-backup-1", "source": anchor["source"], "generation": anchor["generation"],
                        "backup_id": ident, "state_sha256": result["state_sha256"], "database_sha256": sha(database),
                        "behavior_context_database_sha256": sha(context_database),
                        "created_at": datetime.now(UTC).isoformat()}
            payload = {"state": expected, "database": base64.b64encode(database).decode(),
                       "behavior_context_database": base64.b64encode(context_database).decode(),
                       "registry": base64.b64encode(read_file(registry, 1024**2)).decode() if registry.exists() else None}
            if "jsonl" in expected:
                payload["jsonl"] = {name: base64.b64encode(raw).decode()
                                    for name, raw in storage.capture(path).items()}
            if "response" in expected:
                payload["response_database"] = base64.b64encode(
                    read_file(path / response_storage.FILE, response_storage.MAX_BYTES)).decode()
            envelope = sealed(payload, read_file(self.control / "backup.key", 32), manifest)
            encoded = canonical(envelope)
            require(len(encoded) <= MAX_ENVELOPE, "backup_envelope_size_limit")
            atomic(self.root / "backups" / (ident + ".sealed"), encoded)
            return {"backed_up": True, "backup_id": ident, "records": result["records"],
                    "generation": anchor["generation"], "plaintext_bytes": len(database),
                    "context_bytes": len(context_database), "component_bytes": component_bytes,
                    "context_records": expected["behavior_context"]["records"],
                    "jsonl_bytes": sum(row["bytes"] for row in expected.get("jsonl", {}).get("files", {}).values())}

    def restore(self, backup_id, *, max_age=300, stage_root=None):
        local_only()
        require(isinstance(backup_id, str) and IDENT.fullmatch(backup_id), "backup_id")
        with locked(self.control):
            anchor, expected = self._checkpoint(max_age)
            envelope = read_json(self.root / "backups" / (backup_id + ".sealed"))
            payload = unseal(envelope, read_file(self.control / "backup.key", 32), "app-backup-1")
            manifest = envelope["manifest"]
            require(manifest["source"] == anchor["source"] and manifest["generation"] == anchor["generation"]
                    and manifest["backup_id"] == backup_id, "backup_stale_or_foreign")
            require(payload["state"] == expected and sha(canonical(expected)) == manifest["state_sha256"],
                    "backup_checkpoint_mismatch")
            require(("jsonl" in payload) == ("jsonl" in expected), "backup_storage_mode")
            require(("response_database" in payload) == ("response" in expected), "backup_response_mode")
            raw = base64.b64decode(payload["database"], validate=True)
            require(len(raw) <= MAX_DATABASE and sha(raw) == manifest["database_sha256"], "database_digest")
            require("behavior_context_database" in payload and "behavior_context_database_sha256" in manifest,
                    "backup_context_missing")
            context_raw = base64.b64decode(payload["behavior_context_database"], validate=True)
            require(len(context_raw) <= context_storage.MAX_DATABASE
                    and sha(context_raw) == manifest["behavior_context_database_sha256"], "behavior_context_digest")
            component_bytes = len(raw) + len(context_raw)
            # Invalidate the previous restore before doing any fallible staging.
            # A partial retry must never re-admit an older published copy.
            atomic(self.public / "current.json", canonical({"source": anchor["source"],
                "generation": anchor["generation"], "restore_id": None, "release_sha256": None}))
            ident = secrets.token_hex(16)
            root = self.root / "restores" if stage_root is None else Path(stage_root)
            require(root.is_dir() and not root.is_symlink(), "restore_stage_scope")
            stage = root / ident
            stage.mkdir(mode=0o700)
            atomic(stage / "app.sqlite3", raw)
            atomic(stage / context_storage.NAME, context_raw)
            if payload["registry"] is not None:
                registry = base64.b64decode(payload["registry"], validate=True)
                require(len(registry) <= 1024**2, "registry_size")
                component_bytes += len(registry)
                atomic(stage / "sources.json", registry)
            if "jsonl" in expected:
                require(isinstance(payload["jsonl"], dict) and set(payload["jsonl"]) ==
                        {"storage.json", *storage.FILES.values()}, "backup_storage_files")
                for name, encoded in payload["jsonl"].items():
                    raw = base64.b64decode(encoded, validate=True)
                    require(len(raw) <= (4096 if name == "storage.json" else storage.MAX_LOG),
                            "backup_storage_size")
                    component_bytes += len(raw)
                    atomic(stage / name, raw)
            if "response" in expected:
                response_raw = base64.b64decode(payload["response_database"], validate=True)
                require(len(response_raw) <= response_storage.MAX_BYTES, "response_database_size")
                component_bytes += len(response_raw)
                atomic(stage / response_storage.FILE, response_raw)
            require(component_bytes <= MAX_BACKUP_COMPONENT_BYTES, "backup_components_size_limit")
            restored = inspect_state(stage)
            require(restored["state"] == expected, "restored_state_mismatch")
            service = operations(stage)
            fenced = []
            for (tenant, session_id), session in sorted(restored["sessions"].items()):
                principal = Principal("infra-recovery", tenant, frozenset({Role.ADMIN}), "offline_maintenance")
                result = service.revoke(session_id, SessionRevocationRequest(
                    expected_version=session["version"], note="Infrastructure restore: invalidate pre-restore sessions"), principal)
                require(result.status == "REVOKED", "session_fence_failed")
                fenced.append({"tenant": tenant, "session": session_id, "version": result.version})
            after = inspect_state(stage)
            for table, digest in expected["tables"].items():
                if table.startswith("signal_inbox"):
                    require(after["state"]["tables"][table] == digest, "inbox_changed_during_fence")
            require(after["state"]["registry_sha256"] == expected["registry_sha256"], "registry_changed_during_fence")
            require(after["state"].get("jsonl") == expected.get("jsonl"), "storage_changed_during_fence")
            require(after["state"]["behavior_context"] == expected["behavior_context"],
                    "behavior_context_changed_during_fence")
            response_fenced = 0
            if "response" in expected:
                response_fenced = response_storage.fence(stage)
                after = inspect_state(stage)
            release = {"purpose": "app-admission-1", "source": anchor["source"], "generation": anchor["generation"],
                       "restore_id": ident, "application_sha256": after["state"]["application_sha256"],
                       "policy_sha256": after["state"]["policy_sha256"],
                       "registry_sha256": after["state"]["registry_sha256"], "head": after["state"]["head"],
                       "behavior_context": after["state"]["behavior_context"],
                       "fenced_sessions": fenced}
            if "jsonl" in after["state"]:
                release["jsonl"] = after["state"]["jsonl"]
            if "response" in after["state"]:
                release["response"] = after["state"]["response"]
            key = Ed25519PrivateKey.from_private_bytes(read_file(self.control / "signing.key", 32))
            signed = {"release": release, "signature": base64.b64encode(key.sign(canonical(release))).decode()}
            atomic(stage / "release.json", canonical(signed))
            atomic(self.public / "current.json", canonical({"source": anchor["source"],
                "generation": anchor["generation"], "restore_id": ident, "release_sha256": sha(canonical(signed))}))
            # No workload is started here. The orchestrator must verify this
            # admission pin and keep all old writers stopped before startup.
            verify_admission(stage, self.public)
            return {"restored": True, "restore_id": ident, "fenced_sessions": len(fenced),
                    "source_records": restored["records"], "restored_records": after["records"],
                    "context_records": after["state"]["behavior_context"]["records"],
                    "context_preserved": True,
                    "inbox_preserved": True, "generation": anchor["generation"],
                    "response_plans_fenced": response_fenced}


def verify_admission(directory, trust_directory):
    local_only()
    directory, trust_directory = Path(directory), Path(trust_directory)
    trust = read_json(trust_directory / "trust.json")
    current = read_json(trust_directory / "current.json")
    signed = read_json(directory / "release.json")
    require(sha(canonical(signed)) == current["release_sha256"], "admission_pin_mismatch")
    release = signed["release"]
    require(release["purpose"] == "app-admission-1" and release["source"] == current["source"] == trust["source"]
            and release["generation"] == current["generation"] and release["restore_id"] == current["restore_id"],
            "admission_identity")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(trust["public_key"], validate=True)).verify(
            base64.b64decode(signed["signature"], validate=True), canonical(release))
    except (ValueError, InvalidSignature):
        raise RecoveryError("admission_signature") from None
    state = inspect_state(directory)
    require("behavior_context" in release, "admission_context_missing")
    try:
        context_storage.verify_prefix(directory, release["behavior_context"])
    except ContextStoreUnavailable:
        raise RecoveryError("admission_context_changed") from None
    require(("jsonl" in release) == ("jsonl" in state["state"]), "admission_storage_mode")
    if "jsonl" in release:
        storage.verify_prefix(directory, release["jsonl"])
    require(("response" in release) == ("response" in state["state"]), "admission_response_mode")
    if "response" in release:
        response_storage.verify_baseline(directory, release["response"])
    require(state["state"]["application_sha256"] == release["application_sha256"] and
            state["state"]["policy_sha256"] == release["policy_sha256"] and
            state["state"]["registry_sha256"] == release["registry_sha256"], "admission_configuration_changed")
    service = operations(directory)
    with service._transaction() as transaction:
        sequence = release["head"]["sequence"]
        require(type(sequence) is int and 0 <= sequence <= len(transaction[1]), "admission_prefix_missing")
        previous = "0" * 64
        for entry in transaction[1][:sequence]:
            previous = sha((previous + "." + policy_journal._canonical(entry)).encode())
        require(previous == release["head"]["hash"], "admission_prefix_changed")
    for item in release["fenced_sessions"]:
        session = state["sessions"].get((item["tenant"], item["session"]))
        require(session is not None and session["status"] == "REVOKED" and session["version"] >= item["version"],
                "restored_session_revived")
    return {"admission_verified": True, "fenced_sessions": len(release["fenced_sessions"]),
            "context_records": state["state"]["behavior_context"]["records"],
            "generation": release["generation"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["init", "checkpoint", "backup", "restore", "verify"])
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--backup-id")
    parser.add_argument("--restore-id")
    parser.add_argument("--max-age", type=int, default=300)
    parser.add_argument("--full-state", action="store_true", help="Pin full JSONL storage at initialization")
    parser.add_argument("--response-state", action="store_true", help="Also pin the legacy offline response fixture ledger")
    args = parser.parse_args(argv)
    try:
        local_only()
        path = args.directory.resolve()
        allowed = path.is_relative_to((ROOT / "runtime/week3").resolve())
        allowed |= sys.platform == "linux" and Path("/.dockerenv").exists() and path.is_relative_to(Path("/lab"))
        require(allowed, "local_lab_directory_required")
        store = Store(args.directory)
        require(not args.full_state or args.operation == "init", "full_state_init_only")
        require(not args.response_state or args.operation == "init", "response_state_init_only")
        if args.operation == "init":
            result = store.initialize(full_state=args.full_state, response_state=args.response_state)
        elif args.operation == "checkpoint":
            result = store.checkpoint()
        elif args.operation == "backup":
            result = store.backup(max_age=args.max_age)
        elif args.operation == "restore":
            result = store.restore(args.backup_id, max_age=args.max_age)
        else:
            require(isinstance(args.restore_id, str) and IDENT.fullmatch(args.restore_id), "restore_id")
            result = verify_admission(store.root / "restores" / args.restore_id, store.public)
        print(json.dumps(result), flush=True)
        return 0
    except (RecoveryError, LifecycleError, JournalUnavailable, InboxUnavailable, OSError,
            ValueError, TypeError, LookupError, sqlite3.Error):
        print(json.dumps({"recovery": "denied", "error": "RECOVERY_PRECONDITION_FAILED"}), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
