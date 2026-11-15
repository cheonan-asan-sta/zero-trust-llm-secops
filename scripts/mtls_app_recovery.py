"""Container side of the stopped-writer mTLS application cutover."""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from scripts import app_state_recovery as recovery
from scripts import behavior_context_recovery as context
from scripts.ca_recovery_state import atomic, canonical
from scripts.continuous_mtls_assets import service
from scripts.serve_recovered_app import admit

PUBLIC = Path("/admission")
REGISTRY = Path("/signals/sources.json")
WRITERS = ("collector", "app", "worker", "watchdog")
OFFLINE_WRITERS = {
    "worker": ("scripts.signal_worker", "--poll-seconds", "0.2"),
    "watchdog": ("scripts.session_watchdog", "--interval-seconds", "0.2"),
}


def phase(public=PUBLIC):
    value = json.loads(recovery.read_file(public / "phase.json", 4096))
    if value in ({"phase": "original"}, {"phase": "maintenance"}):
        return value
    recovery.require(isinstance(value, dict) and set(value) == {"phase", "restore_id"}
                     and value["phase"] == "approved" and isinstance(value["restore_id"], str)
                     and recovery.IDENT.fullmatch(value["restore_id"]), "mtls_recovery_phase")
    current = json.loads(recovery.read_file(public / "current.json", 4096))
    recovery.require(isinstance(current, dict) and current.get("restore_id") == value["restore_id"],
                     "mtls_recovery_pin")
    return value


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fence(public=PUBLIC):
    recovery.require(phase(public) == {"phase": "original"}, "mtls_recovery_already_fenced")
    result = {"phase": "maintenance"}
    atomic(public / "phase.json", canonical(result))
    return result


def _store(authority, source, registry):
    directory = authority / "store"
    if not directory.exists():
        with tempfile.TemporaryDirectory(dir=authority, prefix="prepare-") as temp:
            prepared = Path(temp) / "store"
            recovery.Store(prepared, source=source, registry_path=registry).initialize(full_state=True)
            prepared.replace(directory)
            sync_directory(authority)
    return recovery.Store(directory, source=source, registry_path=registry)


def frozen_source(source, frozen):
    """Copy the stopped writer boundary without dropping the context journal."""
    # Context SQLite uses rollback journaling. Its clean, closed source is read
    # without opening a writable connection or silently ignoring a crash journal.
    context.capture(source, frozen)
    # The policy SQLite database uses WAL and may need a writable scratch index.
    for name in ("app.sqlite3", "app.sqlite3-wal"):
        path = source / name
        if name == "app.sqlite3" or path.exists():
            atomic(frozen / name, recovery.read_file(path, recovery.MAX_DATABASE))
    for name, body in recovery.storage.capture(source).items():
        atomic(frozen / name, body)


def restore(*, authority=Path("/authority"), source=Path("/source"), registry=REGISTRY,
            public=PUBLIC, destination=Path("/restored")):
    recovery.local_only()
    recovery.require(phase(public) == {"phase": "maintenance"}, "mtls_recovery_not_fenced")
    store = _store(authority, source, registry)
    prepared = authority / "backup.json"
    if not prepared.exists():
        # SQLite may need to recreate its WAL index after a writer dies.
        # Give it writable scratch files and leave the stopped source untouched.
        with tempfile.TemporaryDirectory(prefix="frozen-source-") as temp:
            frozen = Path(temp)
            frozen_source(source, frozen)
            backup_store = recovery.Store(store.root, source=frozen, registry_path=registry)
            backup_store.checkpoint()
            backup = backup_store.backup(max_age=3600)
        atomic(prepared, canonical({"backup_id": backup["backup_id"]}))
    backup_id = json.loads(recovery.read_file(prepared, 4096))["backup_id"]
    with tempfile.TemporaryDirectory(prefix="app-restore-") as temp:
        staging = Path(temp)
        restored = store.restore(backup_id, max_age=3600, stage_root=staging)
        stage = staging / restored["restore_id"]
        # The destination volume is exclusive to the restore job until commit.
        # Only these two unpublished paths can be replaced during recovery.
        candidate = destination / "staging"
        active = destination / "active"
        for path in (candidate, active):
            recovery.require(not path.is_symlink(), "mtls_recovery_destination_scope")
            if path.exists():
                shutil.rmtree(path)
        recovery.snapshot(stage, candidate)
        atomic(candidate / "release.json", recovery.read_file(stage / "release.json"))
        recovery.verify_admission(candidate, store.public)
        recovery.require(recovery.read_file(candidate / "sources.json", 1024**2)
                         == recovery.read_file(registry, 1024**2), "registry_witness_mismatch")
        candidate.replace(active)
        # fsync the destination directory (and all data files) before publishing
        # the separate admission pin. The phase file is the last commit record.
        for path in active.iterdir():
            if path.is_file():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
        sync_directory(active)
        sync_directory(destination)
        for name in ("trust.json", "current.json"):
            atomic(public / name, recovery.read_file(store.public / name, 4096))
        result = {"phase": "approved", "restore_id": restored["restore_id"]}
        atomic(public / "phase.json", canonical(result))
    return result


def run_writer(role, expected):
    current = phase()
    recovery.require(current["phase"] == expected, "mtls_writer_fenced")

    def check_admission():
        if expected == "approved":
            admit(Path("/data/active"), PUBLIC, registry_path=REGISTRY, require_api_key=role == "app")

    if role == "app":
        service(role, before_exec=check_admission)
    elif role == "collector":
        service(role)
    else:
        check_admission()
        os.execv(sys.executable, [sys.executable, "-m", *OFFLINE_WRITERS[role]])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("phase", "fence", "restore", "writer"))
    parser.add_argument("role", nargs="?", choices=WRITERS)
    parser.add_argument("phase", nargs="?", choices=("original", "approved"))
    args = parser.parse_args(argv)
    try:
        if args.action == "writer":
            run_writer(args.role, args.phase)
        else:
            action = {"phase": phase, "fence": fence, "restore": restore}[args.action]
            print(json.dumps(action()))
        return 0
    except (OSError, ValueError, TypeError, LookupError, RuntimeError, sqlite3.Error):
        print("MTLS_APP_RECOVERY_DENIED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
