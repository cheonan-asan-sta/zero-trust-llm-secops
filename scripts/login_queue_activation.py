"""Approve and activate a verified login recovery pair on one Linux host."""

import argparse
import json
import os
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time
from uuid import uuid4

from app.services.sqlite_audit import SQLiteAuditStore
from scripts import login_queue_backup as backup
from scripts.f1_lab.capture_backup import fresh_file, private_directory, private_file, sync
from scripts.login_delivery_spool import LoginDeliverySpool

FILE_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK if os.name == "posix" else 0


class ActivationConflict(RuntimeError):
    """The requested change would violate a recovery precondition."""


@contextmanager
def _private_fd(path, *, create=False):
    flags = os.O_RDWR | FILE_FLAGS
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("Activation control requires private regular files")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _lock(root, name, *, shared=False):
    import fcntl

    with _private_fd(root / name) as fd:
        mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ActivationConflict(f"Managed service holds {name}") from error
        yield


@contextmanager
def _state(root, *, write=False):
    path = root / "selection.sqlite3"
    with _private_fd(path), closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)) as con:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        with con:
            yield con


def _current(con):
    row = con.execute("SELECT * FROM generation ORDER BY number DESC LIMIT 1").fetchone()
    if row is None:
        raise ActivationConflict("Activation control was not initialized")
    return dict(row)


def _scope(con):
    row = con.execute("SELECT origin, tenant_id, collector_subject FROM binding").fetchone()
    if row is None:
        raise ActivationConflict("Approval scope was not initialized")
    return dict(row)


def _handoff(con):
    if not con.execute("SELECT 1 FROM sqlite_master WHERE name = 'host_handoff'").fetchone():
        return None
    direction, receipt = con.execute("SELECT direction, receipt FROM host_handoff ORDER BY rowid DESC LIMIT 1").fetchone()
    return {"direction": direction, "receipt": json.loads(receipt)}


def _record_handoff(con, direction, receipt):
    con.execute("CREATE TABLE IF NOT EXISTS host_handoff (direction TEXT, receipt TEXT)")
    con.execute("INSERT INTO host_handoff VALUES (?, ?)", (direction, json.dumps(receipt)))


def _require_active(con):
    entry = _handoff(con)
    if entry and entry["direction"] == "outgoing":
        raise ActivationConflict("This login queue host was retired by an approved handoff")


def initialize(root, queue, audit, *, handoff=None, fenced_recovery=False, **scope):
    root = private_directory(root)
    for path in (queue, audit):
        backup.source_identity(path)
    queue, audit = queue.resolve(strict=True), audit.resolve(strict=True)
    if queue == audit:
        raise ValueError("Activation requires two distinct databases")
    LoginDeliverySpool(queue, **scope, create=False).counts()
    SQLiteAuditStore.open_existing(audit)
    for name in ("active.lock", "sender.lock", "selection.sqlite3"):
        with _private_fd(root / name, create=True):
            pass
    with _lock(root, "active.lock"), _state(root, write=True) as con:
        if con.execute("SELECT 1 FROM sqlite_master WHERE name = 'generation'").fetchone():
            raise ActivationConflict("Activation control is already initialized")
        if _present(root / "standby-id") and handoff is None:
            raise ActivationConflict("This standby requires its pinned host handoff")
        if _present(root / "disaster-profile.json") != fenced_recovery:
            raise ActivationConflict("This selection requires the enrolled standby recovery method")
        con.execute("CREATE TABLE binding (origin TEXT, tenant_id TEXT, collector_subject TEXT)")
        con.execute("""CREATE TABLE generation (
            number INTEGER PRIMARY KEY, queue TEXT NOT NULL UNIQUE, audit TEXT NOT NULL UNIQUE,
            approval_id TEXT UNIQUE, activated_uid INTEGER NOT NULL, activated_at INTEGER NOT NULL,
            predecessor_state TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE approval (
            id TEXT PRIMARY KEY, base INTEGER NOT NULL, candidate TEXT NOT NULL,
            package_sha256 TEXT NOT NULL, approved_uid INTEGER NOT NULL,
            approved_at INTEGER NOT NULL, note TEXT NOT NULL
        )""")
        con.execute("INSERT INTO binding VALUES (:origin, :tenant_id, :collector_subject)", scope)
        number, predecessor = 1, "enrolled"
        if handoff is not None:
            number = handoff["generation"] + 1
            predecessor = "externally_fenced_host" if fenced_recovery else "approved_host_handoff"
            _record_handoff(con, "incoming", handoff)
        con.execute("INSERT INTO generation VALUES (?, ?, ?, NULL, ?, ?, ?)",
                    (number, str(queue), str(audit), os.geteuid(), int(time()), predecessor))
    sync(root)


def approve(root, package, pin, candidate, key, *, note):
    root = private_directory(root)
    candidate = private_directory(candidate)
    note = note.strip()
    if not 3 <= len(note) <= 300:
        raise ValueError("An approval note of 3–300 characters is required")
    with _state(root) as con:
        _require_active(con)
        base, scope = _current(con)["number"], _scope(con)
    backup.verify_candidate(package, pin, candidate, key, **scope)
    identifier = uuid4().hex
    with _state(root, write=True) as con:
        _require_active(con)
        if _current(con)["number"] != base:
            raise ActivationConflict("Active generation changed during approval")
        con.execute("INSERT INTO approval VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (identifier, base, str(candidate), pin, os.geteuid(), int(time()), note))
    return identifier


def _present(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _predecessor(root, current, candidate, allow_missing):
    pairs = ((Path(current["queue"]), backup.QUEUE), (Path(current["audit"]), backup.AUDIT))
    missing = [not _present(path) for path, _ in pairs]
    if all(missing) and allow_missing:
        sidecars = ("-journal", "-wal", "-shm")
        if any(_present(path.with_name(path.name + suffix)) for path, _ in pairs for suffix in sidecars):
            raise ActivationConflict("The unavailable predecessor still has SQLite sidecars")
        return "unavailable"
    if any(missing):
        raise ActivationConflict("Predecessor pair is missing or incomplete")
    with TemporaryDirectory(prefix="predecessor-", dir=root) as temp:
        for old, name in pairs:
            backup.source_identity(old)
            copy = Path(temp) / name
            backup.copy_database(old, copy)
            if private_file(copy, backup.MAX_DATABASE) != private_file(candidate / name, backup.MAX_DATABASE):
                raise ActivationConflict("Predecessor differs from the candidate; capture a fresh quiesced pair")
    return "verified_identical"


def _approved_candidate(con, identifier):
    _require_active(con)
    current = _current(con)
    approval = con.execute("SELECT * FROM approval WHERE id = ?", (identifier,)).fetchone()
    if approval is None or approval["base"] != current["number"]:
        raise ActivationConflict("Approval is missing or belongs to a former generation")
    candidate = Path(approval["candidate"])
    pair = str(candidate / backup.QUEUE), str(candidate / backup.AUDIT)
    if con.execute("SELECT 1 FROM generation WHERE queue IN (?, ?) OR audit IN (?, ?)", pair * 2).fetchone():
        raise ActivationConflict("Candidate overlaps an existing generation")
    return current, approval, candidate, pair


def activate(root, identifier, package, key, *, allow_missing=False):
    root = private_directory(root)
    with _lock(root, "active.lock"), _state(root, write=True) as con:
        current, approval, candidate, (queue, audit) = _approved_candidate(con, identifier)
        backup.verify_candidate(package, approval["package_sha256"], candidate, key, **_scope(con))
        predecessor = _predecessor(root, current, candidate, allow_missing)
        number = current["number"] + 1
        con.execute("INSERT INTO generation VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (number, queue, audit, identifier, os.geteuid(), int(time()), predecessor))
    return number


def status(root):
    with _state(private_directory(root)) as con:
        history = con.execute("SELECT * FROM generation ORDER BY number").fetchall()
        approvals = con.execute("SELECT * FROM approval ORDER BY rowid").fetchall()
        result = {"scope": _scope(con), "generations": list(map(dict, history)), "approvals": list(map(dict, approvals))}
        if entry := _handoff(con):
            result["host_handoff"] = entry
        return result


@contextmanager
def _active_selection(root):
    root = private_directory(root)
    with _lock(root, "active.lock", shared=True):
        with _state(root) as con:
            _require_active(con)
            current, scope = _current(con), _scope(con)
        for kind in ("queue", "audit"):
            backup.source_identity(Path(current[kind]))
        yield current, scope


@contextmanager
def active_pair(root):
    with _active_selection(root) as (current, scope):
        LoginDeliverySpool(Path(current["queue"]), **scope, create=False).counts()
        SQLiteAuditStore.open_existing(Path(current["audit"]))
        yield current, scope


def stage_login(root, event, evidence):
    """Gateway intake commits to the current pair without becoming a sender."""
    from scripts.keycloak_login_evidence import enqueue_login

    with _active_selection(root) as (current, scope):
        spool = LoginDeliverySpool(Path(current["queue"]), **scope, create=False)
        enqueue_login(spool, event, evidence)


@contextmanager
def managed_collector(root, client, **collector_options):
    from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector

    root = private_directory(root)
    with active_pair(root) as (current, scope), _lock(root, "sender.lock"):
        if str(client.base_url) != scope["origin"]:
            raise ActivationConflict("Collector does not match the selected analysis origin")
        yield KeycloakLoginAnalysisCollector(
            client, spool_path=Path(current["queue"]), tenant_id=scope["tenant_id"],
            collector_subject=scope["collector_subject"], **collector_options,
        )


@contextmanager
def managed_api_settings(root, settings):
    from app.login_queue_api import load_profile

    if settings.audit_backend != "sqlite" or settings.dashboard_login_queue_profile is None:
        raise ValueError("Managed API requires SQLite audit and a dashboard profile")
    with active_pair(root) as (current, scope), TemporaryDirectory(dir=root) as temp:
        profile = load_profile(settings.dashboard_login_queue_profile)
        if (profile.analysis_origin, profile.tenant_id, profile.collector_subject) != (
            scope["origin"], scope["tenant_id"], scope["collector_subject"],
        ):
            raise ActivationConflict("Dashboard profile does not match the selected recovery scope")
        profile_path = Path(temp) / "profile.json"
        fresh_file(profile_path, profile.model_copy(update={"queue_file": Path(current["queue"])}).model_dump_json().encode())
        yield settings.model_copy(update={
            "audit_db_path": Path(current["audit"]), "dashboard_login_queue_profile": profile_path,
        })


def _serve(root, host, port):
    import uvicorn

    from app.config import Settings

    with managed_api_settings(root, Settings()) as active:
        # Uvicorn imports the application after the selected paths have been bound.
        os.environ["AUDIT_DB_PATH"] = str(active.audit_db_path)
        os.environ["DASHBOARD_LOGIN_QUEUE_PROFILE"] = str(active.dashboard_login_queue_profile)
        uvicorn.run("app.main:app", host=host, port=port, workers=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    commands = parser.add_subparsers(dest="action", required=True)
    enroll = commands.add_parser("init")
    enroll.add_argument("queue", type=Path)
    enroll.add_argument("audit", type=Path)
    enroll.add_argument("--origin", required=True)
    enroll.add_argument("--tenant-id", required=True)
    enroll.add_argument("--collector-subject", required=True)
    review = commands.add_parser("approve")
    switch = commands.add_parser("activate")
    for command in (review, switch):
        command.add_argument("package", type=Path)
        command.add_argument("--key-file", type=Path, required=True)
    review.add_argument("sha256")
    review.add_argument("candidate", type=Path)
    review.add_argument("--note", required=True)
    switch.add_argument("approval")
    switch.add_argument("--predecessor-unavailable", action="store_true")
    commands.add_parser("status")
    serve = commands.add_parser("serve-api")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    root = args.control
    if args.action == "init":
        initialize(root, args.queue, args.audit, origin=args.origin.rstrip("/") + "/",
                   tenant_id=args.tenant_id, collector_subject=args.collector_subject)
        return
    if args.action == "serve-api":
        _serve(root, args.host, args.port)
        return
    if args.action == "approve":
        result = {"approval": approve(root, args.package, args.sha256, args.candidate, args.key_file, note=args.note)}
    elif args.action == "activate":
        result = {"generation": activate(root, args.approval, args.package, args.key_file,
                                         allow_missing=args.predecessor_unavailable)}
    else:
        result = status(root)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
