"""SQLite queue for the gateway's original login event and optional signed evidence."""

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from app.services.collector_spool import (
    SpoolBindingMismatch,
    SpoolConflict,
    SpoolFull,
    SpoolUnavailable,
)
from app.services.login_delivery import LoginDeliveryIdentity
from app.zero_trust_models import LoginDeliveryRequest


class LoginDeliverySpool:
    def __init__(self, path, *, origin, tenant_id, collector_subject):
        self.path = Path(path)
        self.tenant_id = tenant_id
        self.collector_subject = collector_subject
        binding = json.dumps([origin, tenant_id, collector_subject])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction(create=True) as con:
            con.execute("CREATE TABLE IF NOT EXISTS login_queue_binding (id INTEGER PRIMARY KEY, binding TEXT NOT NULL)")
            con.execute(
                "CREATE TABLE IF NOT EXISTS login_queue ("
                "seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, "
                "payload_sha256 TEXT NOT NULL, held_status INTEGER)"
            )
            con.execute("INSERT OR IGNORE INTO login_queue_binding VALUES (1,?)", (binding,))
            if con.execute("SELECT binding FROM login_queue_binding WHERE id=1").fetchone() != (binding,):
                raise SpoolBindingMismatch("login queue belongs to another origin or collector")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def _transaction(self, *, create=False):
        try:
            if self.path.is_symlink():
                raise SpoolUnavailable("login queue link rejected")
            target = self.path if create else self.path.resolve().as_uri() + "?mode=rw"
            with closing(sqlite3.connect(target, uri=not create, timeout=5)) as con, con:
                con.execute("PRAGMA synchronous=FULL")
                con.execute("BEGIN IMMEDIATE")
                yield con
        except sqlite3.Error as exc:
            raise SpoolUnavailable("login queue unavailable") from exc

    def enqueue(self, body):
        self._check_owner(body)
        identity = LoginDeliveryIdentity.from_request(body)
        raw = body.model_dump_json()
        if len(raw.encode()) > 1_048_576:
            raise SpoolFull("login queue record too large")
        with self._transaction() as con:
            event_id = body.event.event_id
            stored = con.execute(
                "SELECT payload_sha256 FROM login_queue WHERE event_id=?", (event_id,),
            ).fetchone()
            if stored is not None:
                if stored[0] != identity.payload_sha256:
                    raise SpoolConflict("login event already queued with another payload")
                return
            if con.execute("SELECT count(*) FROM login_queue").fetchone()[0] >= 10000:
                raise SpoolFull("login queue capacity reached")
            con.execute(
                "INSERT INTO login_queue(event_id,payload,payload_sha256) VALUES (?,?,?)",
                (event_id, raw, identity.payload_sha256),
            )

    def _check_owner(self, body):
        if body.tenant_id != self.tenant_id or body.collector_subject != self.collector_subject:
            raise SpoolBindingMismatch("login queue payload belongs to another collector")

    def peek(self):
        with self._transaction() as con:
            row = con.execute(
                "SELECT event_id,payload,payload_sha256 FROM login_queue WHERE held_status IS NULL ORDER BY seq LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        event_id, raw, digest = row
        try:
            body = LoginDeliveryRequest.model_validate_json(raw)
            self._check_owner(body)
            if body.event.event_id != event_id or LoginDeliveryIdentity.from_request(body).payload_sha256 != digest:
                raise ValueError("login queue payload changed")
        except ValueError as exc:
            raise SpoolUnavailable("login queue payload integrity failed") from exc
        return body

    def acknowledge(self, body):
        self._finish(body, None)

    def hold(self, body, status):
        self._finish(body, status)

    def _finish(self, body, status):
        identity = LoginDeliveryIdentity.from_request(body)
        key = (body.event.event_id, identity.payload_sha256)
        with self._transaction() as con:
            if status is None:
                con.execute("DELETE FROM login_queue WHERE event_id=? AND payload_sha256=?", key)
            else:
                con.execute("UPDATE login_queue SET held_status=? WHERE event_id=? AND payload_sha256=?", (status, *key))

    def counts(self):
        with self._transaction() as con:
            pending, held = con.execute(
                "SELECT count(*) - count(held_status),count(held_status) FROM login_queue"
            ).fetchone()
        return {"pending": pending, "held": held}
