"""Local durable inventory/checkpoints; not independent rollback attestation."""

import hashlib
import os
import sqlite3
import stat
from contextlib import contextmanager


class AuditManifestError(RuntimeError):
    pass


class AuditShardManifest:
    def __init__(self, path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.transaction(create=True) as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS shards (name TEXT PRIMARY KEY, size INTEGER NOT NULL, digest TEXT NOT NULL)"
            )

    @contextmanager
    def transaction(self, *, create=False):
        connection = None
        try:
            if self.path.is_symlink():
                raise AuditManifestError("audit manifest link rejected")
            connection = sqlite3.connect(
                self.path if create else self.path.resolve().as_uri() + "?mode=rw",
                uri=not create,
                timeout=5,
            )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            with connection:
                yield connection
        except (OSError, sqlite3.Error) as error:
            raise AuditManifestError("audit manifest unavailable") from error
        finally:
            if connection is not None:
                connection.close()

    def announce(self, path, capacity, *, ensure_file=False):
        with self.transaction() as con:
            existing = con.execute("SELECT 1 FROM shards WHERE name=?", (path.name,)).fetchone()
            if existing is None:
                if con.execute("SELECT count(*) FROM shards").fetchone()[0] >= capacity:
                    raise AuditManifestError("audit manifest capacity exceeded")
                con.execute(
                    "INSERT INTO shards VALUES (?,0,?)",
                    (path.name, hashlib.sha256(b"").hexdigest()),
                )
            if ensure_file:
                if path.is_symlink() or (existing is not None and not path.is_file()):
                    raise AuditManifestError("registered audit writer missing or linked")
                flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                if existing is None:
                    flags |= os.O_CREAT
                fd = os.open(path, flags, 0o600)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise AuditManifestError("audit writer is not a regular file")
                finally:
                    os.close(fd)

    def checkpoint(self, paths, signatures, capacity):
        """Advance only fully verified stable files, rejecting lost/truncated prefixes."""
        with self.transaction() as con:
            old = {
                name: (size, digest)
                for name, size, digest in con.execute("SELECT name,size,digest FROM shards")
            }
            if len(old) > capacity or not set(old) <= {p.name for p in paths}:
                raise AuditManifestError("previously registered audit shard missing")
            for path in paths:
                before = path.stat()
                if signatures[path.name] != (before.st_size, before.st_mtime_ns, before.st_ino):
                    raise AuditManifestError("audit shard changed after verification")
                size, digest = old.get(path.name, (0, hashlib.sha256(b"").hexdigest()))
                if type(size) is not int or size < 0 or before.st_size < size:
                    raise AuditManifestError("audit shard truncated")
                prefix, entire = hashlib.sha256(), hashlib.sha256()
                remaining = size
                with path.open("rb") as stream:
                    while chunk := stream.read(65536):
                        entire.update(chunk)
                        if remaining:
                            prefix.update(chunk[:remaining])
                            remaining = max(0, remaining - len(chunk))
                after = path.stat()
                if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ino,
                ):
                    raise AuditManifestError("audit shard changed during checkpoint")
                if remaining or prefix.hexdigest() != digest:
                    raise AuditManifestError("audit checkpoint prefix changed")
                con.execute(
                    "INSERT OR REPLACE INTO shards VALUES (?,?,?)",
                    (path.name, after.st_size, entire.hexdigest()),
                )
