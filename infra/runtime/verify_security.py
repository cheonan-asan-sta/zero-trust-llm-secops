"""Bounded offline parser/SQLite regression checks, using no real service or data."""

import argparse
import ensurepip
import hashlib
import http.client
import importlib.metadata
import io
import json
import platform
import sqlite3
import sysconfig
import tempfile
from contextlib import closing
from pathlib import Path


class MemorySocket:
    def __init__(self, body):
        self.body = body

    def makefile(self, *_args):
        return io.BytesIO(self.body)


def content_length(value):
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: " + value + b"\r\n\r\nhello"
    response = http.client.HTTPResponse(MemorySocket(wire))
    response.begin()
    result = response.length
    response.close()
    return result


def chunk_size(value):
    # Only parse a tiny size token; never read a negative/unbounded response body.
    response = http.client.HTTPResponse(MemorySocket(value + b"\r\n"))
    try:
        return response._read_next_chunk_size()
    except ValueError:
        return None
    finally:
        response.close()


def sqlite_checks():
    checks = {}
    with tempfile.TemporaryDirectory(prefix="secops-sqlite-check-") as directory:
        source, backup = Path(directory) / "state.db", Path(directory) / "backup.db"
        with closing(sqlite3.connect(source)) as db:
            checks["wal_mode"] = db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript("CREATE TABLE parent(id INTEGER PRIMARY KEY);"
                             "CREATE TABLE child(id INTEGER REFERENCES parent(id));"
                             "INSERT INTO parent VALUES(1); INSERT INTO child VALUES(1);")
            try:
                db.execute("INSERT INTO child VALUES(2)")
                checks["foreign_keys"] = False
            except sqlite3.IntegrityError:
                checks["foreign_keys"] = True
                db.rollback()
            db.execute("CREATE VIRTUAL TABLE search USING fts5(body)")
            db.execute("INSERT INTO search VALUES('local security check')")
            checks["fts5"] = db.execute("SELECT count(*) FROM search WHERE search MATCH 'security'").fetchone()[0] == 1
            db.execute("CREATE VIRTUAL TABLE area USING rtree(id,x1,x2,y1,y2)")
            db.execute("INSERT INTO area VALUES(1,0,1,0,1)")
            checks["rtree"] = db.execute("SELECT count(*) FROM area WHERE x1>=0").fetchone()[0] == 1
            db.commit()
            with closing(sqlite3.connect(backup)) as destination:
                db.backup(destination)
        with closing(sqlite3.connect(backup)) as db:
            checks["backup_integrity"] = db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            checks["backup_rows"] = db.execute("SELECT count(*) FROM child").fetchone()[0] == 1
    # Synthetic values only: ensure a JOIN USING column cannot escape a denied READ.
    with closing(sqlite3.connect(":memory:")) as db:
        db.executescript("CREATE TABLE a(id); CREATE TABLE b(id); INSERT INTO a VALUES(1); INSERT INTO b VALUES(1);")

        def authorizer(action, table, column, *_args):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ and table == "b" and column == "id" else sqlite3.SQLITE_OK

        db.set_authorizer(authorizer)
        try:
            db.execute("SELECT id FROM a RIGHT JOIN b USING(id)").fetchall()
            checks["join_using_authorizer"] = False
        except sqlite3.DatabaseError:
            checks["join_using_authorizer"] = True
    return checks


def report():
    checks = {"python_security_release": platform.python_version() == "3.12.16",
              "sqlite_security_release": sqlite3.sqlite_version == "3.54.1",
              "pip_security_release": importlib.metadata.version("pip") == "26.3",
              "ensurepip_security_release": ensurepip.version() == "26.3",
              "http_valid_content_length": content_length(b"5") == 5,
              "http_optional_whitespace": content_length(b"5 \t") == 5,
              "http_valid_chunk": chunk_size(b"5") == 5,
              "http_chunk_extension": chunk_size(b"5;test=1") == 5}
    for name, value in [("signed", b"+5"), ("underscore", b"5_0"), ("hex_prefix", b"0x5")]:
        checks["http_reject_length_" + name] = content_length(value) is None
    for name, value in [("signed", b"+5"), ("negative", b"-5"), ("underscore", b"1_f"),
                        ("hex_prefix", b"0x5"), ("leading_space", b" 5")]:
        checks["http_reject_chunk_" + name] = chunk_size(value) is None
    checks.update(sqlite_checks())
    with closing(sqlite3.connect(":memory:")) as db:
        source_id = db.execute("SELECT sqlite_source_id()").fetchone()[0]
        compile_options = sorted(row[0] for row in db.execute("PRAGMA compile_options"))
        modules = sorted(row[0] for row in db.execute("PRAGMA module_list"))
    client = Path(sysconfig.get_path("stdlib")) / "http/client.py"
    return {"schema": "secops-runtime-security-check-1", "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version, "sqlite_source_id": source_id,
            "pip": importlib.metadata.version("pip"), "http_client_sha256": hashlib.sha256(client.read_bytes()).hexdigest(),
            "sqlite_compile_options": compile_options, "sqlite_modules": modules,
            "checks": checks, "passed": all(checks.values()),
            "limits": ["Parser tokens and synthetic SQLite files only; no external network or real credentials.",
                       "Version checks are not an exhaustive exploitability or upstream conformance test."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-patched", action="store_true")
    args = parser.parse_args()
    result = report()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if args.require_patched and not result["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
