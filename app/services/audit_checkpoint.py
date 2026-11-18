"""Read-only head export and externally pinned checkpoint import for operators.

A file SHA pin checks the operator-selected bytes, not independent storage or
whether the operator selected the newest checkpoint. Timestamps are descriptive.
"""

import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from app.services.audit_backup import validate_head
from app.services.audit_transfer import canonical, decode, fresh_stage, publish, require, sha
from app.services.sqlite_audit import SQLiteAuditStore

SCHEMA = "sqlite-audit-checkpoint-1"
MAX_BYTES = 16384


def _hex(value):
    return type(value) is str and len(value) == 64 and set(value) <= set("0123456789abcdef")


def _validate(document):
    require(
        type(document) is dict
        and set(document)
        == {
            "schema",
            "captured_at",
            "source_locator_sha256",
            "head",
        },
        "checkpoint fields rejected",
    )
    require(
        document["schema"] == SCHEMA and _hex(document["source_locator_sha256"]),
        "checkpoint schema/source rejected",
    )
    require(
        type(document["captured_at"]) is str
        and datetime.fromisoformat(document["captured_at"]).utcoffset() is not None,
        "checkpoint time must be timezone-aware",
    )
    head = document["head"]
    require(
        type(head) is dict
        and set(head) == {"seq", "digest"}
        and type(head["seq"]) is int
        and 0 <= head["seq"] <= SQLiteAuditStore.MAX_ROWS
        and _hex(head["digest"])
        and (head["seq"] != 0 or head["digest"] == "0" * 64),
        "checkpoint head rejected",
    )
    return document


def capture_checkpoint(database, destination):
    """Never repair/activate a DB or replace an existing output file."""
    with fresh_stage(destination) as (stage, target):
        store = SQLiteAuditStore.open_existing(database)
        with store._transaction() as con:
            tables = {
                r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            require(tables == {"audit_entries", "audit_head"}, "checkpoint audit schema required")
            seq, digest = validate_head(con, store)
            document = _validate(
                {
                    "schema": SCHEMA,
                    "captured_at": datetime.now(UTC).isoformat(),
                    "source_locator_sha256": sha(
                        os.path.normcase(str(store.path.absolute())).encode()
                    ),
                    "head": {"seq": seq, "digest": digest},
                }
            )
        raw = canonical(document) + b"\n"
        require(len(raw) <= MAX_BYTES, "checkpoint size exceeded")
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        publish(stage, target)
        return {
            "checkpoint_sha256": sha(raw),
            "head": document["head"],
            "captured_at": document["captured_at"],
            "automatic_activation_allowed": False,
            "independent_storage_verified": False,
        }


def load_checkpoint(path, expected_sha256):
    """The expected digest must come from the operator's trusted record."""
    require(_hex(expected_sha256), "checkpoint external pin required")
    path = Path(path)
    require(not path.is_symlink(), "checkpoint link rejected")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= MAX_BYTES,
            "checkpoint file rejected",
        )
        if os.name == "posix":
            require(
                before.st_mode & 0o077 == 0 and before.st_uid in {0, os.geteuid()},
                "checkpoint permission rejected",
            )
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        live = path.lstat()
        signature = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_mode,
            value.st_uid,
            value.st_nlink,
        )
        require(
            stat.S_ISREG(live.st_mode)
            and signature(before) == signature(after) == signature(live)
            and len(raw) <= MAX_BYTES
            and sha(raw) == expected_sha256,
            "checkpoint changed or external pin mismatch",
        )
    return _validate(decode(raw))
