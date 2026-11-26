"""POSIX durable bounded status publication with a caller-owned typed validator.

Unsigned advisory snapshots only. The host owner and validator configuration are
trusted; this lock coordinates cooperating publishers, not a hostile host admin.
"""

import os
import stat
import tempfile
from pathlib import Path

from app.services.audit_transfer import canonical, require
from scripts.f1_lab.collector_status_bridge import read_public


def publish(path, value, validate):
    require(os.name == "posix" and hasattr(os, "geteuid") and hasattr(os, "O_NOFOLLOW"),
            "witness_status_posix_required")
    import fcntl

    checked = validate(value)
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "witness_status_output")
    require(all(not p.is_symlink() for p in (path.parent, *path.parent.parents)),
            "witness_status_parent_link")
    info = path.parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and not stat.S_IMODE(info.st_mode) & 0o022, "witness_status_parent_permissions")
    raw = canonical(value) + b"\n"
    require(len(raw) <= 8192, "witness_status_size")
    lock = path.with_name("." + path.name + ".lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "rb") as lease:
        info = os.fstat(lease.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and not stat.S_IMODE(info.st_mode) & 0o077, "witness_status_lock_permissions")
        fcntl.flock(lease.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if path.exists():
            require(path.stat().st_uid == os.geteuid(), "witness_status_previous_owner")
            require(validate(read_public(path)) <= checked, "witness_status_publication_clock")
        fd, temporary = tempfile.mkstemp(prefix=".witness-status-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                os.fchmod(stream.fileno(), 0o644)
                stream.flush()
                os.fsync(stream.fileno())
            require(not path.is_symlink(), "witness_status_output_link")
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
