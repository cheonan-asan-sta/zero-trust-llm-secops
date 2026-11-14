"""Read only this system service's read-only runtime-key credential copy."""

import os
import stat
from pathlib import Path

from scripts.f1_lab.native_jsonl import require

CREDENTIALS_ROOT = Path("/run/credentials")


def read_systemd_key():
    require(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "credential_linux_file_required")
    supplied = os.environ.get("CREDENTIALS_DIRECTORY", "")
    directory = Path(supplied)
    require(
        supplied
        and directory.is_absolute()
        and directory.parent == CREDENTIALS_ROOT
        and directory.name.endswith(".service")
        and not directory.is_symlink(),
        "credential_system_service_directory",
    )
    parent = directory.stat()
    require(parent.st_uid in {0, os.geteuid()} and stat.S_IMODE(parent.st_mode) & 0o007 == 0,
            "credential_private_service_directory")
    path = directory / "runtime-key"
    # No fallback to stdin, another file, environment secret, or network source.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_size == 32
            and before.st_uid in {0, os.geteuid()}
            # systemd may grant the dynamic UID read access through a named
            # ACL; its read-only ACL mask appears as the group bit (0440).
            and stat.S_IMODE(before.st_mode) in {0o400, 0o440},
            "credential_readonly_private_file",
        )
        key = stream.read(33)
        after = os.fstat(stream.fileno())
        require(
            len(key) == 32
            and (before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns),
            "credential_stable_raw_key",
        )
        return key
