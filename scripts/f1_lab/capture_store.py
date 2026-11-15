"""Cooperative, bounded Linux lock for an administrator-owned capture directory."""

import math
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from scripts.f1_lab.native_jsonl import require


@contextmanager
def capture_store_lock(root, *, timeout=5):
    require(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "capture_store_linux")
    import fcntl

    root = Path(root)
    info = root.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and not root.is_symlink()
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "capture_store_private_owner",
    )
    require(
        type(timeout) in {int, float} and math.isfinite(timeout) and 0 < timeout <= 5,
        "capture_store_lock_timeout",
    )
    path = root / ".capture-store.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        lock = os.fstat(fd)
        require(
            stat.S_ISREG(lock.st_mode)
            and lock.st_uid == os.geteuid()
            and stat.S_IMODE(lock.st_mode) == 0o600
            and lock.st_nlink == 1,
            "capture_store_lock_file",
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, "capture_store_lock_busy")
                time.sleep(min(0.025, max(0, deadline - time.monotonic())))
        require(
            root.lstat().st_ino == info.st_ino and path.lstat().st_ino == lock.st_ino,
            "capture_store_replaced",
        )
        yield
    finally:
        os.close(fd)
