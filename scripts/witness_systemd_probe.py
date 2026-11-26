"""Non-secret, test-owned probes of an actual witness service sandbox."""

import argparse
import ctypes
import errno
import json
import os
import socket
import sys
from pathlib import Path


def accessible(path, flags):
    try:
        fd = os.open(path, flags)
    except OSError:
        return False
    os.close(fd)
    return True


def probe(database, private_key, cache):
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise ValueError("Linux service sandbox probe required")
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]

    libc = ctypes.CDLL(None, use_errno=True)
    header, data = Header(0x20080522, 0), (Data * 2)()
    if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError("capability probe unavailable")
    try:
        network = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        ipv4 = False
    else:
        network.close()
        ipv4 = True
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
        unix = True
    debug_denied = {}
    for name, args in (("process_vm_readv", (-1, None, 0, None, 0, 0)), ("pidfd_getfd", (-1, -1, 0))):
        call = getattr(libc, name, None)
        if call is None:
            debug_denied[name] = None
            continue
        ctypes.set_errno(0)
        debug_denied[name] = call(*args) == -1 and ctypes.get_errno() == errno.EPERM
    marker = Path(cache) / "probe-write"
    writable = accessible(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    if writable:
        marker.unlink()
    return {"schema": "local-witness-systemd-probe-1", "uid": os.geteuid(),
            "no_new_privileges": libc.prctl(39, 0, 0, 0, 0) == 1,
            "effective_capabilities": data[0].effective | (data[1].effective << 32),
            "permitted_capabilities": data[0].permitted | (data[1].permitted << 32),
            "inheritable_capabilities": data[0].inheritable | (data[1].inheritable << 32),
            "database_readable": accessible(database, os.O_RDONLY),
            "database_write_open_allowed": accessible(database, os.O_WRONLY),
            "private_key_readable": accessible(private_key, os.O_RDONLY),
            "private_key_write_open_allowed": accessible(private_key, os.O_WRONLY),
            "cache_writable": writable, "ipv4_socket_allowed": ipv4, "unix_socket_allowed": unix,
            "process_memory_syscalls_denied": debug_denied,
            "proc_readable": accessible("/proc/self/status", os.O_RDONLY),
            "automatic_activation_allowed": False, "independent_storage_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--cache", required=True)
    args = parser.parse_args()
    print("WITNESS_SANDBOX_PROBE=" + json.dumps(probe(args.database, args.private_key, args.cache)), flush=True)


if __name__ == "__main__":
    main()
