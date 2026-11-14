"""Bounded local Unix credential provider for systemd LoadCredential.

Root and this host's system manager are trusted. The provider authenticates the
peer's OS UID, not a human. The private key is returned only on this protected
socket and is never placed in a file, argv, environment or provider output.
"""

import os
import socket
import stat
import struct
import threading
from pathlib import Path

from scripts.f1_lab.native_jsonl import require


def peer_uid(connection):
    require(hasattr(socket, "SO_PEERCRED"), "credential_linux_peer_required")
    _, uid, _ = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    return uid


class CredentialSocket:
    """Ephemeral endpoint. The key callback is trusted server configuration.

    This is a local adapter for an existing key owner, not a vault, encrypted
    backup, automatic key issuer, or general secret retrieval API.
    """

    def __init__(self, path, key_supplier, *, allowed_uid=0, maximum_connections=32):
        require(
            type(allowed_uid) is int
            and 0 <= allowed_uid < 4294967295
            and type(maximum_connections) is int
            and 1 <= maximum_connections <= 100,
            "credential_limits",
        )
        self.path, self.supplier = Path(path), key_supplier
        self.allowed_uid, self.maximum = allowed_uid, maximum_connections
        self.stopped = threading.Event()
        self.delivered = self.rejected = 0
        self.sock = self.thread = None
        self.identity = None

    def __enter__(self):
        require(os.name == "posix" and hasattr(socket, "SO_PEERCRED"), "credential_linux_required")
        parent = self.path.parent
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and not parent.is_symlink()
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700
            and not self.path.exists()
            and not self.path.is_symlink(),
            "credential_private_directory",
        )
        require(len(os.fsencode(self.path)) < 100, "credential_socket_path_bound")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.bind(str(self.path))
            self.identity = self.path.lstat().st_ino
            self.path.chmod(0o600)
            self.sock.listen(2)
            self.sock.settimeout(0.2)
            self.thread = threading.Thread(
                target=self.serve, name="systemd-credential-provider", daemon=True
            )
            self.thread.start()
            return self
        except Exception:
            self.close()
            raise

    def serve(self):
        attempts = 0
        try:
            while not self.stopped.is_set() and attempts < self.maximum:
                try:
                    connection, _ = self.sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                attempts += 1
                with connection:
                    try:
                        connection.settimeout(2)
                        require(peer_uid(connection) == self.allowed_uid, "credential_peer_uid")
                        key = self.supplier()
                        require(type(key) is bytes and len(key) == 32, "credential_raw_key_size")
                        connection.sendall(key)
                        self.delivered += 1
                    except (OSError, ValueError, TypeError, RuntimeError):
                        self.rejected += 1
        finally:
            # An exhausted adapter must refuse new connections, not leave a
            # listening socket with no reader until the consumer times out.
            # The owner still verifies/removes the pathname in close().
            self.sock.close()

    def close(self):
        self.stopped.set()
        if self.sock is not None:
            self.sock.close()
        if self.thread is not None:
            self.thread.join(timeout=3)
            require(not self.thread.is_alive(), "credential_provider_did_not_stop")
        if self.identity is not None:
            try:
                info = self.path.lstat()
                require(
                    stat.S_ISSOCK(info.st_mode) and info.st_ino == self.identity,
                    "credential_socket_replaced",
                )
                self.path.unlink()
            except FileNotFoundError:
                pass

    def __exit__(self, *_):
        self.close()
