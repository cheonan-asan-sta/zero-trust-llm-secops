import os
import socket
import sys
from pathlib import Path

import pytest

from scripts.f1_lab.collector_security import security_status
from scripts.f1_lab.systemd_credentials import CredentialSocket


def status(tmp_path, **changes):
    fields = {
        "Uid": "10001 10001 10001 10001",
        "CapEff": "0000000000080004",
        "CapBnd": "0000000000080004",
        "NoNewPrivs": "1",
    }
    fields.update(changes)
    path = tmp_path / "status"
    path.write_text("\n".join(f"{k}:\t{v}" for k, v in fields.items()))
    return path


def test_security_observation_does_not_infer_root_or_caps(tmp_path):
    assert security_status(status(tmp_path)) == {
        "effective_uid": 10001,
        "effective_capabilities": (1 << 19) | (1 << 2),
        "bounding_capabilities": (1 << 19) | (1 << 2),
        "no_new_privileges": True,
    }


@pytest.mark.parametrize(
    "change", [{"Uid": "0 0 0"}, {"CapEff": "unknown"}, {"NoNewPrivs": "maybe"}, {"CapBnd": "0"}]
)
def test_malformed_security_status_is_not_trusted(tmp_path, change):
    with pytest.raises(ValueError):
        security_status(status(tmp_path, **change))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux Unix peer credentials")
@pytest.mark.parametrize("mode", ["valid", "wrong_uid", "wrong_size", "supplier_error"])
def test_socket_transfer_is_bounded_private_and_peer_checked(tmp_path, mode):
    # Keep AF_UNIX's platform pathname limit independent from pytest long names.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="zt-cred-") as directory:
        parent = Path(directory)
        parent.chmod(0o700)
        path = parent / "key.sock"
        secret = b"only-test-fixture-key-not-real!!!"[:32]

        def key():
            if mode == "supplier_error":
                raise RuntimeError("must not be logged")
            return secret if mode != "wrong_size" else b"bad"

        uid = os.geteuid() if mode != "wrong_uid" else os.geteuid() + 1
        with CredentialSocket(path, key, allowed_uid=uid, maximum_connections=1) as provider:
            assert path.is_socket() and path.stat().st_mode & 0o777 == 0o600
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(str(path))
                body = client.recv(33)
            assert body == (secret if mode == "valid" else b"")
            provider.thread.join(timeout=3)
            assert not provider.thread.is_alive()
            assert provider.delivered == (1 if mode == "valid" else 0)
            assert provider.rejected == (0 if mode == "valid" else 1)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(0.5)
                with pytest.raises(ConnectionRefusedError):
                    client.connect(str(path))
        assert not path.exists() and not provider.thread.is_alive()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux Unix peer credentials")
def test_public_parent_symlink_and_existing_file_are_not_modified(tmp_path):
    tmp_path.chmod(0o755)
    with (
        pytest.raises(ValueError, match="private_directory"),
        CredentialSocket(tmp_path / "key.sock", lambda: b"x" * 32),
    ):
        pass
    tmp_path.chmod(0o700)
    existing = tmp_path / "key.sock"
    existing.write_bytes(b"preserve")
    with (
        pytest.raises(ValueError, match="private_directory"),
        CredentialSocket(existing, lambda: b"x" * 32),
    ):
        pass
    assert existing.read_bytes() == b"preserve"
