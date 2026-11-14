import sys

import pytest

from scripts.f1_lab import systemd_credential_reader as reader

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux no-follow credential file open"
)


def fixture(tmp_path, monkeypatch):
    root = tmp_path / "credentials"
    directory = root / "fixture.service"
    directory.mkdir(parents=True)
    path = directory / "runtime-key"
    path.write_bytes(b"test-key-32-bytes-no-real-secret!"[:32])
    path.chmod(0o400)
    directory.chmod(0o700)
    monkeypatch.setattr(reader, "CREDENTIALS_ROOT", root)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))
    return root, directory, path


def test_reads_exact_readonly_systemd_copy(tmp_path, monkeypatch):
    _, _, path = fixture(tmp_path, monkeypatch)
    assert len(path.read_bytes()) == 32 and reader.read_systemd_key() == path.read_bytes()


def test_backup_credential_never_falls_back_to_runtime_signing_key(tmp_path, monkeypatch):
    _, directory, runtime = fixture(tmp_path, monkeypatch)
    with pytest.raises(OSError):
        reader.read_systemd_key(credential_name="capture-backup-key")
    backup = directory / "capture-backup-key"
    backup.write_bytes(b"b" * 32)
    backup.chmod(0o400)
    assert reader.read_systemd_key(credential_name="capture-backup-key") == b"b" * 32
    assert reader.read_systemd_key() == runtime.read_bytes()


@pytest.mark.parametrize("name", ["../runtime-key", "unrelated-key"])
def test_credential_name_is_fixed_not_an_arbitrary_file(tmp_path, monkeypatch, name):
    fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        reader.read_systemd_key(credential_name=name)


def test_accepts_readonly_systemd_acl_mask_in_private_directory(tmp_path, monkeypatch):
    _, _, path = fixture(tmp_path, monkeypatch)
    path.chmod(0o440)
    assert reader.read_systemd_key() == path.read_bytes()


@pytest.mark.parametrize(
    "mode",
    [
        "missing_env",
        "wrong_root",
        "wrong_unit",
        "symlink",
        "writable",
        "public",
        "short",
        "long",
        "directory",
    ],
)
def test_missing_or_unsafe_credentials_never_fall_back(tmp_path, monkeypatch, mode):
    root, _, path = fixture(tmp_path, monkeypatch)
    if mode == "missing_env":
        monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    elif mode == "wrong_root":
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "fixture.service"))
    elif mode == "wrong_unit":
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(root / "not-a-system-service"))
    elif mode == "symlink":
        path.unlink()
        target = tmp_path / "other-key"
        target.write_bytes(b"x" * 32)
        target.chmod(0o400)
        path.symlink_to(target)
    elif mode in {"writable", "public"}:
        path.chmod(0o600 if mode == "writable" else 0o444)
    elif mode in {"short", "long"}:
        path.chmod(0o600)
        path.write_bytes(b"x" * (31 if mode == "short" else 33))
        path.chmod(0o400)
    else:
        path.unlink()
        path.mkdir()
    with pytest.raises((ValueError, OSError)):
        reader.read_systemd_key()
