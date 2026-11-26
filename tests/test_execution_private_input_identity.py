"""Input links remain rejected even where O_NOFOLLOW is unavailable."""

import errno
import os

import pytest

from scripts import behavior_execution_collector as collector


def test_plain_binary_input_is_unchanged(tmp_path):
    path = tmp_path / "private.json"
    path.write_bytes(b'{"note":"line1\\nline2"}\r\n\x1a')
    path.chmod(0o600)
    assert collector.read_private(path) == path.read_bytes()


def test_link_is_rejected_without_no_follow_flag(tmp_path, monkeypatch):
    path = tmp_path / "private.json"
    path.write_bytes(b'{}')
    path.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(OSError) as error:
        collector.read_private(link)
    assert error.value.errno == errno.ELOOP


def test_replaced_input_cannot_be_accepted_under_old_path_identity(tmp_path, monkeypatch):
    path, replacement = tmp_path / "private.json", tmp_path / "replacement.json"
    path.write_bytes(b'{"original":true}')
    replacement.write_bytes(b'{"replacement":true}')
    path.chmod(0o600)
    replacement.chmod(0o600)
    original_open = os.open

    def swapped(target, flags, *args, **kwargs):
        if target == path:
            os.replace(replacement, path)
        return original_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swapped)
    with pytest.raises(ValueError, match="input_changed"):
        collector.read_private(path)
