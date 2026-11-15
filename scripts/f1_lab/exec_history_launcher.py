"""Adapter for preinstalled, administrator-owned oneshot capture units.

The unit runs scripts.collect_exec_history with fixed input/output paths and a
LoadCredential runtime-key. Request clients never provide paths or argv.
"""

import os
import stat
from pathlib import Path

from scripts.f1_lab.exec_history import validate_target
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_execution_evidence import ServiceEvent, ServiceProof
from scripts.f1_lab.systemd_request_launcher import SystemdUnitLauncher


def private_read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and metadata.st_mode & 0o077 == 0,
            "exec_history_private_file",
        )
        raw = stream.read(maximum + 1)
        require(len(raw) <= maximum, "exec_history_input_bound")
        return raw


def private_write(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


class HistoryUnitLauncher(SystemdUnitLauncher):
    def __init__(self, target, argv, directory, *, source_id, key_id):
        super().__init__([target], None, source_id=source_id, key_id=key_id)
        self.argv, self.directory = tuple(argv), Path(directory)
        metadata = self.directory.lstat()
        require(
            os.name == "posix"
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o077 == 0,
            "exec_history_private_directory",
        )
        self.request_sha = None

    def launch(self, request):
        self.target(request)
        validate_target(request, self.argv)
        require(self.request_sha is None, "exec_history_launcher_single_use")
        require(not (self.directory / "capture.json").exists(), "exec_history_old_capture")
        private_write(
            self.directory / "request.json",
            canonical(
                {
                    "request": request.model_dump(mode="json"),
                    "argv": list(self.argv),
                    "source_id": self.source_id,
                    "key_id": self.key_id,
                }
            ),
        )
        self.request_sha = request.authentication_nonce
        super().launch(request)

    def collect(self, request):
        self.target(request)
        require(self.request_sha == request.authentication_nonce, "exec_history_request_binding")
        capture = decode(private_read(self.directory / "capture.json", 16384))
        require(
            set(capture) == {"request_sha256", "event", "proof", "exit_code"}
            and capture["request_sha256"] == self.request_sha
            and type(capture["exit_code"]) is int
            and 0 <= capture["exit_code"] <= 255,
            "exec_history_capture_binding",
        )
        event = ServiceEvent.model_validate(capture["event"])
        proof = ServiceProof.model_validate(capture["proof"])
        require(
            event.mode == "systemd" and event.collection_basis == "ptrace_exec",
            "exec_history_capture_origin",
        )
        return event, proof
