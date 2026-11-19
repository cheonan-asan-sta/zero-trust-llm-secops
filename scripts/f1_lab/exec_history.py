"""Capture a managed child's first successful exec at a kernel ptrace stop.

Opt-in, trusted static targets only. Not host-wide audit/EDR, a containment
sandbox, historical reconstruction, human presence or an authorization source.
"""

import ctypes
import hashlib
import os
import signal
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.shared_execution_collector import (
    boot_id,
    bounded,
    executable_hash,
    runtime_proof,
    snapshot_process,
)
from scripts.f1_lab.shared_execution_evidence import ServiceEvent, digest
from scripts.f1_lab.systemd_request_launcher import SystemdUnitLauncher

TRACEME, CONT, SETOPTIONS = 0, 7, 0x4200
TRACEEXEC, EXITKILL, EXEC_EVENT = 0x10, 0x100000, 4


def ptrace(operation, pid, data=0):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    result = libc.ptrace(operation, pid, None, ctypes.c_void_p(data))
    if result == -1:
        raise OSError(ctypes.get_errno(), "exec_history_ptrace_unavailable")


def wait_owned(pid, deadline):
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.005)
    raise TimeoutError("exec_history_deadline")


def validate_target(request, argv):
    require(
        isinstance(argv, (tuple, list))
        and 1 <= len(argv) <= 256
        and all(isinstance(v, str) and "\0" not in v for v in argv),
        "exec_history_argv",
    )
    body = b"".join(os.fsencode(v) + b"\0" for v in argv)
    require(
        len(body) <= 65536
        and Path(argv[0]).is_absolute()
        and executable_hash(Path(argv[0])) == request.executable_sha256
        and hashlib.sha256(body).hexdigest() == request.command_sha256,
        "exec_history_target_pin",
    )


def collect_owned_exec(
    request, argv, signing_key, *, source_id, key_id, mode="systemd", child_uid=65534, timeout=10
):
    require(
        mode in {"systemd", "local_process_lab"}
        and type(child_uid) is int
        and 0 < child_uid < 4294967295
        and type(timeout) in {int, float}
        and 0 < timeout <= 30
        and sys.platform == "linux"
        and threading.active_count() == 1
        and threading.current_thread() is threading.main_thread()
        and hasattr(signal, "SIGCHLD")
        and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
        and hasattr(os, "fork"),
        "exec_history_linux_configuration",
    )
    validate_target(request, argv)
    require(
        request.issued_at <= datetime.now(UTC) < request.expires_at, "exec_history_request_expired"
    )
    boot = boot_id()
    if mode == "systemd":
        state = SystemdUnitLauncher.state(request.unit)
        require(
            state["LoadState"] == "loaded"
            and state["MainPID"] == str(os.getpid())
            and len(state["InvocationID"]) == 32
            and state["InvocationID"] != "0" * 32,
            "exec_history_manager_binding",
        )
        invocation = state["InvocationID"]
    else:
        invocation = request.request_id
    deadline = time.monotonic() + timeout
    pid, reaped = os.fork(), False
    if pid == 0:
        stage = 121
        try:
            os.setsid()
            stage = 122
            if os.geteuid() == 0:
                os.setgroups([])
                stage = 131
                os.setgid(child_uid)
                stage = 132
                os.setuid(child_uid)
            elif os.geteuid() != child_uid:
                os._exit(126)
            libc = ctypes.CDLL(None)
            stage = 123
            if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
                os._exit(126)
            null = os.open("/dev/null", os.O_RDWR)
            stage = 124
            for fd in (0, 1, 2):
                os.dup2(null, fd)
            os.closerange(3, 65536)
            stage = 125
            ptrace(TRACEME, 0)
            stage = 126
            os.kill(os.getpid(), signal.SIGSTOP)
            stage = 127
            os.execve(argv[0], list(argv), {"PATH": "/usr/bin:/bin", "LANG": "C"})
        except BaseException as error:  # noqa: BLE001 - A fork child must never unwind into the broker.
            try:
                metadata = [
                    line
                    for line in Path("/proc/self/status").read_text().splitlines()
                    if line.startswith(("Uid:", "Gid:", "CapEff:", "NoNewPrivs:", "Seccomp:"))
                ]
                os.write(
                    2,
                    (
                        f"exec_history_child_stage={stage} errno={getattr(error, 'errno', 0)} "
                        + repr(metadata)
                        + "\n"
                    ).encode(),
                )
            finally:
                os._exit(stage)
    try:
        status = wait_owned(pid, deadline)
        reaped = os.WIFEXITED(status) or os.WIFSIGNALED(status)
        require(
            os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP,
            "exec_history_initial_stop"
            + ("_exit_" + str(os.waitstatus_to_exitcode(status)) if reaped else ""),
        )
        ptrace(SETOPTIONS, pid, TRACEEXEC | EXITKILL)
        require(datetime.now(UTC) < request.expires_at, "exec_history_request_expired")
        ptrace(CONT, pid)
        status = wait_owned(pid, deadline)
        reaped = os.WIFEXITED(status) or os.WIFSIGNALED(status)
        require(
            os.WIFSTOPPED(status)
            and os.WSTOPSIG(status) == signal.SIGTRAP
            and status >> 16 == EXEC_EVENT,
            "exec_history_successful_exec_required",
        )
        observed = datetime.now(UTC)
        require(observed < request.expires_at, "exec_history_request_expired")
        actual_boot, process = snapshot_process(pid)
        native_status = bounded(Path("/proc") / str(pid) / "status", 65536).decode("ascii")
        require(
            "NoNewPrivs:\t1\n" in native_status and "CapEff:\t0000000000000000\n" in native_status,
            "exec_history_child_privileges",
        )
        require(
            actual_boot == boot
            and process.parent_pid == os.getpid()
            and process.real_uid == child_uid
            and process.effective_uid == child_uid
            and process.command_sha256 == request.command_sha256
            and process.executable_sha256 == request.executable_sha256,
            "exec_history_kernel_snapshot_binding",
        )
        if mode == "systemd":
            after = SystemdUnitLauncher.state(request.unit)
            require(
                after["MainPID"] == str(os.getpid()) and after["InvocationID"] == invocation,
                "exec_history_manager_changed",
            )
        raw_sha = digest(
            [
                "PTRACE_EVENT_EXEC",
                status,
                request.authentication_nonce,
                boot,
                invocation,
                process.model_dump(mode="json"),
            ]
        )
        event = ServiceEvent(
            tenant_id=request.tenant_id,
            server_id=request.server_id,
            unit=request.unit,
            boot_id=boot,
            invocation_id=invocation,
            process_id=pid,
            observed_at=observed,
            mode=mode,
            collection_basis="ptrace_exec" if mode == "systemd" else "ptrace_exec_lab",
            raw_sha256=raw_sha,
            event_id=digest([request.authentication_nonce, raw_sha]),
        )
        proof = runtime_proof(event, process, signing_key, source_id=source_id, key_id=key_id)
        ptrace(CONT, pid)
        status = wait_owned(pid, deadline)
        reaped = os.WIFEXITED(status) or os.WIFSIGNALED(status)
        require(os.WIFEXITED(status), "exec_history_target_did_not_exit")
        reaped = True
        return event, proof, os.WEXITSTATUS(status)
    except ChildProcessError:
        reaped = True  # Ownership was lost: never signal a potentially reused PID.
        raise ValueError("exec_history_child_ownership_lost") from None
    finally:
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
