"""Fixed, bounded local journalctl reader; no submitted log or command input."""

import os
import re
import selectors
import subprocess
import time
from pathlib import Path

from pydantic import TypeAdapter

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.pam_journal import MAX_RECORDS
from scripts.f1_lab.shared_execution_collector import READ_ENV, boot_id
from scripts.f1_lab.shared_execution_evidence import Token, Unit

FIELDS = ('MESSAGE', '__CURSOR', '__REALTIME_TIMESTAMP', '__MONOTONIC_TIMESTAMP', '_PID', '_UID', '_GID',
          '_COMM', '_EXE', '_TRANSPORT', '_BOOT_ID', '_SYSTEMD_UNIT', '_SYSTEMD_INVOCATION_ID',
          '_AUDIT_LOGINUID', '_AUDIT_SESSION')
JOURNAL_TIMEOUT = 5.0


def unit_invocation(unit):
    unit = TypeAdapter(Unit).validate_python(unit)
    result = subprocess.run(['/usr/bin/systemctl', 'show', '--no-pager',
        '--property=Id,LoadState,ActiveState,InvocationID', '--', unit],
        env=READ_ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=False)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 4096, 'pam_manager_unavailable')
    fields = {}
    for line in result.stdout.decode().splitlines():
        name, separator, value = line.partition('=')
        require(separator and name not in fields, 'pam_manager_shape')
        fields[name] = value
    require(set(fields) == {'Id', 'LoadState', 'ActiveState', 'InvocationID'}
        and fields['Id'] == unit and fields['LoadState'] == 'loaded'
        and fields['ActiveState'] in {'active', 'activating'}, 'pam_manager_unit')
    invocation = TypeAdapter(Token).validate_python(fields['InvocationID'])
    require(invocation != '0'*32, 'pam_manager_invocation')
    return boot_id(), invocation


def stamp(value):
    require(type(value) is int and 0 < value <= 4102444800000000, 'pam_query_time')
    seconds, fraction = divmod(value, 1000000)
    return f'@{seconds}.{fraction:06}'


def journal_rows(unit, start_us, end_us):
    """Bound output while it arrives, including unterminated and binary rows."""
    require(os.name == 'posix' and Path('/proc/1/comm').read_text().strip() == 'systemd',
            'pam_native_systemd')
    unit = TypeAdapter(Unit).validate_python(unit)
    require(0 < end_us-start_us <= 600000000, 'pam_query_window')
    argv = ['/usr/bin/journalctl', '--no-pager', '--output=json', '--all', '--boot=0',
        '--unit', unit, '--since', stamp(start_us), '--until', stamp(end_us),
        '--lines', str(MAX_RECORDS+1), '--output-fields='+','.join(FIELDS)]
    process = subprocess.Popen(argv, env=READ_ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    pending, count, total = bytearray(), 0, 0
    deadline = time.monotonic()+JOURNAL_TIMEOUT
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            os.set_blocking(process.stdout.fileno(), False)
            finished = False
            while not finished:
                remaining = deadline-time.monotonic()
                require(remaining > 0, 'pam_journal_timeout')
                for key, _ in selector.select(min(.2, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        finished = True
                        break
                    total += len(chunk)
                    require(total <= 16*1024**2, 'pam_journal_bytes')
                    pending.extend(chunk)
                    while b'\n' in pending:
                        raw, _, rest = pending.partition(b'\n')
                        require(0 < len(raw) <= 16384, 'pam_journal_row_bytes')
                        pending = bytearray(rest)
                        count += 1
                        require(count <= MAX_RECORDS, 'pam_journal_truncated')
                        yield bytes(raw)
                    require(len(pending) <= 16384, 'pam_journal_partial_row_bytes')
            require(not pending, 'pam_journal_partial_row')
            require(process.wait(timeout=max(.01, deadline-time.monotonic())) == 0, 'pam_journal_exit')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.stdout.close()


def private_parent(path):
    import stat

    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and stat.S_ISDIR(info.st_mode) and not path.is_symlink()
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'pam_private_output_parent')
    require(not re.search(r'[\x00-\x1f\x7f]', str(path)), 'pam_output_path')
    return path
