"""Source-local sensitive-command/PAM cooccurrence; never caller attribution."""

import math
import re
import shlex
from datetime import UTC, datetime

from scripts.f1_lab.native_jsonl import MAX_ROW, require

REASON = 'sudo_sensitive_command_cooccurs_with_root_pam_open'
PREFIX = re.compile(r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) '
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) '
    r'(?P<host>[^\s]{1,255}) sudo(?:\[(?P<pid>[1-9]\d{0,9})\])?: (?P<body>[^\r\n]{1,8192})$')
COMMAND = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?\s+: TTY=[^;\r\n]{1,128} ; '
    r'PWD=[^;\r\n]{1,2048} ; USER=root ; COMMAND=(?P<command>[^\r\n]{1,4096})$')
OPEN = re.compile(r'pam_unix\(sudo:session\): session opened for user root(?:\(uid=0\))? '
    r'by (?:[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?)?\(uid=\d{1,10}\)$')
FILES = frozenset({'/etc/shadow', '/etc/gshadow', '/etc/security/opasswd'})
READERS = frozenset({'cat', '/bin/cat', '/usr/bin/cat', 'head', '/bin/head', '/usr/bin/head',
                    'tail', '/bin/tail', '/usr/bin/tail'})


def sensitive_read(body):
    match = COMMAND.fullmatch(body.lstrip(' '))
    if match is None or re.search(r'[;&|<>`$\x00]', match['command']):
        return False
    try:
        args = shlex.split(match['command'])
    except ValueError:
        return False
    return bool(2 <= len(args) <= 16 and args[0] in READERS and any(arg in FILES for arg in args[1:]))


class SensitiveAuthReview:
    """One preceding row, one source/host, at most one second of latency.

    The alert describes a requested sensitive read near a PAM open. Neither
    command success, same-process causality nor human identity is asserted.
    Known conflicting PIDs disqualify the association; missing PIDs stay unknown.
    """
    def __init__(self, source_sha256):
        require(type(source_sha256) is str and len(source_sha256) == 64
                and set(source_sha256) <= set('0123456789abcdef'), 'sensitive_auth_source')
        self.source, self.ordinal, self.high_water, self.pending, self.disabled = source_sha256, 0, None, None, False

    def observe(self, ordinal, line, moment, *, source_sha256):
        require(type(ordinal) is int and ordinal > 0 and type(line) is str
                and len(line.encode('utf8')) <= MAX_ROW, 'sensitive_auth_row')
        old, self.pending = self.pending, None
        if self.disabled:
            return None
        if source_sha256 != self.source or ordinal != self.ordinal+1:
            self.disabled = True
            return None
        self.ordinal = ordinal
        if moment is None:
            return None
        require(type(moment) in {int,float} and math.isfinite(moment), 'sensitive_auth_time')
        if self.high_water is not None and moment < self.high_water:
            self.disabled = True
            return None
        self.high_water = moment
        match = PREFIX.fullmatch(line.rstrip('\r\n'))
        if match is None:
            return None
        try:
            now = datetime.fromtimestamp(moment, UTC)
            parts = (match['month'], *(int(match[k]) for k in ('day','hour','minute','second')))
            require(moment == int(moment) and parts == (now.strftime('%b'),now.day,now.hour,now.minute,now.second),
                    'sensitive_auth_time_binding')
        except (ValueError,OverflowError,OSError):
            self.disabled = True
            return None
        pid = int(match['pid']) if match['pid'] is not None else None
        if pid is not None and pid >= 4294967295:
            return None
        if sensitive_read(match['body']):
            self.pending = (moment, match['host'], pid)
        elif old is not None and OPEN.fullmatch(match['body']):
            before, host, old_pid = old
            if (0 <= moment-before <= 1 and host == match['host']
                    and (pid is None or old_pid is None or pid == old_pid)):
                return REASON
        return None
