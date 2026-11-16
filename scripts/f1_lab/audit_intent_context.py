"""Observed audit roles/intents for a learned advisory refinement, not trust.

No names, IDs, addresses or absolute times are learned features. UID is the
event-generating process UID; a login target and loginuid remain separate.
"""

import hashlib
import math
import re
import shlex
from dataclasses import dataclass

from scripts.f1_lab.audit_auth_review import AUDIT, field, number
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.raw_observations import raw_features

SSHD = {'/usr/sbin/sshd', '/sbin/sshd'}
SUDO = {'/usr/bin/sudo', '/bin/sudo'}
HARD = ('auth_failure','tls_failure','sensitive_file','sql_injection','path_traversal',
        'shell_payload','command_parameter','uploaded_script','scanner_agent')
PHASES = {'USER_CMD','CRED_REFR','USER_START','USER_END','CRED_DISP'}


def command_intent(value):
    if not value or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){1,4096}',value):
        return 'unknown', ''
    try:
        text = bytes.fromhex(value).decode('utf8')
        if re.search(r'[\x00-\x1f\x7f;&|<>`$]',text):
            return 'unknown', text
        args = shlex.split(text)
    except (UnicodeError,ValueError):
        return 'unknown', ''
    readers = {'cat','head','tail','/bin/cat','/bin/head','/bin/tail',
               '/usr/bin/cat','/usr/bin/head','/usr/bin/tail'}
    if (len(args)==2 and args[0] in readers
            and args[1] in {'/var/log/syslog','/var/log/messages','/var/log/kern.log'}):
        return 'operational_log_read', text
    return 'unknown', text


def tty(value):
    value = value or ''
    value = value.removeprefix('/dev/')
    return value if re.fullmatch(r'pts/\d{1,10}',value) else None


@dataclass(frozen=True)
class IntentObservation:
    source_sha256: str
    ordinal: int
    line_sha256: str
    key: tuple[str,...]
    eligible: bool


class AuditIntentReview:
    def __init__(self, source_sha256):
        require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}',source_sha256), 'intent_source')
        self.source, self.ordinal, self.time, self.disabled = source_sha256, 0, None, False
        self.authentication, self.assignments, self.starts, self.sessions, self.commands, self.hazards = {}, {}, {}, {}, {}, {}

    def observe(self, ordinal, line, moment, *, source_sha256):
        require(type(ordinal) is int and ordinal>0 and type(line) is str and len(line.encode())<=MAX_ROW,
                'intent_row')
        empty = IntentObservation(self.source,ordinal,hashlib.sha256(line.encode()).hexdigest(),('unknown',),False)
        if self.disabled:
            return empty
        if source_sha256 != self.source or ordinal != self.ordinal+1:
            self.disabled=True
            return empty
        self.ordinal=ordinal
        if moment is None:
            self.commands.clear()
            return empty
        require(type(moment) in {int,float} and math.isfinite(moment),'intent_time')
        if self.time is not None and moment<self.time:
            self.disabled=True
            return empty
        self.time=moment
        for mapping,ttl in ((self.authentication,5),(self.assignments,5),(self.starts,5),(self.sessions,3600),
                            (self.commands,2),(self.hazards,300)):
            for key in list(mapping):
                if moment-mapping[key][-1]>ttl:
                    del mapping[key]
            require(len(mapping)<10000,'intent_capacity')
        match=AUDIT.fullmatch(line.rstrip('\r\n'))
        if match is None:
            return empty
        body,kind=match['body'],match['kind']
        if kind in {'SYSTEM_BOOT','SYSTEM_SHUTDOWN','DAEMON_START'}:
            for state in (self.authentication,self.assignments,self.starts,self.sessions,self.commands,self.hazards):
                state.clear()
            return empty
        # Bind the supplied clock to this exact audit record, not a caller's
        # arbitrary timestamp. Same-time earlier source ordinals are visible.
        stamp=re.match(r'^type=[A-Z_]+ msg=audit\((\d+(?:\.\d+)?):',line)
        if stamp is None or float(stamp[1])!=moment:
            self.disabled=True
            return empty
        pid,uid,auid,ses=(number(body,k) for k in ('pid','uid','auid','ses'))
        exe,account,res=field(body,'exe'),field(body,'acct'),field(body,'res')
        success=res=='success'
        session=(auid,ses)
        valid_session=auid is not None and auid>0 and ses is not None
        intent,decoded=command_intent(field(body,'cmd')) if kind=='USER_CMD' else ('unknown','')
        flags=raw_features(line+' '+decoded)
        hazard=any(flags[k] for k in HARD) or exe in {'/bin/su','/usr/bin/su'}
        address=field(body,'addr')
        address_key=(hashlib.sha256(address.encode()).hexdigest()
                     if address and address not in {'?','(none)'} and len(address)<=255 else None)
        if hazard:
            if pid:self.hazards[('pid',pid)]=(moment,)
            if auid is not None:self.hazards[('auid',auid)]=(moment,)
            if address_key:self.hazards[('addr',address_key)]=(moment,)
        blocked=(hazard or ('pid',pid) in self.hazards or ('auid',auid) in self.hazards
                 or address_key is not None and ('addr',address_key) in self.hazards)
        nonroot=bool(account and account not in {'root','(unknown)','?'} and len(account)<=64)
        if kind in {'USER_AUTH','USER_ACCT','CRED_ACQ'} and success and exe in SSHD and pid and nonroot and not blocked:
            previous=self.authentication.get(pid)
            account_sha=hashlib.sha256(account.encode()).hexdigest()
            stages=set(previous[1]) if previous and previous[0]==account_sha else set()
            stages.add(kind)
            self.authentication[pid]=(account_sha,frozenset(stages),moment)
        if kind=='LOGIN' and field(body,'res')=='1' and pid and uid==0 and valid_session and not blocked:
            auth=self.authentication.get(pid)
            if auth and {'USER_ACCT','CRED_ACQ'} <= auth[1]:
                self.assignments[pid]=(session,moment)
        if kind=='USER_START' and success and exe in SSHD and pid and nonroot and valid_session and not blocked:
            auth=self.authentication.get(pid)
            assignment=self.assignments.get(pid)
            if (auth and auth[0]==hashlib.sha256(account.encode()).hexdigest()
                    and {'USER_ACCT','CRED_ACQ'} <= auth[1] and assignment and assignment[0]==session):
                self.starts[pid]=(session,tty(field(body,'terminal')),moment)
        scope=None
        if kind=='USER_LOGIN' and success and exe in SSHD and uid==0 and valid_session and not blocked:
            start=self.starts.get(pid)
            terminal=tty(field(body,'terminal'))
            if start and start[0]==session and number(body,'id')==auid and terminal is not None:
                scope='sshd_nonroot_target_flow'
                self.sessions[session]=(pid,terminal,moment)
        logged_session=self.sessions.get(session) if valid_session else None
        terminal=tty(field(body,'terminal'))
        if (kind=='USER_CMD' and success and pid and uid==auid and valid_session
                and logged_session and terminal==logged_session[1] and not blocked
                and intent=='operational_log_read'):
            scope='diagnostic_sudo_flow'
            self.commands[pid]=(session,terminal,moment)
        elif kind in PHASES-{'USER_CMD'}:
            pending=self.commands.get(pid)
            if (pending and pending[0]==session and terminal==pending[1] and success
                    and account=='root' and exe in SUDO and uid==0 and not blocked):
                scope='diagnostic_sudo_flow'
            elif pid in self.commands:
                del self.commands[pid]
        if kind=='CRED_DISP':
            self.commands.pop(pid,None)
        if kind=='USER_END' and logged_session and logged_session[0]==pid and exe in SSHD:
            self.sessions.pop(session,None)
        key=(scope or 'unknown',kind,'sshd' if exe in SSHD else 'sudo' if exe in SUDO else 'none',
             'root' if uid==0 else 'nonroot' if uid is not None else 'unset',
             'nonroot' if valid_session else 'unset','success' if success else 'other')
        return IntentObservation(self.source,ordinal,empty.line_sha256,key,bool(scope and not blocked))
