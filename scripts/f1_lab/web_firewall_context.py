"""Web-storage firewall requests near netfilter observations; advisory only.

Exact PID/TTY fields bind the requested command to its PAM flow. A later
netfilter event is only same-host/time cooccurrence: no parent/child relation,
successful command, malicious module, person or authorization is inferred.
"""

import math
import re
import shlex
from pathlib import PurePosixPath

from scripts.f1_lab.audit_auth_review import field, number, original_audit_record
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.ordered_audit_login import KEY

REASON='web_storage_firewall_request_cooccurs_with_netfilter_event'
WINDOW=5
SUDO={'/usr/bin/sudo','/bin/sudo'}
FIREWALL={'iptables','ip6tables','/sbin/iptables','/usr/sbin/iptables','/sbin/ip6tables','/usr/sbin/ip6tables'}


def firewall_query(body):
    cwd,encoded=field(body,'cwd'),field(body,'cmd')
    if (not cwd or not cwd.startswith(('/var/www/','/srv/www/','/usr/share/nginx/html/'))
            or '..' in PurePosixPath(cwd).parts or '.' in cwd.split('/') or '//' in cwd
            or not re.search(r'/(?:uploads|cache|tmp)(?:/|$)',cwd)
            or not encoded or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){1,4096}',encoded)):
        return False
    try:
        command=bytes.fromhex(encoded).decode('utf8')
        if re.search(r'[\x00-\x1f\x7f;&|<>`$]',command):return False
        argv=shlex.split(command)
    except (UnicodeError,ValueError):return False
    if argv and argv[0] in FIREWALL:
        flags=argv[1:]
        return bool(1<=len(flags)<=4 and len(flags)==len(set(flags))
            and set(flags)<={'-L','--list','-n','--numeric','-v','--verbose'}
            and sum(f in {'-L','--list'} for f in flags)==1)
    return bool(len(argv)==3 and argv[0] in {'nft','/sbin/nft','/usr/sbin/nft'} and argv[1:]==['list','ruleset'])


def terminal(body):
    value=(field(body,'terminal') or '').removeprefix('/dev/')
    return value if re.fullmatch(r'pts/[0-9]{1,10}',value) else None


def raw_session(body):
    values=tuple(field(body,k) for k in ('auid','ses'))
    return values if all(v and re.fullmatch(r'0|[1-9]\d{0,9}',v) and int(v)<=4294967295 for v in values) else None


class WebFirewallReview:
    def __init__(self,source_sha256):
        require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}',source_sha256),'firewall_context_source')
        self.source,self.ordinal,self.last,self.disabled=source_sha256,0,None,False
        self.pending,self.confirmed={},{}
        self.event=None;self.seen=set();self.origin=None

    def clear(self):
        self.pending.clear();self.confirmed.clear();self.event=None;self.seen.clear();self.origin=None

    def observe(self,ordinal,line,moment,*,source_sha256):
        require(type(ordinal) is int and ordinal>0 and type(line) is str and len(line.encode())<=MAX_ROW,
            'firewall_context_row')
        if self.disabled:return None
        original=original_audit_record(line).rstrip('\r\n')
        match=KEY.fullmatch(original)
        if (source_sha256!=self.source or ordinal!=self.ordinal+1 or type(moment) not in {int,float}
                or not math.isfinite(moment) or match is None
                or re.search(r'[\x00-\x1f\x7f]',original) or float(match['stamp'])!=moment):
            self.disabled=True;self.clear();return None
        serial=int(match['serial']);current=(moment,serial);kind=match['kind'];body=match['body']
        if not 0<serial<2**64 or self.last is not None and (
                moment<self.last[0] or serial<self.last[1] or serial==self.last[1] and moment!=self.last[0]):
            self.disabled=True;self.clear();return None
        self.ordinal,self.last=ordinal,current
        if kind in {'SYSTEM_BOOT','SYSTEM_SHUTDOWN','DAEMON_START'}:
            self.clear();return None
        for table in (self.pending,self.confirmed):
            for pid in list(table):
                if moment-table[pid][0]>WINDOW:del table[pid]
            require(len(table)<10000,'firewall_context_capacity')
        if self.event!=current:
            self.event=None;self.seen.clear();self.origin=None
        if self.event==current:
            if kind in self.seen or kind not in {'SYSCALL','PROCTITLE'}:
                self.event=None;self.origin=None;return None
            self.seen.add(kind)
            return REASON
        pid=number(body,'pid');tty=terminal(body);session=raw_session(body)
        if kind=='USER_CMD':
            if pid:self.pending.pop(pid,None);self.confirmed.pop(pid,None)
            if (pid and number(body,'uid') is not None and tty and session is not None
                    and field(body,'res')=='success' and firewall_query(body)):
                self.pending[pid]=(moment,tty,session,False)
            return None
        if kind in {'CRED_REFR','USER_START','USER_END','CRED_DISP'} and pid:
            seed=self.pending.get(pid)
            matched=(seed and tty==seed[1] and session==seed[2] and number(body,'uid')==0
                and field(body,'acct')=='root' and field(body,'exe') in SUDO and field(body,'res')=='success')
            if kind in {'USER_END','CRED_DISP'} or not matched:
                self.pending.pop(pid,None);self.confirmed.pop(pid,None)
            elif kind=='CRED_REFR':self.pending[pid]=(*seed[:3],True)
            elif kind=='USER_START' and seed[3]:self.confirmed[pid]=seed
            return None
        if kind=='NETFILTER_CFG':
            table=field(body,'table');family=number(body,'family');entries=number(body,'entries')
            if (table and re.fullmatch(r'[A-Za-z0-9_.:-]{1,256}',table) and family is not None
                    and 0<=family<=255 and entries is not None and len(self.confirmed)==1):
                origin=next(iter(self.confirmed.values()))
                if 0<=moment-origin[0]<=WINDOW:
                    self.origin=origin;self.event=current;self.seen={'NETFILTER_CFG'}
                    # One confirmed request can seed only one netfilter event.
                    self.pending.clear();self.confirmed.clear()
                    return REASON
        return None
