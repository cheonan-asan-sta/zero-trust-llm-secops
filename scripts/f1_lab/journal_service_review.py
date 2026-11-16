"""Prior journal process observations near service audit records; advisory only.

Boot/unit/invocation link observed service metadata, never the human caller or
successful exfiltration. Receipt time gates availability; no future backfill.
"""

import bisect
import hashlib
import re
import shlex
from decimal import Decimal, InvalidOperation

from scripts.f1_lab.audit_auth_review import field, number, original_audit_record
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.ordered_audit_login import KEY
from scripts.f1_lab.raw_observations import entropy
from scripts.f1_lab.transfer_evaluation import sha

REASON='prior_journal_service_encoded_dns_error'
WINDOW_US=5_000_000
HEX=re.compile('[a-f0-9]{32}')
UNIT=re.compile(r'[A-Za-z0-9_@.:-]{1,255}[.]service')
SHELLS={'/bin/bash','/usr/bin/bash','/bin/sh','/usr/bin/sh','/bin/dash','/usr/bin/dash'}


def micros(value):
    if type(value) is not str or not re.fullmatch(r'\d{1,12}(?:[.]\d{1,6})?',value):return None
    try:result=Decimal(value)*1_000_000
    except InvalidOperation:return None
    return int(result) if 0<=result<4102444800_000000 else None


def journal_time(row):
    def timestamp(key):
        value=row.get(key)
        return int(value) if type(value) is str and re.fullmatch(r'[1-9]\d{0,15}',value) and int(value)<4102444800_000000 else None
    received=timestamp('__REALTIME_TIMESTAMP');origin=timestamp('_SOURCE_REALTIME_TIMESTAMP')
    if received is None or '_SOURCE_REALTIME_TIMESTAMP' in row and origin is None:return None
    return max(received,origin or received)


def encoded_dns_error(message):
    if type(message) is not str:return False
    match=re.fullmatch(r"dig: '([^'\x00-\x20\x7f]{1,8192})' is not a legal name \(ran out of space\)",message)
    if match is None:return False
    query=match[1];parts=query.removesuffix('.').split('.')
    if not all(parts):return False
    # Multiple long, high-entropy labels with non-hostname base64 characters.
    # This is an attempted query shape, not proof of a sent packet or theft.
    payload=[p for p in parts if 40<=len(p)<=128 and re.fullmatch(r'[A-Za-z0-9+/*=_-]+',p) and entropy(p)>=4.5]
    wire_length=1+sum(1+len(p) for p in parts)
    return bool(wire_length>255 and len(payload)>=3 and any(re.search(r'[+/*=]',p) for p in payload))


def shell_script(row):
    if row.get('_EXE') not in SHELLS or row.get('_UID')!='0':return False
    command=row.get('_CMDLINE')
    if type(command) is not str or re.search(r'[\x00-\x1f\x7f;&|<>`$]',command):return False
    try:argv=shlex.split(command)
    except ValueError:return False
    return bool(len(argv)==2 and argv[0] in SHELLS and re.fullmatch(r'/(?:usr/)?(?:local/)?bin/[^/\x00-\x20]{1,255}',argv[1])
        and argv[1].rsplit('/',1)[-1] not in {'.','..'})


class JournalServiceReview:
    def __init__(self,source_pin,raw_lines,members):
        require(type(source_pin) is str and re.fullmatch('[a-f0-9]{64}',source_pin),'journal_audit_source')
        require(len(raw_lines)<=100000 and all(type(line) is str and len(line.encode())<=MAX_ROW for line in raw_lines),
            'journal_audit_rows')
        body=''.join(raw_lines).encode()
        require(len(body)<=64*1024**2 and hashlib.sha256(body).hexdigest()==source_pin,'journal_audit_source_pin')
        self.source=source_pin;self.ordinal=0;self.last=None;self.disabled=False;self.boot_floor=0
        self.line_pins=[hashlib.sha256(line.encode()).hexdigest() for line in raw_lines]
        self.anchors=[];self.entries=[];self.starts={};self.risks={};self.latest=None;self.position=0
        lookup={}
        for ordinal,line in enumerate(raw_lines,1):
            m=KEY.fullmatch(original_audit_record(line).rstrip('\r\n'))
            if m:
                key=(micros(m['stamp']),m['serial'],m['kind']+' '+m['body'])
                lookup[key]=ordinal if key not in lookup else None
        self.pins=[]
        for member in members:
            path=member['path'];pin=member['sha256'];machine=member['machine_id'];hostname=member['hostname']
            require(sha(path,64*1024**2)==pin and HEX.fullmatch(machine),'journal_sidecar_pin')
            self.pins.append((path,pin));count=size=0
            with open(path,'rb') as stream:
                for n,body in enumerate(stream,1):
                    count+=1;size+=len(body)
                    require(count<=100000 and len(body)<=MAX_ROW and size<=64*1024**2,'journal_sidecar_bound')
                    row=decode(body);available=journal_time(row);boot=row.get('_BOOT_ID')
                    if (available is None or row.get('_MACHINE_ID')!=machine or row.get('_HOSTNAME')!=hostname
                            or type(boot) is not str or HEX.fullmatch(boot) is None):continue
                    reference={'journal_sha256':pin,'journal_ordinal':n,'row_sha256':hashlib.sha256(body).hexdigest()}
                    self.entries.append((available,boot,row,reference))
                    require(len(self.entries)<=200000,'journal_total_records')
                    if row.get('_TRANSPORT')=='audit':
                        origin=row.get('_SOURCE_REALTIME_TIMESTAMP');serial=row.get('_AUDIT_ID');message=row.get('MESSAGE')
                        if type(origin) is str and origin.isdigit() and type(serial) is str and type(message) is str:
                            anchor=lookup.get((int(origin),serial,message))
                            if anchor:self.anchors.append((available,anchor,boot))
        self.entries.sort(key=lambda r:(r[0],r[1],r[3]['journal_sha256'],r[3]['journal_ordinal']))
        self.anchors.sort()
        require(len(self.entries)<=200000,'journal_total_records')
        self.times=[r[0] for r in self.entries]

    def observe(self,ordinal,line,*,source_sha256):
        m=KEY.fullmatch(original_audit_record(line).rstrip('\r\n'))
        current=micros(m['stamp']) if m else None
        if self.disabled:return None
        if (source_sha256!=self.source or ordinal!=self.ordinal+1 or current is None
                or not 1<=ordinal<=len(self.line_pins) or hashlib.sha256(line.encode()).hexdigest()!=self.line_pins[ordinal-1]
                or not 0<int(m['serial'])<2**64 or self.last is not None and (
                    current<int(self.last[0]) or int(m['serial'])<self.last[1]
                    or int(m['serial'])==self.last[1] and current!=self.last[0])):
            self.disabled=True;return None
        self.ordinal,self.last=ordinal,(current,int(m['serial']))
        if m['kind'] in {'SYSTEM_BOOT','SYSTEM_SHUTDOWN','DAEMON_START'}:
            self.risks.clear();self.starts.clear();self.latest=None;self.boot_floor=ordinal
        end=bisect.bisect_right(self.times,current)
        for available,boot,row,reference in self.entries[self.position:end]:
            if self.latest is not None and available==self.latest[0] and boot!=self.latest[1]:
                self.latest=(available,None)
            else:self.latest=(available,boot)
            unit=row.get('UNIT');invocation=row.get('INVOCATION_ID')
            if (row.get('_TRANSPORT')=='journal' and row.get('_PID')=='1' and row.get('_UID')=='0'
                    and row.get('JOB_TYPE')=='start' and type(unit) is str and UNIT.fullmatch(unit)
                    and type(invocation) is str and HEX.fullmatch(invocation)):
                self.starts[boot,unit]=(available,invocation)
            unit=row.get('_SYSTEMD_UNIT');invocation=row.get('_SYSTEMD_INVOCATION_ID')
            start=self.starts.get((boot,unit)) if type(unit) is str else None
            pid=row.get('_PID')
            if (row.get('_TRANSPORT')=='stdout' and type(unit) is str and UNIT.fullmatch(unit)
                    and type(invocation) is str and HEX.fullmatch(invocation) and start and start[1]==invocation
                    and type(pid) is str and re.fullmatch(r'[1-9]\d{0,9}',pid) and int(pid)>1
                    and shell_script(row) and encoded_dns_error(row.get('MESSAGE'))):
                self.risks[boot,unit]=(available,invocation,pid,reference)
        self.position=end
        self.risks={k:v for k,v in self.risks.items() if current-v[0]<=WINDOW_US}
        if m['kind'] not in {'SERVICE_START','SERVICE_STOP'}:return None
        body=m['body'];unit=field(body,'unit')
        if (not unit or UNIT.fullmatch(unit+'.service') is None or number(body,'pid')!=1 or number(body,'uid')!=0
                or field(body,'comm')!='systemd' or field(body,'exe') not in {'/lib/systemd/systemd','/usr/lib/systemd/systemd'}
                or field(body,'res')!='success'):return None
        anchors=[(prior,boot) for available,prior,boot in self.anchors if available<=current and self.boot_floor<prior<ordinal]
        if not anchors:return None
        highest=max(p for p,_ in anchors);boots={boot for p,boot in anchors if p==highest}
        if len(boots)!=1:return None
        boot=next(iter(boots));risk=self.risks.get((boot,unit+'.service'))
        if risk is None or self.latest is None or self.latest[1]!=boot:return None
        start=self.starts.get((boot,unit+'.service'))
        if not start or start[1]!=risk[1]:return None
        return {'reason':REASON,'audit_source_sha256':self.source,'audit_ordinal':ordinal,
            'evidence_age_microseconds':current-risk[0],'reported_process_pid':risk[2],
            'reported_uid':'0','human_caller_verified':False,**risk[3]}

    def verify(self):
        require(all(sha(path,64*1024**2)==pin for path,pin in self.pins),'journal_sidecar_drift')
