"""Causal parser invocation observations for learned triage, never authority.

A replacement is a real policy change, not a no-op or a verified approval.
Only current/earlier physical rows are used; the first status cannot borrow
its later SYSCALL/PROCTITLE. Raw profile names and process IDs are not learned.
"""

import hashlib
import math
import re

from scripts.f1_lab.apparmor_noop import PARSERS, argv_ok, parsed, positive
from scripts.f1_lab.audit_intent_context import IntentObservation
from scripts.f1_lab.native_jsonl import MAX_ROW, require

PROFILE='apparmor-causal-parser-observations-1'
LOOKBACK=5


class AppArmorCausalReview:
    def __init__(self,source_sha256):
        require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}',source_sha256),'apparmor_intent_source')
        self.source,self.ordinal,self.time,self.disabled=source_sha256,0,None,False
        self.events,self.invocations={},{}

    def observe(self,ordinal,line,moment,*,source_sha256):
        require(type(ordinal) is int and ordinal>0 and type(line) is str and len(line.encode())<=MAX_ROW,
            'apparmor_intent_row')
        empty=IntentObservation(self.source,ordinal,hashlib.sha256(line.encode()).hexdigest(),('unknown',),False)
        if self.disabled:return empty
        if (source_sha256!=self.source or ordinal!=self.ordinal+1 or type(moment) not in {int,float}
                or not math.isfinite(moment) or self.time is not None and moment<self.time):
            self.disabled=True;self.events.clear();self.invocations.clear();return empty
        self.ordinal,self.time=ordinal,moment
        for table in (self.events,self.invocations):
            for k in list(table):
                if moment-table[k][-1]>LOOKBACK:del table[k]
            require(len(table)<10000,'apparmor_intent_capacity')
        item=parsed(line)
        if item is None:
            self.events.clear();self.invocations.clear();return empty
        identity,kind,data=item
        if float(identity[0])!=moment:
            self.disabled=True;self.events.clear();self.invocations.clear();return empty
        if kind in {'SYSTEM_BOOT','SYSTEM_SHUTDOWN','DAEMON_START'}:
            self.events.clear();self.invocations.clear();return empty
        if (kind=='SYSCALL' and data.get('pid') in self.invocations
                and (data.get('exe') not in PARSERS or data.get('comm')!='apparmor_parser'
                     or data.get('success')!='yes')):
            self.invocations.pop(data['pid'],None)
        prior=self.events.get(identity,({},moment))[0]
        if kind in prior:
            # A later duplicate cannot rewrite already emitted decisions.
            self.events[identity]=({'invalid':True},moment)
            self.invocations.clear();return empty
        current={**prior,kind:data};self.events[identity]=(current,moment)
        if 'invalid' in current:return empty
        avc=data if kind=='AVC' else current.get('AVC')
        pid=(avc or {}).get('pid')
        mode=None
        if avc is not None:
            name=avc.get('name','')
            good=(avc.get('apparmor')=='STATUS' and avc.get('operation')=='profile_replace'
                and avc.get('comm')=='apparmor_parser' and positive(pid)
                and avc.get('profile')=='unconfined' and re.fullmatch('/[^\x00-\x20\x7f]{1,255}',name)
                and not any(k in avc for k in ('error','denied_mask','requested_mask'))
                and avc.get('info') in {None,'same as current profile, skipping'})
            if not good:
                if pid:self.invocations.pop(pid,None)
                return empty
            mode='changed_profile' if avc.get('info') is None else 'unchanged_profile'
        scope=None;uid=None
        if kind=='AVC' and pid in self.invocations:
            uid=self.invocations[pid][0];scope='prior_parser_invocation'
        if kind=='PROCTITLE' and avc is not None and set(data)=={'proctitle'}:
            system=current.get('SYSCALL',{})
            uid=system.get('uid')
            good=(set(current)=={'AVC','SYSCALL','PROCTITLE'} and system.get('pid')==pid
                and system.get('arch')=='c000003e' and system.get('syscall')=='1'
                and system.get('success')=='yes' and positive(system.get('exit'))
                and system.get('comm')=='apparmor_parser' and system.get('exe') in PARSERS
                and re.fullmatch(r'0|[1-9]\d{0,9}',uid or '') and int(uid)<4294967295
                and not any(k in system for k in ('error','denied_mask'))
                and argv_ok(data['proctitle'],system.get('exe')))
            if good:
                scope='current_parser_invocation';self.invocations[pid]=(uid,moment)
            elif pid:self.invocations.pop(pid,None)
        elif kind=='PROCTITLE' and avc is None:
            self.invocations.pop(current.get('SYSCALL',{}).get('pid'),None)
        if scope is None:return empty
        feature=('apparmor_causal_replace',kind,scope,'observed_root' if uid=='0' else 'observed_nonroot',
            mode,'standard_config_replace')
        return IntentObservation(self.source,ordinal,empty.line_sha256,feature,True)
