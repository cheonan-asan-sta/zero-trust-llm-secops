"""Source-pinned current/past VPN observations for learned advisory triage.

Certificate subject equality and peer claims are observations, never identity,
device health or authority. No raw identifiers/timestamps enter learned values.
"""

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.vpn_context import PREFIX, endpoint
from scripts.f1_lab.vpn_control_review import ControlObservation, observe_control
from scripts.f1_lab.vpn_precision_audit import informational_declaration, signature
from scripts.f1_lab.vpn_risk_retention import retained_contexts

PROFILE='vpn-causal-protocol-1'
ADVERSE_SECONDS=60
PLATFORMS={'linux','solaris','openbsd','mac','netbsd','freebsd','win','android','ios'}
BAD_FLAGS=('auth_failure','tls_failure','sensitive_file','sql_injection','path_traversal','shell_payload',
           'command_parameter','uploaded_script','scanner_agent')


def empty():
    return {'initial':False,'leaf':False,'ku':False,'eku':False,'platform':'unknown','version':'unknown',
            'subject_prior_peer':False,'subject_seen':False}


@dataclass(frozen=True)
class ProtocolObservation:
    source_sha256: str
    ordinal: int
    line_sha256: str
    projection_sha256: str
    available: bool
    protected: bool
    control: ControlObservation | None = None


class ProtocolReview:
    def __init__(self,source_sha256):
        require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}',source_sha256),'protocol_source')
        self.source,self.ordinal,self.time,self.disabled=source_sha256,0,None,False
        self.state,self.subject_peers,self.peer_subjects,self.adverse={},{},{},{}
        self.unbound_adverse=None

    def observe(self,ordinal,line,moment,*,source_sha256):
        require(type(ordinal) is int and ordinal>0 and type(line) is str and len(line.encode())<=MAX_ROW,
                'protocol_row')
        digest=hashlib.sha256(line.encode()).hexdigest()
        def unavailable():
            return ProtocolObservation(self.source,ordinal,digest,hashlib.sha256(canonical({'available':False})).hexdigest(),False,True)
        if self.disabled:return unavailable()
        if source_sha256!=self.source or ordinal!=self.ordinal+1:
            self.disabled=True;return unavailable()
        self.ordinal=ordinal
        if moment is None or type(moment) not in {int,float} or not math.isfinite(moment):
            self.disabled=True;return unavailable()
        try:bound=datetime.fromisoformat(line[:19]).replace(tzinfo=UTC).timestamp()
        except (ValueError,OverflowError,OSError):bound=None
        if bound!=moment or self.time is not None and moment<self.time:
            self.disabled=True;return unavailable()
        self.time=moment
        for table,ttl in ((self.state,300),(self.subject_peers,86400),(self.peer_subjects,86400),
                          (self.adverse,ADVERSE_SECONDS)):
            for k in list(table):
                if moment-table[k][-1]>ttl:del table[k]
            require(len(table)<10000,'protocol_capacity')
        if self.unbound_adverse is not None and moment-self.unbound_adverse>ADVERSE_SECONDS:
            self.unbound_adverse=None
        ep=endpoint(line)
        match=PREFIX.match(line)
        flags=raw_features(line)
        bad=any(flags[k] for k in BAD_FLAGS) or bool(re.search(r'\bVERIFY(?: SCRIPT)? ERROR:',line))
        if bad:
            if ep:
                self.adverse['connection',ep[1]]=(moment,)
                self.adverse['peer',ep[0]]=(moment,)
            else:self.unbound_adverse=moment
        if ep is None or match is None:return unavailable()
        peer,connection,named,initial=ep;body=line[match.end():].rstrip('\r\n')
        current=self.state.get(connection,(empty(),moment))[0].copy()
        if initial:current=empty()
        prior_subject=self.peer_subjects.get(peer)
        subject=re.fullmatch(r'VERIFY OK: depth=0, CN=([^\r\n]{1,256})',body)
        subject_hash=hashlib.sha256(subject[1].encode()).digest() if subject else None
        lookup=self.subject_peers.get(subject_hash) if subject else None
        phase=next((name for text,name in [('TLS: Initial packet','initial'),('VERIFY OK: depth=0','leaf'),
            ('VERIFY OK:','issuer'),('VERIFY KU OK','ku'),('VERIFY EKU OK','eku'),('peer info:','peer_info'),
            ('Control Channel:','control'),('MULTI:','route'),('PUSH:','push')]
            if body.startswith(text)),'data_declaration' if informational_declaration(line) else 'other')
        os_match=re.fullmatch(r'peer info: IV_PLAT=([a-z]{1,32})',body)
        version=re.fullmatch(r'peer info: IV_VER=([0-9])[.][^\r\n]{1,64}',body)
        os_name=os_match[1] if os_match and os_match[1] in PLATFORMS else 'unknown'
        features={'available':True,**current,'phase':phase,'named':named,'peer_subject_observed':prior_subject is not None,
            'current_leaf_seen_before':lookup is not None,
            'current_leaf_other_peer':bool(lookup and any(p!=peer for p in lookup[0])),
            'reported_platform':os_name if os_match else current['platform'],
            'reported_version_major':version[1] if version else current['version']}
        protected=bool(bad or ('connection',connection) in self.adverse or ('peer',peer) in self.adverse
                 or self.unbound_adverse is not None)
        observed=ProtocolObservation(self.source,ordinal,digest,hashlib.sha256(canonical(features)).hexdigest(),True,
            protected,observe_control(self.source,ordinal,line,features,protected))
        # Query the preceding state before publishing this row. A current
        # certificate/claim is visible only as a current observation above.
        if initial:current['initial']=True
        if phase=='ku':current['ku']=True
        if phase=='eku':current['eku']=True
        if os_match:current['platform']=os_name
        if version:current['version']=version[1]
        if subject:
            current.update(leaf=True,subject_seen=lookup is not None,
                subject_prior_peer=bool(lookup and any(p!=peer for p in lookup[0])))
            peers=set(lookup[0]) if lookup else set();peers.add(peer)
            require(len(peers)<=1000,'protocol_subject_capacity')
            self.subject_peers[subject_hash]=(frozenset(peers),moment)
            self.peer_subjects[peer]=(subject_hash,moment)
        self.state[connection]=(current,moment)
        return observed


def feature_key(legacy_projection,observation):
    require(type(legacy_projection) is str and re.fullmatch('[a-f0-9]{64}',legacy_projection)
            and isinstance(observation,ProtocolObservation),'protocol_key')
    return hashlib.sha256(canonical({'profile':PROFILE,'legacy_projection':legacy_projection,
        'protocol_projection':observation.projection_sha256})).hexdigest()


def project(records,source_sha256,legacy_model):
    """Every original ordinal is returned, including unavailable observations."""
    retained=retained_contexts(records,source_sha256,legacy_model.vpn_model)
    by_ordinal={value.base.ordinal:value for value in retained.values()}
    review=ProtocolReview(source_sha256);result={}
    for ordinal,moment,line in records:
        observation=review.observe(ordinal,line,moment,source_sha256=source_sha256)
        context=by_ordinal[ordinal]
        features={**core_features(line),**semantic_observations(line)}
        previous=legacy_model.decide(features,context.base.case_id,context)
        legacy=signature({**context.base.vpn_features,**semantic_observations(line)},context,
            informational_declaration(line))
        result[ordinal]=(legacy,observation,previous)
    require(len(result)==len(records),'protocol_projection_population')
    return result
