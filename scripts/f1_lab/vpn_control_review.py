"""Observed VPN control flow for advisory review, never an authority grant.

Client OS/version claims and exact retained scores/ages are not features here.
Each request/reply phase has its own normal/attack support and attack veto.
"""

import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.vpn_context import PREFIX

PROFILE='causal-vpn-control-1'
SCHEMA='vpn-control-advisory-head-1'
FIELDS=('initial','leaf','ku','eku','named','subject_prior_peer','subject_seen','peer_subject_observed')
REASONS={'vpn_history_risk_review','vpn_strict_past_risk_retained'}


def phase(line):
    prefix=PREFIX.match(line)
    if not prefix or not prefix['name']:return None
    body=line[prefix.end():].rstrip('\r\n')
    if body=="PUSH: Received control message: 'PUSH_REQUEST'":return 'request'
    match=re.fullmatch(r"SENT CONTROL \[([^\[\]\r\n]{1,256})\]: 'PUSH_REPLY,([^'\r\n]{1,4096})' \(status=1\)",body)
    if not match or match[1]!=prefix['name']:return None
    options=match[2].split(',')
    if not 1<=len(options)<=32:return None
    seen=set()
    for token in options:
        bits=token.split(' ')
        if bits[0] in seen:return None
        seen.add(bits[0])
        if bits in [['redirect-gateway','def1'],['block-outside-dns'],['topology','net30'],['topology','subnet']]:continue
        if bits[0] in {'ping','ping-restart','peer-id'} and len(bits)==2 and re.fullmatch(r'0|[1-9]\d{0,7}',bits[1]):
            if (bits[0]=='peer-id' and int(bits[1])<=16777215
                    or bits[0]!='peer-id' and 1<=int(bits[1])<=86400):continue
            return None
        if bits[0]=='cipher' and len(bits)==2 and re.fullmatch(r'(?:AES-(?:128|192|256)-(?:CBC|GCM)|CHACHA20-POLY1305)',bits[1]):continue
        if bits[0]=='route' and len(bits) in {2,3} or bits[0]=='ifconfig' and len(bits)==3:
            try:
                for value in bits[1:]:ipaddress.IPv4Address(value)
                if bits[0]=='route' and len(bits)==3:ipaddress.IPv4Network('0.0.0.0/'+bits[2])
            except ValueError:return None
            continue
        return None
    return 'reply'


@dataclass(frozen=True)
class ControlObservation:
    source_sha256: str
    ordinal: int
    line_sha256: str
    projection_sha256: str
    protected: bool


def observe_control(source,ordinal,line,features,protected):
    """Called after source/order/time validation by ProtocolReview."""
    kind=phase(line)
    if kind is None or not all(features.get(k) is True for k in ('initial','leaf','ku','eku','named')):return None
    require(all(type(features.get(k)) is bool for k in FIELDS) and type(protected) is bool,'control_feature_types')
    value={'profile':PROFILE,'phase':kind,**{k:features[k] for k in FIELDS}}
    return ControlObservation(source,ordinal,hashlib.sha256(line.encode()).hexdigest(),
        hashlib.sha256(canonical(value)).hexdigest(),protected)


class ControlHead:
    def __init__(self,legacy_pin,base_pin):
        require(all(type(p) is str and re.fullmatch('[a-f0-9]{64}',p) for p in (legacy_pin,base_pin)),'control_dependencies')
        self.legacy_pin,self.base_pin=legacy_pin,base_pin
        self.rows={};self.frozen=False

    def add(self,observation,malicious):
        require(not self.frozen and type(malicious) is bool,'control_fit_contract')
        if observation is None:return
        require(isinstance(observation,ControlObservation),'control_observation_type')
        counts=self.rows.setdefault(observation.projection_sha256,[0,0]);counts[int(malicious)]+=1

    def save(self,path):
        require(not self.frozen and self.rows,'control_empty_model')
        self.frozen=True
        value={'schema':SCHEMA,'profile':PROFILE,'minimum_support':5,'rows':self.rows,
            'legacy_models_sha256':self.legacy_pin,'base_model_sha256':self.base_pin,'automatic_enforcement_allowed':False}
        Path(path).write_bytes(canonical(value)+b'\n');return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @classmethod
    def load(cls,path,pin,legacy_pin,base_pin):
        path=Path(path);require(path.is_file() and not path.is_symlink(),'control_model_file')
        with path.open('rb') as stream:body=stream.read(2*1024**2+1)
        require(len(body)<=2*1024**2 and hashlib.sha256(body).hexdigest()==pin,'control_model_pin')
        value=decode(body)
        require(set(value)=={'schema','profile','minimum_support','rows','legacy_models_sha256','base_model_sha256',
            'automatic_enforcement_allowed'} and value['schema']==SCHEMA and value['profile']==PROFILE
            and type(value['minimum_support']) is int and value['minimum_support']==5
            and value['automatic_enforcement_allowed'] is False and value['legacy_models_sha256']==legacy_pin
            and value['base_model_sha256']==base_pin and type(value['rows']) is dict
            and 0<len(value['rows'])<=10000,'control_model_scope')
        for key,counts in value['rows'].items():
            require(re.fullmatch('[a-f0-9]{64}',key) and type(counts) is list and len(counts)==2
                and all(type(n) is int and 0<=n<=1000000 for n in counts),'control_model_counts')
        head=cls(legacy_pin,base_pin);head.rows=value['rows'];head.frozen=True;return head

    def refine(self,previous,observation,*,source_sha256,ordinal,raw):
        require(self.frozen and isinstance(previous,OperationDecision) and previous.automatic_enforcement_allowed is False,
            'control_previous')
        require(type(previous.alert) is bool and type(previous.review) is bool
            and all(type(v) in {int,float} and math.isfinite(v) and 0<=v<=1
                for v in (previous.baseline_score,previous.score)),'control_previous_values')
        if observation is None:return previous
        require(isinstance(observation,ControlObservation) and observation.source_sha256==source_sha256
            and observation.ordinal==ordinal and observation.line_sha256==hashlib.sha256(raw.encode()).hexdigest(),
            'control_observation_binding')
        if observation.protected or previous.baseline_score>=.95 or previous.reason not in REASONS or not previous.alert:return previous
        counts=self.rows.get(observation.projection_sha256)
        if counts is None or counts[0]<5 or counts[1]:return previous
        return OperationDecision(previous.baseline_score,previous.baseline_score,False,True,'learned_vpn_control_review')
