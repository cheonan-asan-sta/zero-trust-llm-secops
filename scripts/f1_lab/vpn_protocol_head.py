"""Frozen normal/attack cell counts; review retained and authority untouched."""

import hashlib
import math
import re
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.vpn_protocol_review import PROFILE, ProtocolObservation, feature_key

SCHEMA='vpn-protocol-advisory-head-1'
REASONS={'vpn_history_risk_review','vpn_strict_past_risk_retained'}


class ProtocolHead:
    def __init__(self,legacy_models_sha256):
        require(type(legacy_models_sha256) is str and re.fullmatch('[a-f0-9]{64}',legacy_models_sha256),
                'protocol_legacy_models')
        self.legacy_models_sha256=legacy_models_sha256;self.rows={};self.frozen=False

    def add(self,legacy_projection,observation,malicious):
        require(not self.frozen and type(malicious) is bool,'protocol_fit_contract')
        if observation.available:
            counts=self.rows.setdefault(feature_key(legacy_projection,observation),[0,0]);counts[int(malicious)]+=1

    def save(self,path):
        require(not self.frozen and self.rows,'protocol_empty_model')
        self.frozen=True
        value={'schema':SCHEMA,'profile':PROFILE,'minimum_support':5,'rows':self.rows,
            'legacy_models_sha256':self.legacy_models_sha256,'automatic_enforcement_allowed':False}
        Path(path).write_bytes(canonical(value)+b'\n')
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @classmethod
    def load(cls,path,pin,legacy_models_sha256):
        path=Path(path);require(path.is_file() and not path.is_symlink(),'protocol_model_file')
        with path.open('rb') as stream:body=stream.read(2*1024**2+1)
        require(len(body)<=2*1024**2 and hashlib.sha256(body).hexdigest()==pin,'protocol_model_pin')
        value=decode(body)
        require(set(value)=={'schema','profile','minimum_support','rows','legacy_models_sha256','automatic_enforcement_allowed'}
            and value['schema']==SCHEMA and value['profile']==PROFILE and type(value['minimum_support']) is int
            and value['minimum_support']==5 and value['automatic_enforcement_allowed'] is False
            and value['legacy_models_sha256']==legacy_models_sha256 and type(value['rows']) is dict
            and 0<len(value['rows'])<=10000,'protocol_model_scope')
        for key,counts in value['rows'].items():
            require(re.fullmatch('[a-f0-9]{64}',key) and type(counts) is list and len(counts)==2
                and all(type(n) is int and 0<=n<=1000000 for n in counts),'protocol_model_counts')
        head=cls(legacy_models_sha256);head.rows=value['rows'];head.frozen=True;return head

    def refine(self,previous,legacy_projection,observation,*,source_sha256,ordinal,raw):
        require(self.frozen and isinstance(previous,OperationDecision)
            and previous.automatic_enforcement_allowed is False,'protocol_previous')
        require(type(previous.alert) is bool and type(previous.review) is bool
            and all(type(v) in {int,float} and math.isfinite(v) and 0<=v<=1
                for v in (previous.baseline_score,previous.score)),'protocol_previous_values')
        require(isinstance(observation,ProtocolObservation) and observation.source_sha256==source_sha256
            and observation.ordinal==ordinal and observation.line_sha256==hashlib.sha256(raw.encode()).hexdigest(),
            'protocol_observation_binding')
        if (not observation.available or observation.protected or previous.baseline_score>=.95
                or previous.reason not in REASONS or not previous.alert):return previous
        counts=self.rows.get(feature_key(legacy_projection,observation))
        if counts is None or counts[0]<5 or counts[1]:return previous
        return OperationDecision(previous.baseline_score,previous.baseline_score,False,True,
            'learned_vpn_protocol_review')
