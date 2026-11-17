"""Frozen categorical training counts for audit intent triage, never grants."""

import hashlib
import json
from pathlib import Path

from scripts.f1_lab.audit_intent_context import IntentObservation
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision

SCHEMA='audit-intent-categorical-head-1'


def key(value):
    return json.dumps(list(value),separators=(',',':'))


class IntentHead:
    def __init__(self, *, minimum_support=5):
        require(type(minimum_support) is int and 5<=minimum_support<=1000,'intent_min_support')
        self.minimum_support=minimum_support
        self.rows={}
        self.frozen=False

    def add(self, observation, malicious):
        require(not self.frozen and isinstance(observation,IntentObservation) and type(malicious) is bool,
                'intent_training_contract')
        if observation.eligible:
            counts=self.rows.setdefault(key(observation.key),[0,0])
            counts[int(malicious)]+=1

    def freeze(self):
        require(not self.frozen and self.rows,'intent_empty_model')
        self.frozen=True
        return {'schema':SCHEMA,'minimum_support':self.minimum_support,'rows':self.rows,
                'scope':'observed categorical intent triage; not authorization or calibrated attack probability'}

    @classmethod
    def load(cls,path,sha256):
        path=Path(path)
        require(path.is_file() and not path.is_symlink(),'intent_model_file')
        with path.open('rb') as stream:
            body=stream.read(256001)
        require(len(body)<=256000 and hashlib.sha256(body).hexdigest()==sha256,'intent_model_pin')
        value=decode(body)
        require(set(value)=={'schema','minimum_support','rows','scope'} and value['schema']==SCHEMA
                and type(value['rows']) is dict and 0<len(value['rows'])<=100,'intent_model_schema')
        model=cls(minimum_support=value['minimum_support'])
        for feature,counts in value['rows'].items():
            fields=decode(feature.encode())
            require(type(fields) is list and len(fields)==6 and all(type(f) is str and len(f)<=64 for f in fields)
                    and feature==key(fields) and type(counts) is list and len(counts)==2
                    and all(type(n) is int and 0<=n<=1000000 for n in counts),'intent_model_counts')
        model.rows=value['rows'];model.frozen=True
        return model

    def refine(self,previous,observation,*,source_sha256,ordinal,raw):
        require(self.frozen and isinstance(previous,OperationDecision)
                and previous.automatic_enforcement_allowed is False,'intent_candidate_contract')
        require(isinstance(observation,IntentObservation) and observation.source_sha256==source_sha256
                and observation.ordinal==ordinal and observation.line_sha256==hashlib.sha256(raw.encode()).hexdigest(),
                'intent_observation_binding')
        if not observation.eligible or previous.reason not in {'missing_context','unchanged'}:
            return previous
        counts=self.rows.get(key(observation.key))
        if counts is None or counts[0]<self.minimum_support or counts[1]:
            return previous
        # Empirically normal supported leaf; review is retained. Any observed
        # attack in the same feature cell vetoes lowering, independent of class
        # imbalance. This remains a candidate requiring source-separated tests.
        return OperationDecision(previous.baseline_score,0.,False,True,'learned_audit_intent_review')

    def save(self,path):
        payload=self.freeze()
        body=canonical(payload)+b'\n'
        Path(path).write_bytes(body)
        return hashlib.sha256(body).hexdigest()
