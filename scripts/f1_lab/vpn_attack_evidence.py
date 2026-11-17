"""Add review from supported attack cells; retain new risk only causally.

This uses frozen development evidence, never grants trust or changes authority.
Normal examples veto attack-cell raising regardless of attack class imbalance.
"""

import math
import re
from datetime import UTC, datetime

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.vpn_context import endpoint
from scripts.f1_lab.vpn_protocol_head import REASONS, ProtocolHead
from scripts.f1_lab.vpn_protocol_review import feature_key

DIRECT_REASON='learned_vpn_attack_evidence_review'
RETAINED_REASON='vpn_learned_attack_evidence_retained'
RETENTION_SECONDS=60


class AttackEvidenceReview:
    def __init__(self,head,source_sha256):
        require(isinstance(head,ProtocolHead) and head.frozen and type(source_sha256) is str
            and re.fullmatch('[a-f0-9]{64}',source_sha256),'vpn_attack_source_contract')
        self.head,self.source=head,source_sha256
        self.ordinal,self.time,self.disabled=0,None,False
        self.retained={}

    def refine(self,previous,legacy_projection,observation,*,ordinal,raw,moment):
        # Always validate the original decision and the exact row binding,
        # including when this optional source review has been disabled.
        normal=self.head.refine(previous,legacy_projection,observation,
            source_sha256=self.source,ordinal=ordinal,raw=raw)
        if self.disabled:return previous
        require(type(ordinal) is int and ordinal>0,'vpn_attack_ordinal')
        try:bound=datetime.fromisoformat(raw[:19]).replace(tzinfo=UTC).timestamp()
        except (ValueError,OverflowError,OSError):bound=None
        if (ordinal!=self.ordinal+1 or moment is None or type(moment) not in {int,float}
                or not math.isfinite(moment) or bound!=moment or self.time is not None and moment<self.time):
            self.disabled=True;self.retained.clear();return previous
        self.ordinal,self.time=ordinal,moment
        if not observation.available:
            self.retained.clear();return previous
        self.retained={k:v for k,v in self.retained.items() if 0<=moment-v[0]<=RETENTION_SECONDS}
        require(len(self.retained)<10000,'vpn_attack_endpoint_bound')
        if previous.reason not in REASONS|{'learned_vpn_protocol_review'}:return previous
        peer=endpoint(raw);connection=peer[1] if peer else None
        cell=self.head.rows.get(feature_key(legacy_projection,observation))
        direct=bool(not normal.alert and cell and cell[0]==0 and cell[1]>=5)
        held=connection is not None and connection in self.retained
        if direct and connection is not None:
            # A repeated/held observation does not extend the first episode.
            self.retained.setdefault(connection,(moment,ordinal))
        if normal.alert:return normal
        if direct or held:
            return OperationDecision(normal.baseline_score,max(.95,normal.score),True,True,
                DIRECT_REASON if direct else RETAINED_REASON)
        return normal
