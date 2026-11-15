"""Retain observed VPN risk briefly; authentication never clears earlier risk.

Offline source-scoped evidence only. A logged IP:port is not a verified identity,
and these decisions never authorize access revocation or automatic blocking.
"""

import hashlib
import math
from dataclasses import dataclass
from itertools import groupby

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import BoundContext, bound_contexts
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.vpn_context import endpoint

LOOKBACK_SECONDS = 60
THRESHOLD = .95


@dataclass(frozen=True)
class RetainedContext:
    base: BoundContext
    prior_score: float = 0.
    evidence_ordinal: int | None = None
    age_seconds: float | None = None


def retained_contexts(records, source_sha256, vpn_model):
    """Query the entire tie batch before adding any of its intrinsic scores.

    Held risk never refreshes its own expiry. Source and exact endpoint scope
    cannot cross calls. Missing time/endpoint has no retained evidence.
    """
    contexts = bound_contexts(records, 'vpn', source_sha256)
    by_ordinal = {c.ordinal: c for c in contexts.values()}
    result, state = {}, {}
    ordered = sorted(records, key=lambda r: (float('inf') if r[1] is None else r[1], r[0]))
    for moment, batch in groupby(ordered, key=lambda r: r[1]):
        batch = list(batch)
        if moment is not None:
            state = {key: value for key, value in state.items() if moment-value[0] <= LOOKBACK_SECONDS}
        pending = {}
        for ordinal, _, line in batch:
            base = by_ordinal[ordinal]
            peer = endpoint(line) if moment is not None else None
            prior = state.get(peer[1]) if peer else None
            result[base.case_id] = (RetainedContext(base, prior[1], prior[2], float(moment-prior[0]))
                                    if prior else RetainedContext(base))
            if peer:
                score = vpn_model.probability(base.vpn_features)
                require(type(score) in {float, int} and math.isfinite(score) and 0 <= score <= 1,
                        'retention_intrinsic_score')
                if score >= THRESHOLD and (peer[1] not in pending or score > pending[peer[1]][0]):
                    pending[peer[1]] = (score, ordinal)
        if moment is not None:
            for key, (score, ordinal) in pending.items():
                require(key in state or len(state) < 10000, 'retention_endpoint_bound')
                state[key] = (moment, score, ordinal)
    return result


class RiskRetention:
    """Add risk only after the existing source/case/core binding checks."""

    def __init__(self, operation_model):
        self.operation_model = operation_model
        self.web_model, self.vpn_model = operation_model.web_model, operation_model.vpn_model

    def decide(self, features, case_id, context=None):
        if not isinstance(context, RetainedContext):
            return self.operation_model.decide(features, case_id, context)
        require(context.base.kind == 'vpn', 'retention_kind')
        value = self.operation_model.decide(features, case_id, context.base)
        require(type(context.prior_score) in {int, float} and math.isfinite(context.prior_score)
                and 0 <= context.prior_score <= 1, 'retention_score')
        if context.evidence_ordinal is None:
            require(context.prior_score == 0 and context.age_seconds is None, 'retention_missing_evidence')
            return value
        require(type(context.evidence_ordinal) is int and context.evidence_ordinal > 0
                and context.evidence_ordinal != context.base.ordinal
                and type(context.age_seconds) in {int, float} and math.isfinite(context.age_seconds)
                and 0 < context.age_seconds <= LOOKBACK_SECONDS and context.prior_score >= THRESHOLD,
                'retention_evidence')
        score = max(value.score, context.prior_score)
        return OperationDecision(value.baseline_score, score, value.alert or score >= THRESHOLD,
                                 value.review or score >= .9, 'vpn_strict_past_risk_retained')


def evidence_case(context):
    """A bounded provenance reference, never an identity/authorization claim."""
    if context.evidence_ordinal is None:
        return None
    return hashlib.sha256((context.base.raw_sha256+':'+str(context.evidence_ordinal)).encode()).hexdigest()
