"""Offline VPN precision diagnostics. Labels never enter candidate inference."""

import hashlib
import math
import re
from collections import Counter, defaultdict
from itertools import groupby

from scripts.f1_lab.line_truth import anchor
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.vpn_context import PREFIX, endpoint
from scripts.f1_lab.vpn_risk_retention import retained_contexts

THRESHOLDS = (.95, .975, .985, .99)
DECLARATION = re.compile(
    r"(?:Outgoing|Incoming) Data Channel: (?:Cipher '[A-Za-z0-9_-]{1,64}' initialized with "
    r"[1-9]\d{0,4} bit key|Using [1-9]\d{0,4} bit message hash '[A-Za-z0-9_-]{1,64}' for HMAC authentication)")


def informational_declaration(line):
    match = PREFIX.match(line)
    return bool(match and match['name'] and DECLARATION.fullmatch(line[match.end():].rstrip('\r\n')))


def metadata_candidate(records, source_sha256, vpn_model, baseline_scores):
    """Rejected hypothesis retained for reproducible counterexamples.

    Only generic, fully parsed declarations lose their supplemental novelty
    score. Earlier evidence stays source/endpoint scoped; equal times are
    withheld and held risk does not renew expiry. No label input is accepted.
    """
    contexts = retained_contexts(records, source_sha256, vpn_model)
    by_ordinal = {value.base.ordinal: value for value in contexts.values()}
    require(set(baseline_scores) == set(contexts), 'precision_baseline_population')
    for score in baseline_scores.values():
        require(type(score) in {float, int} and math.isfinite(score) and 0 <= score <= 1,
                'precision_baseline_score')
    result, state = {}, {}
    ordered = sorted(records, key=lambda r: (float('inf') if r[1] is None else r[1], r[0]))
    for moment, batch in groupby(ordered, key=lambda r: r[1]):
        if moment is not None:
            state = {key: value for key, value in state.items() if moment-value[0] <= 60}
        pending = {}
        for ordinal, _, line in batch:
            context = by_ordinal[ordinal]
            peer = endpoint(line) if moment is not None else None
            declaration = peer is not None and informational_declaration(line)
            intrinsic = (vpn_model.probability(context.base.vpn_features)
                         if context.base.vpn_features['vpn_endpoint_available']
                         else baseline_scores[context.base.case_id])
            require(type(intrinsic) in {float, int} and math.isfinite(intrinsic) and 0 <= intrinsic <= 1,
                    'precision_intrinsic_score')
            prior = state.get(peer[1], (None, 0.))[1] if peer else 0.
            result[context.base.case_id] = max(baseline_scores[context.base.case_id], prior,
                                               0. if declaration else intrinsic)
            if peer and not declaration and intrinsic >= .95:
                pending[peer[1]] = max(intrinsic, pending.get(peer[1], 0.))
        if moment is not None:
            for key, value in pending.items():
                require(key in state or len(state) < 10000, 'precision_endpoint_bound')
                state[key] = (moment, value)
    return result


def validate_rows(rows):
    require(isinstance(rows, list) and 0 < len(rows) <= 100000, 'precision_row_bound')
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'case_id', 'malicious', 'before', 'after', 'signature'},
                'precision_row_schema')
        anchor(row['case_id'])
        anchor(row['signature'])
        require(row['case_id'] not in seen, 'precision_duplicate_case')
        require(type(row['malicious']) is bool
                and all(type(row[k]) is bool or row[k] is None for k in ('before', 'after')), 'precision_row_types')
        seen.add(row['case_id'])


def paired_review(rows):
    """Fewer FP cannot compensate for losing even one existing true positive."""
    validate_rows(rows)
    before, after, changes = counts(), counts(), Counter()
    for row in rows:
        truth, a, b = row['malicious'], row['before'], row['after']
        record(before, truth, a)
        record(after, truth, b)
        if truth and a is True and b is not True:
            changes['lost_true_positives'] += 1
        if not truth and a is True and b is False:
            changes['removed_false_positives'] += 1
        if truth and a is not True and b is True:
            changes['recovered_true_positives'] += 1
    acceptable = (not changes['lost_true_positives'] and before['inference_errors'] == after['inference_errors'] == 0
                  and after['fn'] <= before['fn'] and after['fp'] < before['fp'])
    return {'before': metrics(before), 'after': metrics(after), 'changes': dict(changes),
            'acceptable_without_recall_regression': acceptable}


def collision_bound(rows):
    """Label-assisted diagnostic bound for this projection, not a trained model.

    If a deterministic function keeps every baseline TP for identical observable
    signatures, all normal rows in those same signatures must also remain FP.
    This does not assert impossibility with new authenticated observations.
    """
    validate_rows(rows)
    groups = defaultdict(list)
    for row in rows:
        groups[row['signature']].append(row)
    mandatory, pure, witnesses = 0, 0, []
    for signature, group in groups.items():
        require(len({r['before'] for r in group}) == 1, 'precision_signature_incomplete')
        if group[0]['before'] is not True:
            continue
        positives = [r for r in group if r['malicious']]
        normals = [r for r in group if not r['malicious']]
        if positives and normals:
            mandatory += len(normals)
            witnesses.append({'signature': signature, 'attack_case': positives[0]['case_id'],
                              'normal_case': normals[0]['case_id'],
                              'attack_rows': len(positives), 'normal_rows': len(normals)})
        elif normals:
            pure += len(normals)
    return {'label_assisted_diagnostic_only': True, 'mandatory_fp_if_all_baseline_tp_retained': mandatory,
            'fp_in_unmixed_signatures': pure, 'mixed_signature_count': len(witnesses),
            'witnesses': witnesses, 'scope': 'declared observable projection, not all future models or raw observations'}


def signature(features, retained, declaration):
    return hashlib.sha256(canonical({'features': features, 'retained_score': retained.prior_score,
        'retained_age_seconds': retained.age_seconds, 'generic_channel_declaration': declaration})).hexdigest()
