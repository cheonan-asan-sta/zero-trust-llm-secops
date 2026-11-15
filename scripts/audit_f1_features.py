"""Audit observational ambiguity; oracle bounds are not measured model performance."""

import argparse
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

from app.services.detection_benchmark import DetectionBenchmark, metrics
from app.services.sigma import _lookup


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def rule_fields(engine):
    fields = set()
    for rule in engine.approved_rules:
        for name, selector in rule.detection.items():
            if name == 'condition':
                continue
            for branch in selector if isinstance(selector, list) else [selector]:
                for expression, expected in branch.items():
                    field, *modifiers = expression.split('|')
                    fields.add(field)
                    if 'fieldref' in modifiers:
                        for reference in expected if isinstance(expected, list) else [expected]:
                            fields.add(reference)
    return sorted(fields)


def security_projection(event):
    """Declared security inputs only, excluding IDs, text, time and unsigned approval claims."""
    return {
        'action': event.action.value,
        'user': event.user.model_dump(exclude={'user_id', 'department'}),
        'device': event.device.model_dump(exclude={'device_id'}),
        'network': event.network.model_dump(exclude={'ip', 'location'}),
        'resource': event.resource.model_dump(exclude={'resource_id', 'resource_type'}),
        'auth': event.auth_context.model_dump(exclude={'session_age_minutes'}),
        'behavior': event.behavior.model_dump(exclude={
            'policy_exception_approved', 'policy_exception', 'event_text'}),
    }


def bounds(groups, *, max_fpr=.05, min_precision=.95, min_recall=.95):
    """Optimistic label-aware lookup-table bounds on a fixed input projection, not a trained detector."""
    positive = sum(g['positive'] for g in groups)
    negative = sum(g['negative'] for g in groups)
    total = positive + negative
    irreducible = sum(min(g['positive'], g['negative']) for g in groups)
    # For a fixed positive-prediction size, including groups by positive fraction
    # yields the optimal F1 prefix; labels make this an oracle upper bound only.
    best, tp, fp = None, 0, 0
    for group in sorted(groups, key=lambda g: g['positive'] / (g['positive'] + g['negative']), reverse=True):
        tp += group['positive']
        fp += group['negative']
        candidate = metrics({'tp': tp, 'fp': fp, 'fn': positive-tp, 'tn': negative-fp})['f1']
        if candidate is not None and (best is None or candidate > best):
            best = candidate
    # Exact whole-group selection under the integer FP cap. Identical observations
    # cannot receive different deterministic predictions. Keep the largest TP for
    # each FP cost; precision and recall can then be checked jointly.
    cap = math.floor(negative * max_fpr + 1e-12)
    reachable = {0: 0}
    for group in groups:
        following = dict(reachable)
        for cost, captured in reachable.items():
            next_cost = cost + group['negative']
            if next_cost <= cap:
                following[next_cost] = max(following.get(next_cost, -1), captured + group['positive'])
        reachable = following
    feasible, constrained = False, None
    for cost, captured in reachable.items():
        values = metrics({'tp': captured, 'fp': cost, 'fn': positive-captured, 'tn': negative-cost})
        precision, recall = values['precision'], values['recall']
        if precision is not None and precision >= min_precision and recall is not None:
            constrained = max(constrained if constrained is not None else 0, recall)
            feasible |= negative > 0 and recall >= min_recall and values['f1'] is not None and values['f1'] >= .95
    return {'positive': positive, 'negative': negative, 'groups': len(groups),
            'conflicting_groups': sum(g['positive'] > 0 and g['negative'] > 0 for g in groups),
            'minimum_misclassifications': irreducible,
            'maximum_accuracy_oracle': (total-irreducible)/total if total else None,
            'maximum_f1_oracle': best, 'fp_cap_at_5_percent': cap,
            'maximum_recall_with_precision_95_and_fpr_5_oracle': constrained,
            'all_four_point_targets_feasible_for_projection_oracle': feasible,
            'not_model_performance': True}


def analyze(benchmark):
    fields = rule_fields(benchmark.engine)
    projections = defaultdict(lambda: defaultdict(list))
    approved = {'normal': 0, 'threat': 0}
    for case in benchmark.cases:
        event = case.event
        if event.behavior.policy_exception_approved:
            approved['threat' if case.threat else 'normal'] += 1
        normalized = benchmark.normalizer.normalize(event).event.model_dump(mode='json', exclude_none=True)
        candidates = {'current_rule_fields': {field: _lookup(normalized, field) for field in fields},
                      'declared_security_without_unsigned_approval': security_projection(event)}
        for name, data in candidates.items():
            key = hashlib.sha256(canonical(data)).hexdigest()
            for split in (case.split, 'all_observed'):
                projections[name, split][key].append(case)
    results = {}
    for (name, split), groups in sorted(projections.items()):
        support, conflicts = [], []
        for key, cases in sorted(groups.items()):
            positive = sum(case.threat for case in cases)
            negative = len(cases) - positive
            support.append({'positive': positive, 'negative': negative})
            if positive and negative:
                conflicts.append({'projection_sha256': key, 'positive': positive, 'negative': negative,
                    'threat_example': next(case.case_id for case in cases if case.threat),
                    'normal_example': next(case.case_id for case in cases if not case.threat)})
        results.setdefault(name, {})[split] = {**bounds(support), 'conflicts': conflicts}
    return {'schema': 'f1-feature-ambiguity-audit-1', 'current_rule_field_names': fields,
            'unsigned_approval_claim_counts': approved, 'projections': results,
            'label_aware_oracle_only': True, 'detector_or_labels_changed': False,
            'source': {'manifest_sha256': benchmark.manifest_digest,
                       'ruleset_sha256': benchmark.engine.ruleset_digest_sha256},
            'limits': ['The oracle reads existing labels; it is not an evaluated or deployable classifier.',
                       'Bounds apply only to the declared projection; richer trusted observations may change them.',
                       'Existing holdout has already been observed. No new independent evaluation is performed.',
                       'Unsigned policy exception claims are not evidence of approval authority.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('fresh_audit_output_required')
    result = analyze(DetectionBenchmark())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical(result) + b'\n')
    print(json.dumps({name: {split: {k: v for k, v in report.items() if k != 'conflicts'}
                            for split, report in reports.items()}
                      for name, reports in result['projections'].items()}))


if __name__ == '__main__':
    main()
