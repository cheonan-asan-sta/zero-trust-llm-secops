"""Training-only information and linkage diagnostics, never a fitted classifier."""

import hashlib
import json
from collections import Counter, defaultdict
from fractions import Fraction

from scripts.f1_lab.native_jsonl import require

PROFILES = ('exact', 'bucketed_session_age', 'without_session_age')
LINKS = ('event_reference', 'principal_reference', 'issuer_reference', 'source_ip_reference')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def feature_key(features, profile):
    require(profile in PROFILES and isinstance(features, dict), 'cloud_diagnostic_profile')
    value = dict(features)
    age = value.pop('historical_session_age_seconds', None)
    if profile == 'exact':
        value['historical_session_age_seconds'] = age
    elif profile == 'bucketed_session_age':
        require(age is None or type(age) in (int, float) and age >= 0, 'cloud_diagnostic_age')
        value['historical_session_age_bucket'] = None if age is None else sum(age >= t for t in (1, 60, 300, 3600, 86400, 604800))
    return hashlib.sha256(canonical(value)).hexdigest()


def target_feasibility(groups):
    """Gold-only exact attainable frontier, with an explicit computation bound."""
    normal, attack = (sum(c[i] for c in groups) for i in (0, 1))
    mixed = [c for c in groups if min(c) > 0]
    if not normal or not attack:
        return {'computed': False, 'reason': 'both_classes_required', 'all_targets_feasible': None}
    if len(mixed)*attack > 5000000:
        return {'computed': False, 'reason': 'frontier_computation_bound', 'all_targets_feasible': None}
    # Pure-attack vectors can always be positive and pure-normal vectors
    # negative without hurting any target. For every attainable TP retain the
    # smallest FP; any other assignment at that TP is dominated.
    states = {sum(a for n, a in groups if n == 0): 0}
    for n, a in mixed:
        updated = dict(states)
        for tp, fp in states.items():
            key = tp+a
            updated[key] = min(updated.get(key, normal+1), fp+n)
        states = updated
    target = Fraction(95, 100)
    recall_states = [(tp, fp) for tp, fp in states.items() if Fraction(tp, attack) >= target]
    precision_states = [(tp, fp) for tp, fp in states.items() if tp+fp and Fraction(tp, tp+fp) >= target]
    def all_targets(tp, fp):
        return (tp+fp > 0 and Fraction(tp, tp+fp) >= target and Fraction(tp, attack) >= target
                and Fraction(2*tp, attack+tp+fp) >= target and Fraction(fp, normal) <= Fraction(5, 100))
    best_precision = max((Fraction(tp, tp+fp) for tp, fp in recall_states), default=None)
    best_recall = max((Fraction(tp, attack) for tp, fp in precision_states), default=None)
    return {'computed': True, 'target_precision_recall_f1': 0.95, 'target_max_false_positive_rate': 0.05,
            'all_targets_feasible': any(all_targets(tp, fp) for tp, fp in states.items()),
            'best_precision_at_recall_target': float(best_precision) if best_precision is not None else None,
            'best_recall_at_precision_target': float(best_recall) if best_recall is not None else None,
            'frontier_states': len(states), 'is_model_performance': False, 'is_independent_evaluation': False}


def collision_summary(groups):
    """Exact empirical upper bound for deterministic decisions on these vectors.

    For a candidate F1 f, adding a group improves it iff its positive share
    exceeds f/2. Thus an optimum is a prefix sorted by empirical positive share.
    Gold labels determine this oracle: its score cannot be reported as a model.
    """
    require(all(isinstance(counts, (list, tuple)) and len(counts) == 2
                and all(type(n) is int and n >= 0 for n in counts) and sum(counts) > 0 for counts in groups),
            'cloud_diagnostic_class_counts')
    normal, attack = (sum(c[i] for c in groups) for i in (0, 1))
    mixed = [c for c in groups if min(c) > 0]
    best, best_tp, best_fp, tp, fp = Fraction(0), 0, 0, 0, 0
    for n, a in sorted(groups, key=lambda c: Fraction(c[1], sum(c)), reverse=True):
        tp, fp = tp+a, fp+n
        score = Fraction(2*tp, attack+tp+fp) if attack+tp+fp else Fraction(0)
        if score > best:
            best, best_tp, best_fp = score, tp, fp
    return {'known_normal': normal, 'known_attack': attack, 'unique_vectors': len(groups),
            'mixed_label_vectors': len(mixed), 'rows_in_mixed_label_vectors': sum(sum(c) for c in mixed),
            'minimum_in_sample_classification_errors': sum(min(c) for c in groups),
            'gold_oracle_best_in_sample_f1': float(best) if attack else None,
            'oracle_tp': best_tp, 'oracle_fp': best_fp, 'oracle_fn': attack-best_tp,
            'simultaneous_targets': target_feasibility(groups),
            'is_model_performance': False, 'is_independent_evaluation': False}


class CloudDiagnostics:
    def __init__(self):
        self.vectors = {name: defaultdict(lambda: [0, 0]) for name in PROFILES}
        self.sources = {name: defaultdict(Counter) for name in LINKS}
        self.event_truth = defaultdict(set)
        self.counts = Counter()

    def add(self, view, gold, *, asset):
        require(type(asset) is int and asset in (0, 1), 'cloud_diagnostic_training_asset')
        require(isinstance(gold, dict) and (gold.get('truth') is None or type(gold['truth']) is bool), 'cloud_diagnostic_truth')
        self.counts['rows'] += 1
        if view is None:
            self.counts['unusable_observations'] += 1
            self.counts['known_label_unusable_observations'] += type(gold.get('truth')) is bool
            return
        require(isinstance(view, dict) and isinstance(view.get('features'), dict)
                and isinstance(view.get('provenance'), dict), 'cloud_diagnostic_view')
        self.counts['usable_observations'] += 1
        expected = gold.get('truth')
        if expected is None:
            self.counts['unknown_labels'] += 1
        else:
            self.counts['known_attack' if expected else 'known_normal'] += 1
            for profile in PROFILES:
                self.vectors[profile][feature_key(view['features'], profile)][int(expected)] += 1
        for name in LINKS:
            key = view['provenance'].get(name)
            if key is not None:
                require(isinstance(key, str) and len(key) == 64
                        and all(c in '0123456789abcdef' for c in key), 'cloud_diagnostic_reference')
                self.sources[name][key][asset] += 1
        event = view['provenance'].get('event_reference')
        if event and expected is not None:
            self.event_truth[event].add(expected)

    def summary(self):
        links = {}
        for name, mapping in self.sources.items():
            shared = [counts for counts in mapping.values() if len(counts) > 1]
            links[name] = {'distinct_references': len(mapping), 'shared_across_training_assets': len(shared),
                           'rows_in_shared_references': sum(sum(counts.values()) for counts in shared),
                           'largest_reference_rows': max((sum(c.values()) for c in mapping.values()), default=0)}
        return {'schema': 'f1-cloud-training-diagnostics-1', 'counts': dict(self.counts),
                'profiles': {name: collision_summary(list(vectors.values())) for name, vectors in self.vectors.items()},
                'linkage': links, 'conflicting_event_reference_labels': sum(len(v) > 1 for v in self.event_truth.values()),
                'profile_scope': 'same training rows only; exact age may encode near-unique history; bucket/no-age variants diagnose dependence',
                'linkage_scope': 'principal/issuer/IP equality is not proof of session, physical device, current trust or safe final separation',
                'labels_rewritten': False, 'classifier_fitted': False, 'test_records_read': 0,
                'final_partition_certified': False, 'original_six_domain_goal_replaced': False, 'goal_qualified': False}
