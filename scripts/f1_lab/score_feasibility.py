"""Label-assisted score-order diagnostic; never chooses deployed thresholds.

Every tied score moves as one group. Known-label inference failures remain
FN/FP at every boundary. Exact integer inequalities implement the declared
95/5 targets; undefined class denominators can never pass. This describes one
frozen score projection, not impossibility for new observations or models.
"""

import hashlib
import math
from fractions import Fraction

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical

MAX_GROUPS = 100000
MAX_ROWS = 2000000


def point(tp, fp, positives, normals, errors):
    require(all(type(v) is int and v >= 0 for v in (tp, fp, positives, normals, errors))
            and tp <= positives and fp <= normals and errors <= positives+normals, 'score_audit_counts')
    result = metrics({'tp': tp, 'fp': fp, 'fn': positives-tp, 'tn': normals-fp,
                      'inference_errors': errors})
    result['false_negative_rate'] = (positives-tp)/positives if positives else None
    result['meets_point_targets'] = bool(positives and normals and tp
        and 20*tp >= 19*(tp+fp) and 20*tp >= 19*positives
        and 40*tp >= 19*(tp+fp+positives) and 20*fp <= normals)
    return result


class ScoreAudit:
    """Bounded sufficient statistics, with no raw text or case identifiers."""

    def __init__(self):
        self.groups = {}
        self.current = counts()
        self.rows = self.positives = self.normals = 0
        self.error_normals = self.error_positives = 0

    def add(self, score, malicious, previous, *, failed=False):
        require(type(malicious) is bool and type(failed) is bool
                and (previous is None if failed else type(previous) is bool), 'score_audit_types')
        require(self.rows < MAX_ROWS, 'score_audit_rows')
        if not failed:
            require(type(score) in {int, float} and math.isfinite(score) and 0 <= score <= 1,
                    'score_audit_value')
            require(previous == (score >= .95), 'score_audit_frozen_threshold_mismatch')
            require(score in self.groups or len(self.groups) < MAX_GROUPS, 'score_audit_groups')
            bucket = self.groups.setdefault(score, [0, 0, 0, 0])
            bucket[0 if malicious else 1] += 1
            bucket[2 if malicious else 3] += int(previous)
        else:
            self.error_positives += malicious
            self.error_normals += not malicious
        record(self.current, malicious, previous)
        self.rows += 1
        self.positives += int(malicious)
        self.normals += int(not malicious)

    def report(self):
        require(self.rows > 0, 'score_audit_empty')
        positives, normals = self.positives, self.normals
        errors = self.error_positives+self.error_normals
        tp, fp, retained_tp, retained_fp = 0, self.error_normals, 0, self.error_normals
        frontier, best, safe_best, eligible, safe_eligible = hashlib.sha256(), None, None, 0, 0
        best_ratio = safe_ratio = Fraction(-1)

        def observe(boundary):
            nonlocal best, safe_best, best_ratio, safe_ratio, eligible, safe_eligible
            value = point(tp, fp, positives, normals, errors)
            value.update(boundary=boundary, lost_baseline_tp=self.current['tp']-retained_tp,
                         introduced_fp=fp-retained_fp,
                         removed_baseline_fp=self.current['fp']-retained_fp)
            safe = value['lost_baseline_tp'] == value['introduced_fp'] == 0
            ratio = Fraction(2*tp, tp+fp+positives) if tp+fp+positives else Fraction(0)
            if ratio > best_ratio:
                best, best_ratio = value, ratio
            if safe and ratio > safe_ratio:
                safe_best, safe_ratio = value, ratio
            eligible += value['meets_point_targets']
            safe_eligible += value['meets_point_targets'] and safe
            frontier.update(canonical(value)+b'\n')

        observe({'kind': 'above_maximum', 'score': None})
        for score, bucket in sorted(self.groups.items(), reverse=True):
            p, n, old_tp, old_fp = bucket
            tp, fp = tp+p, fp+n
            retained_tp, retained_fp = retained_tp+old_tp, retained_fp+old_fp
            observe({'kind': 'score_greater_or_equal', 'score': score})
        assert tp+self.error_positives == positives and fp == normals
        return {'population': self.rows, 'positive_rows': positives, 'normal_rows': normals,
                'distinct_scores': len(self.groups), 'boundaries_examined': len(self.groups)+1,
                'current': point(self.current['tp'], self.current['fp'], positives, normals, errors),
                'diagnostic_best_f1': best, 'diagnostic_best_f1_without_new_fp_or_lost_tp': safe_best,
                'point_target_boundaries': eligible, 'safe_point_target_boundaries': safe_eligible,
                'score_only_target_feasible_on_observed_rows': eligible > 0,
                'no_new_fp_or_lost_tp_target_feasible_on_observed_rows': safe_eligible > 0,
                'frontier_sha256': frontier.hexdigest(), 'threshold_adopted': False,
                'labels_used_for_diagnostic': True, 'new_independent_evaluation': False,
                'original_six_domain_goal_qualified': False}
