"""Necessary local metric check before CI; never independent qualification.

Counts and populations are supplied by a separately verified evaluator. This
calculator does not authenticate labels, validate split independence or invoke
Git, CI, providers, deployment or access-control changes.
"""

from fractions import Fraction

from scripts.f1_lab.native_jsonl import require

LOG_KINDS = ('audit-share', 'audit-web', 'auth', 'vpn', 'cpu', 'dns', 'web-access', 'web-error')
SECURITY_DOMAINS = ('credential', 'device', 'privilege', 'lateral', 'exfiltration', 'remote')
COUNTS = ('tp', 'fp', 'fn', 'tn', 'inference_errors', 'unknown')
TARGETS = {'precision': Fraction(95, 100), 'recall': Fraction(95, 100),
           'f1': Fraction(95, 100), 'false_positive_rate': Fraction(5, 100),
           'false_negative_rate': Fraction(5, 100)}


def evaluate(rows, *, track):
    require(track in {'observed_log_kinds', 'original_security_domains'}, 'metric_gate_track')
    expected = LOG_KINDS if track == 'observed_log_kinds' else SECURITY_DOMAINS
    require(type(rows) is list and len(rows) == len(expected), 'metric_gate_population_scope')
    seen, result = set(), []
    for row in rows:
        require(type(row) is dict and set(row) == {'name', 'population', *COUNTS}, 'metric_gate_row_schema')
        name = row['name']
        require(type(name) is str and name in expected and name not in seen, 'metric_gate_name')
        seen.add(name)
        require(all(type(row[k]) is int and 0 <= row[k] <= 10_000_000 for k in ('population', *COUNTS)),
                'metric_gate_integer_counts')
        require(row['population'] > 0 and sum(row[k] for k in COUNTS) == row['population'],
                'metric_gate_denominator')
        tp, fp, fn, tn = (row[k] for k in ('tp', 'fp', 'fn', 'tn'))
        incomplete = bool(row['inference_errors'] or row['unknown'])
        ratios = {'precision': (tp, tp+fp), 'recall': (tp, tp+fn),
                  'f1': (2*tp, 2*tp+fp+fn), 'false_positive_rate': (fp, fp+tn),
                  'false_negative_rate': (fn, fn+tp)}
        values, failures = {}, []
        if incomplete:
            failures.append('incomplete_predictions')
        for metric, (numerator, denominator) in ratios.items():
            value = None if incomplete or denominator == 0 else Fraction(numerator, denominator)
            values[metric] = None if value is None else float(value)
            is_upper = metric in {'false_positive_rate', 'false_negative_rate'}
            if value is None or (value > TARGETS[metric] if is_upper else value < TARGETS[metric]):
                failures.append(metric)
        result.append({'name': name, 'population': row['population'],
            'positive_support': tp+fn, 'negative_support': fp+tn,
            'counts': {k: row[k] for k in COUNTS}, 'metrics': values,
            'metric_targets_met': not failures, 'failed_conditions': failures})
    require(seen == set(expected), 'metric_gate_missing_scope')
    order = {name: index for index, name in enumerate(expected)}
    result.sort(key=lambda r: order[r['name']])
    return {'schema': 'local-metric-gate-1', 'track': track,
        'completed': True, 'local_metric_gate_passed': all(r['metric_targets_met'] for r in result),
        'goal_qualified': False, 'independent_evaluation_verified': False,
        'ci_or_merge_started': False,
        'scope': 'necessary metric condition only; label provenance, candidate binding, independent evaluation and runtime acceptance remain separate',
        'targets': {k: float(v) for k, v in TARGETS.items()}, 'rows': result}
