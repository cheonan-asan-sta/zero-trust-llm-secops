"""Small predeclared threshold comparisons with connected-group outer folds."""

import hashlib
import json
from collections import defaultdict

from app.services.detection_benchmark import confusion, metrics
from scripts.audit_f1_features import security_projection
from scripts.f1_lab.detector import DraftThresholds, ShadowDetector

SELECTION = ('maximize minimum signed margin to four point targets, then F1, '
             'then lower FPR, then earlier declared candidate')
GROUPING = 'connected_family_subject_device_session_and_declared_security_projection'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate_contract(raw):
    contract = json.loads(raw)
    if (set(contract) != {'schema', 'input_role', 'outer_folds', 'grouping', 'selection', 'candidates',
                          'promotion', 'new_independent_evaluation'}
            or contract['schema'] != 'f1-shadow-calibration-1'
            or contract['input_role'] != 'previously_observed_synthetic_development_only'
            or type(contract['outer_folds']) is not int or not 2 <= contract['outer_folds'] <= 5
            or contract['grouping'] != GROUPING or contract['selection'] != SELECTION
            or contract['promotion'] != 'none; diagnostic selection only, no app configuration writes'
            or contract['new_independent_evaluation'] is not False
            or not isinstance(contract['candidates'], list) or not 1 <= len(contract['candidates']) <= 9):
        raise ValueError('calibration_contract')
    seen_ids, seen_parameters = set(), set()
    for candidate in contract['candidates']:
        if (set(candidate) != {'id', 'credential_failures', 'resource_fanout', 'bulk_download_mb'}
                or not isinstance(candidate['id'], str) or not candidate['id'].strip() or len(candidate['id']) > 64
                or candidate['id'] in seen_ids):
            raise ValueError('calibration_candidate_identity')
        parameters = DraftThresholds.model_validate({k: v for k, v in candidate.items() if k != 'id'})
        encoded = canonical(parameters.model_dump())
        if encoded in seen_parameters:
            raise ValueError('calibration_duplicate_parameters')
        seen_ids.add(candidate['id'])
        seen_parameters.add(encoded)
    return contract


def group_tokens(case):
    event = case.event
    projection = hashlib.sha256(canonical(security_projection(event))).hexdigest()
    return [('family', case.family_id), ('subject', event.user.user_id),
            ('device', event.device.device_id), ('session', case.session_id), ('projection', projection)]


def connected_folds(cases, count):
    if type(count) is not int or not 2 <= count <= 5 or not cases:
        raise ValueError('calibration_fold_count')
    if any(case.split != 'development' for case in cases) or len({c.case_id for c in cases}) != len(cases):
        raise ValueError('calibration_development_unique_cases_only')
    parent = list(range(len(cases)))

    def root(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owners = {}
    for index, case in enumerate(cases):
        for token in group_tokens(case):
            owner = owners.setdefault(token, index)
            left, right = root(owner), root(index)
            if left != right:
                parent[max(left, right)] = min(left, right)
    components = defaultdict(list)
    for index in range(len(cases)):
        components[root(index)].append(index)
    if len(components) < count:
        raise ValueError('calibration_insufficient_indivisible_groups')
    groups = sorted(components.values(), key=lambda group: (-len(group),
        hashlib.sha256(canonical(sorted(cases[i].family_id for i in group))).hexdigest()))
    folds = [[] for _ in range(count)]
    for group in groups:
        target = min(range(count), key=lambda i: (len(folds[i]), i))
        folds[target].extend(group)
    token_sets = [{token for index in fold for token in group_tokens(cases[index])} for fold in folds]
    if any(token_sets[i] & token_sets[j] for i in range(count) for j in range(i)):
        raise ValueError('calibration_connected_group_overlap')
    return [sorted(fold) for fold in folds], {'indivisible_components': len(groups),
        'cross_fold_family_subject_device_session_projection_overlap': 0,
        'fold_case_counts': [len(fold) for fold in folds],
        'fold_positive_counts': [sum(cases[i].threat for i in fold) for fold in folds]}


def infer(cases, candidate):
    detector = ShadowDetector(thresholds=DraftThresholds.model_validate({k: v for k, v in candidate.items() if k != 'id'}))
    rows = []
    for case in cases:
        prediction, error = None, None
        try:
            prediction = detector.evaluate(case.event, 'synthetic-lab')
            predicted = prediction['predicted_rule_ids']
        except (ValueError, TypeError, RuntimeError):
            predicted, error = [], 'calibration_inference_failed'
        rows.append({'case_id': case.case_id, 'family_id': case.family_id, 'threat': case.threat,
            'expected_rule_ids': case.expected_rule_ids, 'detected': bool(predicted),
            'predicted_rule_ids': predicted, 'error': error,
            'assessment_status': prediction['assessment_status'] if prediction else 'failed'})
    return rows


def point_score(rows):
    counts = confusion([r['threat'] for r in rows], [r['detected'] for r in rows])
    return {'confusion': counts, 'metrics': metrics(counts),
            'evaluation_errors': sum(r['error'] is not None for r in rows), 'cases': len(rows)}


def rank(result, ordinal):
    values = result['metrics']
    if result['evaluation_errors'] or any(v is None for v in values.values()):
        return (-1, -1., -1., -1., -ordinal)
    minimum_margin = min(values[k]-.95 for k in ('precision', 'recall', 'f1'))
    minimum_margin = min(minimum_margin, .05-values['false_positive_rate'])
    return (0, minimum_margin, values['f1'], -values['false_positive_rate'], -ordinal)


def choose(scores):
    if not scores or not any(rank(result, i)[0] == 0 for i, result in enumerate(scores)):
        raise ValueError('calibration_no_valid_candidate')
    return max(range(len(scores)), key=lambda i: rank(scores[i], i))


def calibrate(cases, contract):
    # Split enforcement happens before inference. Historical holdout is forbidden here.
    folds, audit = connected_folds(cases, contract['outer_folds'])
    candidates = contract['candidates']
    predictions = [infer(cases, candidate) for candidate in candidates]
    outer, held_out = [], []
    for fold_id, evaluation_indices in enumerate(folds):
        excluded = set(evaluation_indices)
        training_indices = [i for i in range(len(cases)) if i not in excluded]
        scores = [point_score([rows[i] for i in training_indices]) for rows in predictions]
        chosen = choose(scores)
        evaluated = [predictions[chosen][i] for i in evaluation_indices]
        held_out.extend(evaluated)
        outer.append({'fold': fold_id, 'training_cases': len(training_indices),
            'evaluation_case_ids': [cases[i].case_id for i in evaluation_indices],
            'selected_candidate': candidates[chosen]['id'], 'training_scores': scores,
            'evaluation': point_score(evaluated)})
    if len(held_out) != len(cases) or len({r['case_id'] for r in held_out}) != len(cases):
        raise ValueError('calibration_outer_population')
    final_scores = [point_score(rows) for rows in predictions]
    final = choose(final_scores)
    return {'group_audit': audit, 'outer_folds': outer, 'out_of_fold_rows': held_out,
        'all_development_candidate_scores': [{'candidate': candidate, **result}
                                            for candidate, result in zip(candidates, final_scores)],
        'selected_from_all_development': candidates[final],
        'selected_by': SELECTION, 'no_app_configuration_changes': True,
        'new_independent_evaluation': False, 'independent_review': 'pending', 'goal_qualified': False}
