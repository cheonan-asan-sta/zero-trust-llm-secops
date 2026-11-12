"""Small categorical raw-observation candidate. Offline advisory experiment only."""

import hashlib
import json
import math

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.raw_observations import raw_features

DOMAINS = {key: (False, True) for key, value in raw_features('').items() if type(value) is bool}
DOMAINS.update({
    'line_size_bucket': tuple(range(7)), 'http_target_size': tuple(range(7)),
    'http_status_class': tuple(range(10)), 'dns_name_size': tuple(range(7)),
    'dns_longest_label_size': tuple(range(6)), 'dns_label_count': tuple(range(6)),
    'dns_label_entropy': tuple(range(7)),
    'http_method': ('none', 'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'),
    'dns_action': ('none', 'query', 'forwarded', 'reply', 'cached'),
    'audit_event_type': ('other', 'USER_AUTH', 'USER_ACCT', 'USER_START', 'USER_END', 'CRED_ACQ',
                         'CRED_DISP', 'CRED_REFR', 'SERVICE_START', 'SERVICE_STOP', 'USER_CMD', 'SYSCALL', 'EXECVE'),
})
FEATURE_CONTRACT_SHA256 = hashlib.sha256(json.dumps(DOMAINS, sort_keys=True).encode()).hexdigest()


def validate(features):
    require(isinstance(features, dict) and features.keys() == DOMAINS.keys(), 'native_feature_population')
    for name, values in DOMAINS.items():
        require(type(features[name]) is type(values[0]) and features[name] in values, 'native_feature_value')


def state(value):
    return json.dumps(value, separators=(',', ':'))


class NativeBayes:
    def __init__(self):
        self.classes = [0, 0]
        self.counts = [{name: {state(value): 0 for value in values} for name, values in DOMAINS.items()} for _ in range(2)]

    def observe_training(self, features, malicious):
        validate(features)
        require(type(malicious) is bool, 'native_training_label')
        index = int(malicious)
        self.classes[index] += 1
        for name, value in features.items():
            self.counts[index][name][state(value)] += 1

    def probability(self, features):
        validate(features)
        require(min(self.classes) > 0, 'native_model_both_classes_required')
        scores = []
        for index, total in enumerate(self.classes):
            score = math.log((total+1)/(sum(self.classes)+2))
            for name, value in features.items():
                score += math.log((self.counts[index][name][state(value)]+1)/(total+len(DOMAINS[name])))
            scores.append(score)
        delta = max(-700.0, min(700.0, scores[0]-scores[1]))
        return 1/(1+math.exp(delta))

    def export(self):
        require(min(self.classes) > 0, 'native_model_both_classes_required')
        return {'schema': 'f1-native-categorical-bayes-1', 'feature_contract_sha256': FEATURE_CONTRACT_SHA256,
                'class_counts': self.classes, 'categorical_counts': self.counts,
                'laplace_alpha': 1, 'class_order': ['normal', 'attack'],
                'operational_scope': 'offline raw-observation advisory candidate; no access effects'}


def shape_reference(features):
    """A new native heuristic reference, not the preserved original app baseline."""
    validate(features)
    return any(features[name] for name in ('auth_failure', 'sensitive_file', 'sql_injection', 'path_traversal',
                                           'shell_payload', 'command_parameter', 'uploaded_script', 'scanner_agent')) or (
        features['dns_name_size'] >= 3 and features['dns_label_entropy'] >= 4)


def counts():
    return dict.fromkeys(('tp', 'fp', 'fn', 'tn', 'inference_errors'), 0)


def record(result, expected, predicted):
    require(type(expected) is bool and (type(predicted) is bool or predicted is None), 'native_score_types')
    if predicted is None:
        # A known-label inference failure is always an error, for either class.
        result['inference_errors'] += 1
        result['fn' if expected else 'fp'] += 1
    else:
        result['tp' if predicted and expected else 'fp' if predicted else 'fn' if expected else 'tn'] += 1


def metrics(result):
    tp, fp, fn, tn = (result[key] for key in ('tp', 'fp', 'fn', 'tn'))
    def ratio(n, d):
        return n/d if d else None
    return {**result, 'population': tp+fp+fn+tn,
            'precision': ratio(tp, tp+fp), 'recall': ratio(tp, tp+fn),
            'f1': ratio(2*tp, 2*tp+fp+fn), 'false_positive_rate': ratio(fp, fp+tn),
            'accuracy': ratio(tp+tn, tp+fp+fn+tn)}
