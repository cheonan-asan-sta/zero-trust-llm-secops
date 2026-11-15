"""Offline HTTP alert refinement; no identity trust, grants or access effects."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from scripts.f1_lab.line_truth import anchor
from scripts.f1_lab.native_bayes import validate
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_heads import NativeHeads, gate, load_frozen_heads
from scripts.f1_lab.native_jsonl import MAX_ROWS, decode, require
from scripts.f1_lab.raw_semantics import PROFILE

EXCLUDED = tuple(sorted(('http_requests_1s', 'http_requests_10s', 'http_requests_60s',
                         'http_targets_60s', 'http_errors_10s')))
RETENTION_FLAGS = ('sql_injection', 'path_traversal', 'shell_payload', 'command_parameter',
                   'uploaded_script', 'sensitive_file', 'scanner_agent', 'http_sql_boolean_comparison',
                   'http_sql_comment', 'http_shell_separator', 'http_template_syntax')
BENIGN_SCORE_MAX = .05
SCHEMA = 'f1-native-web-refinement-1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def fit_http_tree(records):
    """Fit first-development HTTP only; all rows are still consumed to EOF.

    Projection affects training splits only. Inference still validates the full
    existing feature contract. The exported tree is checked for excluded splits.
    """
    tree = NativeBinaryTree(profile=PROFILE, max_depth=8, min_leaf=5)
    tree.names = [name for name in tree.names if name not in EXCLUDED]
    report = {'population': 0, 'http_classes': [0, 0], 'unusable': 0, 'non_http': 0}
    for features, truth in records:
        report['population'] += 1
        require(report['population'] <= MAX_ROWS, 'web_training_population_bound')
        try:
            validate(features, profile=PROFILE)
        except ValueError:
            report['unusable'] += 1
            continue
        require(type(truth) is bool, 'web_training_truth')
        if gate(features, profile=PROFILE) != 'http':
            report['non_http'] += 1
            continue
        tree.observe_training(features, truth)
        report['http_classes'][int(truth)] += 1
    return tree.fit(), report


@dataclass(frozen=True)
class RefinementScore:
    baseline: float
    score: float
    evidence: float | None
    reason: str


class WebRefinement:
    """Retain baseline unless an eligible successful read has a low evidence score.

    This never raises a baseline score or creates a new alert. A low score is
    not authenticated benignity. The operator must keep this experimental
    classifier separate from the PDP and permission/credential decisions.
    """

    def __init__(self, baseline, baseline_sha256, tree, training_preparation_sha256):
        anchor(baseline_sha256)
        anchor(training_preparation_sha256)
        require(isinstance(baseline, NativeHeads) and baseline.profile == PROFILE
                and tree.profile == PROFILE and tree.max_depth == 8 and tree.min_leaf == 5
                and tree.class_balanced, 'web_model_contract')
        self._baseline = NativeHeads.restore(baseline.export())
        self._tree = NativeBinaryTree.restore(tree.export())
        self.baseline_sha256, self.training_sha256 = baseline_sha256, training_preparation_sha256

        def verify(node):
            if 'condition' in node:
                require(node['condition']['feature'] not in EXCLUDED, 'web_excluded_split')
                verify(node['left'])
                verify(node['right'])
        verify(self._tree.root)

    def score(self, features):
        old = self._baseline.probability(features)
        if gate(features, profile=PROFILE) != 'http':
            return RefinementScore(old, old, None, 'non_http_unchanged')
        eligible = (features['http_method'] in {'GET', 'HEAD'} and features['http_status_class'] == 2
                    and features['http_window_available'] and features['http_semantic_available']
                    and not features['http_semantic_parse_error'] and not features['http_encoding_replacement'])
        if not eligible:
            return RefinementScore(old, old, None, 'ineligible_or_unknown_context')
        if (any(features[name] for name in RETENTION_FLAGS)
                or features['http_user_agent_kind'] == 'scanner'
                or features['http_requests_60s'] >= 6 or features['http_requests_1s'] >= 6):
            return RefinementScore(old, old, None, 'retain_security_or_extreme_rate')
        try:
            evidence = self._tree.probability(features)
        except ValueError:
            return RefinementScore(old, old, None, 'refinement_unavailable')
        if evidence > BENIGN_SCORE_MAX:
            return RefinementScore(old, old, evidence, 'retain_ambiguous_score')
        return RefinementScore(old, min(old, evidence), evidence, 'low_evidence_score')

    def probability(self, features):
        return self.score(features).score

    def export(self):
        # The JSON copy prevents callers from mutating either retained model.
        return decode(canonical({'schema': SCHEMA, 'feature_profile': PROFILE,
            'baseline_model_sha256': self.baseline_sha256, 'training_preparation_sha256': self.training_sha256,
            'gate_version': self._baseline.gate_version, 'excluded_features': EXCLUDED,
            'benign_score_max': BENIGN_SCORE_MAX, 'retention_flags': RETENTION_FLAGS,
            'extreme_rate_bucket': 6, 'eligible_methods': ['GET', 'HEAD'], 'eligible_status_class': 2,
            'tree': self._tree.export(), 'scope': 'offline experimental alert refinement only; never grants access'}))


def load_web_refinement(path, expected_sha256, baseline_path, expected_baseline_sha256):
    anchor(expected_sha256)
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2, 'web_artifact_file')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == expected_sha256, 'web_artifact_hash')
    data = decode(body)
    fields = {'schema', 'feature_profile', 'baseline_model_sha256', 'training_preparation_sha256',
              'gate_version', 'excluded_features', 'benign_score_max', 'retention_flags',
              'extreme_rate_bucket', 'eligible_methods', 'eligible_status_class', 'tree', 'scope'}
    require(isinstance(data, dict) and set(data) == fields and data['schema'] == SCHEMA
            and data['feature_profile'] == PROFILE and data['baseline_model_sha256'] == expected_baseline_sha256
            and data['gate_version'] == 'observed-format-2-semantic'
            and data['excluded_features'] == list(EXCLUDED)
            and type(data['benign_score_max']) is float and data['benign_score_max'] == BENIGN_SCORE_MAX
            and data['retention_flags'] == list(RETENTION_FLAGS)
            and type(data['extreme_rate_bucket']) is int and data['extreme_rate_bucket'] == 6
            and data['eligible_methods'] == ['GET', 'HEAD']
            and type(data['eligible_status_class']) is int and data['eligible_status_class'] == 2
            and data['scope'] == 'offline experimental alert refinement only; never grants access',
            'web_artifact_contract')
    baseline = load_frozen_heads(baseline_path, expected_baseline_sha256)
    return WebRefinement(baseline, expected_baseline_sha256, NativeBinaryTree.restore(data['tree']),
                         data['training_preparation_sha256'])
