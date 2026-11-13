"""Frozen-model successful POST refinement for offline alert evaluation only."""

import math

from scripts.f1_lab.native_bayes import validate
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_semantics import PROFILE
from scripts.f1_lab.web_refinement import BENIGN_SCORE_MAX, RETENTION_FLAGS, WebRefinement

REASON = 'successful_post_low_model_evidence'


class SuccessfulPostRefinement:
    """Extend the frozen HTTP tree's eligibility, retaining every attack guard.

    A low model score is not authenticated benignity. The POST body is absent
    from this access-log view; neither identity trust nor access is granted.
    The tree was fitted on all HTTP rows, not solely on GET/HEAD. No fitting or
    threshold selection happens here. Upstream intent/history overrides remain.
    """

    def __init__(self, web_model):
        require(isinstance(web_model, WebRefinement), 'post_frozen_web_model')
        self.web_model = web_model
        self.tree = NativeBinaryTree.restore(web_model.export()['tree'])

    def refine(self, previous, features):
        require(isinstance(previous, OperationDecision) and not previous.automatic_enforcement_allowed,
                'post_previous')
        require(all(type(v) in {int, float} and math.isfinite(v) and 0 <= v <= 1
                    for v in (previous.baseline_score, previous.score))
                and type(previous.alert) is bool and type(previous.review) is bool, 'post_previous_values')
        validate(features, profile=PROFILE)
        if previous.reason != 'unchanged' or not previous.alert:
            return previous
        if (features['http_method'] != 'POST' or features['http_status_class'] != 2
                or not features['http_window_available'] or not features['http_semantic_available']
                or features['http_semantic_parse_error'] or features['http_encoding_replacement']):
            return previous
        if (any(features[name] for name in RETENTION_FLAGS)
                or features['http_user_agent_kind'] == 'scanner'
                or features['http_requests_60s'] >= 6 or features['http_requests_1s'] >= 6):
            return previous
        # A different upstream score, even with a misleading generic reason,
        # cannot be erased by this optional wrapper.
        require(previous.score == self.web_model.probability(features), 'post_baseline_score_binding')
        probability = self.tree.probability(features)
        require(type(probability) in {int, float} and math.isfinite(probability) and 0 <= probability <= 1,
                'post_evidence_probability')
        if probability > BENIGN_SCORE_MAX:
            return previous
        score = min(previous.score, probability)
        return OperationDecision(previous.baseline_score, score, score >= .95, score >= .9, REASON)
