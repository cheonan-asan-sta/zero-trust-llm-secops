"""Observed scanner read requests: offline advisory risk, never proof of an attack."""

import math

from scripts.f1_lab.native_bayes import validate
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_semantics import PROFILE

REASON = 'observed_scanner_read_requires_review'


def refine(previous, features):
    """Preserve every prior alarm; elevate a narrow explicit scanner observation.

    User-Agent is client-controlled and legitimate scanners also use it. This
    hypothesis must pass a paired development comparison before consideration;
    it is not evidence of unauthorized activity or a reason to revoke access.
    """
    require(isinstance(previous, OperationDecision) and not previous.automatic_enforcement_allowed,
            'scanner_previous')
    require(all(type(v) in {int, float} and math.isfinite(v) and 0 <= v <= 1
                for v in (previous.baseline_score, previous.score))
            and type(previous.alert) is bool and type(previous.review) is bool, 'scanner_previous_values')
    validate(features, profile=PROFILE)
    if previous.alert:
        return previous
    if (features['http_method'] not in {'GET', 'HEAD'} or features['http_status_class'] not in {2, 3, 4, 5}
            or not features['http_semantic_available'] or not features['http_window_available']
            or features['http_semantic_parse_error'] or features['http_encoding_replacement']
            or not features['scanner_agent'] or features['http_user_agent_kind'] != 'scanner'):
        return previous
    return OperationDecision(previous.baseline_score, max(previous.score, .95), True, True, REASON)
