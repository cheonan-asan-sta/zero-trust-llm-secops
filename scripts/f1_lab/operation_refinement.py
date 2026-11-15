"""Pinned error-log refinement and VPN risk triage; advisory only, never grants."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from scripts.f1_lab.native_bayes import feature_domains
from scripts.f1_lab.native_heads import gate
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.native_tree import load_frozen
from scripts.f1_lab.operation_context import BoundContext, canonical
from scripts.f1_lab.raw_context import PROFILE as CORE_PROFILE
from scripts.f1_lab.raw_semantics import PROFILE
from scripts.f1_lab.vpn_context import PROFILE as VPN_PROFILE
from scripts.f1_lab.web_refinement import load_web_refinement

SCHEMA = 'f1-error-vpn-policy-1'
POLICY = {'schema': SCHEMA, 'baseline_threshold': .95, 'vpn_alert_threshold': .95,
          'vpn_review_threshold': .9, 'apache_warning_score_cap': .05,
          'context_contract': 'source-sha-ordinal-core-features-strict-past-1',
          'scope': 'offline advisory; VPN risk requires review; no access effects'}


@dataclass(frozen=True)
class OperationDecision:
    baseline_score: float
    score: float
    alert: bool
    review: bool
    reason: str
    automatic_enforcement_allowed: bool = False


class OperationRefinement:
    def __init__(self, web_model, vpn_model):
        require(vpn_model.profile == VPN_PROFILE, 'operation_vpn_profile')
        self.web_model, self.vpn_model = web_model, vpn_model

    def decide(self, features, case_id, context=None):
        baseline = self.web_model.probability(features)
        old_alert = baseline >= POLICY['baseline_threshold']
        if context is None:
            return OperationDecision(baseline, baseline, old_alert, old_alert, 'missing_context')
        require(isinstance(context, BoundContext) and context.case_id == case_id
                and hashlib.sha256((context.raw_sha256+':'+str(context.ordinal)).encode()).hexdigest() == case_id,
                'operation_case_binding')
        core = {name: features[name] for name in feature_domains(CORE_PROFILE)}
        require(hashlib.sha256(canonical(core)).hexdigest() == context.core_sha256, 'operation_feature_binding')
        if context.kind == 'vpn':
            require(gate(features, profile=PROFILE) == 'vpn', 'operation_vpn_gate_binding')
            if context.vpn_features is not None:
                require(hashlib.sha256(canonical(context.vpn_features)).hexdigest() == context.vpn_feature_sha256,
                        'operation_vpn_context_changed')
                require(all(context.vpn_features.get(name) == value for name, value in core.items()),
                        'operation_vpn_core_binding')
            if context.vpn_features is None or not context.vpn_features.get('vpn_endpoint_available'):
                return OperationDecision(baseline, baseline, old_alert, old_alert, 'vpn_context_unavailable')
            score = max(baseline, self.vpn_model.probability(context.vpn_features))
            return OperationDecision(baseline, score, old_alert or score >= POLICY['vpn_alert_threshold'],
                old_alert or score >= POLICY['vpn_review_threshold'], 'vpn_history_risk_review')
        require(context.kind == 'apache_error', 'operation_context_kind')
        observed = context.apache
        if (observed is not None and observed.parsed and observed.warning_candidate
                and observed.client_available and observed.time_available
                and not observed.payload_signal and not observed.recent_security_error):
            score = min(baseline, POLICY['apache_warning_score_cap'])
            return OperationDecision(baseline, score, score >= POLICY['baseline_threshold'],
                                     score >= POLICY['baseline_threshold'], 'apache_missing_directory_warning')
        return OperationDecision(baseline, baseline, old_alert, old_alert, 'retain_apache_or_unknown')


def load_operation_refinement(policy_path, expected_policy_sha256, web_path, expected_web_sha256,
                              heads_path, expected_heads_sha256, vpn_path, expected_vpn_sha256):
    path = Path(policy_path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536, 'operation_policy_file')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == expected_policy_sha256, 'operation_policy_hash')
    data = decode(body)
    expected = {**POLICY, 'web_model_sha256': expected_web_sha256,
                'heads_model_sha256': expected_heads_sha256, 'vpn_model_sha256': expected_vpn_sha256}
    require(data == expected and all(type(data[k]) is float for k in ('baseline_threshold', 'vpn_alert_threshold',
            'vpn_review_threshold', 'apache_warning_score_cap')), 'operation_policy_contract')
    web = load_web_refinement(web_path, expected_web_sha256, heads_path, expected_heads_sha256)
    vpn = load_frozen(vpn_path, expected_vpn_sha256, ordered_binary=True)
    return OperationRefinement(web, vpn)
