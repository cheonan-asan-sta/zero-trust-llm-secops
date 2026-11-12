"""Observation-format heads prevent a large DNS stream dominating rare CPU/auth examples."""

import hashlib
from pathlib import Path

from scripts.f1_lab.native_bayes import validate
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_jsonl import MAX_ROWS, decode, require
from scripts.f1_lab.native_tree import NativeTree
from scripts.f1_lab.raw_context import PROFILE
from scripts.f1_lab.raw_semantics import PROFILE as SEMANTIC_PROFILE
from scripts.f1_lab.vpn_context import PROFILE as VPN_PROFILE

HEADS = ('cpu', 'http', 'dns', 'audit', 'vpn', 'auth', 'other')


def gate(features, *, profile=PROFILE):
    validate(features, profile=profile)
    if features['cpu_available']:
        return 'cpu'
    if features['http_window_available'] or features['http_method'] != 'none':
        return 'http'
    if features['dns_action'] != 'none':
        return 'dns'
    if features['audit_event_type'] != 'other' or profile == SEMANTIC_PROFILE and features['audit_extended_type'] != 'other':
        return 'audit'
    if features['vpn_stage'] != 'none':
        return 'vpn'
    if any(features[name] for name in ('su_observed', 'auth_failure', 'auth_success', 'session_open', 'session_close', 'privilege_tool')):
        return 'auth'
    if profile == SEMANTIC_PROFILE and features['auth_service_kind'] != 'none':
        return 'auth'
    return 'other'


class NativeHeads:
    def __init__(self, *, profile=PROFILE, max_depth=8, min_leaf=5, tree_variant='categorical'):
        require(profile in {PROFILE, VPN_PROFILE, SEMANTIC_PROFILE}, 'heads_rich_profile_required')
        require(tree_variant in {'categorical', 'ordered_binary'}, 'heads_tree_variant')
        self.profile = profile
        self.max_depth, self.min_leaf = max_depth, min_leaf
        self.tree_variant = tree_variant
        kind = NativeTree if tree_variant == 'categorical' else NativeBinaryTree
        self.models = {name: kind(profile=profile, max_depth=max_depth, min_leaf=min_leaf) for name in HEADS}
        self.class_counts = {name: [0, 0] for name in HEADS}
        self.fitted = False

    @property
    def gate_version(self):
        return 'observed-format-2-semantic' if self.profile == SEMANTIC_PROFILE else 'observed-format-1'

    def observe_training(self, features, malicious):
        require(not self.fitted, 'heads_already_fitted')
        name = gate(features, profile=self.profile)
        self.models[name].observe_training(features, malicious)
        self.class_counts[name][int(malicious)] += 1

    def fit(self):
        require(not self.fitted and sum(sum(v) for v in self.class_counts.values()) > 0, 'heads_training_required')
        for name, counts in self.class_counts.items():
            if min(counts) > 0:
                self.models[name].fit()
            else:
                # One observed class is not proof of safety for a new input.
                self.models[name] = None
        self.fitted = True
        return self

    def probability(self, features):
        require(self.fitted, 'heads_not_fitted')
        model = self.models[gate(features, profile=self.profile)]
        require(model is not None, 'heads_insufficient_class_support')
        return model.probability(features)

    def export(self):
        require(self.fitted, 'heads_not_fitted')
        return {'schema': 'f1-native-event-heads-1', 'feature_profile': self.profile, 'gate_version': self.gate_version,
                'tree_variant': self.tree_variant,
                'max_depth': self.max_depth, 'min_leaf': self.min_leaf,
                'class_counts': self.class_counts,
                'models': {name: model.export() if model is not None else None for name, model in self.models.items()},
                'scope': 'offline advisory; gate uses observed features only; unsupported heads abstain'}

    @classmethod
    def restore(cls, payload):
        fields = {'schema', 'feature_profile', 'gate_version', 'max_depth', 'min_leaf', 'class_counts', 'models', 'scope'}
        require(isinstance(payload, dict) and set(payload) in (fields, fields | {'tree_variant'})
                and payload['schema'] == 'f1-native-event-heads-1', 'heads_artifact_schema')
        result = cls(profile=payload['feature_profile'], max_depth=payload['max_depth'], min_leaf=payload['min_leaf'],
                     tree_variant=payload.get('tree_variant', 'categorical'))
        require(payload['gate_version'] == result.gate_version, 'heads_artifact_gate_binding')
        require(isinstance(payload['class_counts'], dict) and set(payload['class_counts']) == set(HEADS)
                and isinstance(payload['models'], dict) and set(payload['models']) == set(HEADS), 'heads_artifact_population')
        total = 0
        for name in HEADS:
            counts = payload['class_counts'][name]
            require(isinstance(counts, list) and len(counts) == 2 and all(type(n) is int and n >= 0 for n in counts),
                    'heads_artifact_counts')
            total += sum(counts)
            model = payload['models'][name]
            if min(counts) == 0:
                require(model is None, 'heads_artifact_unsupported')
                result.models[name] = None
            else:
                kind = NativeTree if result.tree_variant == 'categorical' else NativeBinaryTree
                restored = kind.restore(model)
                require(restored.profile == result.profile and restored.root['counts'] == counts
                        and restored.max_depth == result.max_depth and restored.min_leaf == result.min_leaf
                        and restored.class_balanced, 'heads_artifact_model_binding')
                result.models[name] = restored
            result.class_counts[name] = list(counts)
        require(0 < total <= MAX_ROWS, 'heads_artifact_total')
        result.fitted = True
        return result


def load_frozen_heads(path, expected_sha256):
    path = Path(path)
    require(isinstance(expected_sha256, str) and len(expected_sha256) == 64
            and all(c in '0123456789abcdef' for c in expected_sha256), 'heads_external_anchor')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16*1024**2, 'heads_artifact_file')
    with path.open('rb') as stream:
        body = stream.read(16*1024**2+1)
    require(len(body) <= 16*1024**2 and hashlib.sha256(body).hexdigest() == expected_sha256, 'heads_artifact_hash')
    return NativeHeads.restore(decode(body))
