"""Small weighted categorical decision-tree candidate for offline raw observations.

Identical input vectors retain both class multiplicities. They are compressed
for training work, never removed from evaluation denominators or relabeled.
"""

import hashlib
import json
import math
from pathlib import Path

from scripts.f1_lab.native_bayes import feature_domains, state, validate
from scripts.f1_lab.native_jsonl import MAX_ROWS, decode, require


def gini(normal, attack):
    total = normal+attack
    return 2*normal*attack/total**2 if total else 0.0


class NativeTree:
    def __init__(self, *, profile='base', max_depth=8, min_leaf=5, class_balanced=True):
        require(type(max_depth) is int and 1 <= max_depth <= 12 and type(min_leaf) is int
                and 1 <= min_leaf <= 1000 and type(class_balanced) is bool, 'tree_configuration')
        self.profile, self.domains = profile, feature_domains(profile)
        self.names = sorted(self.domains)
        self.max_depth, self.min_leaf, self.class_balanced = max_depth, min_leaf, class_balanced
        self.table, self.root = {}, None
        self.weights = None

    def observe_training(self, features, malicious):
        require(self.root is None, 'tree_already_fitted')
        validate(features, profile=self.profile)
        require(type(malicious) is bool, 'tree_training_label')
        key = tuple(features[name] for name in self.names)
        require(key in self.table or len(self.table) < 100000, 'tree_unique_vector_bound')
        counts = self.table.setdefault(key, [0, 0])
        counts[int(malicious)] += 1

    def fit(self):
        require(self.root is None and self.table, 'tree_unfitted_training_required')
        totals = [sum(values[i] for values in self.table.values()) for i in range(2)]
        require(min(totals) > 0, 'tree_both_classes_required')
        self.weights = [sum(totals)/(2*total) if self.class_balanced else 1.0 for total in totals]
        self.root = self._grow(list(self.table), 0)
        return self

    def _grow(self, keys, depth):
        counts = [sum(self.table[key][i] for key in keys) for i in range(2)]
        weighted = [counts[i]*self.weights[i] for i in range(2)]
        probability = weighted[1]/sum(weighted)
        node = {'counts': counts, 'probability': probability}
        if depth >= self.max_depth or min(counts) == 0 or sum(counts) < 2*self.min_leaf:
            return node
        best, best_groups, best_gain = None, None, 1e-9
        for position, name in enumerate(self.names):
            groups = {}
            for key in keys:
                groups.setdefault(key[position], []).append(key)
            if len(groups) < 2:
                continue
            child_counts = [[sum(self.table[key][i] for key in group) for i in range(2)] for group in groups.values()]
            if any(sum(count) < self.min_leaf for count in child_counts):
                continue
            impurity = 0.0
            for count in child_counts:
                n, a = count[0]*self.weights[0], count[1]*self.weights[1]
                impurity += (n+a)/sum(weighted)*gini(n, a)
            gain = gini(*weighted)-impurity
            if gain > best_gain:
                best, best_groups, best_gain = name, groups, gain
        if best is not None:
            node.update(feature=best, gain=best_gain,
                        children={state(value): self._grow(group, depth+1) for value, group in best_groups.items()})
        return node

    def probability(self, features):
        require(self.root is not None, 'tree_not_fitted')
        validate(features, profile=self.profile)
        node = self.root
        while 'feature' in node:
            child = node['children'].get(state(features[node['feature']]))
            if child is None:
                # Valid but unseen category: use this node's empirical risk,
                # never an invented safe/healthy default or a grant.
                break
            node = child
        return node['probability']

    def export(self):
        require(self.root is not None, 'tree_not_fitted')
        return {'schema': 'f1-native-categorical-tree-1', 'feature_profile': self.profile,
                'feature_contract_sha256': hashlib.sha256(json.dumps(self.domains, sort_keys=True).encode()).hexdigest(),
                'max_depth': self.max_depth, 'min_leaf': self.min_leaf, 'class_balanced': self.class_balanced,
                'class_weights': self.weights, 'training_unique_vectors': getattr(self, '_restored_unique_vectors', len(self.table)), 'root': self.root,
                'inference_scope': 'offline historical advisory; no access effects; empirical scores not calibrated probabilities'}

    @classmethod
    def restore(cls, payload):
        require(isinstance(payload, dict) and set(payload) == {
            'schema', 'feature_profile', 'feature_contract_sha256', 'max_depth', 'min_leaf', 'class_balanced',
            'class_weights', 'training_unique_vectors', 'root', 'inference_scope'}
            and payload['schema'] == 'f1-native-categorical-tree-1', 'tree_artifact_schema')
        tree = cls(profile=payload['feature_profile'], max_depth=payload['max_depth'],
                   min_leaf=payload['min_leaf'], class_balanced=payload['class_balanced'])
        expected_contract = hashlib.sha256(json.dumps(tree.domains, sort_keys=True).encode()).hexdigest()
        require(payload['feature_contract_sha256'] == expected_contract, 'tree_artifact_feature_contract')
        root = payload['root']
        require(isinstance(root, dict) and isinstance(root.get('counts'), list) and len(root['counts']) == 2
                and all(type(v) is int and v > 0 for v in root['counts']), 'tree_artifact_root_counts')
        totals = root['counts']
        weights = [sum(totals)/(2*v) if tree.class_balanced else 1.0 for v in totals]
        require(isinstance(payload['class_weights'], list) and len(payload['class_weights']) == 2
                and all(type(a) in {int, float} and math.isfinite(a) and math.isclose(a, b, rel_tol=1e-12)
                        for a, b in zip(payload['class_weights'], weights, strict=True)), 'tree_artifact_weights')
        nodes, leaves = 0, 0
        def verify(node, depth):
            nonlocal nodes, leaves
            nodes += 1
            require(nodes <= 100000 and depth <= tree.max_depth and isinstance(node, dict), 'tree_artifact_bound')
            counts = node.get('counts')
            require(isinstance(counts, list) and len(counts) == 2 and all(type(v) is int and v >= 0 for v in counts)
                    and 0 < sum(counts) <= MAX_ROWS, 'tree_artifact_counts')
            weighted = [counts[i]*weights[i] for i in range(2)]
            probability = node.get('probability')
            require(type(probability) in {int, float} and math.isfinite(probability) and 0 <= probability <= 1
                    and math.isclose(probability, weighted[1]/sum(weighted), rel_tol=1e-12, abs_tol=1e-12),
                    'tree_artifact_probability')
            if 'feature' not in node:
                require(set(node) == {'counts', 'probability'}, 'tree_artifact_leaf')
                leaves += 1
                return counts
            require(set(node) == {'counts', 'probability', 'feature', 'gain', 'children'}
                    and node['feature'] in tree.domains and isinstance(node['children'], dict)
                    and 2 <= len(node['children']) <= len(tree.domains[node['feature']]), 'tree_artifact_split')
            allowed = {state(v) for v in tree.domains[node['feature']]}
            require(set(node['children']) <= allowed, 'tree_artifact_categories')
            child_counts = [verify(child, depth+1) for child in node['children'].values()]
            require(all(sum(c) >= tree.min_leaf for c in child_counts)
                    and [sum(c[i] for c in child_counts) for i in range(2)] == counts, 'tree_artifact_conservation')
            impurity = sum(sum(c[i]*weights[i] for i in range(2))/sum(weighted)
                           *gini(c[0]*weights[0], c[1]*weights[1]) for c in child_counts)
            gain = node['gain']
            require(type(gain) in {int, float} and math.isfinite(gain) and gain > 1e-9
                    and math.isclose(gain, gini(*weighted)-impurity, rel_tol=1e-10, abs_tol=1e-12),
                    'tree_artifact_gain')
            return counts
        verify(root, 0)
        unique = payload['training_unique_vectors']
        require(type(unique) is int and leaves <= unique <= min(100000, sum(totals)), 'tree_artifact_unique_count')
        tree.root = json.loads(json.dumps(root, allow_nan=False))
        tree.weights, tree._restored_unique_vectors = weights, unique
        return tree


def load_frozen(path, expected_sha256):
    path = Path(path)
    require(isinstance(expected_sha256, str) and len(expected_sha256) == 64
            and all(c in '0123456789abcdef' for c in expected_sha256), 'tree_external_anchor')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16*1024**2, 'tree_artifact_file')
    with path.open('rb') as stream:
        body = stream.read(16*1024**2+1)
    require(len(body) <= 16*1024**2 and hashlib.sha256(body).hexdigest() == expected_sha256, 'tree_artifact_hash')
    return NativeTree.restore(decode(body))
