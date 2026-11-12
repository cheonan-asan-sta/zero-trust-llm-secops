"""Small weighted categorical decision-tree candidate for offline raw observations.

Identical input vectors retain both class multiplicities. They are compressed
for training work, never removed from evaluation denominators or relabeled.
"""

import hashlib
import json

from scripts.f1_lab.native_bayes import feature_domains, state, validate
from scripts.f1_lab.native_jsonl import require


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
                'class_weights': self.weights, 'training_unique_vectors': len(self.table), 'root': self.root,
                'inference_scope': 'offline historical advisory; no access effects; empirical scores not calibrated probabilities'}
