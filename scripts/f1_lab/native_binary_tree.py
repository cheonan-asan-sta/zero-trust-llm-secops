"""Ordered binary splits for bucket features; rare categories do not veto every split."""

import hashlib
import json
import math

from scripts.f1_lab.native_bayes import validate
from scripts.f1_lab.native_jsonl import MAX_ROWS, require
from scripts.f1_lab.native_tree import NativeTree, gini


class NativeBinaryTree(NativeTree):
    def _grow(self, keys, depth):
        counts = [sum(self.table[key][i] for key in keys) for i in range(2)]
        weighted = [counts[i]*self.weights[i] for i in range(2)]
        node = {'counts': counts, 'probability': weighted[1]/sum(weighted)}
        if depth >= self.max_depth or min(counts) == 0 or sum(counts) < 2*self.min_leaf:
            return node
        best, best_groups, best_gain = None, None, 1e-9
        for position, name in enumerate(self.names):
            values = sorted({key[position] for key in keys})
            ordered = type(self.domains[name][0]) is int
            candidates = values[:-1] if ordered else values
            for value in candidates:
                left, right = [], []
                for key in keys:
                    group = left if (key[position] <= value if ordered else key[position] == value) else right
                    group.append(key)
                child_counts = [[sum(self.table[key][i] for key in group) for i in range(2)] for group in (left, right)]
                if any(sum(c) < self.min_leaf for c in child_counts):
                    continue
                impurity = sum(sum(c[i]*self.weights[i] for i in range(2))/sum(weighted)
                               *gini(c[0]*self.weights[0], c[1]*self.weights[1]) for c in child_counts)
                gain = gini(*weighted)-impurity
                if gain > best_gain:
                    best = {'feature': name, 'operator': 'le' if ordered else 'eq', 'value': value}
                    best_groups, best_gain = (left, right), gain
        if best is not None:
            node.update(condition=best, gain=best_gain, left=self._grow(best_groups[0], depth+1),
                        right=self._grow(best_groups[1], depth+1))
        return node

    def probability(self, features):
        require(self.root is not None, 'binary_tree_not_fitted')
        validate(features, profile=self.profile)
        node = self.root
        while 'condition' in node:
            condition = node['condition']
            value = features[condition['feature']]
            goes_left = value <= condition['value'] if condition['operator'] == 'le' else value == condition['value']
            node = node['left' if goes_left else 'right']
        return node['probability']

    def export(self):
        return {**super().export(), 'schema': 'f1-native-ordered-binary-tree-1'}

    @classmethod
    def restore(cls, payload):
        require(isinstance(payload, dict) and set(payload) == {'schema', 'feature_profile', 'feature_contract_sha256',
                'max_depth', 'min_leaf', 'class_balanced', 'class_weights', 'training_unique_vectors', 'root', 'inference_scope'}
                and payload['schema'] == 'f1-native-ordered-binary-tree-1', 'binary_tree_artifact_schema')
        tree = cls(profile=payload['feature_profile'], max_depth=payload['max_depth'], min_leaf=payload['min_leaf'],
                   class_balanced=payload['class_balanced'])
        require(payload['feature_contract_sha256'] == hashlib.sha256(json.dumps(tree.domains, sort_keys=True).encode()).hexdigest(),
                'binary_tree_feature_contract')
        root = payload['root']
        require(isinstance(root, dict) and isinstance(root.get('counts'), list) and len(root['counts']) == 2
                and all(type(v) is int and v > 0 for v in root['counts']), 'binary_tree_root_counts')
        totals = root['counts']
        weights = [sum(totals)/(2*v) if tree.class_balanced else 1.0 for v in totals]
        require(isinstance(payload['class_weights'], list) and len(payload['class_weights']) == 2
                and all(type(a) in {int, float} and math.isfinite(a) and math.isclose(a, b, rel_tol=1e-12)
                        for a, b in zip(payload['class_weights'], weights, strict=True)), 'binary_tree_weights')
        nodes, leaves = 0, 0
        def verify(node, depth):
            nonlocal nodes, leaves
            nodes += 1
            require(nodes <= 100000 and depth <= tree.max_depth and isinstance(node, dict), 'binary_tree_bound')
            counts = node.get('counts')
            require(isinstance(counts, list) and len(counts) == 2 and all(type(v) is int and v >= 0 for v in counts)
                    and 0 < sum(counts) <= MAX_ROWS, 'binary_tree_counts')
            weighted = [counts[i]*weights[i] for i in range(2)]
            probability = node.get('probability')
            require(type(probability) in {int, float} and math.isfinite(probability) and 0 <= probability <= 1
                    and math.isclose(probability, weighted[1]/sum(weighted), rel_tol=1e-12, abs_tol=1e-12), 'binary_tree_probability')
            if 'condition' not in node:
                require(set(node) == {'counts', 'probability'}, 'binary_tree_leaf')
                leaves += 1
                return counts
            require(set(node) == {'counts', 'probability', 'condition', 'gain', 'left', 'right'}, 'binary_tree_node')
            condition = node['condition']
            require(isinstance(condition, dict) and set(condition) == {'feature', 'operator', 'value'}
                    and condition['feature'] in tree.domains, 'binary_tree_condition')
            domain = tree.domains[condition['feature']]
            require(type(condition['value']) is type(domain[0]) and condition['value'] in domain
                    and condition['operator'] in {'le', 'eq'}
                    and (condition['operator'] != 'le' or type(domain[0]) is int), 'binary_tree_condition_value')
            children = [verify(node[side], depth+1) for side in ('left', 'right')]
            require(all(sum(c) >= tree.min_leaf for c in children)
                    and [sum(c[i] for c in children) for i in range(2)] == counts, 'binary_tree_conservation')
            impurity = sum(sum(c[i]*weights[i] for i in range(2))/sum(weighted)
                           *gini(c[0]*weights[0], c[1]*weights[1]) for c in children)
            gain = node['gain']
            require(type(gain) in {int, float} and math.isfinite(gain) and gain > 1e-9
                    and math.isclose(gain, gini(*weighted)-impurity, rel_tol=1e-10, abs_tol=1e-12), 'binary_tree_gain')
            return counts
        verify(root, 0)
        unique = payload['training_unique_vectors']
        require(type(unique) is int and leaves <= unique <= min(100000, sum(totals)), 'binary_tree_unique_count')
        tree.root = json.loads(json.dumps(root, allow_nan=False))
        tree.weights, tree._restored_unique_vectors = weights, unique
        return tree
