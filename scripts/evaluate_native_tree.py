"""Evaluate a frozen JSON tree on a second development scenario without refitting."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.native_bayes import counts, metrics, record, validate
from scripts.f1_lab.native_heads import load_frozen_heads
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.native_tree import load_frozen
from scripts.fit_native_raw import receipt, rows


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def evaluate(directory, expected_preparation_sha256, model_path, expected_model_sha256, output, *, model_kind='tree'):
    preparation = receipt(directory, expected_preparation_sha256)
    require(model_kind in {'tree', 'heads', 'ordered_tree'}, 'transfer_model_kind')
    tree = load_frozen_heads(model_path, expected_model_sha256) if model_kind == 'heads' else load_frozen(
        model_path, expected_model_sha256, ordered_binary=model_kind == 'ordered_tree')
    require(tree.profile == preparation.get('feature_profile', 'base'), 'transfer_feature_profile')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'fresh_transfer_output')
    output.mkdir(parents=True, mode=0o700)
    before = canonical(tree.export())
    report = {'schema': 'f1-native-tree-transfer-1', 'completed': False, 'scope': preparation['scope'],
              'evaluation_kind': 'cross-scenario development diagnostic; not independent final acceptance',
              'input_preparation_sha256': expected_preparation_sha256, 'model_sha256': expected_model_sha256,
              'refit_performed': False, 'threshold': .5, 'feature_profile': tree.profile,
              'model_kind': model_kind,
              'goal_qualified': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0}
    try:
        total, groups = counts(), [counts() for _pair in preparation['pairs']]
        index, within, cache = 0, 0, {}
        for features, truth in rows(directory, preparation):
            prediction = None
            try:
                validate(features, profile=tree.profile)
                key = tuple(sorted(features.items()))
                if key not in cache:
                    if len(cache) >= 100000:
                        cache.clear()
                    cache[key] = tree.probability(features) >= .5
                prediction = cache[key]
            except ValueError:
                pass
            record(total, truth, prediction)
            record(groups[index], truth, prediction)
            within += 1
            if within == preparation['pairs'][index]['rows']:
                index += 1
                within = 0
        require(canonical(tree.export()) == before, 'frozen_transfer_model_changed')
        report.update(metrics=metrics(total), per_pair=[{'raw_member': pair['raw_member'], 'metrics': metrics(value)}
                      for pair, value in zip(preparation['pairs'], groups, strict=True)],
                      model_state_before_after_sha256=hashlib.sha256(before).hexdigest(),
                      model_unchanged=True, completed=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (output/'evaluation.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--expected-preparation-sha256', required=True)
    parser.add_argument('--model', required=True, type=Path)
    parser.add_argument('--expected-model-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--model-kind', choices=('tree', 'heads', 'ordered_tree'), default='tree')
    args = parser.parse_args()
    report = evaluate(args.directory, args.expected_preparation_sha256, args.model, args.expected_model_sha256, args.output,
                      model_kind=args.model_kind)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
