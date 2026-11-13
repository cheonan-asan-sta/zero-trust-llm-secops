"""Fit observation-format heads on first development data and retain all scoring rows."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.native_bayes import counts, metrics, record, validate
from scripts.f1_lab.native_heads import NativeHeads, gate
from scripts.f1_lab.native_jsonl import require
from scripts.fit_native_raw import receipt, rows


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def fit(directory, expected_sha256, output, *, tree_variant='categorical'):
    preparation = receipt(directory, expected_sha256)
    model = NativeHeads(profile=preparation.get('feature_profile'), tree_variant=tree_variant)
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'fresh_heads_fit')
    output.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-native-heads-fit-1', 'completed': False, 'scope': preparation['scope'],
              'evaluation_kind': 'development resubstitution only', 'training_preparation_sha256': expected_sha256,
              'threshold': .5, 'head_gate': model.gate_version, 'final_candidate_selected': False,
              'tree_variant': tree_variant,
              'goal_qualified': False, 'original_six_domain_goal_replaced': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0}
    try:
        fit_errors = 0
        for features, truth in rows(directory, preparation):
            try:
                validate(features, profile=model.profile)
            except ValueError:
                fit_errors += 1
                continue
            model.observe_training(features, truth)
        model.fit()
        total, groups = counts(), [counts() for _p in preparation['pairs']]
        cache, index, within = {}, 0, 0
        selected_heads = {}
        for features, truth in rows(directory, preparation):
            prediction = None
            try:
                validate(features, profile=model.profile)
                name = gate(features, profile=model.profile)
                selected_heads[name] = selected_heads.get(name, 0)+1
                key = tuple(sorted(features.items()))
                if key not in cache:
                    if len(cache) >= 100000:
                        cache.clear()
                    cache[key] = model.probability(features) >= .5
                prediction = cache[key]
            except ValueError:
                pass
            record(total, truth, prediction)
            record(groups[index], truth, prediction)
            within += 1
            if within == preparation['pairs'][index]['rows']:
                index += 1
                within = 0
        artifact = canonical(model.export())+b'\n'
        (output/'model.json').write_bytes(artifact)
        report.update(metrics=metrics(total), per_pair=[{'raw_member': p['raw_member'], 'metrics': metrics(c)}
                      for p, c in zip(preparation['pairs'], groups, strict=True)], model_sha256=hashlib.sha256(artifact).hexdigest(),
                      head_training_class_counts=model.class_counts, selected_heads=selected_heads,
                      rows_unusable_for_fit=fit_errors, completed=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (output/'fit.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--expected-preparation-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--tree-variant', choices=('categorical', 'ordered_binary'), default='categorical')
    args = parser.parse_args()
    result = fit(args.directory, args.expected_preparation_sha256, args.output, tree_variant=args.tree_variant)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
