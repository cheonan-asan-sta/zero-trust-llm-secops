"""Fit and diagnose native raw candidates on development data, never final acceptance."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.line_truth import anchor
from scripts.f1_lab.native_bayes import (
    NativeBayes,
    counts,
    metrics,
    record,
    shape_reference,
    validate,
)
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_jsonl import MAX_ROW, MAX_ROWS, decode, require
from scripts.f1_lab.native_tree import NativeTree

THRESHOLDS = (.1, .25, .5, .75, .9, .95, .99)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def receipt(directory, expected_sha256):
    directory = Path(directory)
    anchor(expected_sha256)
    path = directory/'preparation.json'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2, 'raw_preparation_receipt')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'raw_preparation_hash')
    data = decode(raw)
    require(data.get('schema') == 'f1-native-raw-input-1' and data.get('completed') is True
            and data.get('inputs_contain_truth') is False and 1 <= len(data['pairs']) <= 64, 'raw_preparation_contract')
    require(sum(row['rows'] for row in data['pairs']) <= MAX_ROWS, 'raw_training_population_bound')
    return data


def rows(directory, preparation):
    directory = Path(directory)
    paths = [directory/name for name in ('inputs.jsonl', 'truth.jsonl')]
    for path in paths:
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == preparation['files'][path.name]['bytes'],
                'raw_prepared_file')
    sha_in, sha_truth, count = hashlib.sha256(), hashlib.sha256(), 0
    with paths[0].open('rb') as inputs, paths[1].open('rb') as truth:
        while body := inputs.readline(MAX_ROW+1):
            gold_body = truth.readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW and 0 < len(gold_body) <= MAX_ROW, 'raw_join_row_bound')
            sha_in.update(body)
            sha_truth.update(gold_body)
            item, gold = decode(body), decode(gold_body)
            require(set(item) == {'case_id', 'features', 'observation_error'}
                    and set(gold) == {'case_id', 'malicious', 'attack_labels'}, 'raw_join_schema')
            anchor(item['case_id'])
            require(item['case_id'] == gold['case_id'] and type(gold['malicious']) is bool, 'raw_join_alignment')
            count += 1
            require(count <= MAX_ROWS, 'raw_join_population')
            yield item['features'], gold['malicious']
        require(not truth.read(1), 'raw_truth_extra_row')
    require(sha_in.hexdigest() == preparation['files']['inputs.jsonl']['sha256']
            and sha_truth.hexdigest() == preparation['files']['truth.jsonl']['sha256']
            and count == sum(row['rows'] for row in preparation['pairs']), 'raw_prepared_hash_or_rows')


def fit(directory, expected_sha256, output, *, include_tree=False, tree_variant='categorical'):
    require(type(include_tree) is bool, 'tree_inclusion_flag')
    require(tree_variant in {'categorical', 'ordered_binary'}
            and (include_tree or tree_variant == 'categorical'), 'raw_tree_variant')
    preparation = receipt(directory, expected_sha256)
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'fresh_raw_fit_output')
    output.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-native-development-fit-1', 'completed': False, 'scope': preparation['scope'],
              'training_preparation_sha256': expected_sha256, 'evaluation': 'development resubstitution only',
              'independent_evaluation': False, 'original_app_baseline_replaced': False,
              'reference': 'new native shape heuristic; not original Sigma engine',
              'original_app_native_measurement': 'not performed; required context must not be manufactured',
              'goal_qualified': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0}
    try:
        profile = preparation.get('feature_profile', 'base')
        model, fit_errors, all_training_counts = NativeBayes(profile=profile), 0, [0, 0]
        tree_class = NativeTree if tree_variant == 'categorical' else NativeBinaryTree
        tree = tree_class(profile=profile) if include_tree else None
        report['tree_variant'] = tree_variant if include_tree else None
        report['feature_profile'] = profile
        for features, truth in rows(directory, preparation):
            all_training_counts[int(truth)] += 1
            try:
                model.observe_training(features, truth)
            except ValueError:
                fit_errors += 1
                continue
            if tree is not None:
                tree.observe_training(features, truth)
        artifact = model.export()
        tree_artifact = tree.fit().export() if tree is not None else None
        report['training'] = {'known_class_counts': all_training_counts, 'fitted_class_counts': model.classes,
                              'rows_unusable_for_fit': fit_errors}
        names = ['native_shape_reference', *('native_bayes_'+str(value) for value in THRESHOLDS)]
        if tree is not None:
            names.append('native_tree_0.5')
        totals = {name: counts() for name in names}
        per_pair = [{name: counts() for name in names} for _pair in preparation['pairs']]
        cache, pair_index, within_pair = {}, 0, 0
        for features, truth in rows(directory, preparation):
            probability, reference, tree_probability = None, None, None
            try:
                validate(features, profile=profile)
                cache_key = tuple(sorted(features.items()))
                if cache_key not in cache:
                    if len(cache) >= 100_000:
                        cache.clear()
                    cache[cache_key] = (model.probability(features), shape_reference(features, profile=profile),
                                        tree.probability(features) if tree is not None else None)
                probability, reference, tree_probability = cache[cache_key]
            except ValueError:
                pass
            predictions = [reference, *(None if probability is None else probability >= value for value in THRESHOLDS)]
            if tree is not None:
                predictions.append(None if probability is None else tree_probability >= .5)
            for name, prediction in zip(names, predictions, strict=True):
                record(totals[name], truth, prediction)
                record(per_pair[pair_index][name], truth, prediction)
            within_pair += 1
            if within_pair == preparation['pairs'][pair_index]['rows']:
                pair_index += 1
                within_pair = 0
        report['metrics'] = {name: metrics(value) for name, value in totals.items()}
        report['per_pair'] = [{'raw_member': pair['raw_member'], 'scores': {name: metrics(value) for name, value in group.items()}}
                              for pair, group in zip(preparation['pairs'], per_pair, strict=True)]
        report['frozen_candidate_selected'] = False
        report['thresholds'] = THRESHOLDS
        model_body = canonical(artifact)+b'\n'
        (output/'model.json').write_bytes(model_body)
        report['model_sha256'] = hashlib.sha256(model_body).hexdigest()
        if tree_artifact is not None:
            tree_body = canonical(tree_artifact)+b'\n'
            (output/'tree-model.json').write_bytes(tree_body)
            report['tree_model_sha256'] = hashlib.sha256(tree_body).hexdigest()
        report['completed'] = True
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
    parser.add_argument('--include-tree', action='store_true')
    parser.add_argument('--tree-variant', choices=('categorical', 'ordered_binary'), default='categorical')
    args = parser.parse_args()
    report = fit(args.directory, args.expected_preparation_sha256, args.output, include_tree=args.include_tree,
                 tree_variant=args.tree_variant)
    print(json.dumps({key: report[key] for key in ('completed', 'evaluation', 'training', 'metrics', 'goal_qualified')}))


if __name__ == '__main__':
    main()
