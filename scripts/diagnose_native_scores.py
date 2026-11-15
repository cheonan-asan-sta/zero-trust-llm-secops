"""Diagnose frozen scores on observed development/calibration, never select a final model.

The fixed threshold grid and error vectors explain failures. Labels enter only
the evaluator's counters, never the frozen model or its features. No refitting,
threshold adoption, relabeling, row removal or independent-final claim occurs.
"""

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from scripts.f1_lab.native_bayes import counts, metrics, record, validate
from scripts.f1_lab.native_heads import load_frozen_heads
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.native_tree import load_frozen
from scripts.fit_native_raw import receipt, rows

THRESHOLDS = (.0001, .001, .01, .025, .05, .1, .25, .5, .75, .9)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def diagnose(directory, expected_preparation_sha256, model_path, expected_model_sha256, output,
             *, thresholds=THRESHOLDS, max_vectors=100000, model_kind='ordered_tree'):
    require(isinstance(thresholds, tuple) and 1 <= len(thresholds) <= 16
            and all(type(value) in {int, float} and math.isfinite(value) and 0 < value <= 1 for value in thresholds)
            and len(set(thresholds)) == len(thresholds) and .5 in thresholds, 'score_diagnostic_thresholds')
    require(type(max_vectors) is int and 1 <= max_vectors <= 100000, 'score_diagnostic_vector_limit')
    require(model_kind in {'ordered_tree', 'heads'}, 'score_diagnostic_model_kind')
    preparation = receipt(directory, expected_preparation_sha256)
    model = load_frozen_heads(model_path, expected_model_sha256) if model_kind == 'heads' else load_frozen(
        model_path, expected_model_sha256, ordered_binary=True)
    require(model.profile == preparation.get('feature_profile', 'base'), 'score_diagnostic_profile')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'fresh_score_diagnostic_output')
    output.mkdir(parents=True, mode=0o700)
    before = canonical(model.export())
    implementation_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = {'schema': 'f1-frozen-score-diagnostic-1', 'completed': False,
              'evaluation_kind': 'observed development/calibration error analysis only', 'scope': preparation['scope'],
              'preparation_sha256': expected_preparation_sha256, 'model_sha256': expected_model_sha256,
              'model_kind': model_kind, 'implementation_sha256': implementation_sha,
              'thresholds': thresholds, 'selected_threshold': None, 'model_refitted': False, 'labels_changed': False,
              'goal_qualified': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0, 'max_unique_vectors': max_vectors}
    try:
        totals = {str(value): counts() for value in thresholds}
        groups = [{str(value): counts() for value in thresholds} for _ in preparation['pairs']]
        # Key is generic feature bytes, never a case ID, timestamp, source name or truth.
        vectors, mass = {}, [Counter() for _ in preparation['pairs']]
        score_sha, count, pair_index, within = hashlib.sha256(), 0, 0, 0
        for features, truth in rows(directory, preparation):
            probability, body = None, None
            try:
                validate(features, profile=model.profile)
            except ValueError:
                pass
            else:
                body = canonical(features)
                if body not in vectors:
                    require(len(vectors) < max_vectors, 'score_diagnostic_unique_vector_bound')
                    try:
                        probability = model.probability(features)
                    except ValueError:
                        # Unsupported heads abstain just as in the frozen evaluator;
                        # these are inference errors, not probabilities of zero.
                        probability = None
                    vectors[body] = {'probability': probability, 'classes': [0, 0],
                                     'per_pair': [[0, 0] for _ in preparation['pairs']]}
                vector = vectors[body]
                probability = vector['probability']
                vector['classes'][int(truth)] += 1
                vector['per_pair'][pair_index][int(truth)] += 1
            count += 1
            score_sha.update(canonical({'ordinal': count, 'probability': probability})+b'\n')
            mass[pair_index][('error' if probability is None else format(probability, '.17g'), int(truth))] += 1
            for threshold in thresholds:
                prediction = None if probability is None else probability >= threshold
                record(totals[str(threshold)], truth, prediction)
                record(groups[pair_index][str(threshold)], truth, prediction)
            within += 1
            if within == preparation['pairs'][pair_index]['rows']:
                pair_index += 1
                within = 0
        require(canonical(model.export()) == before, 'score_diagnostic_model_changed')
        require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == implementation_sha,
                'score_diagnostic_implementation_changed')
        report['metrics'] = {key: metrics(value) for key, value in totals.items()}
        report['per_pair'] = [{'raw_member': pair['raw_member'],
            'metrics': {key: metrics(value) for key, value in group.items()},
            'score_class_mass': [{'score': score, 'normal': histogram[(score, 0)], 'attack': histogram[(score, 1)]}
                                 for score in sorted({key[0] for key in histogram})]}
            for pair, group, histogram in zip(preparation['pairs'], groups, mass, strict=True)]
        errors = [(body, vector) for body, vector in vectors.items()
                  if (vector['probability'] is None or vector['probability'] < .5) and vector['classes'][1]]
        errors.sort(key=lambda item: (-item[1]['classes'][1], hashlib.sha256(item[0]).hexdigest()))
        report['largest_missed_vectors_at_0_5'] = [{'feature_sha256': hashlib.sha256(body).hexdigest(),
            'features': json.loads(body), **vector} for body, vector in errors[:32]]
        report['scored_population'] = count
        report['unique_vectors'] = len(vectors)
        report['probability_sequence_sha256'] = score_sha.hexdigest()
        report['model_unchanged'] = True
        report['completed'] = True
    except (OSError, ValueError, TypeError, KeyError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (output/'diagnostic.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--expected-preparation-sha256', required=True)
    parser.add_argument('--model', required=True, type=Path)
    parser.add_argument('--expected-model-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--model-kind', choices=('ordered_tree', 'heads'), default='ordered_tree')
    parser.add_argument('--thresholds', nargs='+', type=float, default=THRESHOLDS)
    args = parser.parse_args()
    report = diagnose(args.directory, args.expected_preparation_sha256, args.model,
                      args.expected_model_sha256, args.output, model_kind=args.model_kind,
                      thresholds=tuple(args.thresholds))
    print(json.dumps({key: report[key] for key in ('completed', 'metrics', 'scored_population', 'unique_vectors', 'goal_qualified')}))


if __name__ == '__main__':
    main()
