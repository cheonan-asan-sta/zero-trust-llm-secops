"""Prepare every pinned publisher-paired raw row; keep observations and truth separate."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from scripts.f1_lab.line_truth import anchor, annotations, pair_members
from scripts.f1_lab.native_jsonl import MAX_FILE, MAX_ROW, MAX_ROWS, decode, require
from scripts.f1_lab.raw_observations import raw_features, raw_time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def prepare(directory, expected_manifest_sha256, output):
    directory, output = Path(directory), Path(output)
    anchor(expected_manifest_sha256)
    manifest_path = directory/'audit.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink() and manifest_path.stat().st_size <= 1024**2,
            'raw_manifest_file')
    manifest_body = manifest_path.read_bytes()
    require(hashlib.sha256(manifest_body).hexdigest() == expected_manifest_sha256, 'raw_manifest_hash')
    manifest = decode(manifest_body)
    require(manifest.get('completed') is True and 1 <= len(manifest['pairs']) <= 64, 'completed_pair_manifest')
    require(not output.exists() and not output.is_symlink(), 'fresh_raw_output')
    output.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-native-raw-input-1', 'completed': False,
              'source_manifest_sha256': expected_manifest_sha256, 'row_policy': 'every paired raw row retained',
              'scope': manifest['scope'], 'inputs_contain_truth': False, 'labels_changed': False,
              'historical_replay_only': True, 'paid_api_calls': 0, 'aws_sdk_calls': 0,
              'goal_qualified': False, 'pairs': [], 'files': {}}
    stages = {name: output/(name+'.part') for name in ['inputs.jsonl', 'truth.jsonl', 'references.jsonl']}
    try:
        with stages['inputs.jsonl'].open('xb') as inputs, stages['truth.jsonl'].open('xb') as truth, stages['references.jsonl'].open('xb') as refs:
            for i, pair in enumerate(manifest['pairs']):
                provenance = pair['provenance']
                pair_members(provenance['raw_member'], provenance['label_member'])
                raw_path, label_path = directory/f'pair-{i}-raw.source', directory/f'pair-{i}-labels.source'
                require(raw_path.is_file() and not raw_path.is_symlink() and raw_path.stat().st_size <= MAX_FILE,
                        'raw_pair_file')
                labels, _label_report = annotations(label_path, provenance['label_sha256'])
                sha, count, byte_count = hashlib.sha256(), 0, 0
                time_errors, feature_errors, outside, backward = 0, 0, 0, 0
                minimum, maximum, previous = None, None, None
                start, end = provenance['simulation_start'], provenance['simulation_end']
                require(type(start) is int and type(end) is int and 0 <= start < end, 'raw_simulation_bounds')
                # UTC was checked against the pinned host metadata by intake.
                require(manifest['timestamp_basis'] == 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
                        'raw_timezone_intake_contract')
                feature_counts = Counter()
                with raw_path.open('rb') as source:
                    while body := source.readline(MAX_ROW+1):
                        count += 1
                        byte_count += len(body)
                        require(count <= MAX_ROWS and byte_count <= MAX_FILE and len(body) <= MAX_ROW, 'raw_pair_bound')
                        sha.update(body)
                        case = hashlib.sha256((provenance['raw_sha256']+':'+str(count)).encode()).hexdigest()
                        features, moment, observation_error, time_error = None, None, None, None
                        try:
                            line = body.decode('utf-8')
                            features = raw_features(line)
                            feature_counts.update(k for k, v in features.items() if v is True)
                            try:
                                moment = raw_time(line, start, end, source_timezone='UTC')
                            except (ValueError, RecursionError):
                                time_error = 'unparsed_historical_time'
                        except (UnicodeError, ValueError, RecursionError):
                            observation_error = 'unparsed_raw_observation'
                        if observation_error:
                            feature_errors += 1
                        if time_error or moment is None:
                            time_errors += 1
                        if moment is not None:
                            outside += not start <= moment <= end
                            backward += previous is not None and moment < previous
                            minimum = moment if minimum is None else min(minimum, moment)
                            maximum = moment if maximum is None else max(maximum, moment)
                            previous = moment
                        inputs.write(canonical({'case_id': case, 'features': features, 'observation_error': observation_error})+b'\n')
                        truth.write(canonical({'case_id': case, 'malicious': count in labels, 'attack_labels': labels.get(count, ())})+b'\n')
                        refs.write(canonical({'case_id': case, 'pair_id': pair['pair_id'], 'source_line': count,
                                              'source_row_sha256': hashlib.sha256(body).hexdigest(),
                                              'event_time': moment, 'time_error': time_error})+b'\n')
                require(sha.hexdigest() == provenance['raw_sha256'] and count == pair['raw_rows'], 'raw_pair_hash_or_rows')
                require(not labels or max(labels) <= count, 'annotation_outside_raw')
                result = {'raw_member': provenance['raw_member'], 'raw_sha256': sha.hexdigest(),
                          'rows': count, 'malicious': len(labels), 'normal': count-len(labels),
                          'feature_errors': feature_errors, 'time_errors': time_errors, 'outside_simulation': outside,
                          'backward_time_steps': backward, 'minimum_event_time': minimum, 'maximum_event_time': maximum,
                          'positive_feature_counts': dict(feature_counts)}
                report['pairs'].append(result)
        for name, partial in stages.items():
            sha = hashlib.sha256()
            with partial.open('rb') as stream:
                while body := stream.read(1024**2):
                    sha.update(body)
            partial.rename(output/name)
            report['files'][name] = {'sha256': sha.hexdigest(), 'bytes': (output/name).stat().st_size}
        report['completed'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (output/'preparation.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pairs-directory', required=True, type=Path)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = prepare(args.pairs_directory, args.expected_manifest_sha256, args.output)
    print(json.dumps({'completed': report['completed'], 'pairs': report['pairs'], 'goal_qualified': False}))


if __name__ == '__main__':
    main()
