"""Prepare source-pinned historical alert inputs separately from truth/join keys."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from scripts.f1_lab.native_jsonl import alert, require, scan


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def prepare(source, expected_sha256, sensor, directory):
    require(sensor in {'wazuh', 'aminer'}, 'sensor_schema')
    directory = Path(directory)
    require(not directory.exists() and not directory.is_symlink(), 'fresh_directory')
    directory.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-native-alert-input-1', 'completed': False, 'sensor': sensor,
              'source_sha256': expected_sha256, 'row_policy': 'every physical source row retained',
              'historical_replay_only': True, 'truth_in_inputs': False, 'goal_qualified': False,
              'classifier_trained': False, 'full_six_domain_goal_replaced': False}
    errors, findings, severities = Counter(), Counter(), Counter()
    inputs, references = directory/'inputs.jsonl.part', directory/'references.jsonl.part'
    try:
        with inputs.open('xb') as out, references.open('xb') as joins:
            def collect(row):
                case = hashlib.sha256((expected_sha256+':'+str(row.ordinal)).encode()).hexdigest()
                item, problem = None, row.error
                if row.value is not None:
                    try:
                        item = alert(row.value, sensor)
                    except (ValueError, RecursionError):
                        problem = 'unsupported_sensor_observation'
                observation = {'case_id': case, 'features': None, 'trust_claims': None,
                               'observation_error': problem}
                reference = {'case_id': case, 'source_line': row.ordinal,
                             'source_row_sha256': row.sha256, 'entity_reference': None,
                             'event_time': None, 'raw_references': []}
                if item is not None:
                    observation.update(features=item.model_features(), trust_claims=item.trust_claims)
                    reference.update(entity_reference=item.entity_reference, event_time=item.event_time,
                                     raw_references=[{'source_location': r.source_location,
                                                      'content_sha256': r.content_sha256}
                                                     for r in item.raw_references])
                    for name, present in item.model_features()['finding_families'].items():
                        findings[name] += present
                    severities[str(item.severity)] += 1
                if problem:
                    errors[problem] += 1
                out.write(canonical(observation)+b'\n')
                joins.write(canonical(reference)+b'\n')
            report['scan'] = scan(source, expected_sha256, collect)
        report.update(observation_errors=dict(errors), finding_families=dict(findings), severities=dict(severities))
        report['files'] = {}
        for partial in (inputs, references):
            sha = hashlib.sha256()
            with partial.open('rb') as stream:
                while chunk := stream.read(1024**2):
                    sha.update(chunk)
            final = partial.with_suffix('')
            partial.rename(final)
            report['files'][final.name] = {'sha256': sha.hexdigest(), 'bytes': final.stat().st_size}
        report['completed'] = True
    except (OSError, ValueError, RecursionError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (directory/'preparation.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--sensor', required=True, choices=('wazuh', 'aminer'))
    parser.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args()
    report = prepare(args.source, args.expected_sha256, args.sensor, args.directory)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
