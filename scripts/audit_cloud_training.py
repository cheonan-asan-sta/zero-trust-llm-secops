"""Audit only pinned public training assets; retain unknown facts and separate labels."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from scripts.f1_lab.cloud_observations import case_id, partition, partition_with_request_facts
from scripts.f1_lab.line_truth import anchor
from scripts.f1_lab.native_jsonl import decode, require


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def audit(directory, expected_receipt_sha256, output, *, include_request_facts=False):
    require(type(include_request_facts) is bool, 'cloud_request_profile_flag')
    directory, output = Path(directory), Path(output)
    anchor(expected_receipt_sha256)
    receipt = directory/'acquisition.json'
    require(receipt.is_file() and not receipt.is_symlink() and receipt.stat().st_size <= 65536, 'cloud_receipt_file')
    raw_receipt = receipt.read_bytes()
    require(hashlib.sha256(raw_receipt).hexdigest() == expected_receipt_sha256, 'cloud_receipt_hash')
    acquisition = decode(raw_receipt)
    require(acquisition.get('completed') is True and len(acquisition['assets']) == 2
            and acquisition.get('test_archive_downloaded') is False, 'cloud_training_only_contract')
    require(not output.exists() and not output.is_symlink(), 'fresh_cloud_audit')
    output.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-cloud-training-audit-1', 'completed': False, 'acquisition_sha256': expected_receipt_sha256,
              'assets': [], 'test_records_read': 0, 'classifier_fitted': False, 'goal_qualified': False,
              'original_six_domain_goal_replaced': False, 'aws_sdk_calls': 0, 'paid_api_calls': 0}
    report['feature_profile'] = 'cloud-request-facts-2' if include_request_facts else 'cloud-partial-facts-1'
    try:
        for index, asset in enumerate(acquisition['assets']):
            path = directory/f'asset-{index}.json.source'
            require(asset['asset']['path'].startswith('TrainOn/') and path.is_file() and not path.is_symlink()
                    and path.stat().st_size == asset['member']['bytes'] <= 128*1024**2, 'cloud_training_asset')
            body = path.read_bytes()
            require(hashlib.sha256(body).hexdigest() == asset['member']['sha256'], 'cloud_training_hash')
            wrapper = decode(body)
            require(isinstance(wrapper, dict) and isinstance(wrapper.get('Records'), list)
                    and len(wrapper['Records']) <= 100000, 'cloud_records_wrapper')
            counters, kinds, operations = Counter(), Counter(), Counter()
            with (output/f'asset-{index}-observations.jsonl.part').open('xb') as observations, (
                    output/f'asset-{index}-truth.jsonl.part').open('xb') as truth_file:
                for ordinal, item in enumerate(wrapper['Records'], 1):
                    counters['records'] += 1
                    view, gold, problem = None, None, None
                    try:
                        view, gold = (partition_with_request_facts if include_request_facts else partition)(item)
                    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
                        problem = 'unsupported_cloud_observation'
                        # A label can still be known when unrelated observation
                        # parsing fails; keep it in the truth population.
                        from scripts.f1_lab.cloud_observations import label
                        gold = label(item) if isinstance(item, dict) else {'truth': None, 'reason': 'nonobject_record'}
                    identifier = case_id(item, ordinal) if isinstance(item, dict) else f'nonobject-{ordinal}'
                    if view is not None:
                        features = view['features']
                        mfa = features['session_mfa_used']
                        counters['mfa_used' if mfa is True else 'mfa_not_used' if mfa is False else 'mfa_unknown'] += 1
                        counters['session_issuer_present'] += features['session_issuer_present']
                        counters['resources_missing'] += features['resource_count'] is None
                        kinds[features['principal_kind']] += 1
                        operations[features['api_name']] += 1
                    counters['observation_errors'] += problem is not None
                    counters['truth_unknown' if gold['truth'] is None else 'truth_attack' if gold['truth'] else 'truth_normal'] += 1
                    observations.write(canonical({'case_id': identifier, 'observation': view, 'error': problem})+b'\n')
                    truth_file.write(canonical({'case_id': identifier, **gold})+b'\n')
            source_time = path.stat()
            require(source_time.st_size == len(body) and hashlib.sha256(path.read_bytes()).hexdigest() == asset['member']['sha256'],
                    'cloud_source_changed')
            for suffix in ('observations', 'truth'):
                partial = output/f'asset-{index}-{suffix}.jsonl.part'
                partial.rename(partial.with_suffix(''))
            report['assets'].append({'source': asset['asset']['path'], 'source_sha256': asset['member']['sha256'],
                                     'counts': dict(counters), 'principal_kinds': dict(kinds), 'api_operations': dict(operations)})
        report['completed'] = True
    except (OSError, ValueError, TypeError, KeyError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (output/'audit.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--expected-receipt-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--include-request-facts', action='store_true')
    args = parser.parse_args()
    result = audit(args.directory, args.expected_receipt_sha256, args.output, include_request_facts=args.include_request_facts)
    print(json.dumps({'completed': result['completed'], 'assets': result['assets'], 'goal_qualified': False}))


if __name__ == '__main__':
    main()
