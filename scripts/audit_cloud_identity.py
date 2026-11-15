"""Presence and exact-join diagnostics on pinned public training assets only."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from scripts.f1_lab.cloud_observations import KINDS
from scripts.f1_lab.native_jsonl import decode, require

FIELDS = ('userIdentity.principalId', 'userIdentity.arn', 'userIdentity.accountId', 'userIdentity.accessKeyId',
          'userIdentity.credentialId', 'userIdentity.invokedBy', 'userIdentity.sessionContext.sourceIdentity',
          'userIdentity.sessionContext.signInSessionArn', 'userIdentity.sessionContext.sessionIssuer.arn',
          'userIdentity.onBehalfOf.userId', 'userIdentity.onBehalfOf.identityStoreArn', 'userIdentity.inScopeOf.sourceArn',
          'userIdentity.inScopeOf.credentialsIssuedTo', 'sharedEventID', 'requestID', 'recipientAccountId')
JOIN_FIELDS = ('userIdentity.principalId', 'userIdentity.arn', 'userIdentity.accessKeyId', 'userIdentity.credentialId',
               'userIdentity.sessionContext.signInSessionArn', 'sharedEventID')


def field(record, path):
    current = record
    for key in path.split('.'):
        current = current.get(key) if isinstance(current, dict) else None
    return current if isinstance(current, str) and 0 < len(current) <= 8192 and current.strip().casefold() not in {
        '', 'unknown', 'null', 'none', '-', 'hidden_due_to_security_reasons'} else None


def token(path, value):
    return hashlib.sha256((path+'\0'+value).encode()).hexdigest()


def summarize(records):
    fields = defaultdict(Counter)
    population, service_labels, service, candidates = Counter(), Counter(), [], defaultdict(set)
    for record in records:
        require(isinstance(record, dict), 'cloud_identity_record')
        identity = record.get('userIdentity')
        identity = identity if isinstance(identity, dict) else {}
        kind = identity.get('type')
        kind = kind if isinstance(kind, str) and kind in KINDS else 'Unknown'
        population[kind] += 1
        for name in FIELDS:
            if field(record, name) is not None:
                fields[kind][name] += 1
        keys = [token(name, value) for name in JOIN_FIELDS if (value := field(record, name)) is not None]
        if kind == 'AWSService':
            service.append(keys)
            gold = record.get('should_sample')
            service_labels['unknown' if type(gold) is not bool else 'attack' if gold else 'normal'] += 1
        elif (principal := field(record, 'userIdentity.principalId')) is not None:
            # Account-scoped diagnostic identity; identifiers never exported.
            owner = field(record, 'userIdentity.accountId') or '<account-unavailable>'
            target = token('scoped-principal', owner+'\0'+principal)
            for key in keys:
                candidates[key].add(target)
    joined = Counter()
    for keys in service:
        possibilities = set().union(*(candidates.get(key, set()) for key in keys)) if keys else set()
        joined['no_candidate' if not possibilities else 'one_candidate' if len(possibilities) == 1 else 'multiple_candidates'] += 1
    return {'population': dict(population), 'fields_present_by_kind': {kind: {name: counts[name] for name in FIELDS}
            for kind, counts in sorted(fields.items())}, 'service_label_counts': dict(service_labels),
            'service_exact_join_candidates': dict(joined), 'raw_identifiers_displayed_or_exported': 0,
            'candidate_join_verified': False, 'inference_features_changed': False}


def audit(directory, expected_receipt_sha256, output):
    directory, output = Path(directory), Path(output)
    require(isinstance(expected_receipt_sha256, str) and len(expected_receipt_sha256) == 64
            and all(c in '0123456789abcdef' for c in expected_receipt_sha256), 'cloud_identity_receipt_anchor')
    path = directory/'acquisition.json'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536, 'cloud_identity_receipt')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == expected_receipt_sha256, 'cloud_identity_receipt_hash')
    receipt = decode(body)
    require(receipt.get('completed') is True and receipt.get('test_archive_downloaded') is False
            and len(receipt['assets']) == 2, 'cloud_identity_training_only')
    require(not output.exists() and not output.is_symlink(), 'fresh_cloud_identity_audit')
    records, sources = [], {}
    for index, asset in enumerate(receipt['assets']):
        path = directory/f'asset-{index}.json.source'
        require(asset['asset']['path'].startswith('TrainOn/') and path.is_file() and not path.is_symlink()
                and path.stat().st_size == asset['member']['bytes'] <= 128*1024**2, 'cloud_identity_training_asset')
        body = path.read_bytes()
        require(hashlib.sha256(body).hexdigest() == asset['member']['sha256'], 'cloud_identity_training_hash')
        wrapper = decode(body)
        require(isinstance(wrapper, dict) and isinstance(wrapper.get('Records'), list)
                and len(records)+len(wrapper['Records']) <= 50000, 'cloud_identity_record_bound')
        records.extend(wrapper['Records'])
        sources[path.name] = asset['member']['sha256']
    summary = summarize(records)
    for name, digest in sources.items():
        require(hashlib.sha256((directory/name).read_bytes()).hexdigest() == digest, 'cloud_identity_source_changed')
    result = {'schema': 'f1-cloud-training-identity-audit-1', 'completed': True,
              'acquisition_sha256': expected_receipt_sha256, 'source_sha256': sources, 'rows': len(records), **summary,
              'test_records_read': 0, 'classifier_fitted': False, 'original_six_domain_goal_replaced': False,
              'paid_api_calls': 0, 'aws_sdk_calls': 0, 'goal_qualified': False}
    output.mkdir(parents=True, mode=0o700)
    (output/'audit.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--expected-receipt-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.directory, args.expected_receipt_sha256, args.output)))


if __name__ == '__main__':
    main()
