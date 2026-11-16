"""Stage a frozen baseline and allowlisted native DNS observations, without labels."""

import argparse
import json
import shutil
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_dns_native_review import PROFILE, SharedDnsNativeReview
from scripts.f1_lab.shared_dns_transaction_review import PROFILE as TX_PROFILE
from scripts.f1_lab.shared_dns_transaction_review import ROLES, SharedDnsTransactionReview
from scripts.f1_lab.transfer_evaluation import sha
from scripts.stage_vpn_protocol_replay import stage as base_stage


def stage(catalog_path, pin, output):
    report = base_stage(catalog_path, pin, output, profile='apparmor-status')
    out = Path(output)
    report['completed'] = False
    (out / 'stage.json').write_bytes(canonical(report) + b'\n')
    catalog = decode(Path(catalog_path).read_bytes())
    support = catalog.get('shared_dns_support')
    require(type(support) is list and 0 < len(support) <= 16, 'shared_dns_support_population')
    scenarios = {item['name']: item for item in catalog['scenarios']}
    inputs = out / 'inputs'
    folder = inputs / 'native-dns'
    folder.mkdir()
    members, seen = [], set()
    for n, spec in enumerate(support):
        require(type(spec) is dict and set(spec) == {'scenario', 'source_index', 'intake', 'intake_sha256'},
                'shared_dns_support_fields')
        name, index = spec['scenario'], spec['source_index']
        require(name in scenarios and type(index) is int and index >= 0 and (name, index) not in seen,
                'shared_dns_support_source')
        seen.add((name, index))
        source = scenarios[name]
        prep = decode(Path(source['preparation']).read_bytes())
        intake_path = Path(spec['intake'])
        require(sha(intake_path, 65536) == spec['intake_sha256'], 'shared_dns_intake_pin')
        intake = decode(intake_path.read_bytes())
        require(intake['schema'] in {'verified-shared-dns-native-context-1', 'verified-shared-dns-transactions-1'}
                and intake['completed'] is True and intake['admitted_to_offline_native_replay'] is True
                and intake['historical_application_receipt_proven'] is False
                and intake['actor_or_authority_proven'] is False and intake['labels_opened'] is False
                and intake['original_population_changed'] is False and intake['goal_qualified'] is False
                and intake['new_independent_evaluation'] is False
                and intake['preparation_sha256'] == source['preparation_sha256']
                and intake['audit_source_index'] == index and index < len(prep['pairs'])
                and prep['pairs'][index]['raw_member'] == 'gather/internal_share/logs/audit/audit.log'
                and prep['pairs'][index]['raw_sha256'] == intake['audit_source_sha256'], 'shared_dns_intake_scope')
        is_tx = intake['schema'] == 'verified-shared-dns-transactions-1'
        if is_tx:
            require(intake['scenario'] == name and name in ROLES and intake['role'] == ROLES[name]
                    and intake['source_transaction_contract_verified'] is True
                    and intake['producer']['profile'] == TX_PROFILE and intake['projection']['completed'] is True,
                    'shared_dns_transaction_intake_scope')
            expected_files = {'projection/queries.jsonl', 'projection/stats.jsonl', 'projection/observations.jsonl'}
        else:
            require(intake['role'] == 'training' and intake['source_decoder_contract_verified'] is True
                    and intake['producer']['profile'] == PROFILE, 'shared_dns_capture_intake_scope')
            expected_files = {'capture.pcap', 'queries.jsonl', 'stats.jsonl', 'observations.jsonl'}
        require(set(intake['files']) == expected_files,
                'shared_dns_intake_file_inventory')
        report['source_pins'].append({'path': str(intake_path), 'sha256': spec['intake_sha256']})
        for filename, expected in intake['files'].items():
            path = intake_path.parent / filename
            require(sha(path, 2 * 1024**3) == expected, 'shared_dns_intake_file_pin')
            report['source_pins'].append({'path': str(path), 'sha256': expected})
        target = folder / f'source-{n}'
        target.mkdir()
        projection_name = 'projection/observations.jsonl' if is_tx else 'observations.jsonl'
        observed = target / ('shared-dns-transactions.jsonl' if is_tx else 'shared-dns-observations.jsonl')
        shutil.copyfile(intake_path.parent / projection_name, observed)
        require(sha(observed, 128 * 1024**2) == intake['files'][projection_name], 'shared_dns_projection_copy')
        manifest = {'intake_sha256': spec['intake_sha256'],
            'audit_source_sha256': intake['audit_source_sha256'], 'observations_file': observed.name,
            'observations_sha256': sha(observed),
            'historical_application_receipt_proven': False, 'actor_or_authority_proven': False,
            'goal_qualified': False, 'new_independent_evaluation': False}
        if is_tx:
            manifest.update(schema='staged-shared-dns-transactions-1', producer_profile=TX_PROFILE,
                source_transaction_contract_verified=True, eve_sha256=intake['projection']['eve_sha256'],
                transaction_count=intake['projection']['dns_udp_transactions'],
                observation_count=intake['projection']['queries'], scenario=name, role=intake['role'])
        else:
            manifest.update(schema='staged-shared-dns-native-context-1', producer_profile=PROFILE,
                source_decoder_contract_verified=True, capture_sha256=intake['capture']['source_sha256'],
                capture_packets=intake['capture']['packets'], observation_count=intake['capture']['dns_queries'])
        manifest_path = target / 'manifest.json'
        manifest_path.write_bytes(canonical(manifest) + b'\n')
        raw_path = Path(source['raw']) / f'pair-{index}-raw.source'
        require(sha(raw_path, 64 * 1024**2) == manifest['audit_source_sha256'], 'shared_dns_stage_raw_pin')
        with raw_path.open('r', encoding='utf8', newline='') as stream:
            reader_class = SharedDnsTransactionReview if is_tx else SharedDnsNativeReview
            reader = reader_class(manifest['audit_source_sha256'], stream.readlines(), manifest_path, sha(manifest_path))
        reader.verify()
        members.append({'scenario': name, 'source_index': index, 'raw_source_sha256': manifest['audit_source_sha256'],
                        'path': f'/inputs/native-dns/source-{n}/manifest.json', 'sha256': sha(manifest_path)})
    native = inputs / 'native-dns-catalog.json'
    native.write_bytes(canonical({'schema': 'shared-dns-native-sidecars-1', 'goal_qualified': False,
                                 'members': members}) + b'\n')
    (inputs / 'models/head.json').unlink()
    require(all(sha(p['path']) == p['sha256'] for p in report['source_pins']), 'shared_dns_stage_source_drift')
    report.update(completed=True, profile='shared-dns-native', model_sha256=None,
                  frozen_training_parameters_staged=False, native_catalog_sha256=sha(native),
                  input_pins={p.relative_to(inputs).as_posix(): sha(p) for p in inputs.rglob('*') if p.is_file()})
    (out / 'stage.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('catalog', 'sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = stage(args.catalog, args.sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'goal_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
