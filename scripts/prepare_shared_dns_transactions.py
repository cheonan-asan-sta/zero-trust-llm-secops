"""Verify an allowlisted publisher archive for offline native DNS transaction use.

Only the shared host's audit, timezone facts, runtime log and complete EVE are
opened. Existing observed calibration remains observed calibration; no labels,
models, attacker code or configuration are consumed by this reader.
"""

import argparse
import hashlib
import json
import zipfile
from dataclasses import asdict
from pathlib import Path

from app.config import get_settings
from scripts.acquire_f1_packet_archive import ASSET
from scripts.f1_lab.bounded_zip import safe_name
from scripts.f1_lab.dns_transaction_fence import PROFILE
from scripts.f1_lab.dns_transaction_projection import project
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.suricata_single_worker import runtime_profile
from scripts.f1_lab.transfer_evaluation import sha
from scripts.prepare_shared_dns_capture import AUDIT, EVE, FACTS, RUNTIME
from scripts.prepare_transfer_source import timezone
from scripts.prepare_vpn_packet_members import eligible, index_bound

ASSETS = {
    'russellmitchell': {'role': 'training', 'asset': asdict(ASSET),
                      'receipt_schema': 'pinned-packet-training-acquisition-1'},
    'fox': {'role': 'observed_nontraining_calibration', 'receipt_schema': 'f1-public-asset-acquisition-1',
        'asset': {'asset_id': 'ait-lds21-fox', 'bytes': 688586900,
            'data_role': 'publisher_raw_logs_with_separate_line_labels_calibration_only',
            'filename': 'fox_no-pcaps.zip', 'license_id': 'cc-by-nc-sa-4.0',
            'publisher_md5': '27b09dd2876ec08ee99a9b53e8718c92', 'record_id': 19483937,
            'record_version': 'v2_1', 'reference': 'https://zenodo.org/records/19483937'}}}


def archive_fingerprints(path, expected_bytes):
    require(type(expected_bytes) is int and 0 < expected_bytes <= 8 * 1024**3
            and path.is_file() and not path.is_symlink() and path.stat().st_size == expected_bytes,
            'dns_tx_intake_archive_file')
    strong, publisher, total = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    with path.open('rb') as source:
        while body := source.read(1024**2):
            total += len(body)
            require(total <= expected_bytes, 'dns_tx_intake_archive_read_bound')
            strong.update(body)
            publisher.update(body)
    require(total == expected_bytes and path.stat().st_size == expected_bytes, 'dns_tx_intake_archive_read_complete')
    return strong.hexdigest(), publisher.hexdigest()


def run(scenario, acquisition, acquisition_pin, archive, preparation, preparation_pin, raw, output):
    require(get_settings().app_environment in {'local', 'test'}, 'dns_tx_intake_local_test_only')
    require(scenario in ASSETS, 'dns_tx_intake_asset_allowlist')
    spec = ASSETS[scenario]
    acquisition, archive, preparation, raw, output = map(Path, (acquisition, archive, preparation, raw, output))
    require(sha(acquisition, 65536) == acquisition_pin and sha(preparation, 2 * 1024**2) == preparation_pin,
            'dns_tx_intake_external_pins')
    receipt, prep = decode(acquisition.read_bytes()), decode(preparation.read_bytes())
    require(receipt['schema'] == spec['receipt_schema'] and receipt['completed'] is True
            and receipt['asset'] == spec['asset'] and receipt['purpose'] == 'noncommercial_research'
            and receipt['publisher_md5_verified'] is True and receipt['bytes_received'] == spec['asset']['bytes']
            and receipt['archive_extracted'] is False and receipt['code_executed_from_asset'] is False
            and receipt['goal_qualified'] is False, 'dns_tx_intake_receipt_scope')
    if spec['role'] == 'training':
        require(receipt['role'] == 'training' and receipt['new_independent_evaluation'] is False,
                'dns_tx_intake_training_receipt')
    require(prep['completed'] is True and prep['inputs_contain_truth'] is False, 'dns_tx_intake_preparation_scope')
    sources = [(n, pair) for n, pair in enumerate(prep['pairs']) if pair['raw_member'] == AUDIT]
    require(len(sources) == 1, 'dns_tx_intake_exact_audit_source')
    index, pair = sources[0]
    raw_path, manifest_path = raw / f'pair-{index}-raw.source', raw / 'audit.json'
    require(sha(raw_path, 8 * 1024**2) == pair['raw_sha256']
            and sha(manifest_path, 4 * 1024**2) == prep['source_manifest_sha256'], 'dns_tx_intake_original_pins')
    manifest = decode(manifest_path.read_bytes())
    provenance = manifest['pairs'][index]['provenance']
    require(manifest['completed'] is True and manifest['timestamp_basis'] ==
            'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check'
            and provenance['raw_member'] == AUDIT and provenance['raw_sha256'] == pair['raw_sha256'],
            'dns_tx_intake_UTC_and_source_binding')
    archive_pin, md5 = archive_fingerprints(archive, spec['asset']['bytes'])
    require(archive.stat().st_size == spec['asset']['bytes'] and archive_pin == receipt['local_sha256']
            and md5 == spec['asset']['publisher_md5'], 'dns_tx_intake_verified_archive')
    require(not output.exists() and not output.is_symlink(), 'dns_tx_intake_fresh_output')
    output.mkdir(parents=True)
    report = {'schema': 'verified-shared-dns-transactions-1', 'completed': False, 'scenario': scenario,
        'role': spec['role'], 'archive_sha256': archive_pin, 'publisher_md5_verified': True,
        'acquisition_sha256': acquisition_pin, 'preparation_sha256': preparation_pin,
        'raw_manifest_sha256': prep['source_manifest_sha256'], 'audit_source_index': index,
        'audit_source_sha256': pair['raw_sha256'], 'members': [], 'labels_opened': False,
        'source_transaction_contract_verified': False, 'admitted_to_offline_native_replay': False,
        'historical_application_receipt_proven': False, 'actor_or_authority_proven': False,
        'raw_identifiers_learned': False, 'model_fit_or_prediction_performed': False,
        'original_population_changed': False, 'goal_qualified': False, 'new_independent_evaluation': False,
        'paid_api_calls': 0, 'aws_calls': 0}
    try:
        with archive.open('rb') as stream:
            count, boundary = index_bound(stream, expected_bytes=spec['asset']['bytes'])
            stream.seek(0)
            with zipfile.ZipFile(stream) as package:
                infos = package.infolist()
                require(len(infos) == count and len({safe_name(info) for info in infos}) == count,
                        'dns_tx_intake_archive_population')
                by_name = {info.filename: info for info in infos}

                def small(name, maximum):
                    info = by_name[name]
                    eligible(info, boundary, maximum)
                    body = package.read(info)
                    require(len(body) == info.file_size, 'dns_tx_intake_member_read')
                    report['members'].append({'member': name, 'bytes': len(body),
                        'sha256': hashlib.sha256(body).hexdigest(), 'crc32': f'{info.CRC:08x}', 'crc_verified': True})
                    return body

                require(hashlib.sha256(small(AUDIT, 8 * 1024**2)).hexdigest() == pair['raw_sha256'],
                        'dns_tx_intake_same_original_audit')
                require(timezone(decode(small(FACTS, 4 * 1024**2))) == 'UTC', 'dns_tx_intake_host_timezone')
                producer = {**runtime_profile(small(RUNTIME, 4 * 1024**2)), 'profile': PROFILE}
                info = by_name[EVE]
                eligible(info, boundary, 1024**3)
                with package.open(info) as source:
                    projected = project(source, info.file_size, output / 'projection', producer)
                report['members'].append({'member': EVE, 'bytes': projected['bytes'],
                    'sha256': projected['eve_sha256'], 'crc32': f'{info.CRC:08x}', 'crc_verified': True})
        require(archive_fingerprints(archive, spec['asset']['bytes']) == (archive_pin, spec['asset']['publisher_md5'])
                and sha(acquisition, 65536) == acquisition_pin and sha(preparation, 2 * 1024**2) == preparation_pin
                and sha(raw_path, 8 * 1024**2) == pair['raw_sha256']
                and sha(manifest_path, 4 * 1024**2) == prep['source_manifest_sha256']
                and all(sha(output / 'projection' / name) == pin for name, pin in projected['files'].items()),
                'dns_tx_intake_input_drift')
        report.update(completed=True, source_transaction_contract_verified=True,
            admitted_to_offline_native_replay=True, producer=producer, projection=projected,
            files={f'projection/{name}': pin for name, pin in projected['files'].items()},
            native_time_basis='conditional single-worker complete EVE DNS UDP parser prefix sampled before same-host stats wallclock; not application ingestion')
    finally:
        (output / 'run.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('scenario', 'acquisition', 'acquisition-sha256', 'archive', 'preparation', 'preparation-sha256', 'raw', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = run(args.scenario, args.acquisition, args.acquisition_sha256, args.archive,
                 args.preparation, args.preparation_sha256, args.raw, args.output)
    print(json.dumps({'completed': result['completed'], 'role': result['role'],
                      'transactions': result['projection']['dns_udp_transactions'], 'goal_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
