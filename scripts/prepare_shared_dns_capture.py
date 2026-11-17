"""Verify pinned training capture and conditional native decoder bounds.

No labels, attacker/configuration files or programs from the archive are read.
The output describes an offline native-capture observer, not historical app
ingestion, verified human identity, successful theft or automatic enforcement.
"""

import argparse
import hashlib
import json
import shutil
import zipfile
from dataclasses import asdict
from pathlib import Path

from app.config import get_settings
from scripts.acquire_f1_packet_archive import ASSET
from scripts.f1_lab.bounded_zip import safe_name
from scripts.f1_lab.decoder_packet_fence import DecoderPacketFence
from scripts.f1_lab.dns_capture import scan
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.suricata_single_worker import runtime_profile, timestamp_us
from scripts.f1_lab.transfer_evaluation import sha
from scripts.prepare_transfer_source import timezone
from scripts.prepare_vpn_packet_members import eligible, fingerprints, index_bound

HOST = 'gather/internal_share/'
AUDIT = HOST + 'logs/audit/audit.log'
PCAP = HOST + 'logs/suricata/log.pcap.1642684613'
EVE = HOST + 'logs/suricata/eve.json'
RUNTIME = HOST + 'logs/suricata/suricata.log'
FACTS = HOST + 'facts.json'


def run(acquisition, acquisition_pin, archive, preparation, preparation_pin, raw, output):
    require(get_settings().app_environment in {'local', 'test'}, 'dns_intake_local_test_only')
    acquisition, archive, preparation, raw, output = map(Path, (acquisition, archive, preparation, raw, output))
    require(sha(acquisition, 65536) == acquisition_pin and sha(preparation, 2 * 1024**2) == preparation_pin,
            'dns_intake_external_pins')
    receipt, prep = decode(acquisition.read_bytes()), decode(preparation.read_bytes())
    require(receipt['schema'] == 'pinned-packet-training-acquisition-1' and receipt['completed'] is True
            and receipt['asset'] == asdict(ASSET) and receipt['role'] == 'training'
            and receipt['purpose'] == 'noncommercial_research' and receipt['publisher_md5_verified'] is True
            and receipt['bytes_received'] == ASSET.bytes
            and receipt['archive_extracted'] is False and receipt['code_executed_from_asset'] is False
            and receipt['goal_qualified'] is False and receipt['new_independent_evaluation'] is False,
            'dns_intake_acquisition_scope')
    require(prep['completed'] is True and prep['inputs_contain_truth'] is False, 'dns_intake_preparation_scope')
    sources = [(n, pair) for n, pair in enumerate(prep['pairs']) if pair['raw_member'] == AUDIT]
    require(len(sources) == 1, 'dns_intake_exact_audit_source')
    source_index, pair = sources[0]
    raw_path = raw / f'pair-{source_index}-raw.source'
    manifest_path = raw / 'audit.json'
    require(sha(raw_path, 8 * 1024**2) == pair['raw_sha256']
            and sha(manifest_path, 4 * 1024**2) == prep['source_manifest_sha256'], 'dns_intake_raw_manifest_pin')
    manifest = decode(manifest_path.read_bytes())
    require(manifest['completed'] is True and manifest['timestamp_basis'] ==
            'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
            'dns_intake_explicit_UTC')
    provenance = manifest['pairs'][source_index]['provenance']
    require(provenance['raw_member'] == AUDIT and provenance['raw_sha256'] == pair['raw_sha256'],
            'dns_intake_original_audit_binding')
    archive_pin, md5 = fingerprints(archive)
    require(archive_pin == receipt['local_sha256'] and md5 == ASSET.publisher_md5,
            'dns_intake_verified_archive')
    require(not output.exists() and not output.is_symlink(), 'dns_intake_fresh_output')
    output.mkdir(parents=True)
    report = {'schema': 'verified-shared-dns-native-context-1', 'completed': False, 'scenario': 'russellmitchell',
              'role': 'training', 'archive_sha256': archive_pin, 'publisher_md5_verified': True,
              'acquisition_sha256': acquisition_pin, 'preparation_sha256': preparation_pin,
              'raw_manifest_sha256': prep['source_manifest_sha256'], 'audit_source_index': source_index,
              'audit_source_sha256': pair['raw_sha256'], 'members': [], 'labels_opened': False,
              'source_decoder_contract_verified': False, 'admitted_to_offline_native_replay': False,
              'historical_application_receipt_proven': False, 'actor_or_authority_proven': False,
              'raw_identifiers_learned': False, 'model_fit_or_prediction_performed': False,
              'original_population_changed': False, 'goal_qualified': False,
              'new_independent_evaluation': False, 'paid_api_calls': 0, 'aws_calls': 0}
    try:
        with archive.open('rb') as stream:
            count, boundary = index_bound(stream)
            stream.seek(0)
            with zipfile.ZipFile(stream) as package:
                infos = package.infolist()
                require(len(infos) == count and len({safe_name(info) for info in infos}) == count,
                        'dns_intake_archive_population')
                by_name = {info.filename: info for info in infos}
                require({info.filename for info in infos if info.filename.startswith(HOST + 'logs/suricata/log.pcap.')} == {PCAP},
                        'dns_intake_complete_capture_member_set')

                def small(name, maximum):
                    info = by_name[name]
                    eligible(info, boundary, maximum)
                    body = package.read(info)
                    require(len(body) == info.file_size, 'dns_intake_member_read')
                    report['members'].append({'member': name, 'bytes': len(body),
                        'sha256': hashlib.sha256(body).hexdigest(), 'crc32': f'{info.CRC:08x}', 'crc_verified': True})
                    return body

                require(hashlib.sha256(small(AUDIT, 8 * 1024**2)).hexdigest() == pair['raw_sha256'],
                        'dns_intake_same_original_audit')
                require(timezone(decode(small(FACTS, 4 * 1024**2))) == 'UTC', 'dns_intake_host_timezone')
                # Facts are read only to verify timezone, never to fill a missing
                # historic device, person, permission or execution field.
                producer = runtime_profile(small(RUNTIME, 4 * 1024**2))
                info = by_name[PCAP]
                eligible(info, boundary, 2 * 1024**3)
                require(shutil.disk_usage(output).free > info.file_size + 128 * 1024**2,
                        'dns_intake_disk_headroom')
                pcap_path = output / 'capture.pcap'
                digest, total = hashlib.sha256(), 0
                with package.open(info) as source, pcap_path.open('xb') as sink:
                    while body := source.read(1024**2):
                        total += len(body)
                        require(total <= info.file_size, 'dns_intake_pcap_copy_bound')
                        sink.write(body)
                        digest.update(body)
                require(total == info.file_size, 'dns_intake_pcap_complete')
                pcap_pin = digest.hexdigest()
                report['members'].append({'member': PCAP, 'bytes': total, 'sha256': pcap_pin,
                                          'crc32': f'{info.CRC:08x}', 'crc_verified': True})
                parsed = scan(pcap_path, pcap_pin, output / 'queries.jsonl')
                require(parsed['packets'] == producer['reported_packet_count']
                        and producer['runtime_started_us'] * 1000 <= parsed['first_capture_time_ns']
                        <= parsed['last_capture_time_ns'] < (producer['runtime_stopped_second_us'] + 1000000) * 1000,
                        'dns_intake_runtime_capture_population_or_clock')
                info = by_name[EVE]
                eligible(info, boundary, 512 * 1024**2)
                stats, rows, total, digest = [], 0, 0, hashlib.sha256()
                stats_digest = hashlib.sha256()
                with package.open(info) as source, (output / 'stats.jsonl').open('xb') as sink:
                    for body in iter(lambda: source.readline(MAX_ROW + 1), b''):
                        rows += 1
                        total += len(body)
                        require(len(body) <= MAX_ROW and rows <= 1000000 and total <= info.file_size,
                                'dns_intake_eve_bound')
                        digest.update(body)
                        event = decode(body)
                        require(type(event) is dict and type(event.get('event_type')) is str,
                                'dns_intake_event_shape')
                        require(not {'label', 'malicious', 'expected_alert', 'ground_truth', 'attack_labels'} & event.keys(),
                                'dns_intake_no_truth_fields')
                        if event['event_type'] != 'stats':
                            continue
                        value = event['stats']
                        capture, decoder = value['capture'], value['decoder']
                        item = {'ordinal': rows, 'timestamp_us': timestamp_us(event['timestamp']),
                                'kernel_packets': capture['kernel_packets'], 'kernel_drops': capture['kernel_drops'],
                                'decoder_packets': decoder['pkts'], 'uptime': value['uptime'],
                                'row_sha256': hashlib.sha256(body).hexdigest()}
                        stats.append(item)
                        require(len(stats) <= 200000, 'dns_intake_stats_bound')
                        encoded = canonical(item) + b'\n'
                        sink.write(encoded)
                        stats_digest.update(encoded)
                require(total == info.file_size, 'dns_intake_eve_complete')
                report['members'].append({'member': EVE, 'bytes': total, 'sha256': digest.hexdigest(),
                    'crc32': f'{info.CRC:08x}', 'crc_verified': True, 'physical_rows': rows})
        fence = DecoderPacketFence(stats, parsed['packets'])
        require(producer['runtime_started_us'] <= stats[0]['timestamp_us'] <= stats[-1]['timestamp_us']
                < producer['runtime_stopped_second_us'] + 1000000, 'dns_intake_stats_runtime_clock')
        require(sha(output / 'queries.jsonl') == parsed['queries_sha256'], 'dns_intake_query_projection_drift')
        observation_digest = hashlib.sha256()
        with (output / 'queries.jsonl').open('rb') as source, (output / 'observations.jsonl').open('xb') as sink:
            for body in source:
                query = decode(body)
                bound = fence.bound(query['packet_ordinal'], query['capture_time_ns'])
                require(bound is not None, 'dns_intake_capture_decoder_clock_contradiction')
                encoded = canonical({**query, 'source_decoder_bound': asdict(bound)}) + b'\n'
                sink.write(encoded)
                observation_digest.update(encoded)
        require(fingerprints(archive) == (archive_pin, ASSET.publisher_md5)
                and sha(preparation, 2 * 1024**2) == preparation_pin and sha(acquisition, 65536) == acquisition_pin
                and sha(raw_path, 8 * 1024**2) == pair['raw_sha256']
                and sha(manifest_path, 4 * 1024**2) == prep['source_manifest_sha256']
                and sha(pcap_path, 2 * 1024**3) == pcap_pin
                and sha(output / 'queries.jsonl') == parsed['queries_sha256']
                and sha(output / 'stats.jsonl') == stats_digest.hexdigest()
                and sha(output / 'observations.jsonl') == observation_digest.hexdigest(), 'dns_intake_input_drift')
        report.update(completed=True, source_decoder_contract_verified=True, admitted_to_offline_native_replay=True,
            native_time_basis='conditional single-worker complete-PCAP decoder prefix sampled before same-host stats wallclock; not application ingestion',
            producer=producer, capture=parsed, stats_rows=len(stats),
            files={name: sha(output / name) for name in ('capture.pcap', 'queries.jsonl', 'stats.jsonl', 'observations.jsonl')})
    finally:
        (output / 'run.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('acquisition', 'acquisition-sha256', 'archive', 'preparation', 'preparation-sha256', 'raw', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = run(args.acquisition, args.acquisition_sha256, args.archive, args.preparation,
                 args.preparation_sha256, args.raw, args.output)
    print(json.dumps({'completed': result['completed'], 'packets': result['capture']['packets'],
                      'dns_queries': result['capture']['dns_queries'], 'goal_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
