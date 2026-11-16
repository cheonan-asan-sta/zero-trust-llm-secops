"""Verify a pinned full training archive, then copy only VPN PCAP members.

No labels, configurations or executable archive contents are opened. The
existing generic ZIP reader's 2 GiB archive limit remains unchanged.
"""

import argparse
import hashlib
import json
import shutil
import stat
import struct
import zipfile
from dataclasses import asdict
from pathlib import Path

from app.config import get_settings
from scripts.acquire_f1_packet_archive import ASSET, MAXIMUM
from scripts.f1_lab.bounded_zip import MAX_INDEX, MAX_MEMBERS, safe_name
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pcap_initial import MAX_FILE, scan
from scripts.f1_lab.transfer_evaluation import sha

MEMBERS = ('gather/vpn/logs/suricata/log.pcap.1642684648',
           'gather/vpn/logs/suricata/log.pcap.1642964618')
VPN_LOG = 'gather/vpn/logs/openvpn.log'


def fingerprints(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == ASSET.bytes <= MAXIMUM,
            'packet_archive_file')
    strong, publisher = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    with path.open('rb') as stream:
        while body := stream.read(1024**2):
            strong.update(body)
            publisher.update(body)
    return strong.hexdigest(), publisher.hexdigest()


def index_bound(stream):
    """Bound the index before ZipFile allocates it; only the fixed asset size."""
    stream.seek(0, 2)
    size = stream.tell()
    require(size == ASSET.bytes <= MAXIMUM and size >= 22, 'packet_archive_size')
    start = max(0, size - 65557)
    stream.seek(start)
    tail = stream.read(65557)
    offset = tail.rfind(b'PK\x05\x06')
    require(offset >= 0 and len(tail) - offset >= 22, 'packet_archive_end')
    magic, disk, directory_disk, disk_entries, entries, length, position, comment = struct.unpack(
        '<4s4H2IH', tail[offset:offset + 22])
    end = start + offset
    require(magic == b'PK\x05\x06' and end + 22 + comment == size and disk == directory_disk == 0,
            'packet_archive_single_disk')
    boundary = end
    if 65535 in {disk_entries, entries} or 4294967295 in {length, position}:
        require(end >= 20, 'packet_archive_zip64_locator')
        stream.seek(end - 20)
        magic, disk64, record, disks = struct.unpack('<4sIQI', stream.read(20))
        require(magic == b'PK\x06\x07' and disk64 == 0 and disks == 1 and 0 <= record <= end - 76,
                'packet_archive_zip64_locator')
        stream.seek(record)
        body = stream.read(56)
        require(len(body) == 56, 'packet_archive_zip64_end')
        magic, record_size, _made, _needed, disk, directory_disk, disk_entries, entries, length, position = struct.unpack(
            '<4sQ2H2I4Q', body)
        require(magic == b'PK\x06\x06' and 44 <= record_size <= 1024
                and record + 12 + record_size <= end - 20 and disk == directory_disk == 0,
                'packet_archive_zip64_end')
        boundary = record
    require(1 <= entries == disk_entries <= MAX_MEMBERS and 0 < length <= MAX_INDEX
            and 0 <= position < boundary and position + length <= boundary, 'packet_archive_index_bound')
    return entries, position


def eligible(info, boundary, maximum):
    mode = stat.S_IFMT(info.external_attr >> 16)
    require(not info.is_dir() and mode in {0, stat.S_IFREG} and not info.flag_bits & 1
            and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
            and 0 < info.file_size <= maximum and 0 <= info.compress_size <= maximum
            and 0 <= info.header_offset < boundary, 'packet_member_bound')


def run(acquisition, acquisition_pin, archive, vpn_raw, vpn_raw_pin, output):
    require(get_settings().app_environment in {'local', 'test'}, 'packet_intake_local_test_only')
    acquisition, archive, vpn_raw, output = map(Path, (acquisition, archive, vpn_raw, output))
    require(sha(acquisition, 65536) == acquisition_pin, 'packet_acquisition_pin')
    receipt = decode(acquisition.read_bytes())
    require(receipt['schema'] == 'pinned-packet-training-acquisition-1' and receipt['completed'] is True
            and receipt['asset'] == asdict(ASSET) and receipt['purpose'] == 'noncommercial_research'
            and receipt['role'] == 'training' and receipt['publisher_md5_verified'] is True
            and receipt['bytes_received'] == ASSET.bytes and receipt['archive_extracted'] is False
            and receipt['code_executed_from_asset'] is False
            and receipt['goal_qualified'] is False and receipt['new_independent_evaluation'] is False,
            'packet_acquisition_scope')
    archive_pin, publisher = fingerprints(archive)
    require(archive_pin == receipt['local_sha256'] and publisher == ASSET.publisher_md5
            and sha(vpn_raw, 8 * 1024**2) == vpn_raw_pin, 'packet_verified_archive_or_raw_pin')
    require(not output.exists() and not output.is_symlink(), 'packet_intake_fresh_output')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    report = {'schema': 'verified-vpn-packet-members-1', 'completed': False, 'role': 'training',
              'scenario': 'russellmitchell', 'archive_sha256': archive_pin,
              'publisher_md5_verified': True, 'vpn_raw_sha256': vpn_raw_pin, 'members': [],
              'validation_labels_opened': False, 'original_population_changed': False,
              'new_independent_evaluation': False, 'goal_qualified': False, 'aws_calls': 0, 'paid_api_calls': 0}
    try:
        with archive.open('rb') as stream:
            count, boundary = index_bound(stream)
            stream.seek(0)
            with zipfile.ZipFile(stream) as package:
                infos = package.infolist()
                require(len(infos) == count and len({safe_name(i) for i in infos}) == count,
                        'packet_member_population')
                by_name = {i.filename: i for i in infos}
                require(all(name in by_name for name in (*MEMBERS, VPN_LOG)), 'packet_required_members')
                raw_info = by_name[VPN_LOG]
                eligible(raw_info, boundary, 8 * 1024**2)
                for name in MEMBERS:
                    eligible(by_name[name], boundary, MAX_FILE)
                require(shutil.disk_usage(output).free > sum(by_name[n].file_size for n in MEMBERS) + 128 * 1024**2,
                        'packet_member_disk_headroom')
                digest, total = hashlib.sha256(), 0
                with package.open(raw_info) as raw:
                    while body := raw.read(1024**2):
                        total += len(body)
                        require(total <= raw_info.file_size, 'packet_raw_copy_bound')
                        digest.update(body)
                require(total == raw_info.file_size == vpn_raw.stat().st_size and digest.hexdigest() == vpn_raw_pin,
                        'packet_same_vpn_log_bytes')
                for number, name in enumerate(MEMBERS):
                    info = by_name[name]
                    target = output / f'member-{number}.pcap'
                    partial = target.with_suffix('.part')
                    digest, total = hashlib.sha256(), 0
                    with package.open(info) as source, partial.open('xb') as destination:
                        while body := source.read(1024**2):
                            total += len(body)
                            require(total <= info.file_size <= MAX_FILE, 'packet_member_copy_bound')
                            digest.update(body)
                            destination.write(body)
                    require(total == info.file_size, 'packet_member_complete_copy')
                    partial.rename(target)
                    member_pin = digest.hexdigest()
                    observations = output / f'member-{number}-initial.jsonl'
                    parsed = scan(target, member_pin, observations)
                    report['members'].append({'archive_member': name, 'path': target.name,
                        'bytes': total, 'sha256': member_pin, 'crc32': f'{info.CRC:08x}', 'crc_verified': True,
                        'observations': observations.name, **parsed})
        require(fingerprints(archive) == (archive_pin, ASSET.publisher_md5)
                and sha(vpn_raw, 8 * 1024**2) == vpn_raw_pin and sha(acquisition, 65536) == acquisition_pin,
                'packet_archive_or_raw_drift')
        report['same_vpn_log_bytes_verified'] = True
        report['completed'] = True
    finally:
        (output / 'run.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('acquisition', 'acquisition-sha256', 'archive', 'vpn-raw', 'vpn-raw-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = run(args.acquisition, args.acquisition_sha256, args.archive, args.vpn_raw, args.vpn_raw_sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'members': len(result['members']), 'goal_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
