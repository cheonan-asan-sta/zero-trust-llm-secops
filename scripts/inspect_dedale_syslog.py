"""Reproduce a pinned, label-free DEDALE native schema probe from a local ZIP."""

import argparse
import hashlib
import io
import json
import re
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.nested_bzip2_probe import probe


def pinned_json(path, expected):
    require(type(expected) is str and re.fullmatch('[a-f0-9]{64}', expected), 'probe_contract_anchor')
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 100000,
            'probe_contract_file')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == expected, 'probe_contract_hash')
    return decode(data)


def archive_hash(path, maximum):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == maximum,
            'probe_archive_file')
    sha, md5, total = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024**2):
            total += len(chunk)
            require(total <= maximum, 'probe_archive_size')
            sha.update(chunk)
            md5.update(chunk)
    require(total == maximum, 'probe_archive_size')
    return sha.hexdigest(), md5.hexdigest()


def inspect(source, intake, intake_sha256, decoding, decoding_sha256, directory):
    source, directory = Path(source), Path(directory)
    require(not directory.exists(), 'probe_output_exists')
    base = pinned_json(intake, intake_sha256)
    codec = pinned_json(decoding, decoding_sha256)
    require(base['schema_version'] == 'dedale-syslog-schema-intake-1'
            and codec['schema_version'] == 'dedale-nested-decoding-amendment-1', 'probe_contract_schema')
    require(base['role'] == codec['role'] == 'development_schema_probe_only'
            and codec['original_contract_sha256'] == intake_sha256
            and codec['selection_unchanged'] is True
            and codec['independent_final_qualification'] is False
            and codec['model_training_prediction_or_metric_change'] is False, 'probe_role')
    require(base['file']['id'] == 717890 and base['file']['name'] == 'system_logs_syslog.zip'
            and base['claims']['original_population'] == 1681815
            and base['claims']['no_training_or_prediction'] is True, 'probe_source_scope')
    limits = base['selection']
    require(limits['maximum_observed_physical_lines'] == codec['maximum_observed_physical_lines'] == 128
            and limits['maximum_physical_line_bytes'] == codec['maximum_physical_line_bytes'] == 2097152
            and codec['maximum_decoded_bytes'] == 536870912, 'probe_fixed_bounds')
    initial = archive_hash(source, base['file']['bytes'])
    require(initial == (codec['archive_sha256'], base['file']['publisher_md5']), 'probe_archive_hash')
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= limits['maximum_archive_members']
                and len({x.filename for x in entries}) == len(entries), 'probe_archive_inventory')
        require(sum(x.file_size for x in entries) <= limits['maximum_declared_uncompressed_archive_bytes'],
                'probe_archive_expansion')
        regular = []
        for item in entries:
            require(item.orig_filename == item.filename, 'probe_normalized_member_name')
            name = PurePosixPath(item.filename)
            require(not name.is_absolute() and '..' not in name.parts and chr(92) not in item.filename
                    and chr(0) not in item.filename and ':' not in name.parts[0]
                    and not item.flag_bits & 1, 'probe_member_path')
            mode = item.external_attr >> 16
            require(not stat.S_ISLNK(mode), 'probe_member_link')
            if not item.is_dir():
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG), 'probe_member_type')
                regular.append(item)
        require(bool(regular), 'probe_no_regular_member')
        selected = min(regular, key=lambda x: x.filename)
        require(selected.filename == codec['member']
                and selected.file_size == codec['compressed_member_bytes']
                and selected.file_size <= limits['maximum_member_bytes'], 'probe_first_member')
        # A complete read verifies the ZIP member's CRC before interpreting nested bytes.
        with archive.open(selected) as stream:
            body = stream.read(selected.file_size + 1)
        require(len(body) == selected.file_size
                and hashlib.sha256(body).hexdigest() == codec['compressed_member_sha256'],
                'probe_nested_hash')
        result, prefix = probe(io.BytesIO(body), maximum_lines=128,
            maximum_row_bytes=codec['maximum_physical_line_bytes'],
            maximum_decoded_bytes=codec['maximum_decoded_bytes'])
        result.update({'member': selected.filename, 'stored_member_bytes': len(body),
                       'stored_member_sha256': hashlib.sha256(body).hexdigest(),
                       'stored_member_crc32': f'{selected.CRC:08x}', 'archive_members': len(entries)})
    require(archive_hash(source, base['file']['bytes']) == initial, 'probe_archive_changed')
    require(pinned_json(intake, intake_sha256) == base
            and pinned_json(decoding, decoding_sha256) == codec, 'probe_contract_changed')
    result.update({'at': datetime.now(UTC).isoformat(), 'role': base['role'],
                   'intake_sha256': intake_sha256, 'decoding_sha256': decoding_sha256,
                   'archive_sha256': initial[0], 'archive_md5': initial[1],
                   'publisher_md5_verified': True, 'native_ground_truth_bodies_opened': 0,
                   'simulator_bodies_opened': 0, 'metric_or_population_change': False})
    directory.mkdir(parents=True)
    (directory / 'probe.jsonl').write_bytes(prefix)
    (directory / 'run.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'intake', 'intake-sha256', 'decoding', 'decoding-sha256', 'directory'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = inspect(**vars(args))
    print(json.dumps({k: result[k] for k in ('complete', 'probe_lines', 'parse_errors',
        'archive_sha256', 'decoded_sha256', 'new_independent_cases', 'metric_or_population_change')}))


if __name__ == '__main__':
    main()
