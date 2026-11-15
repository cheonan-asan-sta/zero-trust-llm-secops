"""Read-only, bounded ZIP source inventory. Member names never become output paths."""

import hashlib
import re
import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 2*1024**3
MAX_INDEX = 16*1024**2
MAX_MEMBERS = 50000
MAX_MEMBER = 512*1024**2


def require(condition, code):
    if not condition:
        raise ValueError('source_zip_'+code)


def fingerprint(stream):
    stream.seek(0)
    sha = hashlib.sha256()
    while body := stream.read(1024**2):
        sha.update(body)
    return sha.hexdigest()


def index_bounds(stream):
    stream.seek(0, 2)
    size = stream.tell()
    require(22 <= size <= MAX_ARCHIVE, 'archive_size')
    start = max(0, size-65557)
    stream.seek(start)
    tail = stream.read(65557)
    offset = tail.rfind(b'PK\x05\x06')
    require(offset >= 0 and len(tail)-offset >= 22, 'end_record')
    signature, disk, directory_disk, disk_entries, entries, index_size, index_offset, comment = struct.unpack(
        '<4s4H2IH', tail[offset:offset+22])
    end_offset = start+offset
    require(signature == b'PK\x05\x06' and end_offset+22+comment == size and disk == directory_disk == 0,
            'single_disk_end_record')
    if 65535 in {disk_entries, entries} or 4294967295 in {index_size, index_offset}:
        require(end_offset >= 20, 'zip64_locator')
        stream.seek(end_offset-20)
        locator = stream.read(20)
        magic, disk64, record_offset, disks = struct.unpack('<4sIQI', locator)
        require(magic == b'PK\x06\x07' and disk64 == 0 and disks == 1 and 0 <= record_offset <= end_offset-76,
                'zip64_locator')
        stream.seek(record_offset)
        raw = stream.read(56)
        require(len(raw) == 56, 'zip64_end_record')
        magic, record_size, _made, _needed, disk, directory_disk, disk_entries, entries, index_size, index_offset = struct.unpack('<4sQ2H2I4Q', raw)
        require(magic == b'PK\x06\x06' and 44 <= record_size <= 1024
                and record_offset+12+record_size <= end_offset-20 and disk == directory_disk == 0,
                'zip64_end_record')
        boundary = record_offset
    else:
        boundary = end_offset
    require(1 <= entries == disk_entries <= MAX_MEMBERS and 0 < index_size <= MAX_INDEX
            and 0 <= index_offset < boundary and index_offset+index_size <= boundary, 'index_bound')
    return {'archive_bytes': size, 'members': entries, 'index_bytes': index_size, 'index_offset': index_offset}


def safe_name(info):
    name = info.filename
    require(name == info.orig_filename and '\\' not in name and '\x00' not in name
            and not any(ord(char) < 32 for char in name), 'member_name')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and ':' not in name and bool(path.parts), 'member_path')
    normalized = path.as_posix().rstrip('/')
    require(normalized not in {'', '.'}, 'member_path')
    return normalized


def entry(info, boundary):
    name = safe_name(info)
    mode = stat.S_IFMT(info.external_attr >> 16)
    kind = 'directory' if info.is_dir() else 'symlink' if mode == stat.S_IFLNK else 'regular' if mode in {0, stat.S_IFREG} else 'special'
    require(info.file_size >= 0 and info.compress_size >= 0 and 0 <= info.header_offset < boundary, 'member_extent')
    return {'name': name, 'archive_name': info.filename, 'kind': kind, 'bytes': info.file_size,
        'compressed_bytes': info.compress_size, 'crc32': f'{info.CRC:08x}', 'encrypted': bool(info.flag_bits & 1),
        'compression': info.compress_type,
        'bounded_read_eligible': kind == 'regular' and not info.flag_bits & 1 and info.file_size <= MAX_MEMBER
            and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}}


def inspect(path, expected_sha256):
    path = Path(path)
    require(re.fullmatch(r'[a-f0-9]{64}', expected_sha256) is not None, 'external_anchor')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_ARCHIVE, 'regular_archive')
    with path.open('rb') as stream:
        require(fingerprint(stream) == expected_sha256, 'archive_hash')
        bounds = index_bounds(stream)
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            infos = archive.infolist()
            require(len(infos) == bounds['members'], 'index_population')
            rows = [entry(info, bounds['index_offset']) for info in infos]
            require(len({row['name'] for row in rows}) == len(rows), 'duplicate_member')
        require(fingerprint(stream) == expected_sha256, 'archive_changed')
    return {'schema': 'f1-source-zip-inventory-1', 'source_sha256': expected_sha256, **bounds,
        'entries': rows, 'uncompressed_bytes': sum(row['bytes'] for row in rows),
        'bodies_read': 0, 'archive_extracted': False, 'code_executed': False, 'goal_qualified': False}


def copy_member(path, expected_sha256, archive_name, destination, *, maximum_bytes=MAX_MEMBER):
    require(type(maximum_bytes) is int and 0 < maximum_bytes <= MAX_MEMBER, 'member_read_bound')
    inventory = inspect(path, expected_sha256)
    matches = [row for row in inventory['entries'] if row['archive_name'] == archive_name]
    require(len(matches) == 1 and matches[0]['bounded_read_eligible'] and matches[0]['bytes'] <= maximum_bytes,
            'member_not_eligible')
    destination = Path(destination)
    partial = destination.with_name(destination.name+'.part')
    require(not destination.exists() and not destination.is_symlink()
            and not partial.exists() and not partial.is_symlink(), 'fresh_destination')
    total, sha = 0, hashlib.sha256()
    with Path(path).open('rb') as stream:
        require(fingerprint(stream) == expected_sha256, 'archive_hash')
        stream.seek(0)
        bounds = index_bounds(stream)
        require(bounds['members'] == inventory['members'], 'archive_changed')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive, archive.open(archive_name) as source, partial.open('xb') as target:
            while body := source.read(min(1024**2, maximum_bytes-total+1)):
                total += len(body)
                require(total <= maximum_bytes, 'member_read_bound')
                target.write(body)
                sha.update(body)
        require(fingerprint(stream) == expected_sha256, 'archive_changed')
    require(total == matches[0]['bytes'], 'member_size')
    partial.rename(destination)
    return {'source_sha256': expected_sha256, 'archive_member': archive_name, 'bytes': total,
        'sha256': sha.hexdigest(), 'zip_crc_verified_at_eof': True, 'code_executed': False}
