import hashlib
import stat
import struct
import zipfile

import pytest

from scripts.f1_lab import bounded_zip as source


def archive(tmp_path, entries):
    path = tmp_path/'source.zip'
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as result:
        for name, body in entries:
            result.writestr(name, body)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_inventory_does_not_read_member_bodies_extract_paths_or_execute_code(tmp_path, monkeypatch):
    path, anchor = archive(tmp_path, [('root/', b''), ('root/auth.log', b'one\ntwo\n'), ('root/labels/auth.log', b'{"line":2}')])
    monkeypatch.setattr(zipfile.ZipFile, 'open', lambda *_a, **_kw: pytest.fail('inventory must not open member bodies'))
    result = source.inspect(path, anchor)
    assert result['members'] == 3 and result['uncompressed_bytes'] == 18
    assert result['bodies_read'] == 0 and not result['archive_extracted'] and not result['code_executed']
    assert {p.name for p in tmp_path.iterdir()} == {'source.zip'}


@pytest.mark.parametrize('name', ['../outside', '/absolute', 'C:/drive', r'root\outside', 'root/../../outside'])
def test_unsafe_paths_are_rejected_without_creating_any_output(tmp_path, name):
    path, anchor = archive(tmp_path, [(name, b'body')])
    if '\\' in name:
        # Windows' writer normalizes its own separator. Craft an actual stored
        # backslash in both headers so the read-side boundary is exercised.
        body = path.read_bytes().replace(name.replace('\\', '/').encode(), name.encode())
        path.write_bytes(body)
        anchor = hashlib.sha256(body).hexdigest()
    with pytest.raises(ValueError, match='member_(path|name)'):
        source.inspect(path, anchor)
    assert {p.name for p in tmp_path.iterdir()} == {'source.zip'}


def test_aliases_of_the_same_member_are_rejected(tmp_path):
    path, anchor = archive(tmp_path, [('root/auth.log', b'one'), ('root/./auth.log', b'two')])
    with pytest.raises(ValueError, match='duplicate_member'):
        source.inspect(path, anchor)


def test_symlink_is_visible_in_inventory_but_cannot_be_opened_as_regular_data(tmp_path):
    link = zipfile.ZipInfo('link')
    link.create_system, link.external_attr = 3, (stat.S_IFLNK | 0o777) << 16
    path, anchor = archive(tmp_path, [(link, b'/outside')])
    result = source.inspect(path, anchor)
    assert result['entries'][0]['kind'] == 'symlink' and not result['entries'][0]['bounded_read_eligible']
    with pytest.raises(ValueError, match='member_not_eligible'):
        source.copy_member(path, anchor, 'link', tmp_path/'copied')
    assert not (tmp_path/'copied').exists()


def test_exact_member_copy_preserves_original_lines_and_verifies_hash_and_crc(tmp_path):
    body = b'\nline-one\r\nline-two\n'
    path, anchor = archive(tmp_path, [('logs/auth.log', body)])
    target = tmp_path/'opaque-data.bin'
    result = source.copy_member(path, anchor, 'logs/auth.log', target)
    assert target.read_bytes() == body and result['bytes'] == len(body)
    assert result['sha256'] == hashlib.sha256(body).hexdigest() and result['zip_crc_verified_at_eof']
    assert not result['code_executed']
    with pytest.raises(ValueError, match='fresh_destination'):
        source.copy_member(path, anchor, 'logs/auth.log', target)
    assert target.read_bytes() == body


def test_too_large_member_is_rejected_before_creating_a_destination(tmp_path):
    path, anchor = archive(tmp_path, [('auth.log', b'12345')])
    with pytest.raises(ValueError, match='member_not_eligible'):
        source.copy_member(path, anchor, 'auth.log', tmp_path/'output', maximum_bytes=4)
    assert not (tmp_path/'output').exists()


def test_external_archive_anchor_is_checked_before_parsing(tmp_path):
    path, _anchor = archive(tmp_path, [('auth.log', b'body')])
    with pytest.raises(ValueError, match='archive_hash'):
        source.inspect(path, '0'*64)


def test_malicious_directory_population_is_rejected_before_zipfile_materialization(tmp_path, monkeypatch):
    path, _anchor = archive(tmp_path, [('auth.log', b'body')])
    raw = bytearray(path.read_bytes())
    offset = raw.rfind(b'PK\x05\x06')
    struct.pack_into('<HH', raw, offset+8, source.MAX_MEMBERS+1, source.MAX_MEMBERS+1)
    path.write_bytes(raw)
    monkeypatch.setattr(zipfile, 'ZipFile', lambda *_a, **_kw: pytest.fail('must reject oversized index before ZipFile'))
    with pytest.raises(ValueError, match='index_bound'):
        source.inspect(path, hashlib.sha256(raw).hexdigest())


def test_multi_disk_archive_and_trailing_bytes_cannot_masquerade_as_the_pinned_input(tmp_path):
    path, _anchor = archive(tmp_path, [('auth.log', b'body')])
    original = path.read_bytes()
    raw = bytearray(original)
    offset = raw.rfind(b'PK\x05\x06')
    struct.pack_into('<H', raw, offset+4, 1)
    path.write_bytes(raw)
    with pytest.raises(ValueError, match='single_disk'):
        source.inspect(path, hashlib.sha256(raw).hexdigest())
    path.write_bytes(original+b'extra')
    with pytest.raises(ValueError, match='single_disk'):
        source.inspect(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_valid_zip64_index_can_be_read_without_materializing_huge_members(tmp_path):
    path, _anchor = archive(tmp_path, [('auth.log', b'body')])
    raw = path.read_bytes()
    offset = raw.rfind(b'PK\x05\x06')
    end = bytearray(raw[offset:])
    _sig, _disk, _cdisk, _disk_entries, entries, size, start, _comment = struct.unpack('<4s4H2IH', end)
    record = struct.pack('<4sQ2H2I4Q', b'PK\x06\x06', 44, 45, 45, 0, 0, entries, entries, size, start)
    locator = struct.pack('<4sIQI', b'PK\x06\x07', 0, offset, 1)
    struct.pack_into('<HHII', end, 8, 65535, 65535, 4294967295, 4294967295)
    path.write_bytes(raw[:offset]+record+locator+end)
    result = source.inspect(path, hashlib.sha256(path.read_bytes()).hexdigest())
    assert result['members'] == 1 and result['entries'][0]['name'] == 'auth.log'


def test_crc_failure_does_not_publish_a_final_member_file(tmp_path):
    path = tmp_path/'source.zip'
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as result:
        result.writestr('auth.log', b'known-public-payload')
    raw = path.read_bytes().replace(b'known-public-payload', b'wrong-public-payload')
    path.write_bytes(raw)
    with pytest.raises(zipfile.BadZipFile):
        source.copy_member(path, hashlib.sha256(raw).hexdigest(), 'auth.log', tmp_path/'output')
    assert not (tmp_path/'output').exists()
