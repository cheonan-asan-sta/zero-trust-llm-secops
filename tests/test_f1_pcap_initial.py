import hashlib
import json
import struct

import pytest

from scripts.f1_lab.pcap_initial import initial, join_key, scan


def frame(*, ttl=64, source=b'\xc0\x00\x02\x01', port=50000, session=b'12345678'):
    payload = bytes([7 << 3]) + session + b'\0' * 5
    udp = struct.pack('!4H', port, 1194, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 12, 0x4000, ttl, 17, 0,
                     source, b'\xc0\x00\x02\x02') + udp
    return b'\x01' * 12 + b'\x08\x00' + ip


def pcap(rows, *, endian='<', nano=False, link=1, snaplen=65535):
    magic = struct.pack(endian + 'I', 0xa1b23c4d if nano else 0xa1b2c3d4)
    header = magic + struct.pack(endian + 'HH4I', 2, 4, 0, 0, snaplen, link)
    return header + b''.join(struct.pack(endian + '4I', sec, sub, len(packet), len(packet)) + packet
                              for sec, sub, packet in rows)


def test_initial_frame_joins_without_learning_raw_identifiers_or_claiming_identity():
    row = initial(frame())
    assert row['join_key'] == join_key('192.0.2.1', 50000, b'12345678')
    other = initial(frame(source=b'\xc0\x00\x02\x03', port=50001, session=b'ABCDEFGH'))
    assert row['join_key'] != other['join_key'] and row['features'] == other['features']
    assert len(row['features']) == 6 and initial(frame(ttl=63))['features'] != row['features']


@pytest.mark.parametrize('fault', ['ether', 'vlan', 'version', 'ihl', 'fragment', 'more_fragments',
                                 'ttl', 'tcp', 'length', 'udp_length', 'server_direction',
                                 'opcode', 'key_id', 'acks', 'packet_id', 'zero_sid', 'hmac', 'short'])
def test_unsupported_fragmented_truncated_or_later_control_frames_do_not_become_initial_evidence(fault):
    data = bytearray(frame())
    if fault == 'ether': data[12:14] = b'\x86\xdd'
    if fault == 'vlan': data[12:14] = b'\x81\x00'
    if fault == 'version': data[14] = 0x65
    if fault == 'ihl': data[14] = 0x44
    if fault == 'fragment': data[20:22] = b'\x00\x01'
    if fault == 'more_fragments': data[20:22] = b'\x20\x00'
    if fault == 'ttl': data[22] = 0
    if fault == 'tcp': data[23] = 6
    if fault == 'length': data[16:18] = b'\xff\xff'
    if fault == 'udp_length': data[38:40] = b'\x00\x08'
    if fault == 'server_direction': data[34:38] = struct.pack('!2H', 1194, 50000)
    if fault == 'opcode': data[42] = 4 << 3
    if fault == 'key_id': data[42] |= 1
    if fault == 'acks': data[51] = 1
    if fault == 'packet_id': data[55] = 1
    if fault == 'zero_sid': data[43:51] = b'\0' * 8
    if fault == 'hmac': data[16:18] = struct.pack('!H', 62); data[38:40] = struct.pack('!H', 42); data += b'X' * 20
    if fault == 'short': data = data[:20]
    assert initial(bytes(data)) is None


@pytest.mark.parametrize('endian,nano', [('<', False), ('>', False), ('<', True), ('>', True)])
def test_whole_source_pin_all_packet_ordinals_and_integer_capture_time(tmp_path, endian, nano):
    body = pcap([(1700000000, 123, frame()), (1700000001, 0, b''),
                 (1700000002, 456, frame(ttl=63))], endian=endian, nano=nano)
    path = tmp_path / 'input.pcap'; path.write_bytes(body)
    out = tmp_path / 'observations.jsonl'
    result = scan(path, hashlib.sha256(body).hexdigest(), out)
    rows = list(map(json.loads, out.read_bytes().splitlines()))
    assert result['packets'] == 3 and result['initial_frames'] == 2 and result['bytes'] == len(body)
    assert [r['packet_ordinal'] for r in rows] == [1, 3]
    assert rows[0]['capture_time_ns'] == 1700000000000000000 + (123 if nano else 123000)
    assert rows[0]['frame_sha256'] == hashlib.sha256(frame()).hexdigest()
    assert result['frame_authentication_or_device_identity_verified'] is False


@pytest.mark.parametrize('fault', ['pin', 'truncated_header', 'truncated_packet', 'link', 'snaplen', 'fraction'])
def test_incomplete_unsupported_or_mismatched_input_never_publishes_output(tmp_path, fault):
    body = pcap([(1700000000, 123, frame())], link=113 if fault == 'link' else 1,
                snaplen=10 if fault == 'snaplen' else 65535)
    if fault == 'truncated_header': body = body[:32]
    if fault == 'truncated_packet': body = body[:-1]
    if fault == 'fraction': body = body[:28] + struct.pack('<I', 1000000) + body[32:]
    path = tmp_path / 'input.pcap'; path.write_bytes(body)
    out = tmp_path / 'observations.jsonl'
    with pytest.raises(ValueError):
        scan(path, 'f' * 64 if fault == 'pin' else hashlib.sha256(body).hexdigest(), out)
    assert not out.exists() and out.with_suffix('.part').exists()


def test_capture_time_regression_is_reported_without_sorting_or_rewriting_physical_rows(tmp_path):
    body = pcap([(2, 0, frame()), (1, 0, frame())])
    path = tmp_path / 'input.pcap'; path.write_bytes(body)
    out = tmp_path / 'observations.jsonl'
    report = scan(path, hashlib.sha256(body).hexdigest(), out)
    assert report['time_regressions'] == 1
    assert [r['capture_time_ns'] for r in map(json.loads, out.read_bytes().splitlines())] == [2000000000, 1000000000]


def test_existing_output_is_not_overwritten(tmp_path):
    body = pcap([])
    path = tmp_path / 'input.pcap'; path.write_bytes(body)
    out = tmp_path / 'observations.jsonl'; out.write_bytes(b'keep')
    with pytest.raises(ValueError):
        scan(path, hashlib.sha256(body).hexdigest(), out)
    assert out.read_bytes() == b'keep'
