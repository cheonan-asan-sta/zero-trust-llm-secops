import hashlib
import json
import struct

import pytest

from scripts.f1_lab.dns_capture import question, scan
from scripts.f1_lab.suricata_single_worker import VERSION, runtime_profile, timestamp_us
from tests.test_f1_pcap_initial import pcap


def frame(labels=(b'example', b'test'), *, flags=0x100, count=1, qclass=1):
    name = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
    dns = struct.pack('!6H', 1, flags, count, 0, 0, 0) + name + struct.pack('!2H', 1, qclass)
    udp = struct.pack('!4H', 50000, 53, len(dns) + 8, 0) + dns
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
                     b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x02') + udp
    return b'\x01' * 12 + b'\x08\x00' + ip


def runtime(count=2):
    messages = [VERSION, 'Adding interface ens3 from config file', 'Selected pcap-log compression method: none',
                'Using 1 AF_PACKET threads for interface ens3',
                'all 1 packet processing threads, 4 management threads initialized, engine started.',
                f'(W#01-ens3) Kernel: Packets {count}, dropped 0']
    return ('\n'.join(f'20/1/2022 -- 13:16:{23 if n < 5 else 55} - <Notice> - {m}'
                       for n, m in enumerate(messages)) + '\n').encode()


def test_encoding_shape_never_exports_raw_name_or_endpoint_or_identity():
    label = b'ABCDEFGHIJKLMNOP/RSTUVWXYZabcdefghij'
    result = question(frame((label, label, label, b'example', b'test')))
    assert result['encoded_shape'] is True and result['payload_labels'] == 3
    assert 'example' not in json.dumps(result) and '192.0.2' not in json.dumps(result)
    assert question(frame())['encoded_shape'] is False
    assert 'authority' not in result and 'malicious' not in result


@pytest.mark.parametrize('data', [frame(flags=0x8100), frame(count=2), frame(qclass=3),
    frame((b'x' * 64, b'test')), frame(tuple(b'x' * 63 for _ in range(4))), frame((b'bad.label', b'test')),
    frame((b'bad\0label',)), frame((b'bad label',)), b'', frame()[:40]])
def test_unsupported_or_invalid_questions_not_guessed(data):
    assert question(data) is None


@pytest.mark.parametrize('offset,data', [(12, b'\x81\x00'), (14, b'\x65'), (20, b'\x20\x00'),
                                       (23, b'\x06'), (36, b'\x00\x35'), (38, b'\x00\x08')])
def test_unsupported_transport_fragment_and_length(offset, data):
    packet = bytearray(frame())
    packet[offset:offset + len(data)] = data
    if offset == 36:
        packet[36:38] = struct.pack('!H', 50000)
    assert question(bytes(packet)) is None


@pytest.mark.parametrize('endian,nano', [('<', False), ('>', False), ('<', True), ('>', True)])
def test_full_pin_endian_and_integer_timestamp_preserve_nonquery_ordinals(tmp_path, endian, nano):
    source = tmp_path / 'test.pcap'
    source.write_bytes(pcap([(1, 1, b''), (2, 123, frame())], endian=endian, nano=nano))
    output = tmp_path / 'questions.jsonl'
    result = scan(source, hashlib.sha256(source.read_bytes()).hexdigest(), output)
    rows = list(map(json.loads, output.read_bytes().splitlines()))
    assert result['packets'] == 2 and result['dns_queries'] == 1
    assert rows[0]['packet_ordinal'] == 2
    assert rows[0]['capture_time_ns'] == 2000000000 + (123 if nano else 123000)
    assert result['application_receipt_time_proven'] is False and result['actor_or_authority_proven'] is False


@pytest.mark.parametrize('fault', ['hash', 'truncate', 'clock_regression', 'link'])
def test_incomplete_contradictory_source_never_publishes(tmp_path, fault):
    body = pcap([(2, 0, frame()), (1 if fault == 'clock_regression' else 3, 0, frame())],
                link=113 if fault == 'link' else 1)
    if fault == 'truncate':
        body = body[:-1]
    source = tmp_path / 'test.pcap'
    source.write_bytes(body)
    output = tmp_path / 'questions.jsonl'
    with pytest.raises(ValueError):
        scan(source, 'f' * 64 if fault == 'hash' else hashlib.sha256(body).hexdigest(), output)
    assert not output.exists()


def test_reported_native_runtime_profile_has_no_binary_or_actor_attestation():
    value = runtime_profile(runtime())
    assert value['reported_packet_count'] == 2 and value['interface'] == 'ens3'
    assert value['runtime_binary_byte_identity_verified'] is False
    assert value['actor_or_authority_proven'] is False and value['application_receipt_time_proven'] is False


@pytest.mark.parametrize('old,new', [('version 6.0.4', 'version 7.0.0'),
    ('all 1 packet processing', 'all 2 packet processing'), ('dropped 0', 'dropped 1'),
    ('Using 1 AF_PACKET', 'Using 2 AF_PACKET'), ('method: none', 'method: lz4')])
def test_incompatible_or_lossy_runtime_not_approved(old, new):
    with pytest.raises(ValueError):
        runtime_profile(runtime().replace(old.encode(), new.encode()))


def test_prior_failed_start_is_separate_but_failed_latest_start_rejected():
    failed = runtime().replace(b'Kernel: Packets 2, dropped 0', b'[ERRCODE: SC_ERR_FATAL(171)] - failed')
    assert runtime_profile(failed + runtime())['reported_packet_count'] == 2
    with pytest.raises(ValueError):
        runtime_profile(runtime() + failed)


def test_exact_timezone_aware_microseconds_without_float_rounding():
    assert timestamp_us('2022-01-24T13:50:39.298000+0000') == 1643032239298000
    assert timestamp_us('2022-01-24T15:50:39.297999+0200') == 1643032239297999
    with pytest.raises(ValueError):
        timestamp_us('2022-01-24T13:50:39.298000')
