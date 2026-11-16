"""Bounded classic PCAP observations of bare OpenVPN v2 initial UDP frames.

Only exact Ethernet/IPv4/unfragmented UDP/client-reset shapes are supported.
Header observations are not device identity, authentication or authority.
Nothing is published until the complete input SHA has been checked at EOF.
"""

import hashlib
import ipaddress
import re
import struct
from pathlib import Path

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha

MAX_FILE = 2 * 1024**3
MAX_PACKET = 1024**2
MAX_PACKETS = 10000000
MAX_INITIAL = 100000
FORMATS = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
           b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}


def join_key(address, port, session_id):
    """IDs are source-local join material and never learned feature values."""
    require(type(address) is str and str(ipaddress.IPv4Address(address)) == address
            and type(port) is int and 1 <= port <= 65535 and type(session_id) is bytes
            and len(session_id) == 8 and session_id != b'\0' * 8, 'pcap_join_fields')
    return hashlib.sha256(canonical({'address': address, 'port': port, 'session': session_id.hex()})).hexdigest()


def initial(packet):
    if len(packet) < 14 or packet[12:14] != b'\x08\x00':
        return None
    ip = packet[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 15) * 4
    length, identifier, flags = struct.unpack('!HHH', ip[2:8])
    if (not 20 <= ihl <= 60 or len(ip) < ihl + 8 or not ihl + 8 <= length <= len(ip)
            or flags & 0xbfff or not ip[8] or ip[9] != 17):
        return None
    udp = ip[ihl:length]
    sport, dport, udp_size, _checksum = struct.unpack('!4H', udp[:8])
    if not 1 <= sport <= 65535 or sport == 1194 or dport != 1194 or udp_size != len(udp):
        return None
    payload = udp[8:]
    # Opcode 7, key_id 0, SID, zero ACK count and first message ID 0.
    # HMAC/tls-crypt/other versions remain unsupported rather than guessed.
    if (len(payload) != 14 or payload[0] != 7 << 3 or payload[9:] != b'\0' * 5
            or payload[1:9] == b'\0' * 8):
        return None
    address = str(ipaddress.IPv4Address(ip[12:16]))
    features = ('openvpn_initial_udp_v1', f'ttl_{ip[8]}', f'df_{bool(flags & 0x4000)}',
                f'ihl_{ihl}', f'tos_{ip[1]}', 'id_zero' if identifier == 0 else 'id_nonzero')
    return {'join_key': join_key(address, sport, payload[1:9]), 'features': features}


def scan(path, expected_sha256, output):
    path, output = Path(path), Path(output)
    require(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}', expected_sha256), 'pcap_external_anchor')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE, 'pcap_regular_source')
    partial = output.with_suffix('.part')
    require(not output.exists() and not output.is_symlink()
            and not partial.exists() and not partial.is_symlink(), 'pcap_fresh_output')
    digest = hashlib.sha256()
    size = packets = selected = regressions = 0
    previous = None

    def read(stream, amount):
        nonlocal size
        body = stream.read(amount)
        digest.update(body)
        size += len(body)
        require(size <= MAX_FILE, 'pcap_source_bound')
        return body

    with path.open('rb') as source, partial.open('xb') as target:
        header = read(source, 24)
        require(len(header) == 24 and header[:4] in FORMATS, 'pcap_global_header')
        endian, resolution = FORMATS[header[:4]]
        major, minor, _reserved1, _reserved2, snaplen, link = struct.unpack(endian + 'HH4I', header[4:])
        require((major, minor) == (2, 4) and 0 < snaplen <= MAX_PACKET and link == 1, 'pcap_supported_format')
        while header := read(source, 16):
            packets += 1
            require(len(header) == 16 and packets <= MAX_PACKETS, 'pcap_packet_header')
            seconds, fraction, caplen, wirelen = struct.unpack(endian + '4I', header)
            require(fraction < resolution and caplen <= snaplen and caplen <= wirelen <= MAX_PACKET,
                    'pcap_packet_bounds')
            packet = read(source, caplen)
            require(len(packet) == caplen, 'pcap_truncated_packet')
            moment = seconds * 1000000000 + fraction * (1000000000 // resolution)
            regressions += previous is not None and moment < previous
            previous = moment
            row = initial(packet)
            if row is not None:
                selected += 1
                require(selected <= MAX_INITIAL, 'pcap_initial_bound')
                target.write(canonical({'source_sha256': expected_sha256, 'packet_ordinal': packets,
                    'capture_time_ns': moment, 'frame_sha256': hashlib.sha256(packet).hexdigest(),
                    **row}) + b'\n')
        require(digest.hexdigest() == expected_sha256 and size == path.stat().st_size
                and sha(path, MAX_FILE) == expected_sha256, 'pcap_source_hash_or_drift')
    partial.rename(output)
    return {'completed': True, 'source_sha256': expected_sha256, 'observations_sha256': sha(output),
            'packets': packets, 'initial_frames': selected, 'bytes': size, 'time_regressions': regressions,
            'timestamp_resolution': resolution, 'frame_authentication_or_device_identity_verified': False,
            'validation_labels_opened': False, 'goal_qualified': False}
