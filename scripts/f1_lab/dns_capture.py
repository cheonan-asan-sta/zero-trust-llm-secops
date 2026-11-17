"""Bounded classic-PCAP DNS question shapes, without learned endpoint/name IDs."""

import hashlib
import re
import struct
from pathlib import Path

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pcap_initial import FORMATS, MAX_FILE, MAX_PACKET, MAX_PACKETS
from scripts.f1_lab.raw_observations import entropy
from scripts.f1_lab.transfer_evaluation import sha


def question(packet):
    if len(packet) < 14 or packet[12:14] != b'\x08\x00':
        return None
    ip = packet[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
        return None
    ihl = (ip[0] & 15) * 4
    length, _ident, flags = struct.unpack('!HHH', ip[2:8])
    if not 20 <= ihl <= 60 or len(ip) < length or flags & 0xbfff or length < ihl + 8:
        return None
    udp = ip[ihl:length]
    sport, dport, size, _checksum = struct.unpack('!4H', udp[:8])
    if not sport or dport != 53 or size != len(udp) or len(udp) < 20:
        return None
    dns = udp[8:]
    _ident, flags, count, answers, authorities, _additional = struct.unpack('!6H', dns[:12])
    if flags & 0xf800 or count != 1 or answers or authorities:
        return None
    position, labels = 12, []
    while position < len(dns):
        amount = dns[position]
        position += 1
        if amount == 0:
            break
        if not 1 <= amount <= 63 or position + amount > len(dns) or len(labels) >= 127:
            return None
        label = dns[position:position + amount]
        if any(c < 33 or c > 126 or c == 46 for c in label):
            return None
        labels.append(label)
        position += amount
    else:
        return None
    wire_length = 1 + sum(1 + len(label) for label in labels)
    if not labels or position + 4 > len(dns) or wire_length > 255:
        return None
    qtype, qclass = struct.unpack('!HH', dns[position:position + 4])
    if qclass != 1:
        return None
    lengths = [len(label) for label in labels]
    entropies = [entropy(label.decode('ascii')) for label in labels]
    payloads = sum(32 <= size <= 63 and value >= 4.5 for size, value in zip(lengths, entropies, strict=True))
    non_hostname = any(any(c in label for c in (b'+', b'/', b'*', b'=')) for label in labels)
    # A DNS label can legally contain these bytes. This is an encoding shape,
    # not an invalid-DNS verdict, proof of theft or user/device identity.
    return {'qname_sha256': hashlib.sha256(b'.'.join(labels)).hexdigest(), 'qtype': qtype,
            'wire_length': wire_length, 'payload_labels': payloads,
            'non_hostname_base64_characters': non_hostname,
            'encoded_shape': payloads >= 3 and non_hostname}


def scan(path, pin, output):
    path, output = Path(path), Path(output)
    require(type(pin) is str and re.fullmatch('[a-f0-9]{64}', pin), 'dns_capture_external_pin')
    require(path.is_file() and not path.is_symlink() and 24 <= path.stat().st_size <= MAX_FILE,
            'dns_capture_regular_source')
    require(not output.exists() and not output.is_symlink(), 'dns_capture_fresh_output')
    partial = output.with_suffix('.part')
    require(not partial.exists() and not partial.is_symlink(), 'dns_capture_fresh_partial')
    digest = hashlib.sha256()
    total = packets = selected = 0
    previous = first = last = None

    def read(stream, amount):
        nonlocal total
        body = stream.read(amount)
        total += len(body)
        require(total <= MAX_FILE, 'dns_capture_byte_bound')
        digest.update(body)
        return body

    with path.open('rb') as source, partial.open('xb') as sink:
        header = read(source, 24)
        require(len(header) == 24 and header[:4] in FORMATS, 'dns_capture_global_header')
        endian, resolution = FORMATS[header[:4]]
        major, minor, _r1, _r2, snaplen, link = struct.unpack(endian + 'HH4I', header[4:])
        require((major, minor) == (2, 4) and 0 < snaplen <= MAX_PACKET and link == 1, 'dns_capture_format')
        while header := read(source, 16):
            packets += 1
            require(len(header) == 16 and packets <= MAX_PACKETS, 'dns_capture_packet_header')
            seconds, fraction, caplen, wirelen = struct.unpack(endian + '4I', header)
            require(fraction < resolution and caplen <= snaplen and caplen <= wirelen <= MAX_PACKET,
                    'dns_capture_packet_bounds')
            packet = read(source, caplen)
            require(len(packet) == caplen, 'dns_capture_truncated_packet')
            stamp = seconds * 1000000000 + fraction * (1000000000 // resolution)
            require(previous is None or stamp >= previous, 'dns_capture_packet_order')
            first = stamp if first is None else first
            previous = last = stamp
            if (parsed := question(packet)) is not None:
                selected += 1
                require(selected <= 200000, 'dns_capture_query_bound')
                sink.write(canonical({'packet_ordinal': packets, 'capture_time_ns': stamp,
                    'frame_sha256': hashlib.sha256(packet).hexdigest(), **parsed}) + b'\n')
        require(total == path.stat().st_size and digest.hexdigest() == pin and sha(path, MAX_FILE) == pin,
                'dns_capture_source_hash_or_drift')
    partial.rename(output)
    return {'completed': True, 'packets': packets, 'dns_queries': selected, 'bytes': total,
            'source_sha256': pin, 'queries_sha256': sha(output), 'timestamp_resolution': resolution,
            'first_capture_time_ns': first, 'last_capture_time_ns': last, 'capture_time_regressions': 0,
            'application_receipt_time_proven': False, 'actor_or_authority_proven': False}
