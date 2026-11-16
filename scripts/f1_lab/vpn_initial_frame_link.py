"""Diagnostic current-SID links; identity and temporal admission stay unproved.

A one-second timestamp interval or a shared network identifier is not a proof
of feature availability. This module never returns a prediction or permission.
"""

import bisect
import ipaddress
import math
import re
from datetime import UTC, datetime

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.pcap_initial import join_key
from scripts.f1_lab.vpn_context import PREFIX

INITIAL = re.compile(r'TLS: Initial packet from \[AF_INET\]((?:\d{1,3}\.){3}\d{1,3}):'
                     r'(\d{1,5}), sid=([a-fA-F0-9]{8}) ([a-fA-F0-9]{8})')
HEX = re.compile('[a-f0-9]{64}')
FIELDS = {'source_sha256', 'packet_ordinal', 'capture_time_ns', 'frame_sha256', 'join_key', 'features'}
TTLS = frozenset(f'ttl_{n}' for n in range(1, 256))
IHLS = frozenset(f'ihl_{n}' for n in range(20, 61, 4))
TOS = frozenset(f'tos_{n}' for n in range(256))


def validate(row):
    require(type(row) is dict and set(row) == FIELDS, 'wire_link_fields')
    require(all(type(row[k]) is str and HEX.fullmatch(row[k]) for k in
                ('source_sha256', 'frame_sha256', 'join_key')), 'wire_link_hashes')
    require(type(row['packet_ordinal']) is int and 0 < row['packet_ordinal'] <= 10000000
            and type(row['capture_time_ns']) is int and 0 <= row['capture_time_ns'] < 2**63,
            'wire_link_ordinal_or_time')
    f = row['features']
    require(type(f) is list and len(f) == 6 and all(type(s) is str and len(s) <= 64 for s in f),
            'wire_link_feature_types')
    require(f[0] == 'openvpn_initial_udp_v1' and f[1] in TTLS
            and f[2] in {'df_True', 'df_False'} and f[3] in IHLS
            and f[4] in TOS and f[5] in {'id_zero', 'id_nonzero'},
            'wire_link_feature_domain')


class FrameIndex:
    def __init__(self, rows):
        require(type(rows) is list and len(rows) <= 200000, 'wire_link_frame_bound')
        self.rows = {}
        seen = set()
        for row in rows:
            validate(row)
            physical = row['source_sha256'], row['packet_ordinal']
            require(physical not in seen, 'wire_link_duplicate_physical_row')
            seen.add(physical)
            self.rows.setdefault(row['join_key'], []).append({**row, 'features': row['features'].copy()})
        self.times = {}
        for key, values in self.rows.items():
            # Only lookup references are sorted; original PCAP/log ordinals are retained.
            values.sort(key=lambda row: (row['capture_time_ns'], row['source_sha256'], row['packet_ordinal']))
            self.times[key] = [r['capture_time_ns'] for r in values]

    def match(self, line, moment):
        base = {'status': 'not_initial', 'matched': False, 'temporal_availability_proven': False,
                'admitted_to_predictor': False, 'human_or_device_identity_verified': False}
        if type(line) is not str or type(moment) not in {int, float} or not math.isfinite(moment):
            return {**base, 'status': 'raw_time_unavailable'}
        require(len(line.encode()) <= MAX_ROW, 'wire_link_line_bound')
        prefix = PREFIX.match(line)
        if prefix is None:
            return base
        body = line[prefix.end():].rstrip('\r\n')
        if not body.startswith('TLS: Initial packet'):
            return base
        parsed = INITIAL.fullmatch(body)
        if parsed is None or prefix['name'] is not None:
            return {**base, 'status': 'initial_shape_unavailable'}
        try:
            actual = datetime.fromisoformat(line[:19]).replace(tzinfo=UTC).timestamp()
            address = str(ipaddress.IPv4Address(prefix['ip']))
            echoed = str(ipaddress.IPv4Address(parsed[1]))
            port = int(prefix['port'])
            require(actual == moment and moment == int(moment) and 0 <= moment < 4102444800,
                    'wire_link_clock_binding')
            require(address == echoed and port == int(parsed[2]), 'wire_link_endpoint_echo')
            key = join_key(address, port, bytes.fromhex(parsed[3] + parsed[4]))
        except (ValueError, OverflowError, OSError):
            return {**base, 'status': 'initial_binding_unavailable'}
        lower = int(moment) * 1000000000
        values = self.rows.get(key, [])
        times = self.times.get(key, [])
        # Diagnostic coverage window only, not a declaration of availability.
        # Later captures do not invalidate an earlier candidate's unique prefix.
        left = bisect.bisect_left(times, max(0, lower - 1000000000))
        right = bisect.bisect_left(times, lower + 1000000000)
        count = right - left
        if count == 0:
            return {**base, 'status': 'no_compatible_frame', 'compatible_candidates': 0}
        if count > 1:
            return {**base, 'status': 'ambiguous_frame', 'compatible_candidates': count}
        row = values[left]
        relation = ('capture_at_or_before_logged_lower_bound' if row['capture_time_ns'] <= lower
                    else 'capture_within_reported_second')
        return {**base, 'matched': True, 'status': 'unique_reported_id_match', 'compatible_candidates': 1,
                'recorded_time_relation': relation, 'frame': {**row, 'features': row['features'].copy()},
                'binding_scope': 'same pinned source group, reported endpoint and SID; not a trust grant'}
