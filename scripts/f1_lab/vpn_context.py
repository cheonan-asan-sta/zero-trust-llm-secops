"""Strictly earlier OpenVPN endpoint observations; no claims of user authority."""

import hashlib
import ipaddress
import math
import re
from collections import Counter, deque
from itertools import groupby

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.raw_observations import bucket

PROFILE = 'raw-rich-vpn-history-3'
LOOKBACK = 24*60*60
MAX_EVENTS = 100000
MAX_BYTES = 64*1024**2
VPN_DOMAINS = {
    'vpn_endpoint_available': (False, True),
    'vpn_peer_named_now': (False, True),
    'vpn_peer_seen_before': (False, True),
    'vpn_connection_seen_before': (False, True),
    'vpn_peer_named_before': (False, True),
    'vpn_connection_initial_before': (False, True),
    'vpn_peer_prior_rows': tuple(range(7)),
    'vpn_connection_prior_rows': tuple(range(7)),
}
PREFIX = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} '
                    r'(?:(?P<name>[^/\s]{1,256})/)?'
                    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,5})(?:\s|$)')


def empty():
    return {name: values[0] for name, values in VPN_DOMAINS.items()}


def endpoint(line):
    """The logged network peer is not an authenticated person or device ID."""
    match = PREFIX.match(line)
    if match is None:
        return None
    try:
        address = str(ipaddress.IPv4Address(match['ip']))
    except ValueError:
        return None
    port = int(match['port'])
    if not 1 <= port <= 65535:
        return None
    peer = hashlib.sha256(('vpn-peer:'+address).encode()).digest()
    connection = hashlib.sha256(('vpn-endpoint:'+address+':'+str(port)).encode()).digest()
    return peer, connection, bool(match['name']), 'TLS: Initial packet' in line


def ordered_vpn_context(records):
    """One source/host only; all rows at the same timestamp see the same past.

    Missing endpoints/times remain unavailable. Input strings, endpoint hashes,
    names and timestamps are never emitted as learned feature values. Identical
    source rows count once in history, but every input ordinal is returned.
    The 24-hour observation window is sampled log history, not a trust grant.
    """
    require(isinstance(records, list) and len(records) <= MAX_EVENTS, 'vpn_record_bound')
    size, ordinals, parsed = 0, set(), []
    for ordinal, moment, line in records:
        require(type(ordinal) is int and ordinal > 0 and ordinal not in ordinals, 'vpn_unique_ordinal')
        require(isinstance(line, str), 'vpn_line_type')
        size += len(line.encode('utf-8'))
        require(len(line.encode('utf-8')) <= MAX_ROW and size <= MAX_BYTES, 'vpn_input_bytes')
        require(moment is None or type(moment) in {int, float} and math.isfinite(moment), 'vpn_time')
        ordinals.add(ordinal)
        parsed.append((ordinal, moment, line, endpoint(line)))
    parsed.sort(key=lambda row: (float('inf') if row[1] is None else row[1], row[0]))
    queue, seen, peers, connections = deque(), set(), {}, {}
    result = {}
    for moment, tied in groupby(parsed, key=lambda row: row[1]):
        tied = list(tied)
        if moment is None:
            result.update((ordinal, empty()) for ordinal, *_ in tied)
            continue
        while queue and queue[0][0] < moment-LOOKBACK:
            _, digest, peer, connection, named, initial = queue.popleft()
            seen.remove(digest)
            for groups, key, flags in ((peers, peer, (named,)), (connections, connection, (initial,))):
                groups[key]['rows'] -= 1
                groups[key]['flag'] -= flags[0]
                if not groups[key]['rows']:
                    del groups[key]
        # Query the whole tie batch before any of its observations are added.
        for ordinal, _, line, observation in tied:
            features = empty()
            if observation is not None:
                peer, connection, named, _ = observation
                prior_peer, prior_connection = peers.get(peer, Counter()), connections.get(connection, Counter())
                features.update({
                    'vpn_endpoint_available': True, 'vpn_peer_named_now': named,
                    'vpn_peer_seen_before': prior_peer['rows'] > 0,
                    'vpn_connection_seen_before': prior_connection['rows'] > 0,
                    'vpn_peer_named_before': prior_peer['flag'] > 0,
                    'vpn_connection_initial_before': prior_connection['flag'] > 0,
                    'vpn_peer_prior_rows': bucket(prior_peer['rows'], (1, 5, 10, 25, 100, 500)),
                    'vpn_connection_prior_rows': bucket(prior_connection['rows'], (1, 5, 10, 25, 100, 500)),
                })
            result[ordinal] = features
        for _, _, line, observation in tied:
            if observation is None:
                continue
            digest = hashlib.sha256(line.encode('utf-8')).digest()
            if digest in seen:
                continue
            peer, connection, named, initial = observation
            seen.add(digest)
            queue.append((moment, digest, peer, connection, named, initial))
            for groups, key, flag in ((peers, peer, named), (connections, connection, initial)):
                require(key in groups or len(groups) < 10000, 'vpn_group_bound')
                counter = groups.setdefault(key, Counter())
                counter['rows'] += 1
                counter['flag'] += flag
    return result
