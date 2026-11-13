"""Bounded DNS syntax and strictly earlier client query counts; no trust claims."""

import hashlib
import ipaddress
import math
import re
from collections import deque

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.raw_observations import bucket

PROFILE = 'raw-dns-query-context-5'
DNS_DOMAINS = {
    'dns_semantic_available': (False, True),
    'dns_record_type': ('unknown', 'A', 'AAAA', 'PTR', 'TXT', 'MX', 'NS', 'SOA', 'CNAME', 'SRV', 'ANY', 'other'),
    'dns_response_kind': ('none', 'address', 'negative', 'alias', 'other'),
    'dns_local_answer': (False, True),
    'dns_reverse_name': (False, True),
    'dns_query_peer_available': (False, True),
    'dns_query_window_available': (False, True),
    'dns_peer_queries_1s': tuple(range(7)),
    'dns_peer_queries_10s': tuple(range(7)),
    'dns_peer_queries_60s': tuple(range(7)),
    'dns_peer_names_60s': tuple(range(7)),
    'dns_peer_types_60s': tuple(range(7)),
    'dns_peer_reverse_queries_60s': tuple(range(7)),
}
PREFIX = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} '
                    r'(?:(?P<host>[^\s]{1,255}) )?dnsmasq\[(?P<pid>\d{1,10})\]: (?P<message>[^\r\n]{1,4096})\n?$')
QUERY = re.compile(r'^query\[(?P<type>[A-Z0-9]{1,16})\] (?P<name>[^\s]{1,254}) from (?P<peer>[^\s]{1,64})$')
ANSWER = re.compile(r'^(?P<action>reply|cached|/etc/hosts) (?P<name>[^\s]{1,254}) is (?P<answer>[^\s]{1,254})$')
FORWARD = re.compile(r'^forwarded (?P<name>[^\s]{1,254}) to (?P<peer>[^\s]{1,64})$')


def empty():
    return {name: domain[0] for name, domain in DNS_DOMAINS.items()}


def observe_syntax(line):
    require(isinstance(line, str) and len(line.encode('utf8')) <= MAX_ROW, 'dns_line_bound')
    result = empty()
    prefix = PREFIX.fullmatch(line)
    if prefix is None:
        return result, None
    message = prefix['message']
    query, answer, forward = QUERY.fullmatch(message), ANSWER.fullmatch(message), FORWARD.fullmatch(message)
    parsed = query or answer or forward
    if parsed is None:
        return result, None
    name = parsed['name'].rstrip('.').lower()
    if not name or len(name) > 253 or not all(0 < len(part) <= 63 and re.fullmatch(r'[a-z0-9_-]+', part)
                                            for part in name.split('.')):
        return result, None
    result['dns_semantic_available'] = True
    result['dns_reverse_name'] = name.endswith(('.in-addr.arpa', '.ip6.arpa'))
    if answer:
        value = answer['answer']
        result['dns_local_answer'] = answer['action'] == '/etc/hosts'
        if value in {'NXDOMAIN', 'NODATA', 'SERVFAIL'}:
            result['dns_response_kind'] = 'negative'
        elif value == '<CNAME>':
            result['dns_response_kind'] = 'alias'
        else:
            try:
                ipaddress.ip_address(value)
                result['dns_response_kind'] = 'address'
            except ValueError:
                result['dns_response_kind'] = 'other'
    if query is None:
        return result, None
    result['dns_record_type'] = query['type'] if query['type'] in DNS_DOMAINS['dns_record_type'][1:-1] else 'other'
    try:
        peer = str(ipaddress.ip_address(query['peer']))
    except ValueError:
        return result, None
    result['dns_query_peer_available'] = True
    # These digests are transient link keys only, never learned values/identity.
    keys = tuple(hashlib.sha256(value.encode()).digest() for value in
                 ((prefix['host'] or '<physical-source>')+':'+prefix['pid'], peer, name))
    return result, keys


class DNSWindow:
    """One physical source, original stream order. Ties cannot see each other.

    The 1/10/60s counts exclude the current query and every equal-time query.
    Resolver process changes and time regression clear history. Replies lacking
    explicit clients never borrow a client from a name-only association.
    """

    def __init__(self):
        self.groups, self.pending = {}, []
        self.moment, self.scope = None, None

    def observe(self, line, moment):
        features, keys = observe_syntax(line)
        require(moment is None or type(moment) in {int, float} and math.isfinite(moment), 'dns_time')
        if moment is None:
            return features
        if self.moment is not None and moment < self.moment:
            self.groups, self.pending, self.scope = {}, [], None
        if keys is not None and self.scope is not None and keys[0] != self.scope:
            self.groups, self.pending = {}, []
        if keys is not None:
            self.scope = keys[0]
        if self.moment is None or moment > self.moment:
            for previous, peer, name, kind, reverse in self.pending:
                require(peer in self.groups or len(self.groups) < 10000, 'dns_peer_bound')
                queue = self.groups.setdefault(peer, deque())
                require(len(queue) < 100000, 'dns_peer_event_bound')
                queue.append((previous, name, kind, reverse))
            self.pending = []
        self.moment = moment
        for peer in list(self.groups):
            queue = self.groups[peer]
            while queue and queue[0][0] < moment-60:
                queue.popleft()
            if not queue:
                del self.groups[peer]
        if keys is None:
            return features
        _, peer, name = keys
        queue = self.groups.get(peer, ())
        features.update(dns_query_window_available=True,
            dns_peer_queries_1s=bucket(sum(row[0] >= moment-1 for row in queue), (2, 5, 10, 25, 50, 100)),
            dns_peer_queries_10s=bucket(sum(row[0] >= moment-10 for row in queue), (5, 10, 25, 50, 100, 250)),
            dns_peer_queries_60s=bucket(len(queue), (10, 25, 50, 100, 250, 500)),
            dns_peer_names_60s=bucket(len({row[1] for row in queue}), (5, 10, 25, 50, 100, 250)),
            dns_peer_types_60s=bucket(len({row[2] for row in queue}), (1, 2, 3, 4, 5, 6)),
            dns_peer_reverse_queries_60s=bucket(sum(row[3] for row in queue), (2, 5, 10, 25, 50, 100)))
        require(len(self.pending) < 100000, 'dns_tie_batch_bound')
        self.pending.append((moment, peer, name, features['dns_record_type'], features['dns_reverse_name']))
        return features
