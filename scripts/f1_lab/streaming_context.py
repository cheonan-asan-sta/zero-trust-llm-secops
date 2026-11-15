"""Incremental equivalent of the historical HTTP window; never consumes truth."""

import hashlib
import ipaddress
import math
from collections import Counter, deque

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.raw_context import RICH_DOMAINS
from scripts.f1_lab.raw_observations import REQUEST, bucket


def http_fields(line):
    request = REQUEST.search(line)
    if request is None:
        return None
    try:
        client = str(ipaddress.ip_address(line.split(' ', 1)[0]))
    except ValueError:
        client = None
    return client, hashlib.sha256(request[2].encode()).digest(), int(request[3]) >= 400


class IncrementalHTTPWindow:
    """Three expiring queues, bounded active state, inclusive 1/10/60 second edges.

    An event is enqueued once and referenced by each queue. Each reference is
    removed once, so updating does not rescan all clients or a client's history.
    Input must already be ordered by (event time, physical source ordinal).
    """

    def __init__(self, *, max_active=500_000, max_groups=10_000, max_per_client=100_000):
        require(all(type(v) is int and v > 0 for v in (max_active, max_groups, max_per_client)),
                'stream_http_limits')
        self.max_active, self.max_groups, self.max_per_client = max_active, max_groups, max_per_client
        self.groups = {}
        self.queues = {duration: deque() for duration in (1, 10, 60)}
        self.high_water = None
        self.peak_events = self.peak_groups = self.events = 0

    def observe_fields(self, client, target, error, moment):
        empty = {name: domain[0] for name, domain in RICH_DOMAINS.items() if name.startswith('http_')}
        if moment is None:
            return empty
        require(type(moment) in {int, float} and math.isfinite(moment), 'http_window_time')
        require(self.high_water is None or moment >= self.high_water, 'http_window_time_regression')
        self.high_water = moment
        if client is None:
            return empty
        require(isinstance(client, str) and str(ipaddress.ip_address(client)) == client
                and isinstance(target, bytes) and len(target) == 32 and type(error) is bool,
                'stream_http_fields')
        for duration, queue in self.queues.items():
            while queue and queue[0][0] < moment-duration:
                _, key, old_target, old_error = queue.popleft()
                group = self.groups[key]
                group[duration] -= 1
                if duration == 10:
                    group['errors'] -= old_error
                if duration == 60:
                    group['targets'][old_target] -= 1
                    if not group['targets'][old_target]:
                        del group['targets'][old_target]
                    if not group[60]:
                        del self.groups[key]
        require(client in self.groups or len(self.groups) < self.max_groups, 'http_window_group_bound')
        group = self.groups.setdefault(client, {1: 0, 10: 0, 60: 0, 'errors': 0, 'targets': Counter()})
        require(group[60] < self.max_per_client, 'http_window_event_bound')
        require(len(self.queues[60]) < self.max_active, 'stream_http_active_bound')
        event = moment, client, target, error
        for duration, queue in self.queues.items():
            queue.append(event)
            group[duration] += 1
        group['errors'] += error
        group['targets'][target] += 1
        self.events += 1
        self.peak_events = max(self.peak_events, len(self.queues[60]))
        self.peak_groups = max(self.peak_groups, len(self.groups))
        return {'http_window_available': True,
                'http_requests_1s': bucket(group[1], (2, 5, 10, 25, 50, 100)),
                'http_requests_10s': bucket(group[10], (5, 10, 25, 50, 100, 250)),
                'http_requests_60s': bucket(group[60], (10, 25, 50, 100, 250, 500)),
                'http_targets_60s': bucket(len(group['targets']), (5, 10, 25, 50, 100, 250)),
                'http_errors_10s': bucket(group['errors'], (2, 5, 10, 25, 50, 100))}

    def observe(self, line, moment):
        fields = http_fields(line)
        if fields is None:
            return {name: domain[0] for name, domain in RICH_DOMAINS.items() if name.startswith('http_')}
        return self.observe_fields(*fields, moment)
