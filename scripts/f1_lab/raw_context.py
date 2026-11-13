"""Additional observations and causal HTTP windows, with no publisher labels."""

import hashlib
import ipaddress
import math
import re
from collections import Counter, deque

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.raw_observations import REQUEST, bucket

PROFILE = 'raw-rich-http-window-2'
RICH_DOMAINS = {
    'cpu_available': (False, True), 'cpu_parse_error': (False, True),
    'cpu_total_bucket': tuple(range(7)), 'cpu_user_bucket': tuple(range(7)),
    'cpu_nice_bucket': tuple(range(7)), 'cpu_system_bucket': tuple(range(7)),
    'su_observed': (False, True), 'web_working_directory': (False, True),
    'audit_uid_available': (False, True), 'audit_uid_is_zero': (False, True),
    'audit_interactive': (False, True), 'audit_hex_command': (False, True),
    'decoded_sensitive_file': (False, True), 'decoded_shell_payload': (False, True),
    'vpn_stage': ('none', 'initial', 'verify', 'authenticate', 'established', 'disconnect', 'control', 'other'),
    'http_window_available': (False, True),
    'http_requests_1s': tuple(range(7)), 'http_requests_10s': tuple(range(7)),
    'http_requests_60s': tuple(range(7)), 'http_targets_60s': tuple(range(7)), 'http_errors_10s': tuple(range(7)),
}


def extra_observations(line):
    features = {name: values[0] for name, values in RICH_DOMAINS.items()}
    if line.startswith('{'):
        try:
            record = decode(line.encode('utf-8'))
            cpu = record.get('system', {}).get('cpu')
            if cpu is not None:
                values = {name: cpu[name]['norm']['pct'] for name in ('total', 'user', 'nice', 'system')}
                require(all(type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 1
                            for value in values.values()), 'normalized_cpu_observation')
                features['cpu_available'] = True
                for name, value in values.items():
                    features['cpu_'+name+'_bucket'] = bucket(value, (.05, .15, .3, .5, .75, .9))
        except (ValueError, TypeError, KeyError, AttributeError):
            features['cpu_parse_error'] = True
    features['su_observed'] = bool(re.search(r'\bsu\[\d+\]|pam_unix\(su:|\b[Ss]uccessful su\b', line))
    features['web_working_directory'] = bool(re.search(r'(?:PWD=|cwd=")/var/www/', line))
    features['audit_interactive'] = bool(re.search(r'(?:terminal=|TTY=)/?(?:dev/)?(?:pts/|tty)', line))
    uid = re.search(r'(?:^|\s)uid=(\d+)\b', line)
    if uid:
        features['audit_uid_available'] = True
        features['audit_uid_is_zero'] = int(uid[1]) == 0
    command = re.search(r'\bcmd=([A-Fa-f0-9]{2,2048})(?:\s|$)', line)
    if command and len(command[1]) % 2 == 0:
        # Decode a bounded audit data field; never run it as a command.
        decoded = bytes.fromhex(command[1]).decode('utf-8', errors='replace')
        features['audit_hex_command'] = True
        features['decoded_sensitive_file'] = bool(re.search(r'/etc/(?:shadow|passwd)\b|/\.ssh/authorized_keys', decoded))
        features['decoded_shell_payload'] = bool(re.search(r'/dev/tcp/|\b(?:system|passthru|shell_exec)\s*\(', decoded))
    if re.match(r'^\d{4}-\d{2}-\d{2} ', line):
        stages = [('initial', r'TLS: Initial packet'), ('verify', r'VERIFY |Certificate has EKU|certificate extended key'),
                  ('authenticate', r'AUTH_FAILED|AUTH-PAM|authentication'),
                  ('established', r'Peer Connection Initiated|Initialization Sequence Completed|PUSH_REPLY'),
                  ('disconnect', r'client-instance exiting|SIGTERM|Connection reset'),
                  ('control', r'Control Channel:|TLS: soft reset|TLS: move_session|TLS: tls_multi_process')]
        features['vpn_stage'] = next((name for name, pattern in stages if re.search(pattern, line, re.IGNORECASE)), 'other')
    return features


class HTTPWindow:
    """Bounded event-time replay state. IDs are keys only; no keys are emitted.

    The caller orders historical rows by (event time, original line number).
    Only current and earlier requests contribute. This is not a live collector
    or an authenticated statement about a user's authority.
    """
    def __init__(self):
        self.groups = {}
        self.high_water = None

    def observe(self, line, moment):
        empty = {name: values[0] for name, values in RICH_DOMAINS.items() if name.startswith('http_')}
        request = REQUEST.search(line)
        if request is None or moment is None:
            return empty
        require(type(moment) in {int, float} and math.isfinite(moment), 'http_window_time')
        require(self.high_water is None or moment >= self.high_water, 'http_window_time_regression')
        self.high_water = moment
        try:
            client = str(ipaddress.ip_address(line.split(' ', 1)[0]))
        except ValueError:
            return empty
        # One instance is scoped to one physical source/host by the preparer.
        for key in [key for key, queue in self.groups.items() if queue[-1][0] < moment-60]:
            del self.groups[key]
        require(client in self.groups or len(self.groups) < 10000, 'http_window_group_bound')
        queue = self.groups.setdefault(client, deque())
        while queue and queue[0][0] < moment-60:
            queue.popleft()
        require(len(queue) < 100000, 'http_window_event_bound')
        target = hashlib.sha256(request[2].encode()).digest()
        queue.append((moment, target, int(request[3]) >= 400))
        last10 = [item for item in queue if item[0] >= moment-10]
        n1 = sum(item[0] >= moment-1 for item in last10)
        return {'http_window_available': True,
                'http_requests_1s': bucket(n1, (2, 5, 10, 25, 50, 100)),
                'http_requests_10s': bucket(len(last10), (5, 10, 25, 50, 100, 250)),
                'http_requests_60s': bucket(len(queue), (10, 25, 50, 100, 250, 500)),
                'http_targets_60s': bucket(len(Counter(item[1] for item in queue)), (5, 10, 25, 50, 100, 250)),
                'http_errors_10s': bucket(sum(item[2] for item in last10), (2, 5, 10, 25, 50, 100))}


def ordered_http_context(records):
    """(ordinal, event_time, text) -> features keyed by original ordinal."""
    window = HTTPWindow()
    result = {}
    for ordinal, moment, line in sorted(records, key=lambda row: (float('inf') if row[1] is None else row[1], row[0])):
        require(ordinal not in result, 'duplicate_http_row')
        result[ordinal] = window.observe(line, moment)
    return result
