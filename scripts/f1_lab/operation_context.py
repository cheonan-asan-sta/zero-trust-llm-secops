"""Source-bound Apache/OpenVPN observations, with no labels or authority claims."""

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter, deque
from dataclasses import dataclass
from itertools import groupby
from urllib.parse import unquote

from scripts.f1_lab.line_truth import anchor
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.vpn_context import ordered_vpn_context

MAX_EVENTS = 100000
MAX_BYTES = 64*1024**2
HEADER = re.compile(r'^\[[^\]\r\n]{1,64}\] \[(?P<module>[A-Za-z0-9_]{1,32}):(?P<level>[A-Za-z]{1,10})\] '
                    r'\[pid \d{1,10}(?::tid \d{1,20})?\](?: \[client (?P<client>[^\]\r\n]{1,128})\])? (?P<message>[^\r\n]*)$')
WARNING = re.compile(r'^PHP Warning:\s+scandir\([^\r\n]{0,16384}\): '
                     r'(?:failed to open dir: |\(errno 2\): )No such file or directory in '
                     r'[^\r\n]{1,16384} on line \d{1,10}\s*$')
EXECUTION = re.compile(r'\b(?:eval|assert|exec|system|passthru|shell_exec|popen|proc_open|include|require)\s*\(', re.IGNORECASE)
PAYLOAD_FLAGS = ('sql_injection', 'path_traversal', 'shell_payload', 'command_parameter',
                 'uploaded_script', 'sensitive_file', 'scanner_agent')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def core_features(line):
    return {**raw_features(line), **extra_observations(line)}


@dataclass(frozen=True)
class ApacheContext:
    parsed: bool = False
    warning_candidate: bool = False
    recent_security_error: bool = False
    payload_signal: bool = False
    client_available: bool = False
    time_available: bool = False


@dataclass(frozen=True)
class BoundContext:
    case_id: str
    kind: str
    raw_sha256: str
    ordinal: int
    core_sha256: str
    apache: ApacheContext | None = None
    vpn_features: dict | None = None
    vpn_feature_sha256: str | None = None


def apache_fields(line):
    require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'apache_line_bound')
    match = HEADER.fullmatch(line.rstrip('\r\n'))
    if match is None:
        return None
    client = None
    if match['client']:
        host, _, port = match['client'].rpartition(':')
        try:
            if port.isdigit() and 1 <= int(port) <= 65535:
                client = hashlib.sha256(str(ipaddress.ip_address(host)).encode()).digest()
        except ValueError:
            pass
    message, decoded = match['message'], match['message']
    for _ in range(2):
        decoded = unquote(decoded)
    # raw_features performs one additional decode, for at most two layers here.
    base = raw_features(unquote(message))
    payload = (any(base[name] for name in PAYLOAD_FLAGS) or bool(EXECUTION.search(decoded))
               or bool(re.search(r';|\|\||&&|\$\(|`|<\?php', decoded)))
    level = match['level'].lower()
    warning = (bool(re.fullmatch(r'php\d*', match['module'].lower())) and level == 'warn'
               and WARNING.fullmatch(message) is not None)
    return client, level, warning, payload


def bound_contexts(records, kind, source_sha256):
    """One physical source; equal timestamps query the same strictly earlier past.

    Peer/client hashes remain internal grouping keys. Keys, account names and
    absolute timestamps never enter model features. Missing time/peer means
    unavailable, not benign. Labels are not accepted by this interface.
    """
    anchor(source_sha256)
    require(kind in {'apache_error', 'vpn'} and isinstance(records, list) and len(records) <= MAX_EVENTS,
            'operation_source_kind_or_rows')
    ordinals, size = set(), 0
    for ordinal, moment, line in records:
        require(type(ordinal) is int and ordinal > 0 and ordinal not in ordinals, 'operation_unique_ordinal')
        require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'operation_line_bound')
        size += len(line.encode('utf-8'))
        require(size <= MAX_BYTES, 'operation_source_bytes')
        require(moment is None or type(moment) in {int, float} and math.isfinite(moment), 'operation_time')
        ordinals.add(ordinal)
    vpn = ordered_vpn_context(records) if kind == 'vpn' else {}
    apache, queue, clients = {}, deque(), Counter()
    if kind == 'apache_error':
        parsed = {n: apache_fields(line) for n, _, line in records}
        ordered = sorted(records, key=lambda r: (float('inf') if r[1] is None else r[1], r[0]))
        for moment, tied in groupby(ordered, key=lambda r: r[1]):
            tied = list(tied)
            if moment is not None:
                while queue and queue[0][0] < moment-60:
                    _, client = queue.popleft()
                    clients[client] -= 1
                    if not clients[client]:
                        del clients[client]
            for ordinal, _, _ in tied:
                item = parsed[ordinal]
                if item is None:
                    apache[ordinal] = ApacheContext(time_available=moment is not None)
                else:
                    client, _, warning, payload = item
                    apache[ordinal] = ApacheContext(True, warning,
                        bool(moment is not None and client is not None and clients[client]),
                        payload, client is not None, moment is not None)
            if moment is not None:
                for ordinal, _, _ in tied:
                    item = parsed[ordinal]
                    if item and item[0] is not None and (item[1] in {'error', 'crit', 'alert', 'emerg'} or item[3]):
                        client = item[0]
                        require(client in clients or len(clients) < 10000, 'apache_client_bound')
                        clients[client] += 1
                        queue.append((moment, client))
    result = {}
    for ordinal, _, line in records:
        core = core_features(line)
        context = {**core, **vpn[ordinal]} if kind == 'vpn' else None
        case_id = hashlib.sha256((source_sha256+':'+str(ordinal)).encode()).hexdigest()
        result[case_id] = BoundContext(case_id, kind, source_sha256, ordinal,
            hashlib.sha256(canonical(core)).hexdigest(), apache.get(ordinal), context,
            hashlib.sha256(canonical(context)).hexdigest() if context is not None else None)
    return result
