"""Reported runtime shape for the one-worker native decoder/capture contract.

This verifies a pinned reported log, not a running binary or a remote attestation.
Final counters must still be checked against the complete PCAP and EVE input.
"""

import re
from datetime import UTC, datetime

from scripts.f1_lab.native_jsonl import require

PREFIX = re.compile(r'(?P<day>\d{1,2})/(?P<month>\d{1,2})/(?P<year>\d{4}) -- '
                    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) - <[A-Za-z]+> - (?P<message>.*)')
VERSION = 'This is Suricata version 6.0.4 RELEASE running in SYSTEM mode'
THREADS = 'all 1 packet processing threads, 4 management threads initialized, engine started.'
FOOTER = re.compile(r'\(W#01-(?P<interface>[A-Za-z0-9_.:-]{1,32})\) Kernel: Packets (?P<count>\d{1,8}), dropped 0')


def timestamp_us(value):
    require(type(value) is str and len(value) <= 64, 'native_stats_timestamp_type')
    moment = datetime.fromisoformat(value)
    require(moment.tzinfo is not None, 'native_stats_timestamp_timezone')
    delta = moment.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    result = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    require(0 <= result < 4102444800_000000, 'native_stats_timestamp_bound')
    return result


def runtime_profile(body):
    require(type(body) is bytes and 0 < len(body) <= 4 * 1024**2, 'suricata_runtime_log_bound')
    lines = body.decode('utf8').splitlines()
    parsed = []
    for ordinal, line in enumerate(lines, 1):
        require(len(line.encode()) <= 65536, 'suricata_runtime_log_line_bound')
        match = PREFIX.fullmatch(line)
        if match is None:
            continue
        values = match.groupdict()
        stamp = datetime(*(int(values[k]) for k in ('year', 'month', 'day', 'hour', 'minute', 'second')), tzinfo=UTC)
        parsed.append((ordinal, int(stamp.timestamp()) * 1000000, values['message']))
    starts = [n for n, value in enumerate(parsed) if value[2].startswith('This is Suricata version ')]
    require(starts and parsed[starts[-1]][2] == VERSION, 'suricata_reported_version')
    block = parsed[starts[-1]:]
    messages = [value[2] for value in block]
    require(sum(message == THREADS for message in messages) == 1
            and not any(re.match(r'\[ERRCODE: (?:SC_ERR_FATAL|SC_ERR_AFP_CREATE)\(', message) for message in messages),
            'suricata_single_successful_worker')
    ends = [(value, FOOTER.fullmatch(value[2])) for value in block if FOOTER.fullmatch(value[2])]
    require(len(ends) == 1, 'suricata_single_capture_footer')
    (end_row, footer) = ends[0]
    interface = footer['interface']
    require(messages.count(f'Using 1 AF_PACKET threads for interface {interface}') == 1
            and f'Adding interface {interface} from config file' in messages
            and 'Selected pcap-log compression method: none' in messages,
            'suricata_single_capture_interface')
    # More workers/interfaces cannot be hidden by also reporting the expected one.
    require(sum('AF_PACKET threads for interface ' in message for message in messages) == 1
            and sum('packet processing threads,' in message for message in messages) == 1,
            'suricata_conflicting_capture_workers')
    return {'profile': 'suricata-6.0.4-single-af-packet-worker-complete-capture-1',
            'interface': interface, 'reported_packet_count': int(footer['count']),
            'reported_kernel_drops': 0, 'version_log_ordinal': block[0][0],
            'worker_log_ordinal': next(value[0] for value in block if value[2] == THREADS),
            'footer_log_ordinal': end_row[0], 'runtime_started_us': block[0][1],
            'runtime_stopped_second_us': end_row[1], 'runtime_binary_byte_identity_verified': False,
            'actor_or_authority_proven': False, 'application_receipt_time_proven': False}
