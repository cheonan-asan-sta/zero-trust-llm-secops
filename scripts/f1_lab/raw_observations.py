"""Historical raw-log observations, without labels, identity defaults or access effects."""

import math
import re
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import unquote

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require

MONTHS = {name: i+1 for i, name in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                           'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'))}
AUDIT = re.compile(r'\bmsg=audit\((\d+(?:\.\d+)?):\d+\)')
SYSLOG = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ')
ACCESS_TIME = re.compile(r'\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})\]')
ERROR_TIME = re.compile(r'^\[[A-Z][a-z]{2} ([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))? (\d{4})\]')
REQUEST = re.compile(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) (.{1,16384}?) HTTP/[0-9.]+" (\d{3})\b')
DNS = re.compile(r'\b(query\[[A-Z0-9]+\]|forwarded|reply|cached)\s+(\S+)')


def raw_time(line, start, end, *, source_timezone):
    """UTC is accepted only as explicit configuration from publisher host metadata.

    No timestamp is guessed from a scenario name or an attack schedule. Bounds
    resolve yearless syslog timestamps; they never become classifier features.
    """
    require(source_timezone == 'UTC' and type(start) is int and type(end) is int
            and 0 <= start < end < 4102444800, 'raw_time_contract')
    require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'raw_line_bound')
    try:
        if match := AUDIT.search(line):
            value = float(match[1])
            require(math.isfinite(value) and 0 <= value < 4102444800, 'audit_time')
            return value
        if line.startswith('{'):
            record = decode(line.encode('utf-8'))
            value = record.get('@timestamp')
            require(isinstance(value, str), 'json_event_time')
            moment = datetime.fromisoformat(value)
            require(moment.tzinfo is not None, 'json_event_timezone')
            return moment.timestamp()
        if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line):
            return datetime.fromisoformat(line[:19]).replace(tzinfo=UTC).timestamp()
        if match := ACCESS_TIME.search(line):
            day, month, year, hour, minute, second, sign, oh, om = match.groups()
            require(int(oh) <= 23 and int(om) <= 59, 'http_time_offset')
            offset = timedelta(hours=int(oh), minutes=int(om))*(1 if sign == '+' else -1)
            return datetime(int(year), MONTHS[month], int(day), int(hour), int(minute), int(second),
                            tzinfo=timezone(offset)).timestamp()
        if match := ERROR_TIME.match(line):
            month, day, hour, minute, second, microsecond, year = match.groups()
            return datetime(int(year), MONTHS[month], int(day), int(hour), int(minute), int(second),
                            int((microsecond or '').ljust(6, '0')), tzinfo=UTC).timestamp()
        if match := SYSLOG.match(line):
            month, day, hour, minute, second = match.groups()
            years = {datetime.fromtimestamp(start, UTC).year, datetime.fromtimestamp(end, UTC).year}
            values = [datetime(year, MONTHS[month], int(day), int(hour), int(minute), int(second), tzinfo=UTC).timestamp()
                      for year in sorted(years)]
            inside = [value for value in values if start <= value <= end]
            require(len(inside) == 1 or len(values) == 1, 'ambiguous_syslog_year')
            return inside[0] if inside else values[0]
    except (KeyError, TypeError, OverflowError) as error:
        raise ValueError('native_source_raw_time_parse') from error
    raise ValueError('native_source_raw_time_format')


def bucket(value, boundaries):
    return sum(value >= bound for bound in boundaries)


def entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count/len(value))*math.log2(count/len(value)) for count in counts.values())


def raw_features(line):
    """Fixed generic semantic/shape features; arbitrary tokens and IDs are not emitted.

    A suspicious feature is an observation, not an authorization decision or a
    gold label. High DNS entropy and scanner strings can also be legitimate.
    """
    require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'raw_line_bound')
    decoded = unquote(line)
    lower = decoded.lower()
    patterns = {
        'auth_failure': r'authentication fail|failed password|invalid user|login fail|res=failed|auth_failed',
        'auth_success': r'accepted password|accepted publickey|authentication success|res=success',
        'session_open': r'session opened|session_open|type=user_start',
        'session_close': r'session closed|session_close|type=user_end',
        'privilege_tool': r'\bsudo\b|exe="/(?:usr/)?bin/su"|/bin/su\b',
        'sensitive_file': r'/etc/(?:shadow|passwd)\b|/\.ssh/authorized_keys',
        'sql_injection': r'\bunion\s+(?:all\s+)?select\b|\bor\s+[\x27\"]?1[\x27\"]?\s*=\s*[\x27\"]?1\b',
        'path_traversal': r'\.\./|\.\.\\',
        'shell_payload': r'/dev/tcp/|\b(?:nc|netcat)\s+[^\n]*\s-e\s|\b(?:system|passthru|shell_exec)\s*\(',
        'command_parameter': r'[?&](?:cmd|exec|command|shell)=',
        'uploaded_script': r'/uploads/[^ ?\"]*\.(?:php|phtml|jsp|asp)(?:[? \"/]|$)',
        'scanner_agent': r'\b(?:nmap|wpscan|sqlmap|nikto|gobuster|dirbuster)\b',
        'http_forbidden': r'client denied|access forbidden|permission denied',
        'cron': r'\bcron\b',
        'service_stop': r'type=service_stop|service stopped',
        'service_start': r'type=service_start|service started',
        'tls_failure': r'tls error|tls handshake failed|authentication/decryption failed',
    }
    features = {name: bool(re.search(pattern, lower)) for name, pattern in patterns.items()}
    features['line_size_bucket'] = bucket(len(line), (80, 160, 320, 640, 1280, 2560))
    request = REQUEST.search(line)
    features['http_method'] = request[1] if request else 'none'
    features['http_status_class'] = int(request[3])//100 if request else 0
    features['http_target_size'] = bucket(len(request[2]), (32, 64, 128, 256, 512, 1024)) if request else 0
    dns = DNS.search(line)
    features['dns_action'] = dns[1].split('[')[0] if dns else 'none'
    query = dns[2] if dns else ''
    parts = query.rstrip('.').split('.') if query else []
    longest = max(parts, key=len) if parts else ''
    features['dns_name_size'] = bucket(len(query), (32, 64, 96, 128, 192, 256))
    features['dns_longest_label_size'] = bucket(len(longest), (12, 24, 40, 52, 63))
    features['dns_label_count'] = bucket(len(parts), (2, 3, 4, 6, 10))
    features['dns_label_entropy'] = bucket(entropy(longest), (2, 3, 3.5, 4, 4.5, 5))
    features['dns_non_hostname_chars'] = bool(query and re.search(r'[^a-zA-Z0-9._-]', query))
    features['dns_negative_reply'] = bool(dns and re.search(r'\b(?:NXDOMAIN|NODATA|SERVFAIL)\b', line))
    # Fixed audit event vocabulary, not arbitrary strings from a source.
    audit_type = re.match(r'^type=([A-Z_]+) ', line)
    known = {'USER_AUTH', 'USER_ACCT', 'USER_START', 'USER_END', 'CRED_ACQ', 'CRED_DISP',
             'CRED_REFR', 'SERVICE_START', 'SERVICE_STOP', 'USER_CMD', 'SYSCALL', 'EXECVE'}
    features['audit_event_type'] = audit_type[1] if audit_type and audit_type[1] in known else 'other'
    return features
