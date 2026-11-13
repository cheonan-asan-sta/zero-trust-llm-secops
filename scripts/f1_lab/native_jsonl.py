"""Pinned, bounded historical JSONL observations. No labels or live trust claims.

Callbacks receive every physical row, including parse failures. A callback's
output is provisional until scan() returns successfully after its EOF hash check.
Downloaded content is parsed as data, never imported or executed.
"""

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

MAX_FILE = 1024**3
MAX_ROW = 2*1024**2
MAX_ROWS = 2_000_000


def require(condition, code):
    if not condition:
        raise ValueError('native_source_'+code)


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, 'duplicate_key')
        result[key] = value
    return result


def decode(body):
    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), 'nonfinite_json')
        return number
    return json.loads(body.decode('utf-8'), object_pairs_hook=pairs, parse_float=finite_float,
                      parse_constant=lambda _value: require(False, 'nonfinite_json'))


@dataclass(frozen=True)
class Row:
    ordinal: int
    sha256: str
    value: dict | None
    error: str | None


def scan(path, expected_sha256, callback, *, max_row_bytes=MAX_ROW, max_rows=MAX_ROWS):
    """Scan one regular immutable JSONL file; one row/error per physical line."""
    path = Path(path)
    require(isinstance(expected_sha256, str) and re.fullmatch(r'[a-f0-9]{64}', expected_sha256), 'external_anchor')
    require(type(max_row_bytes) is int and 1 <= max_row_bytes <= MAX_ROW
            and type(max_rows) is int and 1 <= max_rows <= MAX_ROWS, 'read_bounds')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE, 'regular_file')
    with path.open('rb') as stream:
        initial, total = hashlib.sha256(), 0
        while chunk := stream.read(1024**2):
            total += len(chunk)
            require(total <= MAX_FILE, 'file_bound')
            initial.update(chunk)
        require(initial.hexdigest() == expected_sha256, 'file_hash')
        stream.seek(0)
        final, rows, errors, observed = hashlib.sha256(), 0, 0, 0
        while body := stream.readline(max_row_bytes+1):
            rows += 1
            require(rows <= max_rows, 'row_count_bound')
            row_sha = hashlib.sha256()
            oversized = len(body) > max_row_bytes
            for_chunk = body
            while True:
                row_sha.update(for_chunk)
                final.update(for_chunk)
                observed += len(for_chunk)
                require(observed <= MAX_FILE, 'file_bound')
                if not oversized or for_chunk.endswith(b'\n'):
                    break
                for_chunk = stream.readline(max_row_bytes+1)
                if not for_chunk:
                    break
            value, error = None, 'row_bound' if oversized else None
            if not oversized:
                try:
                    value = decode(body)
                    if not isinstance(value, dict):
                        value, error = None, 'object_required'
                except (ValueError, UnicodeError, RecursionError):
                    error = 'invalid_json'
            errors += error is not None
            callback(Row(rows, row_sha.hexdigest(), value, error))
        require(final.hexdigest() == expected_sha256 and observed == total, 'source_changed')
    return {'schema': 'f1-native-jsonl-scan-1', 'source_sha256': expected_sha256, 'bytes': total,
            'physical_rows': rows, 'parsed_rows': rows-errors, 'parse_errors': errors,
            'source_verified_before_and_after': True, 'goal_qualified': False}


def text(value, *, maximum=8192):
    require(isinstance(value, str) and 0 < len(value) <= maximum and '\x00' not in value, 'text_field')
    return value


def timestamp(value):
    require(type(value) in {int, float} and math.isfinite(value) and 0 <= value < 4102444800, 'event_time')
    return float(value)


@dataclass(frozen=True)
class RawReference:
    text: str
    source_location: str

    @property
    def content_sha256(self):
        # Only line terminators are normalized; spaces remain significant.
        return hashlib.sha256(self.text.rstrip('\r\n').encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class Alert:
    sensor: str
    event_time: float
    detection_time: float | None
    entity_reference: str
    finding: str
    severity: int | None
    raw_references: tuple[RawReference, ...]

    def model_features(self):
        """Fixed semantic vocabulary; never retain arbitrary identifiers as tokens.

        This is an untrained feature candidate, not a validated classifier. The
        original description remains an observation for evidence inspection.
        """
        families = {
            'authentication_failure': r'authentication fail|failed password|invalid user|login fail|brute.?force',
            'authentication_success': r'authentication success|accepted password|accepted publickey|login success',
            'privilege': r'privilege|sudo|superuser|rootcheck',
            'malware': r'malware|trojan|virus|web.?shell|ransomware',
            'reconnaissance': r'port.?scan|network.?scan|service.?scan|reconnaissance',
            'web_attack': r'sql injection|cross.?site scripting|web attack|directory traversal',
            'execution': r'remote command|code execution|reverse shell|command injection',
            'exfiltration': r'exfiltration|data leak|dns tunnel',
            'integrity': r'file integrity|checksum change|file modified|new file',
            'software_update': r'software update|database update|package upgrade',
            'service_health': r'service stop|service start|daemon stop|daemon start',
            'anomaly': r'anomal|unusual|new event|new path|new value|new combination',
        }
        return {'sensor': self.sensor, 'severity': self.severity,
                'finding_families': {name: bool(re.search(pattern, self.finding, re.IGNORECASE))
                                     for name, pattern in families.items()}}

    @property
    def trust_claims(self):
        return dict.fromkeys(('identity_active', 'mfa_verified', 'device_managed',
                              'device_healthy', 'resource_role', 'business_approval'))


def alert(value, sensor):
    """Adapt sensor observations, never publisher truth or synthetic defaults."""
    require(isinstance(value, dict) and sensor in {'wazuh', 'aminer'}, 'sensor_schema')
    # These are gold-label fields, not sensor fields. Do not silently consume a
    # pre-labeled export as inference input even when its values are null.
    require(not {'labels', 'label', 'ground_truth', 'event_label', 'time_label'} & value.keys(), 'truth_in_input')
    try:
        if sensor == 'wazuh':
            level = value['rule']['level']
            require(type(level) is int and 0 <= level <= 16, 'severity')
            instant = datetime.fromisoformat(text(value['@timestamp'], maximum=64))
            require(instant.tzinfo is not None, 'timezone_required')
            reference = ()
            if 'full_log' in value:
                reference = (RawReference(text(value['full_log'], maximum=MAX_ROW),
                                          text(value['location'], maximum=4096)),)
            return Alert('wazuh', timestamp(instant.timestamp()), None,
                         text(value['agent']['ip'], maximum=128), text(value['rule']['description']), level, reference)
        logs = value['LogData']
        raw, locations, times = logs['RawLogData'], logs['LogResources'], logs['Timestamps']
        detections = logs['DetectionTimestamp']
        require(isinstance(raw, list) and 1 <= len(raw) <= 1024 and isinstance(locations, list)
                and len(locations) in {1, len(raw)} and isinstance(times, list) and 1 <= len(times) <= 1024
                and isinstance(detections, list) and 1 <= len(detections) <= 1024, 'aminer_arrays')
        for moment in times+detections:
            timestamp(moment)
        refs = tuple(RawReference(text(line, maximum=MAX_ROW),
                                  text(locations[0 if len(locations) == 1 else i], maximum=4096))
                     for i, line in enumerate(raw))
        return Alert('aminer', max(times), max(detections), text(value['AMiner']['ID'], maximum=128),
                     text(value['AnalysisComponent']['AnalysisComponentName']), None, refs)
    except (KeyError, TypeError, OverflowError) as error:
        raise ValueError('native_source_missing_sensor_field') from error
