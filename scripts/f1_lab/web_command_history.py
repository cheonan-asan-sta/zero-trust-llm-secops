"""Source-local credential-read history for advisory webshell triage only."""

import hashlib
import ipaddress
import math
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.web_residual import ACCESS, INTRINSIC_NAMES, encoded_argv_request
from scripts.f1_lab.web_sensitive_read import read_intent

WINDOW_SECONDS = 60
MAX_RECORDS = 2000000
MAX_BYTES = 512 * 1024**2
MAX_KEYS = 10000
REASON = 'encoded_command_after_credential_read_intent'


def request_key(line):
    """Spoofable source/path correlation, never authenticated identity."""
    match = ACCESS.fullmatch(line.rstrip('\r\n'))
    if match is None or '\ufffd' in line:
        return None
    try:
        client = str(ipaddress.ip_address(line.split(' ', 1)[0]))
        target = match['target']
        for _ in range(2):
            target = unquote(target, errors='strict')
        url = urlsplit(target)
        if (url.scheme or url.netloc or url.fragment or '\\' in url.path
                or re.search(r'[\x00-\x20\x7f]', url.path)
                or not url.path.startswith('/') or url.path.startswith('//')):
            return None
        # Preserve path case: origin servers may treat it as significant.
        path = posixpath.normpath(url.path)
        return hashlib.sha256(canonical([client, path])).hexdigest()
    except (ValueError, UnicodeError):
        return None


@dataclass(frozen=True)
class CommandHistoryEvidence:
    case_id: str
    source_sha256: str
    ordinal: int
    intrinsic_sha256: str
    seed_case_id: str
    seed_ordinal: int
    seed_time: float
    event_time: float
    request_key_sha256: str


def build_evidence(records, source_sha256):
    """Consume a physical source in ordinal order; no labels or future rows.

    Only a credential-file read intent seeds the 60-second window. Ordinary
    encoded commands cannot seed or extend it. Equal timestamps are not past.
    A backwards timestamp clears history; unknown time cannot produce evidence.
    """
    require(isinstance(source_sha256, str) and re.fullmatch('[a-f0-9]{64}', source_sha256),
            'command_history_source')
    seeds, result = {}, {}
    previous_ordinal, previous_time, size, count = 0, None, 0, 0
    for ordinal, moment, line in records:
        count += 1
        require(count <= MAX_RECORDS and type(ordinal) is int and ordinal > previous_ordinal,
                'command_history_order_or_rows')
        require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'command_history_line')
        size += len(line.encode('utf-8'))
        require(size <= MAX_BYTES and (moment is None or type(moment) in {int, float}
                                      and math.isfinite(moment)), 'command_history_bytes_or_time')
        previous_ordinal = ordinal
        if moment is None:
            continue
        if previous_time is not None and moment < previous_time:
            seeds.clear()
        previous_time = moment
        # The key set is bounded. Pruning occurs only for relevant rows below.
        if not encoded_argv_request(line):
            continue
        key = request_key(line)
        if key is None:
            continue
        case = hashlib.sha256((source_sha256 + ':' + str(ordinal)).encode()).hexdigest()
        seed = seeds.get(key)
        if seed is not None and 0 < moment - seed[0] <= WINDOW_SECONDS:
            features = core_features(line)
            result[case] = CommandHistoryEvidence(case, source_sha256, ordinal,
                hashlib.sha256(canonical({name: features[name] for name in INTRINSIC_NAMES})).hexdigest(),
                seed[2], seed[1], seed[0], moment, key)
        if read_intent(line) == 'encoded_credential_file_read_intent':
            if key not in seeds and len(seeds) >= MAX_KEYS:
                seeds = {k: v for k, v in seeds.items() if moment - v[0] <= WINDOW_SECONDS}
            require(key in seeds or len(seeds) < MAX_KEYS, 'command_history_key_bound')
            seeds[key] = (moment, ordinal, case)
    return result


def refine(previous, features, case_id, observed=None):
    require(isinstance(previous, OperationDecision) and not previous.automatic_enforcement_allowed,
            'command_history_previous')
    require(all(type(v) in {int, float} and math.isfinite(v) and 0 <= v <= 1
                for v in (previous.baseline_score, previous.score))
            and type(previous.alert) is bool and type(previous.review) is bool, 'command_history_previous_values')
    if observed is None:
        return previous
    require(isinstance(observed, CommandHistoryEvidence) and observed.case_id == case_id,
            'command_history_evidence')
    require(all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v) for v in
                (observed.source_sha256, observed.request_key_sha256, observed.intrinsic_sha256))
            and type(observed.ordinal) is int and type(observed.seed_ordinal) is int
            and 0 < observed.seed_ordinal < observed.ordinal, 'command_history_binding')
    for ordinal, expected in ((observed.ordinal, case_id), (observed.seed_ordinal, observed.seed_case_id)):
        require(hashlib.sha256((observed.source_sha256 + ':' + str(ordinal)).encode()).hexdigest() == expected,
                'command_history_case')
    require(all(type(v) in {int, float} and math.isfinite(v) for v in (observed.seed_time, observed.event_time))
            and 0 < observed.event_time - observed.seed_time <= WINDOW_SECONDS, 'command_history_window')
    require(hashlib.sha256(canonical({name: features[name] for name in INTRINSIC_NAMES})).hexdigest()
            == observed.intrinsic_sha256, 'command_history_features')
    return OperationDecision(previous.baseline_score, max(previous.score, .95), True, True, REASON)
