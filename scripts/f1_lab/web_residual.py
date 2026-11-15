"""Source-bound, additive web evidence for offline alert review, never access."""

import base64
import binascii
import hashlib
import ipaddress
import math
import re
from collections import Counter, deque
from dataclasses import dataclass
from itertools import groupby
from urllib.parse import unquote, urlsplit

from scripts.f1_lab.line_truth import anchor
from scripts.f1_lab.native_bayes import feature_domains
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import HEADER, canonical, core_features
from scripts.f1_lab.operation_refinement import OperationDecision, OperationRefinement
from scripts.f1_lab.raw_context import PROFILE as CORE_PROFILE
from scripts.f1_lab.raw_context import RICH_DOMAINS

POLICY = {'schema': 'f1-web-residual-policy-1', 'scope': 'observed development advisory only; no access effects',
          'alert_floor': .95, 'error_window_seconds': 60, 'prior_distinct_missing_scripts': 3,
          'max_decode_layers': 2, 'max_query_values': 32, 'max_encoded_value': 4096,
          'max_argv_items': 32, 'score_lowering_allowed': False, 'encoded_argv_action': 'review_only'}
MAX_RECORDS, MAX_BYTES = 500000, 256*1024**2
INTRINSIC_NAMES = tuple(name for name in feature_domains(CORE_PROFILE)
                       if name not in {key for key in RICH_DOMAINS if key.startswith('http_')})
ACCESS = re.compile(r'^\S+ \S+ \S+ \[[^\]\r\n]{1,64}\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT) '
                    r'(?P<target>[^"\r\n]{1,16384}) HTTP/[0-9.]+" [1-5][0-9]{2} (?:\d+|-) '
                    r'"[^"\r\n]{0,16384}" "[^"\r\n]{0,4096}"$')
MISSING = re.compile(r"^script '(?P<path>/[^'\r\n]{1,4096})' not found or unable to stat(?:, referer: [^\r\n]{1,4096})?$")
COMMANDS = frozenset({'cat', 'ls', 'uname', 'id', 'whoami', 'pwd', 'lsb_release', 'netstat', 'ss',
                      'tar', 'wget', 'curl', 'mysql', 'ps', 'find', 'sh', 'bash', 'python', 'python3', 'perl'})


def encoded_argv_request(line):
    """Do not decode arbitrary log bodies or execute the decoded command list."""
    require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'web_residual_access_line')
    if '\ufffd' in line:
        return False
    match = ACCESS.fullmatch(line.rstrip('\r\n'))
    if match is None:
        return False
    target = match['target']
    try:
        for _ in range(POLICY['max_decode_layers']):
            target = unquote(target, errors='strict')
        parsed = urlsplit(target)
        # Origin-form only. A host, query token, agent or referer is not proof.
        if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith('/'):
            return False
        if not re.search(r'/uploads/[^/\s]+(?:/[^/\s]+)*\.(?:php|phtml|jsp|asp|aspx)$', parsed.path, re.IGNORECASE):
            return False
        values = parsed.query.split('&') if parsed.query else []
        if not 1 <= len(values) <= POLICY['max_query_values']:
            return False
        for field in values:
            key, separator, value = field.partition('=')
            if not key or not separator or not 4 <= len(value) <= POLICY['max_encoded_value']:
                continue
            if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', value) is None or len(value) % 4:
                continue
            try:
                raw = base64.b64decode(value, validate=True)
                argv = decode(raw)
            except (ValueError, UnicodeError, binascii.Error, RecursionError):
                continue
            if (not isinstance(argv, list) or not 2 <= len(argv) <= POLICY['max_argv_items']
                    or not all(isinstance(v, str) and 0 < len(v) <= 1024 and not re.search(r'[\x00-\x1f]', v) for v in argv)):
                continue
            executable = argv[0]
            command = executable.rsplit('/', 1)[-1]
            if command in COMMANDS or re.fullmatch(r'\./[A-Za-z0-9_./-]{1,256}\.sh', executable):
                return True
    except (ValueError, UnicodeError, RecursionError):
        return False
    return False


def missing_script(line):
    match = HEADER.fullmatch(line.rstrip('\r\n'))
    if match is None or re.fullmatch(r'php\d*', match['module'], re.IGNORECASE) is None or match['level'].lower() != 'error':
        return None
    item = MISSING.fullmatch(match['message'])
    if item is None or not match['client']:
        return None
    host, _, port = match['client'].rpartition(':')
    try:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            return None
        client = str(ipaddress.ip_address(host))
    except ValueError:
        return None
    return hashlib.sha256(client.encode()).digest(), hashlib.sha256(item['path'].encode()).digest()


@dataclass(frozen=True)
class WebEvidence:
    case_id: str
    source_sha256: str
    ordinal: int
    core_sha256: str
    reason: str


def build_evidence(records, kind, source_sha256):
    """Strictly earlier, same physical source/client history; no label parameter."""
    anchor(source_sha256)
    require(kind in {'access', 'error'} and isinstance(records, list) and len(records) <= MAX_RECORDS,
            'web_residual_source_bound')
    ordinals, size = set(), 0
    for ordinal, moment, line in records:
        require(type(ordinal) is int and ordinal > 0 and ordinal not in ordinals, 'web_residual_ordinal')
        require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'web_residual_line')
        size += len(line.encode('utf-8'))
        require(size <= MAX_BYTES and (moment is None or type(moment) in {int, float} and math.isfinite(moment)),
                'web_residual_bytes_or_time')
        ordinals.add(ordinal)
    reasons = {}
    if kind == 'access':
        reasons = {n: 'uploaded_script_encoded_argv' for n, _, line in records if encoded_argv_request(line)}
    else:
        queue, clients = deque(), {}
        ordered = sorted(records, key=lambda r: (float('inf') if r[1] is None else r[1], r[0]))
        for moment, tied in groupby(ordered, key=lambda r: r[1]):
            batch = [(n, missing_script(line)) for n, _, line in tied]
            if moment is None:
                continue
            while queue and queue[0][0] < moment-POLICY['error_window_seconds']:
                _, client, target = queue.popleft()
                clients[client][target] -= 1
                if not clients[client][target]:
                    del clients[client][target]
                if not clients[client]:
                    del clients[client]
            for ordinal, item in batch:
                if item is not None:
                    previous = clients.get(item[0], {})
                    if len(previous) >= POLICY['prior_distinct_missing_scripts'] and item[1] not in previous:
                        reasons[ordinal] = 'same_client_distinct_missing_script_burst'
            # Equal timestamps cannot use each other as history.
            for _, item in batch:
                if item is not None:
                    client, target = item
                    require(client in clients or len(clients) < 10000, 'web_residual_client_bound')
                    clients.setdefault(client, Counter())[target] += 1
                    queue.append((moment, client, target))
    output = {}
    for ordinal, _, line in records:
        if ordinal not in reasons:
            continue
        case_id = hashlib.sha256((source_sha256+':'+str(ordinal)).encode()).hexdigest()
        intrinsic = core_features(line)
        output[case_id] = WebEvidence(case_id, source_sha256, ordinal,
            hashlib.sha256(canonical({name: intrinsic[name] for name in INTRINSIC_NAMES})).hexdigest(), reasons[ordinal])
    return output


class WebResidualRefinement:
    """Only raises advisory scores. Baseline decisions remain observable."""

    def __init__(self, baseline):
        require(isinstance(baseline, OperationRefinement), 'web_residual_baseline')
        self.baseline = baseline

    def refine(self, previous, features, case_id, evidence=None):
        require(isinstance(previous, OperationDecision) and not previous.automatic_enforcement_allowed,
                'web_residual_previous_decision')
        if evidence is None:
            return previous
        require(isinstance(evidence, WebEvidence) and evidence.case_id == case_id
                and type(evidence.ordinal) is int and evidence.ordinal > 0, 'web_residual_case_binding')
        anchor(evidence.source_sha256)
        require(hashlib.sha256((evidence.source_sha256+':'+str(evidence.ordinal)).encode()).hexdigest() == case_id,
                'web_residual_source_binding')
        require(evidence.reason in {'uploaded_script_encoded_argv', 'same_client_distinct_missing_script_burst'},
                'web_residual_evidence_reason')
        # The frozen preparation adds HTTP history later. This parser does not
        # consume those six window fields; it binds all intrinsic row features.
        core = {name: features[name] for name in INTRINSIC_NAMES}
        require(hashlib.sha256(canonical(core)).hexdigest() == evidence.core_sha256, 'web_residual_feature_binding')
        if evidence.reason == 'uploaded_script_encoded_argv':
            # Structured arguments may be legitimate. Retain the alarm score
            # and send new evidence for review without inventing authorization.
            return OperationDecision(previous.baseline_score, previous.score, previous.alert, True, evidence.reason)
        return OperationDecision(previous.baseline_score, max(previous.score, POLICY['alert_floor']),
                                 True, True, evidence.reason)

    def decide(self, features, case_id, context=None, evidence=None):
        return self.refine(self.baseline.decide(features, case_id, context), features, case_id, evidence)
