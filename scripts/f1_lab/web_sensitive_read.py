"""Additive request-intent triage; never asserts successful access or authority."""

import base64
import binascii
import hashlib
import math
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.web_residual import ACCESS, INTRINSIC_NAMES, POLICY

REASONS = frozenset({'encoded_credential_file_read_intent', 'encoded_account_database_read_intent'})
CAT_FLAGS = frozenset({'--show-all', '--number-nonblank', '--show-ends', '--number',
                       '--squeeze-blank', '--show-tabs', '--show-nonprinting'})


def read_intent(line):
    """Parse bounded argv data, without evaluating shell, following URLs or opening files."""
    require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'sensitive_read_line_bound')
    if '\ufffd' in line:
        return None
    matched = ACCESS.fullmatch(line.rstrip('\r\n'))
    if matched is None:
        return None
    target = matched['target']
    try:
        for _ in range(POLICY['max_decode_layers']):
            target = unquote(target, errors='strict')
        url = urlsplit(target)
        if url.scheme or url.netloc or url.fragment or '\\' in url.path or not re.search(
                r'^/[^\s]*/uploads/[^\s]+\.(?:php|phtml|jsp|asp|aspx)$|^/uploads/[^\s]+\.(?:php|phtml|jsp|asp|aspx)$',
                posixpath.normpath(url.path), re.IGNORECASE):
            return None
        fields = url.query.split('&') if url.query else []
        if not 1 <= len(fields) <= POLICY['max_query_values']:
            return None
        intents = set()
        for field in fields:
            key, sep, value = field.partition('=')
            if (not key or not sep or not 4 <= len(value) <= POLICY['max_encoded_value']
                    or len(value) % 4 or re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', value) is None):
                continue
            try:
                argv = decode(base64.b64decode(value, validate=True))
            except (ValueError, UnicodeError, binascii.Error, RecursionError):
                continue
            if (not isinstance(argv, list) or not 2 <= len(argv) <= POLICY['max_argv_items']
                    or not all(isinstance(v, str) and 0 < len(v) <= 1024
                               and not re.search(r'[\x00-\x1f]', v) for v in argv)
                    or argv[0] not in {'cat', '/bin/cat', '/usr/bin/cat'}):
                continue
            paths, options = [], True
            for argument in argv[1:]:
                if options and argument == '--':
                    options = False
                elif options and argument.startswith('-') and argument != '-':
                    if argument not in CAT_FLAGS and not re.fullmatch(r'-[AbenstuvET]+', argument):
                        paths = []
                        break
                else:
                    paths.append(posixpath.normpath(argument))
            for path in paths:
                name = posixpath.basename(path)
                if (path in {'/etc/shadow', '/etc/gshadow'} or name in {'wp-config.php', '.env'}
                        or path.endswith('/.aws/credentials')):
                    intents.add('encoded_credential_file_read_intent')
                elif path in {'/etc/passwd', '/etc/group'}:
                    intents.add('encoded_account_database_read_intent')
        if 'encoded_credential_file_read_intent' in intents:
            return 'encoded_credential_file_read_intent'
        return next(iter(intents)) if intents else None
    except (ValueError, UnicodeError, RecursionError):
        return None


@dataclass(frozen=True)
class SensitiveReadEvidence:
    case_id: str
    source_sha256: str
    ordinal: int
    intrinsic_sha256: str
    reason: str


def evidence(line, source_sha256, ordinal):
    require(isinstance(source_sha256, str) and re.fullmatch('[a-f0-9]{64}', source_sha256)
            and type(ordinal) is int and ordinal > 0, 'sensitive_read_source')
    reason = read_intent(line)
    if reason is None:
        return None
    case = hashlib.sha256((source_sha256 + ':' + str(ordinal)).encode()).hexdigest()
    core = core_features(line)
    return SensitiveReadEvidence(case, source_sha256, ordinal,
        hashlib.sha256(canonical({name: core[name] for name in INTRINSIC_NAMES})).hexdigest(), reason)


def refine(previous, features, case_id, observed=None):
    require(isinstance(previous, OperationDecision) and not previous.automatic_enforcement_allowed,
            'sensitive_read_previous')
    require(all(type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 1
                for value in (previous.baseline_score, previous.score))
            and type(previous.alert) is bool and type(previous.review) is bool, 'sensitive_read_previous_values')
    if observed is None:
        return previous
    require(isinstance(observed, SensitiveReadEvidence) and observed.case_id == case_id
            and observed.reason in REASONS and type(observed.ordinal) is int and observed.ordinal > 0
            and isinstance(observed.source_sha256, str) and re.fullmatch('[a-f0-9]{64}', observed.source_sha256),
            'sensitive_read_evidence')
    require(hashlib.sha256((observed.source_sha256 + ':' + str(observed.ordinal)).encode()).hexdigest() == case_id,
            'sensitive_read_binding')
    require(hashlib.sha256(canonical({name: features[name] for name in INTRINSIC_NAMES})).hexdigest()
            == observed.intrinsic_sha256, 'sensitive_read_features')
    return OperationDecision(previous.baseline_score, max(previous.score, .95), True, True, observed.reason)
