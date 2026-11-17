"""Source-bound, completed audit-event no-op observations; advisory only."""

import hashlib
import math
import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath

from scripts.f1_lab.audit_auth_review import original_audit_record
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision

EVENT = re.compile(
    r"type=(?P<kind>[A-Z_]{1,32}) msg=audit\((?P<time>\d{1,12}(?:\.\d{1,9})?):"
    r"(?P<serial>\d{1,20})\): (?P<body>[^\r\n\x00]{1,8192})"
)
PARSERS = frozenset({'/sbin/apparmor_parser', '/usr/sbin/apparmor_parser'})
FLAGS = frozenset({'-r', '--replace', '-T', '--skip-read-cache', '-W', '--write-cache'})
CAP = 0.05
MAX_SOURCE_ROWS = 100000
MAX_EVENTS = 50000
MAX_SOURCE_BYTES = 64 * 1024**2


def fields(body):
    try:
        parts = shlex.split(body, comments=False, posix=True)
        pairs = [part.split('=', 1) for part in parts]
        if (not 0 < len(pairs) <= 128 or any(len(p) != 2 for p in pairs)
                or len({p[0] for p in pairs}) != len(pairs)
                or any(not re.fullmatch(r'[a-z][a-z0-9_]{0,31}', p[0]) for p in pairs)):
            return None
        return dict(pairs)
    except ValueError:
        return None


def parsed(line):
    if not isinstance(line, str) or len(line.encode('utf8')) > MAX_ROW:
        return None
    line = original_audit_record(line).removesuffix('\n').removesuffix('\r')
    if re.search(r'[\x00-\x1f\x7f]', line):
        return None
    match = EVENT.fullmatch(line)
    if match is None or int(match['serial']) == 0:
        return None
    values = fields(match['body'])
    if values is None:
        return None
    return (match['time'], match['serial']), match['kind'], values


def positive(value):
    return bool(value and re.fullmatch(r'[1-9]\d{0,9}', value) and int(value) < 4294967295)


def argv_ok(value, executable):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){1,4096}', value):
        return False
    try:
        args = bytes.fromhex(value).decode('utf8').split('\x00')
    except UnicodeError:
        return False
    if args[-1:] == ['']:
        args.pop()
    if not 3 <= len(args) <= 8 or args[0] not in {executable, 'apparmor_parser'}:
        return False
    options = [a for a in args[1:] if a.startswith('-')]
    paths = [a for a in args[1:] if not a.startswith('-')]
    if (not set(options) <= FLAGS or len(options) != len(set(options))
            or sum(a in {'-r', '--replace'} for a in options) != 1 or len(paths) != 1):
        return False
    path = paths[0]
    return bool(re.fullmatch(r'/etc/apparmor\.d/[A-Za-z0-9_./-]{1,255}', path)
                and '..' not in PurePosixPath(path).parts
                and '.' not in path.split('/') and '//' not in path
                and not path.endswith('/') and path != '/etc/apparmor.d/')


def no_op(group):
    """A STATUS line alone, replacement, or a parser name is never enough."""
    if len(group) != 3 or {kind for _, kind, _ in group} != {'SYSCALL', 'AVC', 'PROCTITLE'}:
        return False
    data = {kind: values for _, kind, values in group}
    system, avc, proc = data['SYSCALL'], data['AVC'], data['PROCTITLE']
    if (avc.get('apparmor') != 'STATUS' or avc.get('operation') != 'profile_replace'
            or avc.get('info') != 'same as current profile, skipping'
            or avc.get('comm') != 'apparmor_parser'
            or any(k in avc for k in ('error', 'denied_mask', 'requested_mask'))
            or not positive(avc.get('pid')) or system.get('pid') != avc['pid']):
        return False
    if (system.get('arch') != 'c000003e' or system.get('syscall') != '1'
            or system.get('success') != 'yes' or not positive(system.get('exit'))
            or system.get('comm') != 'apparmor_parser' or system.get('exe') not in PARSERS
            or any(k in system for k in ('error', 'denied_mask'))
            or set(proc) != {'proctitle'}):
        return False
    return argv_ok(proc['proctitle'], system['exe'])


@dataclass(frozen=True)
class NoopContext:
    source_sha256: str
    ordinal: int
    line_sha256: str
    event_sha256: str
    completed_at_ordinal: int
    kind: str


def contexts(lines, expected_source_sha256):
    """One immutable physical source only. No labels, filenames or host IDs.

    Offline event completion may use other records of the exact same audit
    event. It is not a strictly past row-level real-time predictor. Any repeated
    event type or event identity, unknown/invalid record, oversized event or
    regressed event timestamp makes that event ineligible.
    """
    require(isinstance(expected_source_sha256, str)
            and re.fullmatch('[0-9a-f]{64}', expected_source_sha256), 'apparmor_source_sha')
    digest, groups, blocked, row_pins = hashlib.sha256(), {}, set(), {}
    high_water, size = None, 0
    for ordinal, raw in enumerate(lines, 1):
        require(ordinal <= MAX_SOURCE_ROWS and isinstance(raw, bytes)
                and len(raw) <= MAX_ROW, 'apparmor_source_bound')
        size += len(raw)
        require(size <= MAX_SOURCE_BYTES, 'apparmor_source_bytes')
        digest.update(raw)
        prefix = re.match(rb'type=[^ ]+ msg=audit\((\d{1,12}(?:\.\d{1,9})?):(\d{1,20})\):', raw)
        try:
            line = raw.decode('utf8')
        except UnicodeError:
            if prefix:
                blocked.add((prefix[1].decode('ascii'), prefix[2].decode('ascii')))
            continue
        observation = parsed(line)
        if observation is None:
            # Do not accept a valid subset of an otherwise malformed event.
            if prefix:
                blocked.add((prefix[1].decode('ascii'), prefix[2].decode('ascii')))
            continue
        key, kind, values = observation
        stamp = float(key[0])
        if high_water is not None and stamp < high_water:
            blocked.add(key)
        high_water = max(stamp, high_water) if high_water is not None else stamp
        if key not in groups:
            require(len(groups) < MAX_EVENTS, 'apparmor_event_bound')
            groups[key] = []
        group = groups[key]
        if len(group) == 3 or any(k == kind for _, k, _ in group):
            blocked.add(key)
            continue
        group.append((ordinal, kind, values))
        row_pins[ordinal] = hashlib.sha256(raw).hexdigest()
    require(digest.hexdigest() == expected_source_sha256, 'apparmor_source_changed')
    result = {}
    for key, group in groups.items():
        if key in blocked or not no_op(group):
            continue
        event_sha = hashlib.sha256(canonical([expected_source_sha256, key,
                                               [[n, k, row_pins[n]] for n, k, _ in group]])).hexdigest()
        for ordinal, kind, _ in group:
            # The successful write row was not the false-positive shape and is
            # not suppressed; only the status/argument description is refined.
            if kind in {'AVC', 'PROCTITLE'}:
                result[ordinal] = NoopContext(expected_source_sha256, ordinal, row_pins[ordinal],
                                              event_sha, max(n for n, _, _ in group), kind)
    return result


def refine(previous, context, *, source_sha256, ordinal, raw):
    require(isinstance(previous, OperationDecision)
            and previous.automatic_enforcement_allowed is False
            and type(previous.alert) is bool and type(previous.review) is bool
            and all(type(v) in {int, float} and math.isfinite(v) and 0 <= v <= 1
                    for v in (previous.baseline_score, previous.score)), 'apparmor_previous')
    if context is None:
        return previous
    require(isinstance(context, NoopContext) and isinstance(raw, bytes)
            and len(raw) <= MAX_ROW and type(ordinal) is int and ordinal > 0
            and isinstance(source_sha256, str) and re.fullmatch('[0-9a-f]{64}', source_sha256)
            and context.source_sha256 == source_sha256
            and type(context.ordinal) is int and context.ordinal == ordinal
            and context.line_sha256 == hashlib.sha256(raw).hexdigest()
            and type(context.completed_at_ordinal) is int and context.completed_at_ordinal >= ordinal
            and context.kind in {'AVC', 'PROCTITLE'}
            and re.fullmatch('[0-9a-f]{64}', context.event_sha256), 'apparmor_context_binding')
    # Causal threat decisions or authenticated execution evidence always win.
    if previous.reason not in {'missing_context', 'unchanged'}:
        return previous
    return OperationDecision(previous.baseline_score, min(previous.score, CAP), False, True,
                             'apparmor_unchanged_profile_event_review')
