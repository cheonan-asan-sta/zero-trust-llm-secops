"""Conservative no-op contexts must never whitelist arbitrary policy activity."""

import hashlib
from dataclasses import replace

import pytest

from scripts.f1_lab import apparmor_noop as mod
from scripts.f1_lab.operation_refinement import OperationDecision


def event(stamp='1700000000.123', serial='71', pid='812'):
    argv = b'/sbin/apparmor_parser\x00-r\x00-T\x00-W\x00/etc/apparmor.d/usr.bin.example'.hex()
    prefix = f'msg=audit({stamp}:{serial}): '
    return [
        (f'type=SYSCALL {prefix}arch=c000003e syscall=1 success=yes exit=372 pid={pid} '
        'uid=0 auid=4294967295 ses=4294967295 comm="apparmor_parser" exe="/sbin/apparmor_parser"\n'),
        (f'type=AVC {prefix}apparmor="STATUS" operation="profile_replace" '
        f'info="same as current profile, skipping" profile="unconfined" name="/usr/bin/example" '
        f'pid={pid} comm="apparmor_parser"\n'),
        f'type=PROCTITLE {prefix}proctitle={argv}\n',
    ]


def prepared(lines=None):
    rows = [v.encode() if isinstance(v, str) else v for v in (lines if lines is not None else event())]
    pin = hashlib.sha256(b''.join(rows)).hexdigest()
    return rows, pin, mod.contexts(iter(rows), pin)


def test_complete_same_event_only_reduces_generic_alert_and_keeps_review():
    rows, pin, observed = prepared()
    assert set(observed) == {2, 3}
    assert observed[2].completed_at_ordinal == 3
    assert observed[2].event_sha256 == observed[3].event_sha256
    old = OperationDecision(.99, .99, True, True, 'unchanged')
    result = mod.refine(old, observed[2], source_sha256=pin, ordinal=2, raw=rows[1])
    assert result.baseline_score == .99 and result.score == .05
    assert not result.alert and result.review and not result.automatic_enforcement_allowed
    assert result.reason == 'apparmor_unchanged_profile_event_review'


@pytest.mark.parametrize('kind', [0, 1, 2])
def test_missing_any_required_event_part_leaves_candidate_unavailable(kind):
    rows = event()
    rows.pop(kind)
    assert prepared(rows)[2] == {}


@pytest.mark.parametrize(('index', 'old', 'new'), [
    (1, 'apparmor="STATUS"', 'apparmor="DENIED"'),
    (1, 'apparmor="STATUS"', 'apparmor="ALLOWED"'),
    (1, 'profile_replace', 'profile_remove'),
    (1, 'profile_replace', 'profile_load'),
    (1, 'info="same as current profile, skipping" ', ''),
    (1, 'same as current profile, skipping', 'profile changed'),
    (1, 'pid=812', 'pid=813'),
    (1, 'comm="apparmor_parser"', 'comm="sudo"'),
    (1, 'profile="unconfined"', 'error=-71 profile="unconfined"'),
    (1, 'profile="unconfined"', 'denied_mask="w" profile="unconfined"'),
    (1, 'profile="unconfined"', 'requested_mask="w" profile="unconfined"'),
    (1, 'pid=812', 'pid=812 pid=812'),
    (1, 'info="same as current profile, skipping"', 'info="same as current profile, skipping'),
    (0, 'success=yes', 'success=no'),
    (0, 'exit=372', 'exit=-13'),
    (0, 'exit=372', 'exit=0'),
    (0, 'arch=c000003e', 'arch=40000003'),
    (0, 'syscall=1', 'syscall=59'),
    (0, 'exe="/sbin/apparmor_parser"', 'exe="/tmp/apparmor_parser"'),
    (0, 'comm="apparmor_parser"', 'comm="sh"'),
    (0, 'pid=812', 'pid=0'),
    (0, 'pid=812', 'pid=4294967295'),
    (2, 'proctitle=', 'other='),
    (2, 'proctitle=', 'extra=yes proctitle='),
    (2, 'proctitle=', 'proctitle=Z'),
])
def test_adverse_ambiguous_malformed_or_unbound_record_never_suppresses(index, old, new):
    rows = event()
    assert old in rows[index]
    rows[index] = rows[index].replace(old, new)
    assert prepared(rows)[2] == {}


@pytest.mark.parametrize('args', [
    ['/sbin/apparmor_parser', '-R', '/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser', '--remove', '/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser', '-r', '--Complain', '/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser', '-r', '-r', '/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser', '-r', '--replace', '/etc/apparmor.d/example'],
    ['/tmp/apparmor_parser', '-r', '/etc/apparmor.d/example'],
    ['/bin/sh', '-c', '/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser', '-r', '/tmp/example'],
    ['/sbin/apparmor_parser', '-r', '/etc/apparmor.d/../passwd'],
    ['/sbin/apparmor_parser', '-r', '/etc/apparmor.d/./example'],
    ['/sbin/apparmor_parser', '-r', '/etc/apparmor.d//example'],
    ['/sbin/apparmor_parser', '-r', '/etc/apparmor.d/'],
    ['/sbin/apparmor_parser', '-r', '/etc/apparmor.d/example', '/etc/apparmor.d/other'],
    ['/sbin/apparmor_parser', '/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser', '-r', '/etc/apparmor.d/example;sh'],
])
def test_arguments_require_single_standard_profile_replacement_without_other_actions(args):
    rows = event()
    value = '\0'.join(args).encode().hex()
    rows[2] = rows[2].split('proctitle=')[0] + f'proctitle={value}\n'
    assert prepared(rows)[2] == {}


@pytest.mark.parametrize('part', [0, 1, 2])
def test_duplicate_and_conflicting_event_records_invalidate_whole_event(part):
    rows = event()
    assert prepared(rows + [rows[part]])[2] == {}
    rows[part] = rows[part].replace('pid=812', 'pid=999')
    assert prepared(event() + [rows[part]])[2] == {}


@pytest.mark.parametrize('suffix', [
    'type=UNKNOWN msg=audit(1700000000.123:71): other=value\n',
    'type=AVC msg=audit(1700000000.123:71): broken field\n',
    'type=AVC msg=audit(1700000000.123:71): value="unterminated\n',
    b'type=AVC msg=audit(1700000000.123:71): bad=\xff\n',
    'type=AVC msg=audit(1700000000.123:71): extra=\x00\n',
])
def test_extra_invalid_or_unknown_same_event_record_is_not_skipped(suffix):
    assert prepared(event() + [suffix])[2] == {}


def test_same_pid_nearby_time_different_serial_and_other_sources_cannot_join():
    left, right = event(), event(serial='72')
    assert prepared([left[0], right[1], left[2]])[2] == {}
    assert prepared([left[0], left[2]])[2] == {}
    assert prepared([left[1]])[2] == {}


def test_regressed_source_event_is_unavailable_without_borrowing_later_history():
    assert prepared(event(stamp='1700000001.123') + event())[2].keys() == {2, 3}


@pytest.mark.parametrize('field,value', [
    ('source_sha256', 'f'*64), ('ordinal', 1), ('line_sha256', 'f'*64),
    ('completed_at_ordinal', 1), ('kind', 'SYSCALL'), ('event_sha256', 'bad'),
])
def test_cross_source_ordinal_bytes_and_completion_binding(field, value):
    rows, pin, observed = prepared()
    wrong = replace(observed[2], **{field: value})
    with pytest.raises(ValueError, match='apparmor_context_binding'):
        mod.refine(OperationDecision(.99, .99, True, True, 'unchanged'), wrong,
                   source_sha256=pin, ordinal=2, raw=rows[1])


@pytest.mark.parametrize('reason', [
    'web_service_account_su', 'web_service_su_followed_by_account_transition',
    'signed_execution_policy_violation', 'encoded_credential_file_read_intent', 'unknown',
])
def test_causal_or_unknown_prior_risk_is_preserved(reason):
    rows, pin, observed = prepared()
    old = OperationDecision(.99, .99, True, True, reason)
    assert mod.refine(old, observed[2], source_sha256=pin, ordinal=2, raw=rows[1]) is old


def test_missing_context_keeps_previous_identity_and_mismatched_source_hash_fails():
    old = OperationDecision(.99, .99, True, True, 'unchanged')
    assert mod.refine(old, None, source_sha256='f'*64, ordinal=1, raw=b'') is old
    with pytest.raises(ValueError, match='apparmor_source_changed'):
        mod.contexts([v.encode() for v in event()], 'f'*64)


def test_bounded_sources_fail_instead_of_partially_suppressing(monkeypatch):
    monkeypatch.setattr(mod, 'MAX_SOURCE_ROWS', 2)
    with pytest.raises(ValueError, match='apparmor_source_bound'):
        prepared()


def test_event_bound_fails_instead_of_partially_suppressing(monkeypatch):
    monkeypatch.setattr(mod, 'MAX_EVENTS', 1)
    with pytest.raises(ValueError, match='apparmor_event_bound'):
        prepared(event() + event(stamp='1700000001.123', serial='72'))
