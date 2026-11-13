"""Causality, source isolation and advisory-only command-history controls."""

import base64
import hashlib
import json
from dataclasses import replace

import pytest

from scripts.f1_lab import web_command_history as history
from scripts.f1_lab.operation_context import core_features
from scripts.f1_lab.operation_refinement import OperationDecision

SOURCE = 'a' * 64


def request(argv, client='192.0.2.1', path='/uploads/tool.php'):
    value = base64.b64encode(json.dumps(argv).encode()).decode()
    return (f'{client} - - [08/Feb/2022:07:56:00 +0000] "GET {path}?args={value} HTTP/1.1" '
            '200 100 "-" "test-agent"')


def case(ordinal, source=SOURCE):
    return hashlib.sha256((source + ':' + str(ordinal)).encode()).hexdigest()


def seed(**kwargs):
    return request(['cat', '/etc/shadow'], **kwargs)


def test_later_command_has_bound_advisory_evidence():
    line = request(['tar', '-czf', 'archive.tgz', 'data'])
    evidence = history.build_evidence([(1, 100, seed()), (2, 130, line)], SOURCE)
    observed = evidence[case(2)]
    assert observed.seed_case_id == case(1)
    assert observed.event_time - observed.seed_time == 30
    before = OperationDecision(.1, .1, False, False, 'unchanged')
    after = history.refine(before, core_features(line), case(2), observed)
    assert after.alert and after.review and after.score == .95
    assert after.baseline_score == .1 and not after.automatic_enforcement_allowed
    assert after.reason == history.REASON


@pytest.mark.parametrize('argv', [
    ['cat', '/etc/passwd'], ['cat', '/etc/group'], ['cat', 'readme.txt'],
    ['ls', '-la'], ['curl', 'https://example.invalid/file'],
])
def test_noncredential_command_cannot_seed(argv):
    assert not history.build_evidence([(1, 100, request(argv)),
        (2, 110, request(['wget', 'https://example.invalid/file']))], SOURCE)


@pytest.mark.parametrize('change', [
    {'client': '192.0.2.2'}, {'path': '/uploads/other.php'},
    {'path': '/Uploads/tool.php'}, {'path': '/uploads/Tool.php'},
    {'path': '/uploads/tool.php/extra'}, {'path': '/admin/tool.php'},
])
def test_unrelated_client_or_path_cannot_inherit(change):
    assert not history.build_evidence([(1, 100, seed()),
        (2, 110, request(['wget', 'https://example.invalid/file'], **change))], SOURCE)


@pytest.mark.parametrize('moment', [None, 99, 100, 160.001])
def test_future_equal_unknown_and_expired_time(moment):
    assert not history.build_evidence([(1, 100, seed()), (2, moment, request(['id', '-u']))], SOURCE)


def test_window_inclusive_and_unseeded_commands_do_not_extend_it():
    lines = [(1, 100, seed()), (2, 150, request(['id', '-u'])),
             (3, 160, request(['ls', '-l'])), (4, 161, request(['uname', '-a']))]
    assert set(history.build_evidence(lines, SOURCE)) == {case(2), case(3)}


def test_backward_unrelated_timestamp_clears_history():
    lines = [(1, 100, seed()), (2, 99, 'unparsed'), (3, 110, request(['id', '-u']))]
    assert not history.build_evidence(lines, SOURCE)


def test_equal_time_seed_is_not_past_and_future_seed_cannot_help():
    lines = [(1, 100, request(['id', '-u'])), (2, 100, seed()), (3, 100, request(['id', '-u']))]
    assert not history.build_evidence(lines, SOURCE)


def test_physical_sources_do_not_share_history():
    history.build_evidence([(1, 100, seed())], SOURCE)
    assert not history.build_evidence([(1, 110, request(['id', '-u']))], 'b' * 64)


@pytest.mark.parametrize('path', [
    'https://example.invalid/uploads/tool.php', '//example.invalid/uploads/tool.php',
    '/uploads/tool.php#fragment', '/uploads/%00tool.php', '/uploads/\\tool.php',
])
def test_ambiguous_origin_cannot_create_a_key(path):
    assert history.request_key(request(['id', '-u'], path=path)) is None


def test_ordinal_and_time_contracts():
    for records in ([(2, 100, seed()), (1, 101, seed())],
                    [(1, 100, seed()), (1, 101, seed())], [(True, 100, seed())],
                    [(1, float('nan'), seed())], [(1, True, seed())]):
        with pytest.raises(ValueError):
            history.build_evidence(records, SOURCE)


def test_source_limits_fail_instead_of_silent_truncation(monkeypatch):
    monkeypatch.setattr(history, 'MAX_RECORDS', 1)
    with pytest.raises(ValueError, match='order_or_rows'):
        history.build_evidence([(1, 100, seed()), (2, 101, seed())], SOURCE)
    monkeypatch.setattr(history, 'MAX_BYTES', 1)
    with pytest.raises(ValueError, match='bytes_or_time'):
        history.build_evidence([(1, 100, seed())], SOURCE)


def test_key_bound_and_expiration(monkeypatch):
    monkeypatch.setattr(history, 'MAX_KEYS', 1)
    with pytest.raises(ValueError, match='key_bound'):
        history.build_evidence([(1, 100, seed()), (2, 101, seed(client='192.0.2.2'))], SOURCE)
    assert not history.build_evidence([(1, 100, seed()), (2, 161, seed(client='192.0.2.2'))], SOURCE)


@pytest.mark.parametrize('fields', [
    {'source_sha256': 'b' * 64}, {'ordinal': 3}, {'seed_ordinal': 2},
    {'seed_case_id': 'b' * 64}, {'case_id': 'b' * 64}, {'intrinsic_sha256': 'b' * 64},
    {'event_time': 100}, {'event_time': 161}, {'seed_time': float('nan')},
    {'request_key_sha256': 'invalid'},
])
def test_tampered_evidence_rejected(fields):
    line = request(['id', '-u'])
    item = history.build_evidence([(1, 100, seed()), (2, 110, line)], SOURCE)[case(2)]
    before = OperationDecision(.1, .1, False, False, 'unchanged')
    with pytest.raises(ValueError):
        history.refine(before, core_features(line), case(2), replace(item, **fields))


def test_prior_alarm_is_never_lowered_and_absence_is_identity():
    line = request(['id', '-u'])
    item = history.build_evidence([(1, 100, seed()), (2, 110, line)], SOURCE)[case(2)]
    before = OperationDecision(.99, .99, True, True, 'unchanged')
    assert history.refine(before, core_features(line), case(2)) is before
    after = history.refine(before, core_features(line), case(2), item)
    assert after.score == .99 and after.alert
    with pytest.raises(ValueError):
        history.refine(replace(before, automatic_enforcement_allowed=True), core_features(line), case(2), item)
