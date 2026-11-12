from datetime import UTC, datetime

import pytest

from scripts.f1_lab.raw_observations import raw_features, raw_time

START = int(datetime(2022, 1, 21, tzinfo=UTC).timestamp())
END = int(datetime(2022, 1, 25, tzinfo=UTC).timestamp())


@pytest.mark.parametrize('line', [
    'type=USER_AUTH msg=audit(1642723200.125:1): res=success',
    'Jan 21 00:00:00 host auth: login',
    '2022-01-21 00:00:00 user TLS: handshake',
    'host - - [21/Jan/2022:00:00:00 +0000] "GET / HTTP/1.1" 200 100',
    '[Fri Jan 21 00:00:00.125000 2022] [error] text',
    '{"@timestamp":"2022-01-21T00:00:00.125Z"}',
])
def test_native_formats_keep_real_historical_time(line):
    result = raw_time(line, START, END, source_timezone='UTC')
    assert START <= result < START+1


def test_http_offset_is_used_not_guessed_utc():
    line = 'host - - [21/Jan/2022:01:00:00 +0100] "GET / HTTP/1.1" 200 1'
    assert raw_time(line, START, END, source_timezone='UTC') == START


def test_outside_time_remains_observable_for_audit():
    assert raw_time('Jan 20 23:59:59 host event', START, END, source_timezone='UTC') == START-1


def test_naive_json_time_is_not_guessed():
    with pytest.raises(ValueError, match='timezone'):
        raw_time('{"@timestamp":"2022-01-21T00:00:00"}', START, END, source_timezone='UTC')


def test_source_timezone_must_be_explicit():
    with pytest.raises(ValueError, match='raw_time_contract'):
        raw_time('Jan 21 00:00:00 host event', START, END, source_timezone=None)


def test_year_boundary_resolved_only_within_declared_simulation():
    start = int(datetime(2021, 12, 31, tzinfo=UTC).timestamp())
    end = int(datetime(2022, 1, 2, tzinfo=UTC).timestamp())
    assert raw_time('Jan 1 00:00:00 host event', start, end, source_timezone='UTC') == START-20*86400
    with pytest.raises(ValueError, match='ambiguous_syslog_year'):
        raw_time('Jun 1 00:00:00 host event', start, end, source_timezone='UTC')


def test_features_do_not_memorize_ips_hostnames_dates_or_unknown_tokens():
    a = '203.0.113.1 - alice [21/Jan/2022:00:00:00 +0000] "GET /index HTTP/1.1" 200 100'
    b = '192.0.2.100 - bobby [24/Jan/2022:12:12:12 +0000] "GET /other HTTP/1.1" 200 100'
    assert raw_features(a) == raw_features(b)
    assert not any(isinstance(value, str) and any(token in value for token in ['alice', '203.0.113', '2022'])
                   for value in raw_features(a).values())


def test_dns_shapes_not_domain_lookup():
    a = raw_features('Jan 21 00:00:00 dnsmasq: query[A] www.example.com from 192.0.2.1')
    b = raw_features('Jan 24 00:00:00 dnsmasq: query[A] www.another.org from 203.0.113.1')
    assert a == b and a['dns_action'] == 'query'


def test_decoded_web_signals_are_observations_not_labels():
    result = raw_features('"GET /?cmd=cat%20/etc/shadow&x=../../etc/passwd HTTP/1.1" 403 10')
    assert result['command_parameter'] and result['path_traversal'] and result['sensitive_file']
    assert result['http_status_class'] == 4 and 'malicious' not in result and 'ground_truth' not in result


def test_scanner_hint_can_be_legitimate_and_has_no_automatic_deny():
    features = raw_features('"GET / HTTP/1.1" 200 100 "Nmap"')
    assert features['scanner_agent'] and not {'detected', 'allow', 'deny'} & features.keys()


def test_boolean_and_generic_audit_features():
    result = raw_features('type=USER_AUTH msg=audit(1642723200:1): exe="/bin/su" res=failed')
    assert result['privilege_tool'] and result['auth_failure']
    assert result['audit_event_type'] == 'USER_AUTH'
