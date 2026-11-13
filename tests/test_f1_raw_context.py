import json

import pytest

from scripts.f1_lab.native_bayes import NativeBayes
from scripts.f1_lab.raw_context import PROFILE, HTTPWindow, extra_observations, ordered_http_context
from scripts.f1_lab.raw_observations import raw_features


def request(client='192.0.2.1', path='/index'):
    return f'{client} - - [21/Jan/2022:00:00:00 +0000] "GET {path} HTTP/1.1" 404 10'


def test_cpu_values_are_observations_and_missing_is_distinguished():
    cpu = {'@timestamp': '2022-01-21T00:00:00Z', 'system': {'cpu': {
        name: {'norm': {'pct': value}} for name, value in [('total', 1), ('user', .1), ('nice', .9), ('system', 0)]}}}
    observed = extra_observations(json.dumps(cpu))
    missing = extra_observations('no cpu evidence')
    assert observed['cpu_available'] and observed['cpu_total_bucket'] == 6
    assert not missing['cpu_available'] and not missing['cpu_parse_error']
    assert not {'healthy', 'malicious', 'ground_truth'} & observed.keys()


def test_invalid_cpu_is_not_filled_as_zero_healthy():
    result = extra_observations('{"system":{"cpu":{"total":{"norm":{"pct":99}}}}}')
    assert result['cpu_parse_error'] and not result['cpu_available']


def test_audit_command_decoded_as_data_without_running_it(tmp_path):
    marker = tmp_path/'must-not-exist'
    command = 'cat /etc/shadow; touch '+str(marker)
    result = extra_observations('type=USER_CMD uid=1000 cmd='+command.encode().hex()+' terminal=pts/1')
    assert result['audit_hex_command'] and result['decoded_sensitive_file'] and result['audit_interactive']
    assert result['audit_uid_available'] and not result['audit_uid_is_zero'] and not marker.exists()


def test_privilege_tool_does_not_memorize_account_name():
    a = extra_observations('su[123]: Successful su for alice by service')
    b = extra_observations('su[987]: Successful su for bobby by daemon')
    assert a == b and a['su_observed']


def test_window_prefix_unchanged_when_future_requests_are_added():
    earlier = [(1, 10, request()), (2, 11, request(path='/two'))]
    first = ordered_http_context(earlier)
    extended = ordered_http_context([*earlier, (3, 12, request(path='/future'))])
    assert first[1] == extended[1] and first[2] == extended[2]
    assert first[1]['http_requests_1s'] == 0 and first[2]['http_requests_1s'] == 1


def test_client_ids_are_grouping_only_and_clients_are_isolated():
    window = HTTPWindow()
    first = window.observe(request(), 10)
    other = window.observe(request(client='203.0.113.1'), 10)
    again = window.observe(request(), 10)
    assert first == other and again['http_requests_1s'] > first['http_requests_1s']
    assert not any('192.0.2' in str(v) for v in again.values())


def test_stable_original_ordinal_ties_and_unsorted_source():
    result = ordered_http_context([(3, 12, request()), (2, 10, request()), (1, 10, request())])
    assert result[1]['http_requests_1s'] == 0 and result[2]['http_requests_1s'] == 1
    assert result[3]['http_requests_1s'] == 0


def test_window_expiration_and_clock_regression_fail_closed():
    window = HTTPWindow()
    first = window.observe(request(), 10)
    assert window.observe(request(), 71) == first
    with pytest.raises(ValueError, match='time_regression'):
        window.observe(request(), 70)


def test_unknown_client_and_time_do_not_manufacture_context():
    assert not HTTPWindow().observe(request(client='unknown'), 10)['http_window_available']
    assert not HTTPWindow().observe(request(), None)['http_window_available']


def test_explicit_model_profile_preserves_base_contract():
    base = raw_features(request())
    rich = {**base, **extra_observations(request())}
    with pytest.raises(ValueError, match='feature_population'):
        NativeBayes().observe_training(rich, True)
    model = NativeBayes(profile=PROFILE)
    for truth in (False, True):
        model.observe_training(rich, truth)
    assert model.export()['feature_profile'] == PROFILE and model.probability(rich) == .5
