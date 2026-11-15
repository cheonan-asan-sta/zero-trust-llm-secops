import json

import pytest

from scripts.f1_lab.native_bayes import NativeBayes, validate
from scripts.f1_lab.raw_context import PROFILE as OLD_PROFILE
from scripts.f1_lab.raw_context import extra_observations
from scripts.f1_lab.raw_observations import raw_features
from scripts.f1_lab.raw_semantics import (
    PROFILE,
    history_empty,
    ordered_auth_context,
    semantic_observations,
    subject_reference,
)


def request(target, agent='Mozilla/5.0'):
    return f'192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "GET {target} HTTP/1.1" 200 10 "-" "{agent}"\n'


def log(message, *, service='su', second=0, host='server'):
    return f'Jan 21 00:00:{second:02d} {host} {service}[123]: {message}\n'


def test_http_shapes_do_not_emit_host_account_parameter_or_path_identifiers():
    a = semantic_observations(request('/alice/report.php?tenant=alpha&id=123'))
    b = semantic_observations(request('/bobby/result.php?target=bravo&no=456'))
    assert a == b and a['http_semantic_available']
    assert a['http_path_extension'] == 'script'
    assert not any(value in str(a) for value in ('alice', 'tenant', '192.0.2', 'authorized', 'healthy'))


def test_twice_encoded_form_sql_is_an_observation_not_executed(tmp_path):
    marker = tmp_path/'not-created'
    observed = semantic_observations(request('/index.php?q=%2527+OR+123%253D123--&cmd=$(touch+'+str(marker)+')'))
    assert observed['http_percent_layers'] == 2 and observed['http_sql_boolean_comparison']
    assert observed['http_sql_comment'] and observed['http_shell_separator'] and not marker.exists()


def test_query_bound_does_not_turn_bad_uri_into_available_normal_context():
    observed = semantic_observations(request('/?'+('&'.join('x=1' for _ in range(65)))))
    assert observed['http_semantic_parse_error'] and not observed['http_semantic_available']


@pytest.mark.parametrize('target', ['http://[broken/', '//[broken/'])
def test_malformed_url_remains_parse_error(target):
    observed = semantic_observations(request(target))
    assert observed['http_semantic_parse_error'] and not observed['http_semantic_available']


@pytest.mark.parametrize('agent,expected', [('curl/7.0', 'http_client'), ('sqlmap/1', 'scanner'),
                                           ('Googlebot/2.1', 'bot'), ('Mozilla/5.0', 'browser')])
def test_claimed_agent_is_coarse_observation_without_device_health(agent, expected):
    observed = semantic_observations(request('/a.css', agent))
    assert observed['http_user_agent_kind'] == expected and observed['http_path_extension'] == 'static'
    assert not {'device_healthy', 'managed', 'mfa'} & observed.keys()


def test_audit_unset_missing_invalid_and_assigned_ids_stay_distinct():
    unset = semantic_observations('type=LOGIN uid=33 auid=4294967295 ses=4294967295 exe="/bin/su"')
    assert unset['auth_observed_uid_kind'] == 'system_range' and unset['audit_login_uid_available']
    assert not unset['audit_login_uid_assigned'] and unset['audit_program_kind'] == 'su'
    assigned = semantic_observations('type=LOGIN uid=1001 auid=1001 ses=12 ')
    assert assigned['audit_login_uid_assigned'] and assigned['audit_session_assigned']
    missing = semantic_observations('type=LOGIN uid=0 ')
    assert not missing['audit_login_uid_available'] and not missing['audit_session_available']
    invalid = semantic_observations('type=LOGIN uid=9999999999 auid=9999999999 ses=9999999999 ')
    assert invalid['auth_observed_uid_kind'] == 'unknown' and not invalid['audit_login_uid_available']


def test_http_text_cannot_manufacture_audit_or_root_authority_observations():
    observed = semantic_observations(request('/?text=uid=0+auid=0+ses=1+USER=root+exe="/bin/su"'))
    assert observed['auth_observed_uid_kind'] == 'unknown' and not observed['audit_login_uid_assigned']
    assert not observed['auth_target_root_observed'] and observed['audit_program_kind'] == 'none'


def test_root_prefix_is_not_the_root_account():
    assert semantic_observations(log('session opened for user root by (uid=33)'))['auth_target_root_observed']
    assert not semantic_observations(log('session opened for user root-admin by (uid=33)'))['auth_target_root_observed']


def test_subject_requires_explicit_account_and_expected_service_format():
    assert subject_reference(log('Successful su for alice by service')) is not None
    assert subject_reference(log('New session c1 of user alice.', service='systemd-logind')) == subject_reference(log('Successful su for alice by service'))
    assert subject_reference(log('Successful su for alice by service', service='unrelated')) is None
    assert subject_reference(log('unknown message')) is None


def test_auth_history_respects_source_order_ties_and_never_uses_future_rows():
    first = (1, 1, log('Successful su for alice by service'))
    second = (2, 1, log('New session c1 of user alice.', service='systemd-logind'))
    result = ordered_auth_context([second, first])
    assert not result[1]['auth_subject_prior_privilege_tool']
    assert result[2]['auth_subject_prior_privilege_tool']
    extended = ordered_auth_context([first, second, (3, 2, log('alice : TTY=pts/1 ; USER=root ; COMMAND=/bin/cat /etc/shadow', service='sudo'))])
    assert all(result[key] == extended[key] for key in result)


def test_account_names_are_only_local_link_keys_and_renaming_is_invariant():
    def replay(name):
        return ordered_auth_context([(1, 1, log('Successful su for '+name+' by daemon')),
                                     (2, 2, log('New session c1 of user '+name+'.', service='systemd-logind'))])
    assert replay('alice') == replay('bobby')
    isolated = ordered_auth_context([(1, 1, log('Successful su for alice by daemon')),
                                    (2, 2, log('New session c1 of user bobby.', service='systemd-logind'))])
    assert not isolated[2]['auth_subject_prior_privilege_tool']
    assert not ordered_auth_context([(1, 2, log('New session c1 of user alice.', service='systemd-logind'))])[1]['auth_subject_prior_privilege_tool']


def test_expiration_duplicate_and_missing_subject_do_not_inflate_or_merge():
    first = log('Successful su for alice by daemon')
    next_line = log('New session c1 of user alice.', service='systemd-logind')
    multiple = ordered_auth_context([(1, 1, first), (2, 1, first), (3, 2, next_line), (4, 63, next_line)])
    single = ordered_auth_context([(1, 1, first), (3, 2, next_line)])
    assert multiple[3] == single[3] and len(multiple) == 4
    assert not multiple[4]['auth_subject_prior_privilege_tool']
    assert ordered_auth_context([(1, None, first), (2, 2, 'no subject')]) == {1: history_empty(), 2: history_empty()}


@pytest.mark.parametrize('records', [[(1, True, log('x'))], [(1, float('nan'), log('x'))],
                                    [(1, 1, log('x')), (1, 2, log('x'))], [(1, 1, None)]])
def test_bad_context_inputs_are_rejected(records):
    with pytest.raises(ValueError):
        ordered_auth_context(records)


def test_profile_is_explicit_and_preserves_old_feature_contract():
    text = request('/a.php?q=UNION+SELECT')
    old = {**raw_features(text), **extra_observations(text)}
    validate(old, profile=OLD_PROFILE)
    new = {**old, **semantic_observations(text)}
    validate(new, profile=PROFILE)
    with pytest.raises(ValueError, match='feature_population'):
        validate(new, profile=OLD_PROFILE)
    model = NativeBayes(profile=PROFILE)
    for truth in (False, True):
        model.observe_training(new, truth)
    assert model.probability(new) == .5 and 'alice' not in json.dumps(model.export())
