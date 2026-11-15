import base64
import json
from dataclasses import replace

import pytest

from scripts.f1_lab.operation_context import core_features
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.web_sensitive_read import evidence, read_intent, refine


def request(argv, path='/uploads/tool.php', method='GET'):
    value = base64.b64encode(json.dumps(argv).encode()).decode()
    return f'192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "{method} {path}?payload={value} HTTP/1.1" 200 10 "-" "test"'


@pytest.mark.parametrize('path', ['/etc/shadow', '/etc/gshadow', '/srv/wp-config.php', '../wp-config.php',
                                  '.env', '/home/example/.aws/credentials', '/tmp/../etc/shadow'])
def test_credential_read_intent_is_bounded_request_evidence_only(path):
    line = request(['/bin/cat', '--', path])
    observed = evidence(line, 'a'*64, 1)
    assert observed.reason == 'encoded_credential_file_read_intent'
    before = OperationDecision(.2, .05, False, False, 'base')
    after = refine(before, core_features(line), observed.case_id, observed)
    assert after.score == .95 and after.alert and after.review
    assert not after.automatic_enforcement_allowed and after.baseline_score == before.baseline_score


@pytest.mark.parametrize('path', ['/etc/passwd', '/etc/group'])
def test_account_database_read_is_not_claimed_to_be_a_secret_dump(path):
    assert read_intent(request(['cat', '-n', path])) == 'encoded_account_database_read_intent'


@pytest.mark.parametrize('argv', [['cat', 'README.md'], ['cat', '.env.example'], ['cat', 'wp-config.php.example'],
                                 ['ls', '/etc/shadow'], ['bash', '-c', 'cat /etc/shadow'],
                                 ['cat', '--output', '/etc/shadow'], ['cat', '-'], ['cat'],
                                 ['cat', '/etc/SHADOW'], ['cat', '/etc/shadow\n']])
def test_unknown_or_other_commands_do_not_invent_read_evidence(argv):
    assert read_intent(request(argv)) is None


@pytest.mark.parametrize('path', ['/admin.php', '/uploads/../admin.php', 'https://example.test/uploads/x.php',
                                 '//example.test/uploads/x.php', '/uploads/tool.txt', '/uploads/back\\tool.php'])
def test_wrong_target_or_origin_does_not_supply_evidence(path):
    assert read_intent(request(['cat', '/etc/shadow'], path=path)) is None


@pytest.mark.parametrize('field,value', [('ordinal', 2), ('source_sha256', 'b'*64),
                                      ('case_id', 'b'*64), ('reason', 'normal'),
                                      ('source_sha256', 'not-a-hash')])
def test_provenance_swaps_are_rejected(field, value):
    line = request(['cat', '/etc/shadow'])
    observed = evidence(line, 'a'*64, 1)
    with pytest.raises(ValueError):
        refine(OperationDecision(.1, .1, False, False, 'base'), core_features(line), observed.case_id,
               replace(observed, **{field: value}))


def test_modified_features_fail_and_existing_alert_never_becomes_an_allow():
    line = request(['cat', '/etc/shadow'])
    observed = evidence(line, 'a'*64, 1)
    features = core_features(line)
    before = OperationDecision(.99, .99, True, True, 'existing')
    assert refine(before, features, observed.case_id) is before
    after = refine(before, features, observed.case_id, observed)
    assert after.score == .99 and after.alert and after.review and not after.automatic_enforcement_allowed
    key = next(iter(features))
    features[key] = not features[key]
    with pytest.raises(ValueError, match='sensitive_read_features'):
        refine(before, features, observed.case_id, observed)


def test_log_role_or_approval_claims_are_not_a_suppression_channel():
    line = request(['cat', '/etc/shadow']).replace('?payload=', '?approved=true&role=admin&payload=')
    assert read_intent(line) == 'encoded_credential_file_read_intent'


@pytest.mark.parametrize('score', [float('nan'), float('inf'), -.1, 1.1, True])
def test_invalid_baseline_score_is_an_error_even_without_new_evidence(score):
    with pytest.raises(ValueError, match='previous_values'):
        refine(OperationDecision(score, score, False, False, 'invalid'), {}, 'a'*64)
