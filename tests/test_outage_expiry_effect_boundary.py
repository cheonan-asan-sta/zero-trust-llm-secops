import copy
import hashlib

import pytest

from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.test_continuous_mtls_runtime import Checks

EVENT = 'runtime-outage-observation'


def history(expired):
    initial = {'version': 1, 'status': 'ACTIVE', 'decision': 'ALLOW',
        'tenant_id': 'local', 'session_id': 'runtime-outage', 'user_id': 'employee',
        'device_id': 'device', 'resource_id': 'documents', 'action': 'READ',
        'event_id': 'mint-fixture', 'reason_codes': ['POLICY_SATISFIED'], 'evidence': ['original'],
        'evaluated_at': '2026-11-14T01:00:00+00:00', 'grant_expires_at': '2026-11-14T01:01:00+00:00',
        'signal_expires_at': '2026-11-14T01:01:30+00:00', 'challenge_id': None, 'challenge_expires_at': None}
    result = [initial]
    if expired:
        result.append({**initial, 'version': 2, 'status': 'HELD', 'decision': 'HOLD',
            'event_id': 'check-fixture', 'reason_codes': ['POLICY_SATISFIED', 'SIGNAL_PROOF_EXPIRED'],
            'evaluated_at': '2026-11-14T01:01:31+00:00', 'grant_expires_at': None})
    previous = result[-1]
    result.append({**previous, 'version': previous['version']+1, 'status': 'REVOKED', 'decision': 'DENY',
        'reason_codes': [*previous['reason_codes'], 'CONTINUOUS_IDENTITY_DENY'],
        'evidence': [*previous['evidence'], 'identity:employee:'+EVENT],
        'event_id': 'obs-'+hashlib.sha256(('local.'+EVENT+'.runtime-outage').encode()).hexdigest(),
        'evaluated_at': '2026-11-14T01:02:00+00:00', 'grant_expires_at': None})
    return result


@pytest.mark.parametrize('expired', [False, True])
def test_exact_one_adverse_effect_with_or_without_separate_expiry(expired):
    value = history(expired)
    original = copy.deepcopy(value)
    result = object.__new__(Checks).outage_history(value, EVENT)
    assert result == {'history_versions': 3 if expired else 2, 'expiry_transitions': int(expired), 'adverse_transitions': 1}
    assert value == original


@pytest.mark.parametrize('change', ['duplicate_deny', 'revival', 'wrong_reason', 'wrong_event', 'wrong_evidence',
    'scope', 'version_gap', 'boolean_version', 'new_grant', 'new_challenge', 'missing_revoke',
    'premature_hold', 'hold_after_grant_before_proof_expiry', 'unrelated_hold', 'modified_hold_evidence'])
def test_unsafe_or_unbound_history_is_not_accepted_as_expiry_race(change):
    value = history(True)
    if change == 'duplicate_deny':
        value.append({**value[-1], 'version': 4})
    elif change == 'revival':
        value[-1].update(status='ACTIVE', decision='ALLOW')
    elif change == 'wrong_reason':
        value[-1]['reason_codes'][-1] = 'SIGNAL_SOURCE_REVOKED'
    elif change == 'wrong_event':
        value[-1]['event_id'] = 'obs-'+'0'*64
    elif change == 'wrong_evidence':
        value[-1]['evidence'][-1] = 'identity:other:'+EVENT
    elif change == 'scope':
        value[1]['device_id'] = 'other'
    elif change == 'version_gap':
        value[-1]['version'] = 4
    elif change == 'boolean_version':
        value[0]['version'] = True
    elif change == 'new_grant':
        value[-1]['grant_expires_at'] = '2026-11-14T01:10:00+00:00'
    elif change == 'new_challenge':
        value[-1]['challenge_id'] = 'new'
    elif change == 'missing_revoke':
        value.pop()
    elif change in {'premature_hold', 'hold_after_grant_before_proof_expiry'}:
        value[1]['evaluated_at'] = ('2026-11-14T01:00:50+00:00' if change == 'premature_hold'
                                    else '2026-11-14T01:01:10+00:00')
    elif change == 'unrelated_hold':
        value[1]['reason_codes'][-1] = 'CONTINUOUS_DEVICE_HOLD'
    else:
        value[1]['evidence'] = ['replacement']
    with pytest.raises(RuntimeFailure, match='outage_policy'):
        object.__new__(Checks).outage_history(value, EVENT)
