from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models import SecurityEvent
from app.services.detection_benchmark import DetectionBenchmark
from scripts import evaluate_f1_shadow as evaluation
from scripts.f1_lab import detector as module
from scripts.f1_lab.approvals import (
    ApprovalContext,
    ApprovalVerifier,
    Authority,
    event_digest,
    sign,
)
from scripts.f1_lab.detector import RULE_IDS, DraftThresholds, ShadowDetector


@pytest.fixture
def event():
    return DetectionBenchmark().cases[0].event.model_copy(deep=True)


def with_context(event, deviations):
    now = datetime.now(UTC)
    event.timestamp = now
    key = Ed25519PrivateKey.generate()
    context = ApprovalContext(approval_id='approval-'+uuid4().hex, tenant_id='a',
        issuer_id='owner', key_id='key', event_sha256=event_digest(event), user_id=event.user.user_id,
        device_id=event.device.device_id, resource_id=event.resource.resource_id, action=event.action,
        permitted_deviations=deviations, maximum_download_mb=event.behavior.download_volume_mb,
        issued_at=now, expires_at=now+timedelta(minutes=1))
    authority = Authority('a', 'owner', 'key', key.public_key(), frozenset(deviations),
        frozenset({event.user.user_id}), frozenset({event.device.device_id}),
        frozenset({event.resource.resource_id}), frozenset({event.action}),
        now-timedelta(minutes=1), now+timedelta(hours=1))
    return ShadowDetector(approval_verifier=ApprovalVerifier((authority,))), sign(context, key), now


def test_signed_business_context_only_reduces_its_explicit_scoped_signal(event):
    assert ShadowDetector().evaluate(event, 'a')['detected']
    detector, proof, now = with_context(event, ['authentication_failure'])
    result = detector.evaluate(event, 'a', approval=proof, now=now)
    assert result['signed_context_status'] == 'verified' and not result['detected']
    assert result['context_only_suppressed_signals'] == ['REPEATED_AUTHENTICATION_FAILURE']
    assert result['access_grants'] == result['session_changes'] == result['external_calls'] == 0


@pytest.mark.parametrize('danger,domain', [('inactive', 'credential'), ('mfa_failed', 'credential'),
                                         ('compromised', 'device'), ('at_risk', 'device')])
def test_even_valid_business_context_cannot_remove_hard_danger_signals(event, danger, domain):
    if danger == 'inactive':
        event.user.active = False
    elif danger == 'mfa_failed':
        event.auth_context.mfa = 'failed'
    else:
        event.device.security_posture = danger
    detector, proof, now = with_context(event, ['authentication_failure', 'new_unmanaged_device'])
    result = detector.evaluate(event, 'a', approval=proof, now=now)
    assert result['signed_context_status'] == 'verified'
    assert RULE_IDS[domain] in result['predicted_rule_ids']
    assert result['access_grants'] == 0


def test_legacy_unsigned_flag_and_fake_approver_never_reduce_a_shadow_alert(event):
    original = ShadowDetector().evaluate(event, 'a')
    event.behavior.policy_exception_approved = True
    event.behavior.policy_exception = {'approved_by': 'admin', 'reason': 'trust me'}
    assert ShadowDetector().evaluate(event, 'a') == original


def test_wrong_tenant_or_expired_context_is_ignored_without_ignoring_danger(event):
    detector, proof, now = with_context(event, ['authentication_failure'])
    for tenant, instant in [('b', now), ('a', now+timedelta(minutes=2))]:
        result = detector.evaluate(event, tenant, approval=proof, now=instant)
        assert result['signed_context_status'] == 'rejected'
        assert result['detected'] and result['context_only_suppressed_signals'] == []


def test_missing_verifier_cannot_turn_signed_looking_data_into_approval(event):
    _, proof, now = with_context(event, ['authentication_failure'])
    result = ShadowDetector().evaluate(event, 'a', approval=proof, now=now)
    assert result['detected'] and result['signed_context_status'] == 'rejected'


@pytest.mark.parametrize('action', ['LOGIN', 'READ', 'DOWNLOAD', 'ADMIN', 'REMOTE_ACCESS'])
def test_unknown_unmanaged_new_device_is_visible_for_every_action(event, action):
    raw = event.analysis_payload()
    raw['action'] = action
    raw['device'].update(managed=False, security_posture='unknown')
    raw['behavior']['new_device'] = True
    if action == 'REMOTE_ACCESS':
        raw['network']['access_method'] = 'remote'
    result = ShadowDetector().evaluate(SecurityEvent.model_validate(raw), 'a')
    assert RULE_IDS['device'] in result['predicted_rule_ids']


def test_role_mismatch_is_not_limited_to_admin_operations(event):
    event.action = 'DOWNLOAD'
    event.user.role = 'viewer'
    event.resource.required_role = 'administrator'
    assert RULE_IDS['privilege'] in ShadowDetector().evaluate(event, 'a')['predicted_rule_ids']


def test_shadow_is_unavailable_in_production(event, monkeypatch):
    monkeypatch.setattr(module, 'get_settings', lambda: SimpleNamespace(app_environment='production'))
    with pytest.raises(ValueError, match='local_test_only'):
        ShadowDetector().evaluate(event, 'a')


@pytest.mark.parametrize('amount', [float('inf'), float('nan')])
def test_nonfinite_observations_cannot_bypass_thresholds(event, amount):
    event.behavior.download_volume_mb = amount
    with pytest.raises(ValueError, match='nonfinite'):
        ShadowDetector().evaluate(event, 'a')


def test_scoring_keeps_failed_inference_in_the_denominator_and_fails_gate():
    rows = [{'case_id': 'one', 'family_id': 'f', 'threat': True, 'detected': False,
             'expected_rule_ids': ['rule'], 'predicted_rule_ids': [], 'error': 'failed'}]
    result = evaluation.score(rows, ['rule'])
    assert result['case_count'] == 1 and result['confusion']['fn'] == 1
    assert result['evaluation_errors'] == 1 and not result['gate_passed']


def test_configuration_changes_are_fingerprinted():
    first = ShadowDetector()
    second = ShadowDetector(thresholds=DraftThresholds(resource_fanout=6))
    assert first.config_sha256 != second.config_sha256


def test_untyped_threshold_payload_cannot_replace_validated_configuration():
    with pytest.raises(TypeError, match='threshold_contract'):
        ShadowDetector(thresholds={'resource_fanout': 0})


def test_missing_resource_role_is_inconclusive_without_inventing_a_threat_label(event):
    event.action = 'ADMIN'
    event.user.active = True
    event.user.role = 'employee'
    event.resource.required_role = None
    event.device.managed = True
    event.device.security_posture = 'healthy'
    event.auth_context.authentication_result = 'success'
    event.auth_context.failed_attempts = 0
    event.auth_context.mfa = 'passed'
    event.network.access_method = 'internal'
    event.behavior.distinct_resources_10m = 1
    result = ShadowDetector().evaluate(event, 'a')
    assert result['evidence_gaps'] == ['RESOURCE_REQUIRED_ROLE_NOT_SUPPLIED']
    assert result['assessment_status'] == 'inconclusive' and not result['detected']
    assert result['no_alert_is_access_authorization'] is False


def test_small_sensitive_transfer_cannot_prove_the_absence_of_slow_cumulative_exfiltration(event):
    event.action = 'DOWNLOAD'
    event.resource.sensitivity = 'critical'
    event.behavior.download_volume_mb = 10
    result = ShadowDetector().evaluate(event, 'a')
    assert 'AUTHENTICATED_CUMULATIVE_VOLUME_NOT_ASSESSED' in result['evidence_gaps']
    assert result['access_grants'] == 0


def test_inconclusive_rows_remain_in_metric_denominators():
    rows = [{'case_id': 'one', 'family_id': 'f', 'threat': True, 'detected': False,
             'expected_rule_ids': ['rule'], 'predicted_rule_ids': [], 'error': None,
             'assessment_status': 'inconclusive'}]
    result = evaluation.score(rows, ['rule'])
    assert result['inconclusive_cases'] == result['case_count'] == result['confusion']['fn'] == 1
    assert result['inconclusive_kept_in_denominator'] and not result['gate_passed']
