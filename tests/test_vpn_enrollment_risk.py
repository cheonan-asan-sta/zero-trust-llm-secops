"""Fresh explicit enrollment revocation is an adverse fact, not missing proof."""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.vpn_gateway_collector import collect_connection
from scripts.f1_lab.vpn_risk_retention import RiskRetention
from scripts.f1_lab.vpn_signal_controls import VPNControls, arguments, sha
from scripts.f1_lab.vpn_verified_signals import VerifiedVPNRisk
from tests.test_vpn_gateway_collector import CLAIMS, connected


@pytest.mark.parametrize('revoked', [False,True])
def test_real_tls_revocation_adds_alert_even_when_original_detector_misses(tmp_path, revoked, record_property):
    observation, _ = connected(tmp_path, lambda tls: collect_connection(tls, **CLAIMS))
    baseline = RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.),
        SimpleNamespace(profile=PROFILE, probability=lambda _: 0.)))
    c = VPNControls(tmp_path/'control', baseline, now=observation.connection.observed_at)
    c.enrollment_registry['bindings'][0].update(client_certificate_sha256=observation.connection.client_certificate_sha256,
                                              enabled=not revoked)
    c.write()
    c.enrollments.expected_sha256 = sha(c.directory/'enrollments.json')
    row = c.build(gateway_observation=observation)
    before = baseline.decide(row['features'],row['case_id'],row['context'])
    after = VerifiedVPNRisk(baseline,c.bridge).decide(**arguments(row))
    assert not before.alert and after.alert is revoked
    assert after.evidence_state == ('adverse' if revoked else 'approved')
    assert not after.automatic_enforcement_allowed
    record_property('policy_control_kind','vpn')
    record_property('expected_policy_alert',str(revoked).lower())
    record_property('before_alert',str(before.alert).lower())
    record_property('after_alert',str(after.alert).lower())
    record_property('baseline_scores_are_fixture_inputs','true')


@pytest.mark.parametrize('untrusted', ['hash','wrong_device','missing_identity','missing_gateway_signature'])
def test_missing_or_untrusted_evidence_is_never_called_verified_revocation(tmp_path, untrusted):
    baseline = RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.),
        SimpleNamespace(profile=PROFILE, probability=lambda _: 0.)))
    c = VPNControls(tmp_path/'control',baseline)
    c.enrollment_registry['bindings'][0]['enabled'] = False
    if untrusted == 'wrong_device':
        c.enrollment_registry['bindings'][0]['device_id'] = 'other'
    c.write()
    c.enrollments.expected_sha256 = sha(c.directory/'enrollments.json')
    row = c.build()
    if untrusted == 'hash':
        (c.directory/'enrollments.json').write_bytes(b'{}')
    elif untrusted == 'missing_identity':
        row['evidence'] = row['evidence'].model_copy(update={'identity':None})
    elif untrusted == 'missing_gateway_signature':
        row['evidence'] = row['evidence'].model_copy(update={'binding':row['evidence'].binding.model_copy(update={'signature':'A'*86})})
    after = VerifiedVPNRisk(baseline,c.bridge).decide(**arguments(row))
    assert not after.alert and after.evidence_state == 'unavailable'


def test_recent_verified_revocation_is_not_erased_by_quick_reenrollment(tmp_path):
    baseline = RiskRetention(OperationRefinement(SimpleNamespace(probability=lambda _: 0.),
        SimpleNamespace(profile=PROFILE, probability=lambda _: 0.)))
    c=VPNControls(tmp_path/'control',baseline)
    c.enrollment_registry['bindings'][0]['enabled']=False
    c.write()
    c.enrollments.expected_sha256=sha(c.directory/'enrollments.json')
    model=VerifiedVPNRisk(baseline,c.bridge)
    assert model.decide(**arguments(c.build())).alert
    c.enrollment_registry['bindings'][0]['enabled']=True
    c.enrollment_registry['version']=2
    c.write()
    c.enrollments.expected_sha256=sha(c.directory/'enrollments.json')
    later=c.build(index=2,now=c.now+timedelta(seconds=1))
    result=model.decide(**arguments(later))
    assert result.alert and result.reason=='vpn_recent_verified_adverse'
